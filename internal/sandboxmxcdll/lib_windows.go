//go:build windows

package sandboxmxcdll

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/marmutapp/superbased-observer/internal/sandboxmxc"
)

// lib_windows.go is the real I/O: files opened denying writers, the
// Authenticode check through WinVerifyTrust on the held handle, and the
// library loaded with LoadLibraryEx from the bundle directory (its
// dependencies resolved from that directory and System32 only), its
// functions called through SyscallN. No CGO.

// HostEnv is the real I/O for the bundle in dir.
func HostEnv(dir string, active bool, probeDoc, checkDoc []byte) Env {
	m, ok := sandboxmxc.ManifestFor(runtime.GOARCH)
	return Env{
		Windows: true, Active: active, Build: windowsBuild, Dir: dir,
		Manifest: m, HasPinnedSet: ok,
		Open: openHeld, Verify: verifyAuthenticode, Load: loadLibrary,
		ProbeDoc: probeDoc, CheckDoc: checkDoc,
	}
}

// windowsBuild reads the build and UBR (RtlGetVersion is not shimmed;
// the UBR and the edition are only in the registry).
func windowsBuild() (int, int, string) {
	v := windows.RtlGetVersion()
	build := int(v.BuildNumber)
	ubr, edition := 0, ""
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err == nil {
		if n, _, err := k.GetIntegerValue("UBR"); err == nil {
			ubr = int(n)
		}
		if s, _, err := k.GetStringValue("EditionID"); err == nil {
			edition = s
		}
		_ = k.Close()
	}
	return build, ubr, edition
}

// openHeld opens path for reading with only read sharing (no writer, no
// delete or rename while it is held) and refuses a reparse point.
func openHeld(path string) (HeldFile, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil,
		windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		_ = windows.CloseHandle(h)
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		_ = windows.CloseHandle(h)
		return nil, fmt.Errorf("%s is a link or a directory", path)
	}
	return os.NewFile(uintptr(h), path), nil
}

// verifyAuthenticode checks the embedded signature of the held file (the
// handle, so the bytes checked are the bytes hashed). Revocation is not
// fetched (no network call from a sandbox probe); the hash pin, taken
// from a file whose signature the release job verified, is the primary
// check.
func verifyAuthenticode(path string, hf HeldFile) error {
	f, ok := hf.(*os.File)
	if !ok {
		return errors.New("not a held file")
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	fi := windows.WinTrustFileInfo{Size: uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})), FilePath: p, File: windows.Handle(f.Fd())}
	data := &windows.WinTrustData{
		Size:                            uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:                        windows.WTD_UI_NONE,
		RevocationChecks:                windows.WTD_REVOKE_NONE,
		UnionChoice:                     windows.WTD_CHOICE_FILE,
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(&fi),
		ProvFlags:                       windows.WTD_CACHE_ONLY_URL_RETRIEVAL,
	}
	verr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	_ = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	runtime.KeepAlive(&fi)
	return verr
}

// dll is the loaded mxc_ffi.
type dll struct {
	mu     sync.Mutex
	h      windows.Handle
	procs  map[string]uintptr
	closed bool
}

// The exports this driver calls.
var dllExports = []string{
	"mxc_version", "mxc_probe_request_json_with_error", "mxc_run_json",
	"mxc_run_result_free", "mxc_string_free", "mxc_error_detail_free",
}

// loadLibrary loads mxc_ffi from the held file's path. LOAD_LIBRARY_SEARCH
// flags keep the loader from searching the current directory or PATH for
// the library's own dependencies.
func loadLibrary(path string, _ HeldFile) (Library, error) {
	h, err := windows.LoadLibraryEx(path, 0, windows.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	if err != nil {
		return nil, fmt.Errorf("LoadLibraryEx: %w", err)
	}
	d := &dll{h: h, procs: map[string]uintptr{}}
	for _, name := range dllExports {
		p, err := windows.GetProcAddress(h, name)
		if err != nil {
			_ = windows.FreeLibrary(h)
			return nil, fmt.Errorf("the library has no %s: %w", name, err)
		}
		d.procs[name] = p
	}
	return d, nil
}

func (d *dll) call(name string, args ...uintptr) uintptr {
	r, _, _ := syscall.SyscallN(d.procs[name], args...)
	return r
}

// cstr copies a NUL-terminated UTF-8 string the library returned.
func cstr(p uintptr) string {
	if p == 0 {
		return ""
	}
	// Reinterpret the word without a uintptr-to-Pointer conversion: the
	// pointer is owned by the library, never by the Go heap.
	return windows.BytePtrToString(*(**byte)(unsafe.Pointer(&p)))
}

// errorDetail is MxcErrorDetail (four owned char pointers).
type errorDetail struct {
	Message, Operation, NativeCode, Remediation uintptr
}

func (e errorDetail) native(status int) *NativeError {
	return &NativeError{Status: status, Message: cstr(e.Message), Operation: cstr(e.Operation), NativeCode: cstr(e.NativeCode), Remediation: cstr(e.Remediation)}
}

// runResult is MxcRunResult (x64 layout: three int32, padding, then
// pointers).
type runResult struct {
	Status, ExitCode, TimedOut int32
	_                          int32
	Stdout, Stderr             uintptr
	Error                      errorDetail
	Metadata, Warnings         uintptr
}

func (d *dll) Version() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return ""
	}
	return cstr(d.call("mxc_version"))
}

func cbytes(doc []byte) ([]byte, error) {
	if len(doc) == 0 || strings.IndexByte(string(doc), 0) >= 0 {
		return nil, errors.New("a request document must be non-empty and contain no NUL")
	}
	return append(append([]byte(nil), doc...), 0), nil
}

func (d *dll) ProbeRequest(doc []byte) ([]byte, error) {
	req, err := cbytes(doc)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil, errors.New("library closed")
	}
	var out uintptr
	var detail errorDetail
	st := int32(d.call("mxc_probe_request_json_with_error", uintptr(unsafe.Pointer(&req[0])), uintptr(unsafe.Pointer(&out)), uintptr(unsafe.Pointer(&detail)))) //nolint:gosec // G115: a C int status
	runtime.KeepAlive(req)
	if st != 0 {
		e := detail.native(int(st))
		d.call("mxc_error_detail_free", uintptr(unsafe.Pointer(&detail)))
		return nil, e
	}
	if out == 0 {
		return nil, errors.New("the probe returned a null answer")
	}
	s := cstr(out)
	d.call("mxc_string_free", out)
	return []byte(s), nil
}

func (d *dll) RunOneShot(doc []byte) (RunResult, error) {
	req, err := cbytes(doc)
	if err != nil {
		return RunResult{}, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return RunResult{}, errors.New("library closed")
	}
	var r runResult
	st := int32(d.call("mxc_run_json", uintptr(unsafe.Pointer(&req[0])), 0, uintptr(unsafe.Pointer(&r)))) //nolint:gosec // G115: a C int status
	runtime.KeepAlive(req)
	out := RunResult{Status: int(st), ExitCode: int(r.ExitCode), TimedOut: r.TimedOut != 0, Warnings: cstr(r.Warnings), Stdout: capped(cstr(r.Stdout))}
	if st != 0 {
		out.Error = r.Error.native(int(st))
	}
	d.call("mxc_run_result_free", uintptr(unsafe.Pointer(&r)))
	return out, nil
}

// capped keeps at most MaxCapturedOutput bytes.
func capped(s string) string {
	if len(s) > MaxCapturedOutput {
		return s[:MaxCapturedOutput]
	}
	return s
}

func (d *dll) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	return windows.FreeLibrary(d.h)
}

// tokenIsAppContainer is TOKEN_INFORMATION_CLASS TokenIsAppContainer.
const tokenIsAppContainer = 29

// InsideAppContainer reports whether this process runs with an AppContainer
// token: a fact a box cannot forge, since a ProcessContainer child can
// never drop its AppContainer token. It is not, alone, proof of an
// Observer box (any vendor's AppContainer has one): AppContainerSID, held
// against the SID the run's host helper read from the box process
// (ProcessTree), lets the caller check the container is its own (audit
// finding F1).
func InsideAppContainer() bool {
	var v uint32
	var n uint32
	err := windows.GetTokenInformation(windows.GetCurrentProcessToken(), tokenIsAppContainer, (*byte)(unsafe.Pointer(&v)), uint32(unsafe.Sizeof(v)), &n)
	return err == nil && v != 0
}

// tokenAppContainerSid is TOKEN_INFORMATION_CLASS TokenAppContainerSid.
const tokenAppContainerSid = 31

// AppContainerSID returns this process's AppContainer SID in string form,
// and whether the process runs with an AppContainer token at all (the SID
// is "" when it cannot be read).
func AppContainerSID() (string, bool) {
	return tokenAppContainerSID(windows.GetCurrentProcessToken())
}

// tokenAppContainerSID is tok's AppContainer SID in string form, and
// whether tok is an AppContainer token at all (the SID is "" when it
// cannot be read).
func tokenAppContainerSID(tok windows.Token) (string, bool) {
	var v, vn uint32
	if err := windows.GetTokenInformation(tok, tokenIsAppContainer, (*byte)(unsafe.Pointer(&v)), uint32(unsafe.Sizeof(v)), &vn); err != nil || v == 0 {
		return "", false
	}
	var n uint32
	_ = windows.GetTokenInformation(tok, tokenAppContainerSid, nil, 0, &n)
	if n == 0 || n > 4096 {
		return "", true
	}
	buf := make([]byte, n)
	if err := windows.GetTokenInformation(tok, tokenAppContainerSid, &buf[0], n, &n); err != nil {
		return "", true
	}
	// TOKEN_APPCONTAINER_INFORMATION is one PSID; the SID it points at
	// lives in the same buffer.
	sid := *(**windows.SID)(unsafe.Pointer(&buf[0]))
	if sid == nil {
		return "", true
	}
	s := sid.String()
	runtime.KeepAlive(buf)
	return s, true
}

// procDeriveAppContainerSid is userenv's DeriveAppContainerSidFromAppContainerName.
var procDeriveAppContainerSid = windows.NewLazySystemDLL("userenv.dll").NewProc("DeriveAppContainerSidFromAppContainerName")

// AppContainerProfileSID derives the SID of the AppContainer profile named
// name, in string form. Box detection uses it only to say, on a mismatch,
// which SID a profile named after the run's containerId would have: MXC
// 1.0.1 names its AppContainer profile itself, not after the containerId
// (Windows 11 Pro rerun 2026-10-22; sandboxmxc/identity.go).
func AppContainerProfileSID(name string) (string, error) {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return "", err
	}
	if err := procDeriveAppContainerSid.Find(); err != nil {
		return "", err
	}
	var sid *windows.SID
	hr, _, _ := procDeriveAppContainerSid.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&sid)))
	if hr != 0 || sid == nil {
		return "", fmt.Errorf("DeriveAppContainerSidFromAppContainerName: 0x%x", hr)
	}
	defer func() { _ = windows.FreeSid(sid) }()
	return sid.String(), nil
}

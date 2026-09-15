//go:build windows

package termsession

import (
	"fmt"
	"os"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// newOSSpawner returns the native-Windows ConPTY-backed spawner. It launches
// an observer launcher inside a pseudoconsole (ConPTY, Win10 1809+) and reaps
// the whole child tree through a job object with KILL_ON_JOB_CLOSE — the
// Windows analog of the unix Setsid→kill(-pgid) tree reap. CGO-free: every
// call goes through golang.org/x/sys/windows.
func newOSSpawner() Spawner { return windowsSpawner{} }

// conPTYAvailable reports whether kernel32 exposes CreatePseudoConsole. It is
// present on Windows 10 1809 (build 17763) and later; on older Windows the
// probe fails and the launch seam stays unwired (the "Launch here" button is
// hidden — the honest fallback). Computed once.
var conPTYAvailable = sync.OnceValue(func() bool {
	return windows.NewLazySystemDLL("kernel32.dll").NewProc("CreatePseudoConsole").Find() == nil
})

// ptySupported reports whether this Windows host can host the embedded
// terminal. True on a ConPTY-capable host — so cmd wires the launch seam and
// the dashboard shows the "Launch here" button natively, no WSL required.
func ptySupported() bool { return conPTYAvailable() }

type windowsSpawner struct{}

// Spawn builds a pseudoconsole around a server-derived launcher argv, starts
// the process attached to it inside a kill-on-close job object, and returns a
// conPTY. On failure every allocated handle is released before returning.
func (windowsSpawner) Spawn(spec Spec) (PTY, error) {
	if !conPTYAvailable() {
		return nil, ErrPlatformUnsupported
	}

	// Resolve argv[0] BEFORE allocating any handle: CreateProcess with a NULL
	// lpApplicationName appends only ".exe" and never consults %PATHEXT%, so a
	// bare `npm` (which ships as npm.cmd) would fail with
	// ERROR_FILE_NOT_FOUND. The resolved absolute path is passed as
	// lpApplicationName AND kept as argv[0] in the command line — the child's
	// GetCommandLineW is lpCommandLine verbatim, so dropping argv[0] would
	// shift every argument. .cmd/.bat needs no %COMSPEC% wrapper: the loader
	// recognises the extension and re-launches through cmd.exe itself (that is
	// what os/exec does too). SECURITY INVARIANT: launching a .cmd/.bat via
	// CreateProcess IS the BatBadBut vector (CVE-2024-24576) whenever an
	// attacker influences argv — it is safe here ONLY because every argv token
	// is a compile-time registry constant (the request contributes a map key,
	// never a token). A hand-built cmd.exe wrapper would not change that
	// invariant and would add cmd's own quote-stripping bugs. Keep argv
	// server-derived. (DI-01)
	argv, err := resolveSpawnArgv(spec.argv())
	if err != nil {
		return nil, err
	}

	cols, rows := spec.Cols, spec.Rows
	if cols == 0 {
		cols = 80
	}
	if rows == 0 {
		rows = 24
	}

	// Two pipes: one feeds the child's input (we keep the write end), one
	// drains its output (we keep the read end). ConPTY takes the opposite
	// ends and holds its own references, so we close our copies of those
	// after CreatePseudoConsole.
	var inRead, inWrite, outRead, outWrite windows.Handle
	if err := windows.CreatePipe(&inRead, &inWrite, nil, 0); err != nil {
		return nil, fmt.Errorf("termsession: create input pipe: %w", err)
	}
	if err := windows.CreatePipe(&outRead, &outWrite, nil, 0); err != nil {
		_ = windows.CloseHandle(inRead)
		_ = windows.CloseHandle(inWrite)
		return nil, fmt.Errorf("termsession: create output pipe: %w", err)
	}

	var hpc windows.Handle
	err = windows.CreatePseudoConsole(windows.Coord{X: int16(cols), Y: int16(rows)}, inRead, outWrite, 0, &hpc)
	// ConPTY now holds its own references to the ends it consumes.
	_ = windows.CloseHandle(inRead)
	_ = windows.CloseHandle(outWrite)
	if err != nil {
		_ = windows.CloseHandle(inWrite)
		_ = windows.CloseHandle(outRead)
		return nil, fmt.Errorf("termsession: create pseudoconsole: %w", err)
	}

	// cleanup releases everything allocated so far; used on every error path
	// after the ConPTY exists but before we hand ownership to a conPTY.
	cleanup := func() {
		windows.ClosePseudoConsole(hpc)
		_ = windows.CloseHandle(inWrite)
		_ = windows.CloseHandle(outRead)
	}

	// STARTUPINFOEX carrying the pseudoconsole as a proc-thread attribute.
	attrList, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("termsession: alloc attribute list: %w", err)
	}
	defer attrList.Delete()
	if err := attrList.Update(
		windows.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
		handleAttrValue(&hpc),
		unsafe.Sizeof(hpc),
	); err != nil {
		cleanup()
		return nil, fmt.Errorf("termsession: set pseudoconsole attribute: %w", err)
	}

	var si windows.StartupInfoEx
	si.Cb = uint32(unsafe.Sizeof(si))
	si.ProcThreadAttributeList = attrList.List()
	// Bind the child's standard handles to the PSEUDOCONSOLE, not to the
	// daemon's own stdio. Without STARTF_USESTDHANDLES the child inherits the
	// parent's standard handles; the console re-resolves inherited CONSOLE
	// handles when the child attaches to the pseudoconsole, but PIPE and FILE
	// handles are not re-resolved. So a daemon whose stdio is redirected — the
	// normal shape: `observer start > log`, nohup, a service wrapper, and `go
	// test` — hands every terminal child a stdin already at EOF and a stdout
	// that bypasses the terminal into the daemon's log (the "exited, exit 0,
	// no output" symptom, DI-08b). NULL handles here make the console attach
	// assign CONIN$/CONOUT$ instead, which is what we want.
	//
	// Caveat, stated honestly: STARTF_USESTDHANDLES is documented as requiring
	// inheritable handles and bInheritHandles=TRUE (vacuous for NULL), while
	// CreateProcess documents these fields as "copied unchanged … without
	// validation". This is therefore INFERENCE FROM MEASURED BEHAVIOUR on
	// Windows 11 build 26200 (verified with both a console-parent and a
	// pipe-parent), which is why TestConPTYSpawnCapturesStdout pins it — that
	// test runs under `go test`'s piped stdio, i.e. the failing shape. The
	// spec-conformant fallback, if a future build breaks this, is to point the
	// three handles at the ConPTY pipe ends with bInheritHandles=true plus a
	// PROC_THREAD_ATTRIBUTE_HANDLE_LIST naming exactly them — at the cost of
	// interleaving the child's raw bytes with conhost's VT stream.
	si.Flags |= windows.STARTF_USESTDHANDLES
	si.StdInput, si.StdOutput, si.StdErr = 0, 0, 0

	// Job object: TerminateJobObject (or closing the last handle) reaps the
	// whole `observer <tool>` → `<tool>` tree — the unix kill(-pgid) analog.
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("termsession: create job object: %w", err)
	}
	var jeli windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	jeli.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&jeli)),
		uint32(unsafe.Sizeof(jeli)),
	); err != nil {
		_ = windows.CloseHandle(job)
		cleanup()
		return nil, fmt.Errorf("termsession: configure job object: %w", err)
	}

	// Command line from the validated, server-derived argv (never client
	// argv), with the LookPath-resolved argv[0] kept in place.
	// ComposeCommandLine applies Windows quoting.
	cmdline, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(argv))
	if err != nil {
		_ = windows.CloseHandle(job)
		cleanup()
		return nil, fmt.Errorf("termsession: build command line: %w", err)
	}
	// lpApplicationName: the absolute program path. Passing it also removes
	// CreateProcess's implicit current-directory search (small hardening).
	appName, err := windows.UTF16PtrFromString(argv[0])
	if err != nil {
		_ = windows.CloseHandle(job)
		cleanup()
		return nil, fmt.Errorf("termsession: build application name: %w", err)
	}
	// lpCurrentDirectory: the child's working directory. A fresh launch sets
	// Spec.Dir to the operator-allow-listed, canonicalized project root; empty
	// (a handoff launch) keeps nil = inherit the daemon's cwd, matching unix's
	// cmd.Dir semantics. Before this it was ALWAYS nil on Windows, so the
	// validated project root was decorative there.
	var dir *uint16
	if spec.Dir != "" {
		dir, err = windows.UTF16PtrFromString(spec.Dir)
		if err != nil {
			_ = windows.CloseHandle(job)
			cleanup()
			return nil, fmt.Errorf("termsession: build working directory: %w", err)
		}
	}

	flags := uint32(windows.CREATE_SUSPENDED | windows.EXTENDED_STARTUPINFO_PRESENT)
	var env *uint16
	if spec.Env != nil {
		block, err := makeEnvBlock(spec.Env)
		if err != nil {
			_ = windows.CloseHandle(job)
			cleanup()
			return nil, fmt.Errorf("termsession: build environment: %w", err)
		}
		env = block
		flags |= windows.CREATE_UNICODE_ENVIRONMENT
	}

	// Start suspended so we can assign the child to the job BEFORE it runs —
	// no descendant can escape the tree kill.
	//
	// bInheritHandles stays false: Spec.ExtraFiles (the out-of-band control
	// channel the unix backend inherits at fd 3) is UNIMPLEMENTED on Windows,
	// so a Windows daemon's children get OBSERVER_OOB_FD=3 with no handle
	// behind it and OOB correlation never fires there (honest-zero gap). If it
	// is implemented later it needs bInheritHandles=true plus a
	// PROC_THREAD_ATTRIBUTE_HANDLE_LIST naming exactly that handle — which is
	// compatible with the NULL standard handles set above.
	var pi windows.ProcessInformation
	if err := windows.CreateProcess(appName, cmdline, nil, nil, false, flags, env, dir, &si.StartupInfo, &pi); err != nil {
		_ = windows.CloseHandle(job)
		cleanup()
		return nil, fmt.Errorf("termsession: create process for observer %s: %w", spec.Subcommand, err)
	}

	if err := windows.AssignProcessToJobObject(job, pi.Process); err != nil {
		_ = windows.TerminateProcess(pi.Process, 1)
		_ = windows.CloseHandle(pi.Thread)
		_ = windows.CloseHandle(pi.Process)
		_ = windows.CloseHandle(job)
		cleanup()
		return nil, fmt.Errorf("termsession: assign job object: %w", err)
	}
	if _, err := windows.ResumeThread(pi.Thread); err != nil {
		_ = windows.TerminateJobObject(job, 1)
		_ = windows.CloseHandle(pi.Thread)
		_ = windows.CloseHandle(pi.Process)
		_ = windows.CloseHandle(job)
		cleanup()
		return nil, fmt.Errorf("termsession: resume thread: %w", err)
	}
	_ = windows.CloseHandle(pi.Thread)

	return &conPTY{
		hpc:     hpc,
		job:     job,
		process: pi.Process,
		pid:     int(pi.ProcessId),
		in:      os.NewFile(uintptr(inWrite), "conpty-in"),
		out:     os.NewFile(uintptr(outRead), "conpty-out"),
	}, nil
}

// The windows backend reports its child's pid, so the Manager can publish a
// ProcessEvent for it (compile-time pin — the unix sibling has the same
// assertion, so neither platform can silently lose the seam).
var _ ProcessReporter = (*conPTY)(nil)

// conPTY wraps a ConPTY (hpc) + its job object + the launcher process. The
// pipe ends are wrapped as *os.File so Read/Write get the runtime's poller
// (concurrent Read/Close is safe). Handle ownership is split to avoid any
// double-close: Wait closes the process handle (it runs exactly once, from
// the manager's waitExit); Kill terminates+closes the job; the ConPTY and
// pipes close once via teardownOnce (shared by Kill and Close).
type conPTY struct {
	hpc     windows.Handle
	job     windows.Handle
	process windows.Handle
	pid     int      // OS pid of the launcher child (ProcessInformation.ProcessId)
	in      *os.File // child stdin (we write keystrokes here)
	out     *os.File // child stdout (we read terminal output here)

	killOnce     sync.Once
	teardownOnce sync.Once
	procOnce     sync.Once
}

// Pid implements [ProcessReporter]: the OS pid of the launcher child inside
// the kill-on-close job object. It is the Windows counterpart of the unix
// process-group leader pid — the whole `observer <tool>` → `<tool>` job hangs
// off it — so an injected process-attribution sink can seed against it
// identically on both platforms.
func (p *conPTY) Pid() int { return p.pid }

func (p *conPTY) Read(b []byte) (int, error)  { return p.out.Read(b) }
func (p *conPTY) Write(b []byte) (int, error) { return p.in.Write(b) }

func (p *conPTY) Resize(rows, cols uint16) error {
	if cols == 0 {
		cols = 80
	}
	if rows == 0 {
		rows = 24
	}
	return windows.ResizePseudoConsole(p.hpc, windows.Coord{X: int16(cols), Y: int16(rows)})
}

// Wait blocks until the launcher process exits and returns its exit code. It
// is the sole owner of the process handle close (the manager calls it exactly
// once); TerminateJobObject in Kill unblocks it by killing the process.
func (p *conPTY) Wait() (int, error) {
	defer p.procOnce.Do(func() { _ = windows.CloseHandle(p.process) })
	if _, err := windows.WaitForSingleObject(p.process, windows.INFINITE); err != nil {
		return -1, fmt.Errorf("termsession: wait: %w", err)
	}
	var code uint32
	if err := windows.GetExitCodeProcess(p.process, &code); err != nil {
		return -1, fmt.Errorf("termsession: exit code: %w", err)
	}
	return int(code), nil
}

// closeMaster releases the pseudoconsole and both pipe ends exactly once.
// Closing the ConPTY signals the child EOF; closing the pipes unblocks any
// pending Read. Shared by Kill and Close.
//
// ORDER IS LOAD-BEARING: ClosePseudoConsole flushes the remaining output and,
// per its documentation, the caller must "either close the output pipe before
// calling ClosePseudoConsole or … continue reading from the pipe until after
// ClosePseudoConsole has returned"; on builds before 26100 it otherwise "will
// wait indefinitely". Close() runs this with the child still alive and nothing
// draining, so we close the OUTPUT pipe first, then the pseudoconsole, then
// the input pipe.
func (p *conPTY) closeMaster() {
	p.teardownOnce.Do(func() {
		_ = p.out.Close()
		windows.ClosePseudoConsole(p.hpc)
		_ = p.in.Close()
	})
}

// Kill force-reaps the whole child tree and releases the job + master
// handles. Idempotent. The process handle itself is closed by Wait.
func (p *conPTY) Kill() error {
	p.killOnce.Do(func() {
		_ = windows.TerminateJobObject(p.job, 1)
		_ = windows.CloseHandle(p.job)
	})
	p.closeMaster()
	return nil
}

// Close releases the master handles without force-killing the child (used
// when detaching); Kill is the authoritative teardown.
func (p *conPTY) Close() error {
	p.closeMaster()
	return nil
}

// handleAttrValue returns the lpValue UpdateProcThreadAttribute expects for a
// handle-VALUED proc-thread attribute such as
// PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, whose value IS the HPCON itself (MS's
// own ConPTY sample passes hPC directly as lpValue, not &hPC — passing the
// address would hand the console a pointer where it reads a handle).
//
// It reinterprets the handle variable's own memory rather than writing
// unsafe.Pointer(uintptr(h)). That direct conversion is what `go vet`'s
// unsafeptr check flags, and the check is right to flag it in general: the
// compiler and GC treat unsafe.Pointer as a real pointer, so materialising one
// out of an arbitrary integer is exactly the pattern that hides bugs. Reading
// the bytes through a *windows.Handle keeps every conversion pointer-typed
// (vet-clean, no behaviour change) and mirrors what the C call does when it
// passes a HANDLE in an LPVOID slot. The value never leaves this call, and an
// OS handle lies outside every Go heap span, so the GC simply ignores it.
func handleAttrValue(h *windows.Handle) unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(h))
}

// makeEnvBlock builds a double-NUL-terminated UTF-16 environment block from a
// KEY=VALUE slice. nil → inherit the daemon's block; the dashboard launcher
// passes an explicit block built by launchChildEnv (daemon env + ExtraEnv +
// widened PATH + OOB vars, case-deduped), so this is the common path there.
func makeEnvBlock(env []string) (*uint16, error) {
	var buf []uint16
	for _, e := range env {
		u, err := windows.UTF16FromString(e)
		if err != nil {
			return nil, err
		}
		buf = append(buf, u...) // includes the trailing NUL
	}
	buf = append(buf, 0) // extra NUL terminates the block
	if len(buf) < 2 {
		buf = []uint16{0, 0} // an empty block is still two NULs
	}
	return &buf[0], nil
}

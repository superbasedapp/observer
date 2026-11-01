//go:build windows

package sandboxmxcdll

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/marmutapp/superbased-observer/internal/sandboxmxc"
)

// desktop_windows.go gives a run's box a desktop of its own (Windows 11 Pro
// rerun 2026-10-25, D1; sandboxmxc/ui.go): the host helper creates it on
// its own window station with the DACL sandboxmxc.DesktopSDDL builds, starts
// wxc-exec on it through STARTUPINFO.lpDesktop (MXC 1.0.1 starts the box on
// the desktop wxc-exec runs on), narrows the box's entry to the box's own
// AppContainer SID once it is read, and closes it when the run ends.
// WinSta0\Default is never changed.

var (
	user32                  = windows.NewLazySystemDLL("user32.dll")
	procCreateDesktopW      = user32.NewProc("CreateDesktopW")
	procCloseDesktop        = user32.NewProc("CloseDesktop")
	procOpenDesktopW        = user32.NewProc("OpenDesktopW")
	procGetProcessWinSta    = user32.NewProc("GetProcessWindowStation")
	procGetUserObjectInfoW  = user32.NewProc("GetUserObjectInformationW")
	procCreateWindowStation = user32.NewProc("CreateWindowStationW")
	procCloseWindowStation  = user32.NewProc("CloseWindowStation")
	procSetProcessWinSta    = user32.NewProc("SetProcessWindowStation")
)

var procIsProcessInJob = windows.NewLazySystemDLL("kernel32.dll").NewProc("IsProcessInJob")

// winstaAllAccess is WINSTA_ALL_ACCESS with READ_CONTROL and WRITE_DAC
// (WINSTA_ALL_ACCESS holds no standard right), for the helper's own handle.
const winstaAllAccess = 0x0000037F | 0x00020000 | 0x00040000

// stationMu serialises the helper's SetProcessWindowStation switch
// (CreateDesktop creates on the calling process's window station).
var stationMu sync.Mutex

// desktopAllAccess is DESKTOP_ALL_ACCESS for the helper's own handle.
const desktopAllAccess = 0x000F01FF

// desktopReadObjects is DESKTOP_READOBJECTS, the existence check's access.
const desktopReadObjects = 0x0001

// uoiName is GetUserObjectInformation's UOI_NAME.
const uoiName = 2

// RunDesktop is one run's desktop, held open by the helper for the run,
// and, from CreateRunStation, the private window station it is on.
type RunDesktop struct {
	mu   sync.Mutex
	h    uintptr
	ws   uintptr
	user string
	// Path is "<window station>\<desktop>", the lpDesktop wxc-exec starts
	// on.
	Path string
	// Station is the window station's name: the run's own (CreateRunStation)
	// or this process's (CreateRunDesktop).
	Station string
	// addedStationEntry: CreateRunStation added the ALL APPLICATION PACKAGES
	// box entry to the station's DACL (the station had none of its own), so
	// ReleaseStationEntry may remove exactly that entry when no other
	// Observer run is live (WINFIX4 audit finding 3). False when the station
	// already admitted boxes (the browsers' sandboxes' entry, which Observer
	// never touches).
	addedStationEntry bool
}

// CreateRunStation opens the logon session's alternate window station
// (CreateWindowStation with no name, which a standard user may call; a
// NAMED station is refused to one, sandboxmxc/ui.go), creating it with the
// DACL sandboxmxc.StationSDDL builds when this is the first caller, and
// creates the run's own desktop, named desktop, on it (sandboxmxc.
// DesktopSDDL, the box entry open to ALL APPLICATION PACKAGES until Narrow
// names the box's SID). A station that already exists keeps its DACL with
// the box entry merged in (ensureStationBoxEntry), so a box can connect to
// it; nothing else of it changes. A desktop name that already exists on the
// station is refused. Close frees both handles. WinSta0 and its desktops
// are never changed (RERUN2 D2).
func CreateRunStation(desktop string) (*RunDesktop, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("read the user's SID: %w", err)
	}
	user := u.User.Sid.String()
	wsddl, err := sandboxmxc.StationSDDL(user)
	if err != nil {
		return nil, err
	}
	dsddl, err := sandboxmxc.DesktopSDDL(user, "")
	if err != nil {
		return nil, err
	}
	wsd, err := windows.SecurityDescriptorFromString(wsddl)
	if err != nil {
		return nil, fmt.Errorf("window station security descriptor: %w", err)
	}
	dsd, err := windows.SecurityDescriptorFromString(dsddl)
	if err != nil {
		return nil, fmt.Errorf("desktop security descriptor: %w", err)
	}
	wsa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: wsd}
	dsa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: dsd}
	dp, err := windows.UTF16PtrFromString(desktop)
	if err != nil {
		return nil, err
	}
	ws, _, werr := procCreateWindowStation.Call(0, 0, winstaAllAccess, uintptr(unsafe.Pointer(&wsa)))
	if ws == 0 {
		return nil, fmt.Errorf("CreateWindowStation (the logon session's alternate station): %w", werr)
	}
	station := userObjectName(ws)
	if station == "" || strings.EqualFold(station, "WinSta0") {
		_, _, _ = procCloseWindowStation.Call(ws)
		return nil, fmt.Errorf("the alternate window station is %q, not one of its own", station)
	}
	added, err := ensureStationBoxEntry(ws)
	if err != nil {
		_, _, _ = procCloseWindowStation.Call(ws)
		return nil, fmt.Errorf("the box entry of window station %s: %w", station, err)
	}
	stationMu.Lock()
	old, _, _ := procGetProcessWinSta.Call()
	if old == 0 {
		stationMu.Unlock()
		_, _, _ = procCloseWindowStation.Call(ws)
		return nil, errors.New("this process has no window station")
	}
	if r, _, serr := procSetProcessWinSta.Call(ws); r == 0 {
		stationMu.Unlock()
		_, _, _ = procCloseWindowStation.Call(ws)
		return nil, fmt.Errorf("SetProcessWindowStation: %w", serr)
	}
	// CreateDesktop opens a desktop that already exists instead of failing,
	// so an existing name on the shared station is refused first.
	if o, _, oerr := procOpenDesktopW.Call(uintptr(unsafe.Pointer(dp)), 0, 0, desktopReadObjects); o != 0 || errors.Is(oerr, windows.ERROR_ACCESS_DENIED) {
		if o != 0 {
			_, _, _ = procCloseDesktop.Call(o)
		}
		_, _, _ = procSetProcessWinSta.Call(old)
		stationMu.Unlock()
		_, _, _ = procCloseWindowStation.Call(ws)
		return nil, fmt.Errorf("desktop %s already exists on %s", desktop, station)
	}
	h, _, cerr := procCreateDesktopW.Call(uintptr(unsafe.Pointer(dp)), 0, 0, 0, desktopAllAccess, uintptr(unsafe.Pointer(&dsa)))
	// Back to the helper's own station before anything else, whatever
	// CreateDesktop answered.
	_, _, _ = procSetProcessWinSta.Call(old)
	stationMu.Unlock()
	if h == 0 {
		_, _, _ = procCloseWindowStation.Call(ws)
		return nil, fmt.Errorf("CreateDesktop %s on %s: %w", desktop, station, cerr)
	}
	return &RunDesktop{h: h, ws: ws, user: user, Path: station + `\` + desktop, Station: station, addedStationEntry: added}, nil
}

// ReleaseStationEntry removes the ALL APPLICATION PACKAGES box entry from
// the run's window station when CreateRunStation added it (the station had
// none) and otherRunLive reports no other Observer run still uses the
// station (WINFIX4 audit finding 3, the ReleaseManagedRoutes Leave rule):
// only the entry Observer added, never an entry the browsers' sandboxes put
// there. A station that already admitted boxes is left untouched. It is
// called before Close while the station handle is still open; it is a no-op
// otherwise.
func (d *RunDesktop) ReleaseStationEntry(otherRunLive func() bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.addedStationEntry || d.ws == 0 {
		return
	}
	if otherRunLive != nil && otherRunLive() {
		return
	}
	if err := removeStationBoxEntry(d.ws); err == nil {
		d.addedStationEntry = false
	}
}

// CreateRunDesktop creates the desktop name on this process's window
// station, its box entry open to ALL APPLICATION PACKAGES until Narrow
// names the box's SID. A name that already exists is refused, so a run
// never shares another's desktop.
func CreateRunDesktop(name string) (*RunDesktop, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("read the user's SID: %w", err)
	}
	user := u.User.Sid.String()
	sddl, err := sandboxmxc.DesktopSDDL(user, "")
	if err != nil {
		return nil, err
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, fmt.Errorf("desktop security descriptor: %w", err)
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	np, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	ws, _, _ := procGetProcessWinSta.Call()
	if ws == 0 {
		return nil, errors.New("this process has no window station")
	}
	station := userObjectName(ws)
	if station == "" {
		return nil, errors.New("the window station's name cannot be read")
	}
	// CreateDesktop opens a desktop that already exists instead of failing,
	// so an existing name (one this user can open, or one it is denied) is
	// refused first.
	if o, _, oerr := procOpenDesktopW.Call(uintptr(unsafe.Pointer(np)), 0, 0, desktopReadObjects); o != 0 || errors.Is(oerr, windows.ERROR_ACCESS_DENIED) {
		if o != 0 {
			_, _, _ = procCloseDesktop.Call(o)
		}
		return nil, fmt.Errorf("desktop %s already exists", name)
	}
	h, _, cerr := procCreateDesktopW.Call(uintptr(unsafe.Pointer(np)), 0, 0, 0, desktopAllAccess, uintptr(unsafe.Pointer(&sa)))
	if h == 0 {
		return nil, fmt.Errorf("CreateDesktop %s: %w", name, cerr)
	}
	return &RunDesktop{h: h, user: user, Path: station + `\` + name, Station: station}, nil
}

// Narrow replaces the desktop's DACL with the one naming boxSID instead of
// ALL APPLICATION PACKAGES. Processes already on the desktop keep their
// connection; every later process of the box is admitted by its own SID.
func (d *RunDesktop) Narrow(boxSID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.h == 0 {
		return errors.New("the desktop is closed")
	}
	// The window station is shared by every run of the logon session, so
	// only the run's own desktop is narrowed.
	sddl, err := sandboxmxc.DesktopSDDL(d.user, boxSID)
	if err != nil {
		return err
	}
	return setWindowObjectDACL(d.h, sddl)
}

// setWindowObjectDACL replaces a window station's or desktop's DACL with
// sddl's, protected.
func setWindowObjectDACL(h uintptr, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetSecurityInfo(windows.Handle(h), windows.SE_WINDOW_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

// ensureStationBoxEntry merges the box entry of sandboxmxc.StationSDDL
// (StationBoxAccess for ALL APPLICATION PACKAGES) into the station's DACL,
// for a station another caller created: without it a box process cannot
// connect to the station and user32 does not initialise. A station this
// helper created already carries it, and the merge changes nothing.
func ensureStationBoxEntry(ws uintptr) (added bool, err error) {
	sd, err := windows.GetSecurityInfo(windows.Handle(ws), windows.SE_WINDOW_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return false, err
	}
	ac, err := windows.StringToSid(sandboxmxc.SIDAllApplicationPackages)
	if err != nil {
		return false, err
	}
	if dacl != nil && aclGrants(dacl, ac, sandboxmxc.StationBoxAccess) {
		// Another caller's station already admits a box: it is left as it is,
		// and Observer never removes it (added stays false).
		return false, nil
	}
	merged, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.ACCESS_MASK(sandboxmxc.StationBoxAccess),
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(ac),
		},
	}}, dacl)
	if err != nil {
		return false, err
	}
	if err := windows.SetSecurityInfo(windows.Handle(ws), windows.SE_WINDOW_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, merged, nil); err != nil {
		return false, err
	}
	return true, nil
}

// removeStationBoxEntry removes the one ALL APPLICATION PACKAGES allow
// entry that grants StationBoxAccess from the station's DACL (the entry
// ensureStationBoxEntry added), leaving every other entry as it is.
func removeStationBoxEntry(ws uintptr) error {
	sd, err := windows.GetSecurityInfo(windows.Handle(ws), windows.SE_WINDOW_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return err
	}
	ac, err := windows.StringToSid(sandboxmxc.SIDAllApplicationPackages)
	if err != nil {
		return err
	}
	kept := make([]windows.EXPLICIT_ACCESS, 0, int(dacl.AceCount))
	const inheritOnly = 0x08
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return err
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if ace.Header.AceType == windows.ACCESS_ALLOWED_ACE_TYPE && ace.Header.AceFlags&inheritOnly == 0 &&
			sid.Equals(ac) && uint32(ace.Mask) == sandboxmxc.StationBoxAccess {
			// The exact entry Observer added; drop it.
			continue
		}
		mode := windows.ACCESS_MODE(windows.GRANT_ACCESS)
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			mode = windows.DENY_ACCESS
		}
		kept = append(kept, windows.EXPLICIT_ACCESS{
			AccessPermissions: ace.Mask,
			AccessMode:        mode,
			Inheritance:       uint32(ace.Header.AceFlags),
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_UNKNOWN,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		})
	}
	next, err := windows.ACLFromEntries(kept, nil)
	if err != nil {
		return err
	}
	return windows.SetSecurityInfo(windows.Handle(ws), windows.SE_WINDOW_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, next, nil)
}

// aclGrants reports whether dacl holds an allow entry for sid, applying to
// the object itself (not inherit-only), whose mask includes every bit of
// want.
func aclGrants(dacl *windows.ACL, sid *windows.SID, want uint32) bool {
	const inheritOnly = 0x08
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return false
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags&inheritOnly != 0 {
			continue
		}
		if (*windows.SID)(unsafe.Pointer(&ace.SidStart)).Equals(sid) && uint32(ace.Mask)&want == want {
			return true
		}
	}
	return false
}

// StationAdmitsBoxes reports whether the run's window station grants ALL
// APPLICATION PACKAGES sandboxmxc.StationBoxAccess.
func (d *RunDesktop) StationAdmitsBoxes() (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ws == 0 {
		return false, errors.New("no window station of the run's")
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(d.ws), windows.SE_WINDOW_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, err
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return false, err
	}
	ac, err := windows.StringToSid(sandboxmxc.SIDAllApplicationPackages)
	if err != nil {
		return false, err
	}
	return aclGrants(dacl, ac, sandboxmxc.StationBoxAccess), nil
}

// StationSDDL reads the window station's DACL back ("" with no station of
// the run's own).
func (d *RunDesktop) StationSDDL() (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ws == 0 {
		return "", nil
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(d.ws), windows.SE_WINDOW_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return "", err
	}
	return sd.String(), nil
}

// SDDL reads the desktop's DACL back (for the run's log and the tests).
func (d *RunDesktop) SDDL() (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.h == 0 {
		return "", errors.New("the desktop is closed")
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(d.h), windows.SE_WINDOW_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return "", err
	}
	return sd.String(), nil
}

// Close closes the helper's handles, the desktop's and then the window
// station's; Windows destroys each once no process or thread uses it.
func (d *RunDesktop) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.h != 0 {
		_, _, _ = procCloseDesktop.Call(d.h)
		d.h = 0
	}
	if d.ws != 0 {
		_, _, _ = procCloseWindowStation.Call(d.ws)
		d.ws = 0
	}
}

func userObjectName(h uintptr) string {
	buf := make([]uint16, 256)
	var n uint32
	r, _, _ := procGetUserObjectInfoW.Call(h, uoiName, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)*2), uintptr(unsafe.Pointer(&n)))
	if r == 0 {
		return ""
	}
	return windows.UTF16ToString(buf)
}

// Started is a process StartOnDesktop started, in a job of its own that the
// helper holds.
type Started struct {
	mu  sync.Mutex
	h   windows.Handle
	job windows.Handle
	PID uint32
}

// newKillOnCloseJob is an anonymous job whose processes all end when its
// last handle closes (JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE). Its handle is not
// inheritable, so the helper alone holds it: a killed helper ends wxc-exec
// and the box under it (WINFIX2 audit finding 9). It carries no UI limit:
// with any, wxc-exec cannot create the box (ERROR_NOT_SUPPORTED, see
// sandboxmxc.JobUIRestrictions); the box's first process sets them on a
// nested job of its own (EnterUIRestrictedJob).
func newKillOnCloseJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, fmt.Errorf("CreateJobObject: %w", err)
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE},
	}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		_ = windows.CloseHandle(job)
		return 0, fmt.Errorf("SetInformationJobObject: %w", err)
	}
	return job, nil
}

// uiJobMu serialises EnterUIRestrictedJob.
var uiJobMu sync.Mutex

// EnterUIRestrictedJob puts this process in a new job, nested under the
// job it is in, whose UI limit class is class, and returns the class this
// process then reads on its own job (OwnJobUIClass) and whether this call
// put it there. A process whose job already carries every bit of class is
// left as it is (entered false). Every process this one creates afterwards
// starts inside the job and cannot leave it (the job grants no breakaway).
// An error means the limits are not in force; the caller must not start the
// tool (RERUN2 D2, fail closed).
//
// The job's only handle is closed before the class is read back, on every
// path (WINFIX4 audit finding 1): every process of the box shares this
// process's AppContainer, so any of them can open it with PROCESS_DUP_HANDLE
// and duplicate a handle it holds; with the full-access job handle the
// tool cleared all eight limits for the whole box (measured: 0xFF became
// 0x0). A process stays in its job and the job keeps its limits while any
// process is in it, so nothing needs the handle; the job has no name, so
// nothing can open it again, and with no handle left nothing can change it.
func EnterUIRestrictedJob(class uint32) (uint32, bool, error) {
	uiJobMu.Lock()
	defer uiJobMu.Unlock()
	if have, in, err := OwnJobUIClass(); err == nil && in && have&class == class {
		return have, false, nil
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, false, fmt.Errorf("CreateJobObject: %w", err)
	}
	ui := windows.JOBOBJECT_BASIC_UI_RESTRICTIONS{UIRestrictionsClass: class}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectBasicUIRestrictions, uintptr(unsafe.Pointer(&ui)), uint32(unsafe.Sizeof(ui))); err != nil {
		_ = windows.CloseHandle(job)
		return 0, false, fmt.Errorf("SetInformationJobObject(UI limits): %w", err)
	}
	aerr := windows.AssignProcessToJobObject(job, windows.CurrentProcess())
	// Closed whatever the assignment answered, and before anything else
	// runs: no handle that can change the job survives this call.
	cerr := windows.CloseHandle(job)
	if aerr != nil {
		return 0, false, fmt.Errorf("AssignProcessToJobObject: %w", aerr)
	}
	if cerr != nil {
		return 0, true, fmt.Errorf("close the job's handle: %w", cerr)
	}
	have, in, err := OwnJobUIClass()
	if err != nil {
		return 0, true, fmt.Errorf("read the job's UI limits back: %w", err)
	}
	if !in || have&class != class {
		return have, true, fmt.Errorf("the job's UI limits read back as 0x%X, want 0x%X", have, class)
	}
	return have, true, nil
}

// OwnJobUIClass reads the UI limit class of the job this process is in
// (QueryInformationJobObject with no handle: the innermost job), and
// whether it is in a job at all.
func OwnJobUIClass() (uint32, bool, error) {
	var in int32
	if r, _, err := procIsProcessInJob.Call(uintptr(windows.CurrentProcess()), 0, uintptr(unsafe.Pointer(&in))); r == 0 {
		return 0, false, err
	}
	if in == 0 {
		return 0, false, nil
	}
	var ui windows.JOBOBJECT_BASIC_UI_RESTRICTIONS
	if err := windows.QueryInformationJobObject(0, windows.JobObjectBasicUIRestrictions, uintptr(unsafe.Pointer(&ui)), uint32(unsafe.Sizeof(ui)), nil); err != nil {
		return 0, true, err
	}
	return ui.UIRestrictionsClass, true, nil
}

// StartOnDesktop starts exe with args, in dir, with exactly env (KEY=VALUE),
// on desktop (lpDesktop, "<station>\<desktop>"), with stdin, stdout and
// stderr as its standard handles: the os/exec start the helper used before,
// with the one field os/exec cannot set. Only those three handles are
// inherited (PROC_THREAD_ATTRIBUTE_HANDLE_LIST). The process starts in a
// kill-on-close job only the helper holds (newKillOnCloseJob), so when the
// helper ends, however it ends, wxc-exec and the box end too.
func StartOnDesktop(exe string, args []string, dir string, env []string, desktop string, stdin, stdout, stderr *os.File) (*Started, error) {
	return Start(StartSpec{Exe: exe, Args: args, Dir: dir, Env: env, Desktop: desktop, Stdin: stdin, Stdout: stdout, Stderr: stderr})
}

// StartSpec is one Start: StartOnDesktop's arguments. The standard handles
// are passed to wxc-exec inheritable, and MXC passes wxc-exec's on to the
// box: a box writes to those handles, never to a console of its own that
// anybody sees (RERUN2 D1, measured: a pseudo console given to wxc-exec by
// attribute, with handles it did not inherit, left the box's output in a
// console with no window).
type StartSpec struct {
	Exe                   string
	Args                  []string
	Dir                   string
	Env                   []string
	Desktop               string
	Stdin, Stdout, Stderr *os.File
}

// Start is StartOnDesktop with a StartSpec.
func Start(spec StartSpec) (*Started, error) {
	exe, args, dir, env, desktop := spec.Exe, spec.Args, spec.Dir, spec.Env, spec.Desktop
	stdin, stdout, stderr := spec.Stdin, spec.Stdout, spec.Stderr
	argv := append([]string{exe}, args...)
	cmdline, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(argv))
	if err != nil {
		return nil, err
	}
	exep, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return nil, err
	}
	var dirp *uint16
	if dir != "" {
		if dirp, err = windows.UTF16PtrFromString(dir); err != nil {
			return nil, err
		}
	}
	block, err := envBlock(env)
	if err != nil {
		return nil, err
	}
	deskp, err := windows.UTF16PtrFromString(desktop)
	if err != nil {
		return nil, err
	}
	self := windows.CurrentProcess()
	var inherit []windows.Handle
	dup := func(f *os.File) (windows.Handle, error) {
		if f == nil {
			return 0, nil
		}
		var h windows.Handle
		if err := windows.DuplicateHandle(self, windows.Handle(f.Fd()), self, &h, 0, true, windows.DUPLICATE_SAME_ACCESS); err != nil {
			return 0, err
		}
		inherit = append(inherit, h)
		return h, nil
	}
	defer func() {
		for _, h := range inherit {
			_ = windows.CloseHandle(h)
		}
	}()
	var si windows.StartupInfoEx
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Desktop = deskp
	si.Flags = windows.STARTF_USESTDHANDLES
	if si.StdInput, err = dup(stdin); err != nil {
		return nil, fmt.Errorf("stdin: %w", err)
	}
	if si.StdOutput, err = dup(stdout); err != nil {
		return nil, fmt.Errorf("stdout: %w", err)
	}
	if si.StdErr, err = dup(stderr); err != nil {
		return nil, fmt.Errorf("stderr: %w", err)
	}
	// Started suspended, so it is in the run's job before it runs anything
	// (a child it starts is in the job too).
	flags := uint32(windows.CREATE_UNICODE_ENVIRONMENT | windows.CREATE_SUSPENDED)
	inheritHandles := len(inherit) > 0
	if inheritHandles {
		al, err := windows.NewProcThreadAttributeList(1)
		if err != nil {
			return nil, err
		}
		defer al.Delete()
		if err := al.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&inherit[0]), uintptr(len(inherit))*unsafe.Sizeof(inherit[0])); err != nil {
			return nil, err
		}
		si.ProcThreadAttributeList = al.List()
		flags |= windows.EXTENDED_STARTUPINFO_PRESENT
	}
	job, err := newKillOnCloseJob()
	if err != nil {
		return nil, fmt.Errorf("the run's job: %w", err)
	}
	var pi windows.ProcessInformation
	if err := windows.CreateProcess(exep, cmdline, nil, nil, inheritHandles, flags, &block[0], dirp, &si.StartupInfo, &pi); err != nil {
		_ = windows.CloseHandle(job)
		return nil, fmt.Errorf("CreateProcess %s: %w", exe, err)
	}
	if err := windows.AssignProcessToJobObject(job, pi.Process); err != nil {
		_ = windows.TerminateProcess(pi.Process, 1)
		_ = windows.CloseHandle(pi.Thread)
		_ = windows.CloseHandle(pi.Process)
		_ = windows.CloseHandle(job)
		return nil, fmt.Errorf("the run's job: AssignProcessToJobObject: %w", err)
	}
	if _, err := windows.ResumeThread(pi.Thread); err != nil {
		_ = windows.TerminateJobObject(job, 1)
		_ = windows.CloseHandle(pi.Thread)
		_ = windows.CloseHandle(pi.Process)
		_ = windows.CloseHandle(job)
		return nil, fmt.Errorf("ResumeThread %s: %w", exe, err)
	}
	_ = windows.CloseHandle(pi.Thread)
	return &Started{h: pi.Process, job: job, PID: pi.ProcessId}, nil
}

// Kill ends every process of the run's job (wxc-exec and the box under it)
// with code. A no-op once Wait has returned.
func (s *Started) Kill(code uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.job == 0 {
		return nil
	}
	return windows.TerminateJobObject(s.job, code)
}

// JobPIDs lists the processes in the run's job (for the tests and the
// helper's log).
func (s *Started) JobPIDs() ([]uint32, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.job == 0 {
		return nil, errors.New("the run's job is closed")
	}
	// JOBOBJECT_BASIC_PROCESS_ID_LIST: two DWORD counts, then the ids
	// (ULONG_PTR each).
	var list struct {
		Assigned uint32
		InList   uint32
		IDs      [256]uintptr
	}
	if err := windows.QueryInformationJobObject(s.job, windows.JobObjectBasicProcessIdList, uintptr(unsafe.Pointer(&list)), uint32(unsafe.Sizeof(list)), nil); err != nil {
		return nil, err
	}
	n := list.InList
	if n > uint32(len(list.IDs)) {
		n = uint32(len(list.IDs))
	}
	out := make([]uint32, 0, n)
	for _, p := range list.IDs[:n] {
		out = append(out, uint32(p)) //nolint:gosec // G115: a process id
	}
	return out, nil
}

// closeJob closes the helper's job handle, which ends every process still
// in the job: what a killed helper's exit does (the tests use it).
func (s *Started) closeJob() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.job != 0 {
		_ = windows.CloseHandle(s.job)
		s.job = 0
	}
}

// Wait waits for the process and returns its exit code, then closes its
// handle and the run's job (anything left in the job ends with it).
func (s *Started) Wait() (int, error) {
	if _, err := windows.WaitForSingleObject(s.h, windows.INFINITE); err != nil {
		return 0, err
	}
	var code uint32
	err := windows.GetExitCodeProcess(s.h, &code)
	_ = windows.CloseHandle(s.h)
	s.closeJob()
	return int(code), err
}

// envBlock is env as a UTF-16 environment block (each KEY=VALUE followed by
// a NUL, one more NUL at the end); an entry holding a NUL is refused.
func envBlock(env []string) ([]uint16, error) {
	var b []uint16
	for _, kv := range env {
		if strings.ContainsRune(kv, 0) {
			return nil, errors.New("an environment entry contains NUL")
		}
		b = append(b, windows.StringToUTF16(kv)...)
	}
	if len(b) == 0 {
		b = append(b, 0)
	}
	return append(b, 0), nil
}

package sandboxmxc

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// ui.go is the box's user interface (Windows 11 Pro rerun 2026-10-25, D1):
// the MXC ui block of the run's document and the per-run desktop the box is
// started on.
//
// Without a ui block MXC 1.0.1's wxc-exec applies the Win32k system call
// mitigation to the box process, so every program that imports user32.dll
// (powershell.exe, timeout.exe, most System32 tools) fails to start with
// STATUS_DLL_INIT_FAILED; MXC's own message for that exit names
// `ui.disable: false` as the remedy. With Win32k on, the box would join the
// interactive desktop (wxc-exec starts it on the desktop wxc-exec itself
// runs on, WinSta0\Default for a process started from a console). The
// driver therefore starts wxc-exec on a desktop of its own per run, whose
// DACL names the user and the box only (DesktopSDDL), and leaves
// WinSta0\Default as it was. MXC 1.0.1 has no desktop or STARTUPINFO field
// (generated/v1_0_0/wire.d.ts: Ui is clipboard, disable and injection;
// ProcessContainerUi is the job's UI limits), so the desktop is the
// helper's STARTUPINFO.lpDesktop for wxc-exec, which the box inherits.

// UI is the contract's cross-platform user-interface policy (Ui).
type UI struct {
	// Disable is false only for a tool whose row says it needs user32.dll
	// (integration SandboxSpec.NeedsWin32k): MXC then keeps Win32k system
	// calls on (see above). For every other tool it is true and MXC keeps
	// the Win32k mitigation, the smaller attack surface (WINFIX2 audit
	// finding 4).
	Disable bool `json:"disable"`
	// Clipboard is always "none".
	Clipboard string `json:"clipboard"`
	// Injection is always false.
	Injection bool `json:"injection"`
}

// UIClipboardNone is the closed clipboard policy.
const UIClipboardNone = "none"

// BoxUI is the ui block of a run's document: Win32k on only when the tool
// needs user32.dll, the clipboard and input injection always closed.
func BoxUI(needsWin32k bool) *UI {
	return &UI{Disable: !needsWin32k, Clipboard: UIClipboardNone, Injection: false}
}

// ProcessContainerUI is the contract's ProcessContainer user-interface
// policy (ProcessContainerUi in generated/v1_0_0/wire.d.ts; the SDK's
// BaseProcessUiConfig), the job UI limits MXC applies to the box (WINFIX2
// audit finding 3).
type ProcessContainerUI struct {
	// Isolation is "container", the widest of MXC's four levels
	// (container, desktop, handles, atoms): the box gets its own desktop
	// resources, USER handles and global atom table. The SDK's own
	// processContainer request (dist/v1/container.js) sets these four values.
	Isolation string `json:"isolation"`
	// DesktopSystemControl is false: no desktop switching or system-wide UI
	// control.
	DesktopSystemControl bool `json:"desktopSystemControl"`
	// SystemSettings is "none": no change to system parameters.
	SystemSettings string `json:"systemSettings"`
	// IME is false: no input method editor (a console tool needs none).
	IME bool `json:"ime"`
}

// The strictest job UI values.
const (
	// UIIsolationContainer is ProcessContainerUi.isolation's widest level.
	UIIsolationContainer = "container"
	// UISystemSettingsNone closes system settings.
	UISystemSettingsNone = "none"
)

// BoxProcessUI is the one processContainer.ui block every run's document
// carries.
func BoxProcessUI() *ProcessContainerUI {
	return &ProcessContainerUI{Isolation: UIIsolationContainer, DesktopSystemControl: false, SystemSettings: UISystemSettingsNone, IME: false}
}

// DesktopBoxAccess is what the box may do on its desktop: read and write
// objects, create windows and menus, enumerate, read the security
// descriptor. Never DESKTOP_HOOKCONTROL, DESKTOP_JOURNALRECORD,
// DESKTOP_JOURNALPLAYBACK, DESKTOP_SWITCHDESKTOP, DELETE, WRITE_DAC or
// WRITE_OWNER. Measured on Windows 11 (2026-10-25): READOBJECTS alone is
// not enough for user32 to initialise; this set is.
const DesktopBoxAccess uint32 = 0x0001 | 0x0002 | 0x0004 | 0x0040 | 0x0080 | 0x00020000

// SIDAllApplicationPackages is ALL APPLICATION PACKAGES, the trustee of the
// desktop's box entry until the box's own SID is known: MXC 1.0.1 names the
// AppContainer profile itself at start (identity.go), so no SID exists to
// name before the box's first process does, and that process needs the
// desktop to initialise user32. The helper narrows the entry to the box's
// SID as soon as it reads it (DesktopSDDL with a box SID).
const SIDAllApplicationPackages = "S-1-15-2-1"

// DesktopName is the run's desktop name: the run id and a random nonce
// (WINFIX2 audit finding 2: the run id alone is not secret, and until the
// box's SID is read the desktop admits any AppContainer that names it).
// nonce is 16 random bytes the caller drew; the name has no separator.
func DesktopName(runID string, nonce [16]byte) string {
	return "observer-" + runID + "-" + hex.EncodeToString(nonce[:])
}

// The box's window station (Windows 11 Pro run 3 RERUN2, D2): a desktop of
// its own on WinSta0 was not enough. WinSta0's own DACL lets any process of
// the user's logon session, an AppContainer one included, open
// WinSta0\Default and move a thread there, and from there the box saw the
// foreground window and copied screen pixels. A desktop name resolves
// against the caller's own window station, so a box whose process runs on
// another, non-interactive window station has no Default to open, no
// foreground window and no visible screen to copy. The helper therefore
// starts wxc-exec with lpDesktop "<station>\<desktop>" on such a station.
//
// The station cannot be per run: a standard user may not create a NAMED
// window station (CreateWindowStation answers "Access is denied", measured
// on Windows 11 2026-10-26), only the logon session's own alternate one
// (lpwinsta NULL, named "Service-0x0-<logon id>$"), which every caller of
// that logon session shares (browser sandboxes use it the same way). Its
// DACL is therefore StationSDDL, never narrowed to one box; what keeps runs
// apart there is the per-run desktop (DesktopSDDL, narrowed to the box's
// SID) and the job's UI limits (JobUIRestrictions: the clipboard, global
// atoms and other processes' USER handles closed).

// StationBoxAccess is what the box may do with its window station: read its
// attributes and use its global atoms, which a process needs to connect to
// the station and initialise user32, plus READ_CONTROL. Never
// WINSTA_ACCESSCLIPBOARD, WINSTA_CREATEDESKTOP, WINSTA_ENUMDESKTOPS,
// WINSTA_ENUMERATE, WINSTA_EXITWINDOWS, WINSTA_READSCREEN,
// WINSTA_WRITEATTRIBUTES, DELETE, WRITE_DAC or WRITE_OWNER.
const StationBoxAccess uint32 = 0x0002 | 0x0020 | 0x00020000

// StationSDDL is the protected DACL the helper gives the logon session's
// alternate window station when it is the one that creates it: full access
// for the user and StationBoxAccess for ALL APPLICATION PACKAGES (the
// station is shared by every run, so no single box SID can be named).
// Nothing else. A station that already exists keeps its DACL, with the box
// entry added (sandboxmxcdll.CreateRunStation).
func StationSDDL(userSID string) (string, error) {
	if !sidString(userSID) {
		return "", fmt.Errorf("%w: user %q", ErrDesktopSID, userSID)
	}
	return fmt.Sprintf("D:P(A;;GA;;;%s)(A;;0x%X;;;%s)", userSID, StationBoxAccess, SIDAllApplicationPackages), nil
}

// JobUIRestrictions is the UI limit class every process of a box runs under
// (RERUN2 D2): JOB_OBJECT_UILIMIT_HANDLES (0x01), READCLIPBOARD (0x02),
// WRITECLIPBOARD (0x04), SYSTEMPARAMETERS (0x08), DISPLAYSETTINGS (0x10),
// GLOBALATOMS (0x20), DESKTOP (0x40) and EXITWINDOWS (0x80), every limit
// JOBOBJECT_BASIC_UI_RESTRICTIONS has. The run's document asks MXC for job
// UI limits too (processContainer.ui), but a box probe read no limit on its
// job (class 0x0). The helper cannot set them on the kill-on-close job it
// holds for wxc-exec: measured on Windows 11 26200, a job with any one of
// the eight limits makes wxc-exec's CreateProcessW with
// PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT fail with ERROR_NOT_SUPPORTED
// (50), so no box starts. The box's first Observer process, which runs
// before the tool, puts itself in a nested job carrying them
// (sandboxmxcdll.EnterUIRestrictedJob); every later process of the box,
// the tool included, is created inside it and cannot leave it.
const JobUIRestrictions uint32 = 0x01 | 0x02 | 0x04 | 0x08 | 0x10 | 0x20 | 0x40 | 0x80

// JobUIFlagNames names each bit of a JOBOBJECT_BASIC_UI_RESTRICTIONS class,
// lowest bit first (for the run's inner log and the probe).
var JobUIFlagNames = []string{"HANDLES", "READCLIPBOARD", "WRITECLIPBOARD", "SYSTEMPARAMETERS", "DISPLAYSETTINGS", "GLOBALATOMS", "DESKTOP", "EXITWINDOWS"}

// JobUIClassText is class as its flag names ("none" for zero).
func JobUIClassText(class uint32) string {
	var out []string
	for i, n := range JobUIFlagNames {
		if class&(1<<uint(i)) != 0 {
			out = append(out, n)
		}
	}
	if rest := class &^ 0xFF; rest != 0 {
		out = append(out, fmt.Sprintf("0x%X", rest))
	}
	if len(out) == 0 {
		return "none"
	}
	return strings.Join(out, ",")
}

// ErrDesktopSID is returned for a user or box SID that is not a SID string.
var ErrDesktopSID = errors.New("sandboxmxc: a desktop trustee is not a SID string")

// DesktopSDDL is the protected DACL of the run's desktop: full access for
// the user, DesktopBoxAccess for boxSID, or for ALL APPLICATION PACKAGES
// while boxSID is "" (the window before the box's SID is read). Nothing
// else: no Everyone, no other user, no inherited entry.
func DesktopSDDL(userSID, boxSID string) (string, error) {
	if !sidString(userSID) {
		return "", fmt.Errorf("%w: user %q", ErrDesktopSID, userSID)
	}
	box := SIDAllApplicationPackages
	if boxSID != "" {
		if !sidString(boxSID) || !strings.HasPrefix(boxSID, "S-1-15-2-") {
			return "", fmt.Errorf("%w: box %q", ErrDesktopSID, boxSID)
		}
		box = boxSID
	}
	return fmt.Sprintf("D:P(A;;GA;;;%s)(A;;0x%X;;;%s)", userSID, DesktopBoxAccess, box), nil
}

// sidString reports whether s has the shape of a SID string (S-1-<digits
// and dashes>).
func sidString(s string) bool {
	if !strings.HasPrefix(s, "S-1-") || len(s) > 200 || strings.HasSuffix(s, "-") {
		return false
	}
	for _, r := range s[4:] {
		if !(r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return !strings.Contains(s, "--")
}

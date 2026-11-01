package sandboxmxc

import (
	"errors"
	"strings"
	"testing"
)

// TestStationSDDLAdmitsTheUserAndTheBoxesOnly (RERUN2 D2): the alternate
// window station admits the user and the box entry and nothing else, with
// no clipboard, screen, desktop creation or enumeration right for a box.
func TestStationSDDLAdmitsTheUserAndTheBoxesOnly(t *testing.T) {
	const user = "S-1-5-21-1-2-3-1001"
	s, err := StationSDDL(user)
	if err != nil || s != "D:P(A;;GA;;;"+user+")(A;;0x20022;;;S-1-15-2-1)" {
		t.Fatalf("StationSDDL: %q %v", s, err)
	}
	if _, err := StationSDDL("not-a-sid"); err == nil {
		t.Fatal("a user trustee that is not a SID was accepted")
	}
	// No WINSTA_ACCESSCLIPBOARD (0x4), CREATEDESKTOP (0x8), WRITEATTRIBUTES
	// (0x10), EXITWINDOWS (0x40), ENUMERATE (0x100), READSCREEN (0x200),
	// ENUMDESKTOPS (0x1) or DELETE / WRITE_DAC / WRITE_OWNER.
	if StationBoxAccess&(0x1|0x4|0x8|0x10|0x40|0x100|0x200|0x00010000|0x00040000|0x00080000) != 0 {
		t.Fatalf("the box's station access %#x holds a right it must not", StationBoxAccess)
	}
}

// TestJobUIRestrictionsAreEveryLimit (RERUN2 D2): the helper's job carries
// all eight JOB_OBJECT_UILIMIT flags, and their names read back in order.
func TestJobUIRestrictionsAreEveryLimit(t *testing.T) {
	if JobUIRestrictions != 0xFF {
		t.Fatalf("JobUIRestrictions = %#x, want 0xFF", JobUIRestrictions)
	}
	if got := JobUIClassText(JobUIRestrictions); got != "HANDLES,READCLIPBOARD,WRITECLIPBOARD,SYSTEMPARAMETERS,DISPLAYSETTINGS,GLOBALATOMS,DESKTOP,EXITWINDOWS" {
		t.Fatalf("JobUIClassText = %q", got)
	}
	if JobUIClassText(0) != "none" || JobUIClassText(0x41) != "HANDLES,DESKTOP" {
		t.Fatal("JobUIClassText of 0 or 0x41")
	}
}

// TestDocumentKeepsWin32kWithTheUIClosed: a run of a tool that needs
// user32.dll carries the ui block that keeps Win32k on (without it MXC
// 1.0.1 applies the Win32k mitigation and every program importing
// user32.dll fails with STATUS_DLL_INIT_FAILED: Windows 11 Pro rerun
// 2026-10-25, D1); any other run keeps the mitigation (WINFIX2 audit
// finding 4); both with the clipboard and input injection closed, and a
// document opening either is refused.
func TestDocumentKeepsWin32kWithTheUIClosed(t *testing.T) {
	t.Parallel()
	plan := RunPlan{
		RunID: "r1", Argv: []string{`C:\o\observer.exe`, "claude"}, Cwd: `C:\w`,
		SystemRoot: `C:\Windows`, LocalAppData: `C:\t\observer-sbx-r1\localappdata`,
	}
	for _, needs := range []bool{false, true} {
		plan.NeedsWin32k = needs
		d, err := BuildDocument(plan)
		if err != nil {
			t.Fatalf("BuildDocument: %v", err)
		}
		b, err := d.Encode()
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		want := `"ui":{"disable":true,"clipboard":"none","injection":false}`
		if needs {
			want = `"ui":{"disable":false,"clipboard":"none","injection":false}`
		}
		if !strings.Contains(string(b), want) {
			t.Fatalf("NeedsWin32k=%v: want %s in %s", needs, want, b)
		}
	}
	d, err := BuildDocument(plan)
	if err != nil {
		t.Fatalf("BuildDocument: %v", err)
	}
	if _, err := ProbeDocument(`C:\Windows\System32\cmd.exe`, `C:\Windows`, `C:\t\p\localappdata`); err != nil {
		t.Fatalf("ProbeDocument: %v", err)
	}
	for name, ui := range map[string]*UI{
		"clipboard read":  {Clipboard: "read"},
		"clipboard all":   {Clipboard: "all"},
		"clipboard empty": {Clipboard: ""},
		"injection":       {Clipboard: UIClipboardNone, Injection: true},
	} {
		bad := d
		bad.UI = ui
		if err := bad.Validate(); !errors.Is(err, ErrUIOpen) {
			t.Errorf("%s: Validate = %v, want ErrUIOpen", name, err)
		}
	}
}

// TestDesktopSDDL: the run's desktop names the user (full access) and the
// box (DesktopBoxAccess) and nobody else; before the box's SID is known the
// box entry is ALL APPLICATION PACKAGES; a trustee that is not a SID, or a
// box SID that is not an AppContainer SID, is refused.
func TestDesktopSDDL(t *testing.T) {
	t.Parallel()
	const user = "S-1-5-21-1-2-3-1001"
	const box = "S-1-15-2-1-2-3-4-5-6-7"
	for _, c := range []struct {
		name, user, box, want string
		err                   bool
	}{
		{name: "before the box SID", user: user, want: "D:P(A;;GA;;;" + user + ")(A;;0x200C7;;;S-1-15-2-1)"},
		{name: "narrowed", user: user, box: box, want: "D:P(A;;GA;;;" + user + ")(A;;0x200C7;;;" + box + ")"},
		{name: "user not a SID", user: "Everyone", err: true},
		{name: "user with an ACE injected", user: user + ")(A;;GA;;;WD", err: true},
		{name: "box not an AppContainer SID", user: user, box: "S-1-1-0", err: true},
		{name: "box with an ACE injected", user: user, box: box + ")(A;;GA;;;WD", err: true},
	} {
		got, err := DesktopSDDL(c.user, c.box)
		if c.err {
			if !errors.Is(err, ErrDesktopSID) {
				t.Errorf("%s: err = %v, want ErrDesktopSID", c.name, err)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%s: DesktopSDDL = %q, %v; want %q", c.name, got, err, c.want)
		}
	}
	if DesktopBoxAccess&(0x0008|0x0010|0x0020|0x0100|0x00010000|0x00040000|0x00080000) != 0 {
		t.Fatalf("the box may never hook, journal, switch desktops, delete or change the DACL or owner: %#x", DesktopBoxAccess)
	}
	var n [16]byte
	n[0], n[15] = 0xab, 0x01
	if got := DesktopName("abc", n); got != "observer-abc-ab000000000000000000000000000001" {
		t.Fatalf("DesktopName = %q", got)
	}
	var m [16]byte
	m[1] = 1
	if DesktopName("abc", m) == DesktopName("abc", n) || strings.ContainsAny(DesktopName("abc", n), `\/`) {
		t.Fatalf("DesktopName = %q", DesktopName("abc", n))
	}
}

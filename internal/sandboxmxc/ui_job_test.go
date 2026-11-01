package sandboxmxc

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// TestDocumentSetsTheStrictestJobUILimits (WINFIX2 audit finding 3): every
// run's document carries processContainer.ui at the strictest values (its
// own desktop resources, handles and atoms; no desktop or system-settings
// control; no IME), with or without enumerate-only paths, and Validate
// refuses a document that leaves it out or loosens any of them. Before,
// only the cross-platform ui block was set and the job's UI limits were
// MXC's defaults.
func TestDocumentSetsTheStrictestJobUILimits(t *testing.T) {
	for _, enumerate := range []bool{false, true} {
		d, err := BuildDocument(RunPlan{
			RunID: "r1", Argv: []string{`C:\o\observer.exe`, "claude"}, Cwd: `C:\w\proj`,
			ReadWrite: []string{`C:\w\proj`}, SystemRoot: `C:\Windows`, LocalAppData: `C:\t\box\localappdata`,
			EnumerateAncestors: enumerate,
		})
		if err != nil {
			t.Fatalf("BuildDocument(enumerate=%v): %v", enumerate, err)
		}
		if d.ProcessContainer == nil || d.ProcessContainer.UI == nil || *d.ProcessContainer.UI != *BoxProcessUI() {
			t.Fatalf("enumerate=%v: processContainer.ui = %+v", enumerate, d.ProcessContainer)
		}
		b, err := d.Encode()
		if err != nil {
			t.Fatal(err)
		}
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(b, &raw); err != nil {
			t.Fatal(err)
		}
		var pc map[string]json.RawMessage
		if err := json.Unmarshal(raw["processContainer"], &pc); err != nil {
			t.Fatal(err)
		}
		got := string(pc["ui"])
		for _, want := range []string{`"isolation":"container"`, `"desktopSystemControl":false`, `"systemSettings":"none"`, `"ime":false`} {
			if !strings.Contains(got, want) {
				t.Fatalf("encoded processContainer.ui %s lacks %s", got, want)
			}
		}
		if enumerate && d.ProcessContainer.Filesystem == nil {
			t.Fatal("the enumerate-only paths were lost beside the ui limits")
		}
	}
	base, _ := BuildDocument(RunPlan{RunID: "r1", Argv: []string{`C:\o\observer.exe`, "claude"}, Cwd: `C:\w`, SystemRoot: `C:\Windows`, LocalAppData: `C:\t\l`})
	loosen := []func(*ProcessContainerUI){
		func(u *ProcessContainerUI) { u.Isolation = "atoms" },
		func(u *ProcessContainerUI) { u.DesktopSystemControl = true },
		func(u *ProcessContainerUI) { u.SystemSettings = "all" },
		func(u *ProcessContainerUI) { u.IME = true },
	}
	for i, f := range loosen {
		d := base
		ui := *BoxProcessUI()
		f(&ui)
		d.ProcessContainer = &ProcessContainer{UI: &ui}
		if err := d.Validate(); !errors.Is(err, ErrJobUIOpen) {
			t.Errorf("loosening %d: Validate = %v, want ErrJobUIOpen", i, err)
		}
	}
	d := base
	d.ProcessContainer = nil
	if err := d.Validate(); !errors.Is(err, ErrJobUIOpen) {
		t.Errorf("no processContainer: Validate = %v, want ErrJobUIOpen", err)
	}
}

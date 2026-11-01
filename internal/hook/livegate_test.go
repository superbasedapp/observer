package hook

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// gateHookTarget gates target's hook writer for one test.
func gateHookTarget(t *testing.T, target string, g integration.LiveGate) {
	t.Helper()
	prev := hookLiveGateFor
	hookLiveGateFor = func(tool string) integration.LiveGate {
		if tool == target {
			return g
		}
		return prev(tool)
	}
	t.Cleanup(func() { hookLiveGateFor = prev })
}

// TestLiveGateRefusal pins the writer-side gate (DEC-12): a gated target is
// refused before anything is read or written, with the shared wording and
// a not-covered skip kind; an ungated target passes; the test-only switch
// lets the real writer run.
func TestLiveGateRefusal(t *testing.T) {
	home := t.TempDir()
	reg, err := NewRegistry(Options{BinaryPath: "/usr/local/bin/observer", HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	gateHookTarget(t, "synthetic", "LC77")
	res, gated := reg.liveGateRefusal("synthetic")
	if !gated {
		t.Fatal("a gated target was not refused")
	}
	if !res.Skipped || res.SkipKind != SkipLiveGated || res.CoveredElsewhere() {
		t.Errorf("refusal = %+v, want a not-covered live-gated skip", res)
	}
	if !strings.Contains(res.SkipReason, "built, waiting on live check LC77") {
		t.Errorf("SkipReason = %q, want the shared DEC-12 wording", res.SkipReason)
	}
	if _, gated := reg.liveGateRefusal("claude-code"); gated {
		t.Error("an ungated target was refused")
	}
	runLiveGatedHookWriters = true
	t.Cleanup(func() { runLiveGatedHookWriters = false })
	if _, gated := reg.liveGateRefusal("synthetic"); gated {
		t.Error("the test-only switch did not let the writer run")
	}
	entries, _ := os.ReadDir(home)
	if len(entries) != 0 {
		t.Errorf("the refusal touched the home: %v", entries)
	}
}

// TestEveryGatedHookWriterRefuses: every registry row whose hook writer is
// gated is refused by Register itself (the backstop for a caller that forgot
// the gate), and nothing is written.
func TestEveryGatedHookWriterRefuses(t *testing.T) {
	for _, w := range integration.LiveGatedWriters() {
		if w.Kind != "hooks" {
			continue
		}
		home := t.TempDir()
		reg, err := NewRegistry(Options{BinaryPath: "/usr/local/bin/observer", HomeDir: home})
		if err != nil {
			t.Fatal(err)
		}
		res := reg.Register(w.Tool)
		if !res.Skipped || res.SkipKind != SkipLiveGated {
			t.Errorf("%s: Register = %+v, want a live-gated skip", w.Tool, res)
		}
		if n := countFiles(t, home); n != 0 {
			t.Errorf("%s: a gated writer wrote %d file(s)", w.Tool, n)
		}
	}
}

func countFiles(t *testing.T, root string) int {
	t.Helper()
	n := 0
	_ = filepath.WalkDir(root, func(_ string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			n++
		}
		return nil
	})
	return n
}

// TestLiveGateRowsAreUnique pins that every gated target has one row and
// names a live check.
func TestLiveGateRowsAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, row := range liveGateRows {
		if row.target == "" || len(row.liveChecks) == 0 {
			t.Errorf("gate row %+v has an empty field", row)
		}
		if seen[row.target] {
			t.Errorf("target %q is gated twice", row.target)
		}
		seen[row.target] = true
	}
}

// TestLiveGateNoteWording pins the one wording the doctor and the skip
// reason share (the same as the integration registry's gate).
func TestLiveGateNoteWording(t *testing.T) {
	if got, want := LiveGateNote("WSL-4"), "built, waiting on live check WSL-4"; got != want {
		t.Fatalf("LiveGateNote = %q, want %q", got, want)
	}
	if got, want := LiveGateNote(joinLiveChecks([]string{"WSL-4", "FU-87"})), "built, waiting on live check WSL-4 and FU-87"; got != want {
		t.Fatalf("multi-check note = %q, want %q", got, want)
	}
}

// TestLiveGateRefusesRegisterAndHidesTarget runs the gate over a real,
// detectable cross-OS target (codex-windows): with a gate row, Register
// writes nothing whatever Force says, Installed omits the target and
// InstalledLiveGated names it; without the row the same registry writes
// it. Unregister is never gated.
func TestLiveGateRefusesRegisterAndHidesTarget(t *testing.T) {
	cases := []struct {
		name  string
		gated bool
		force bool
	}{
		{name: "gated", gated: true},
		{name: "gated, force does not lift it", gated: true, force: true},
		{name: "not gated writes", gated: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			winHome := mkWinConfigHome(t, ".codex")
			forceHookCrossmount(t, []crossmount.HomeRoot{{OS: crossmount.OSWindows, Path: winHome}}, map[string]bool{winHome: true})
			if c.gated {
				setLiveGateForTest(t, "codex-windows", "LC-TEST")
			} else {
				setLiveGateForTest(t, "codex-windows", "")
			}
			home := t.TempDir()
			r, err := NewRegistry(Options{
				BinaryPath:    "/home/u/bin/observer",
				HomeDir:       home,
				ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
				WSLDistro:     "Ubuntu",
				Force:         c.force,
			})
			if err != nil {
				t.Fatal(err)
			}
			r = clearSandboxPin(r)
			hooksFile := filepath.Join(winHome, ".codex", "hooks.json")

			res := r.Register("codex-windows")
			_, statErr := os.Stat(hooksFile)
			installed := containsString(r.Installed(), "codex-windows")
			gatedList := r.InstalledLiveGated()

			if !c.gated {
				if res.Error != nil || res.Skipped || statErr != nil {
					t.Fatalf("ungated Register = %+v, stat err %v; want a write", res, statErr)
				}
				if !installed || len(gatedList) != 0 {
					t.Fatalf("ungated: Installed has target=%v, gated=%v", installed, gatedList)
				}
				return
			}
			if !res.Skipped || res.SkipKind != SkipLiveGated || res.Error != nil {
				t.Fatalf("gated Register = %+v, want a SkipLiveGated skip", res)
			}
			if !strings.Contains(res.SkipReason, "built, waiting on live check LC-TEST") {
				t.Errorf("SkipReason = %q", res.SkipReason)
			}
			if res.CoveredElsewhere() {
				t.Error("a gated target must never read as covered")
			}
			if !os.IsNotExist(statErr) {
				t.Fatalf("gated Register wrote %s (stat err %v)", hooksFile, statErr)
			}
			if installed {
				t.Errorf("Installed() lists the gated target: %v", r.Installed())
			}
			if len(gatedList) != 1 || gatedList[0].Target != "codex-windows" || gatedList[0].LiveCheck != "LC-TEST" {
				t.Errorf("InstalledLiveGated() = %+v", gatedList)
			}
			if u := r.Unregister("codex-windows"); u.Error != nil {
				t.Errorf("Unregister of a gated target errored: %v", u.Error)
			}
		})
	}
}

// TestLiveGatedTargetsSorted pins the exported listing order.
func TestLiveGatedTargetsSorted(t *testing.T) {
	setLiveGateForTest(t, "zz-test-wsl", "WSL-4")
	setLiveGateForTest(t, "aa-test-wsl", "WSL-5")
	got := LiveGatedTargets()
	idx := map[string]int{}
	for i, g := range got {
		idx[g.Target] = i
	}
	if idx["aa-test-wsl"] > idx["zz-test-wsl"] {
		t.Errorf("LiveGatedTargets not sorted: %+v", got)
	}
	if id, ok := LiveCheckGate("aa-test-wsl"); !ok || id != "WSL-5" {
		t.Errorf("LiveCheckGate = %q, %v", id, ok)
	}
}

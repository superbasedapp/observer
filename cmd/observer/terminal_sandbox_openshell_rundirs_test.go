//go:build !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxopenshell"
)

// rundirsSecret is written into an unreadable plan; no note or hint may
// ever carry it (names and ages only, never a dir's contents).
const rundirsSecret = "sk-ant-SENTINEL-0000"

// writeRunDir makes a run dir under stateDir aged by age, with a plan file
// holding body when body is not nil.
func writeRunDir(t *testing.T, stateDir, runID string, body []byte, age time.Duration) {
	t.Helper()
	dir := openShellRunDir(stateDir, runID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	at := time.Now().Add(-age)
	if body != nil {
		p := filepath.Join(dir, "plan.json")
		if err := os.WriteFile(p, body, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, at, at); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chtimes(dir, at, at); err != nil {
		t.Fatal(err)
	}
}

// TestOpenShellUnreadableRunNotes (tracker F-032, the O5 sweep's L5 class):
// one case per kind of run dir the reaper cannot remove. Each is named with
// its age, whether it has a plan file and whether it still holds a gateway;
// nothing read from inside the dir is ever shown.
func TestOpenShellUnreadableRunNotes(t *testing.T) {
	stateDir := t.TempDir()
	junk := []byte(`{"version":999,"note":"` + rundirsSecret + `"}`)
	writeRunDir(t, stateDir, "run-noplan-old01", nil, 3*time.Hour)
	writeRunDir(t, stateDir, "run-noplan-new01", nil, 0)
	writeRunDir(t, stateDir, "run-otherbuild01", junk, 50*time.Hour)

	notes := openShellUnreadableRunNotes(stateDir, time.Now())
	got := map[string]sandboxopenshell.RunDirNote{}
	for _, n := range notes {
		got[n.Name] = n
	}
	for _, tc := range []struct {
		name            string
		planless, holds bool
		minAge, maxAge  time.Duration
	}{
		// An old plan-less dir never had a box and holds nothing.
		{"run-noplan-old01", true, false, 3*time.Hour - time.Minute, 3*time.Hour + time.Minute},
		// A young plan-less dir may be a launch still composing.
		{"run-noplan-new01", true, true, 0, time.Minute},
		// A plan this build cannot read always holds, whatever its age.
		{"run-otherbuild01", false, true, 50*time.Hour - time.Minute, 50*time.Hour + time.Minute},
	} {
		n, ok := got[tc.name]
		if !ok {
			t.Fatalf("%s not named: %+v", tc.name, notes)
		}
		age := time.Duration(n.AgeSeconds) * time.Second
		if n.Planless != tc.planless || n.Holds != tc.holds || age < tc.minAge || age > tc.maxAge {
			t.Errorf("%s: %+v, want planless %v holds %v age in [%s, %s]", tc.name, n, tc.planless, tc.holds, tc.minAge, tc.maxAge)
		}
	}
	if len(notes) != 3 {
		t.Fatalf("notes %+v, want 3", notes)
	}

	hint := openShellRunDirsHint(stateDir, time.Now())
	for _, w := range []string{"run-noplan-old01 (no plan file, 3 h old)", "run-otherbuild01 (a plan this build cannot read, box " + sandboxopenshell.SandboxName("run-otherbuild01") + ", 2 d old)", sandboxopenshell.RunDirsRemedy} {
		if !strings.Contains(hint, w) {
			t.Errorf("hint %q lacks %q", hint, w)
		}
	}
	// The plan's version (999) is looked for with the state dir's path
	// removed: a random temp dir name can hold "999" itself (lane FU7 saw
	// TestOpenShellUnreadableRunNotes3109996222 fail on that alone).
	if strings.Contains(hint, rundirsSecret) || strings.Contains(strings.ReplaceAll(hint, stateDir, ""), "999") {
		t.Fatalf("the hint carries the plan's contents: %q", hint)
	}
	// Nothing was removed.
	for _, id := range []string{"run-noplan-old01", "run-noplan-new01", "run-otherbuild01"} {
		if _, err := os.Stat(openShellRunDir(stateDir, id)); err != nil {
			t.Fatalf("%s was removed: %v", id, err)
		}
	}
	if h := openShellRunDirsHint(t.TempDir(), time.Now()); h != "" {
		t.Fatalf("an empty state dir has a hint: %q", h)
	}
}

// TestOpenShellRunDirsShowWhenUnlisted (tracker F-032): the probe names
// the run dirs the reaper cannot remove even while openshell is not
// listed, the case where a gateway left running waits on row G2, so
// `observer sandbox status` and `observer doctor` (both read the probe's
// note) say why.
func TestOpenShellRunDirsShowWhenUnlisted(t *testing.T) {
	stateDir := t.TempDir()
	writeRunDir(t, stateDir, "run-otherbuild02", []byte("not json"), time.Hour)
	d := &openShellDriver{r: &sandboxRuntime{observerDir: t.TempDir()}, cfg: config.TerminalSandboxOpenShellConfig{StateDir: stateDir}}
	if d.listed() {
		t.Fatal("openshell is listed in an empty config")
	}
	p := d.probe(context.Background())
	if !strings.Contains(p.Hint, "run-otherbuild02 (a plan this build cannot read") {
		t.Fatalf("the unlisted probe's hint %q does not name the run dir", p.Hint)
	}
}

// TestOpenShellLogNotWantedWait (tracker F-032): row G2's reason is logged
// once per change of the run dirs that hold the gateway, never on a pass
// where nothing changed, and never for another row.
func TestOpenShellLogNotWantedWait(t *testing.T) {
	stateDir := t.TempDir()
	var buf strings.Builder
	log := slog.New(slog.NewTextHandler(&buf, nil))
	g2 := sandboxopenshell.GatewayDecision{Rule: "G2", Action: sandboxopenshell.GatewayWait, Reason: "why"}
	if k := openShellLogNotWantedWait(log, openShellUnreadableRunNotes(stateDir, time.Now()), g2, ""); k != "" || buf.Len() != 0 {
		t.Fatalf("nothing to name: key %q, log %q", k, buf.String())
	}
	writeRunDir(t, stateDir, "run-otherbuild03", []byte("x"), time.Hour)
	notes := openShellUnreadableRunNotes(stateDir, time.Now())
	k := openShellLogNotWantedWait(log, notes, g2, "")
	if k != "run-otherbuild03" || !strings.Contains(buf.String(), "reason=why") {
		t.Fatalf("first wait: key %q, log %q", k, buf.String())
	}
	buf.Reset()
	if k2 := openShellLogNotWantedWait(log, notes, g2, k); k2 != k || buf.Len() != 0 {
		t.Fatalf("an unchanged wait logged again: %q", buf.String())
	}
	if k3 := openShellLogNotWantedWait(log, notes, sandboxopenshell.GatewayDecision{Rule: "G1"}, k); k3 != "" || buf.Len() != 0 {
		t.Fatalf("another row logged: %q", buf.String())
	}
}

// TestOpenShellRunDirsShowWhenInactiveOrSwitchedOff (fix round 1 of lane
// FU1): the gateway release path keeps a gateway running for a run dir the
// reaper cannot remove after the openshell component was deselected or the
// sandbox master switch turned off, so the note reaches the probes `observer
// sandbox status` and `observer doctor` read in both cases. One case per
// way the row is off.
func TestOpenShellRunDirsShowWhenInactiveOrSwitchedOff(t *testing.T) {
	requireUnstampedBuild(t)
	for _, tc := range []struct {
		name     string
		mod      func(cfg *config.Config)
		inactive bool
	}{
		{"component not selected (the default)", func(*config.Config) {}, true},
		{"component selected, master switch off", func(cfg *config.Config) {
			cfg.Components.Add = []string{openShellComponentID}
			cfg.Terminal.Sandbox.Enabled = false
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Default()
			tc.mod(&cfg)
			observerDir := t.TempDir()
			writeRunDir(t, openShellStateDir(observerDir, ""), "run-otherbuild04", []byte("not json"), time.Hour)
			r := &sandboxRuntime{cfg: cfg.Terminal.Sandbox, observerDir: observerDir}
			r.buildSandboxDrivers(cfg)
			if _, inactive := r.inactiveDrivers[sandboxbackend.BackendOpenShell]; inactive != tc.inactive {
				t.Fatalf("inactive = %v, want %v", inactive, tc.inactive)
			}
			p, ok := r.driverProbes(context.Background())[sandboxbackend.BackendOpenShell]
			if !ok {
				t.Fatal("no openshell probe")
			}
			if !strings.Contains(p.Hint, "run-otherbuild04 (a plan this build cannot read") {
				t.Fatalf("hint %q does not name the run dir", p.Hint)
			}
		})
	}
	// With no state dir at all, the inactive note is empty.
	cfg := config.Default()
	r := &sandboxRuntime{cfg: cfg.Terminal.Sandbox, observerDir: t.TempDir()}
	r.buildSandboxDrivers(cfg)
	if h := r.driverProbes(context.Background())[sandboxbackend.BackendOpenShell].Hint; h != "" {
		t.Fatalf("an empty state dir has a note: %q", h)
	}
}

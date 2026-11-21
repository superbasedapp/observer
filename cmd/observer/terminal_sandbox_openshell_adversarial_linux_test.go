//go:build linux && !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/sandboxopenshell"
)

// writeOpenShellForeignRun writes a run dir whose plan this binary cannot
// read: a plan version from another build (an upgrade while the run is
// live), the O5 sweep L1 shape.
func writeOpenShellForeignRun(t *testing.T, stateDir, runID string, age time.Duration) string {
	t.Helper()
	dir := openShellRunDir(stateDir, runID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"version":999,"run_id":"` + runID + `"}`)
	if err := openShellWriteExcl(filepath.Join(dir, "plan.json"), body); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-age)
	for _, p := range []string{filepath.Join(dir, "plan.json"), dir} {
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// TestOpenShellReaperSparesAnUnreadableRun (O5 sweep L1, adversarial rows
// A2 and A4): a live run whose plan another build wrote (the plan version
// moved in an upgrade) is never read as gone. The label pass lists its box
// under this install's label; the run dir claims it by its name, so no
// delete is sent, while an abandoned readable run beside it is still
// reaped. The lifecycle counts it as a recorded run, and as a live one
// while a helper holds it or it is young, so the managed gateway is never
// stopped or restarted under it.
func TestOpenShellReaperSparesAnUnreadableRun(t *testing.T) {
	stateDir := t.TempDir()
	gw := sandboxopenshell.Target{Gateway: "openshell"}
	old := writeOpenShellRun(t, stateDir, "run-old-00000001", gw, time.Hour)
	writeOpenShellForeignRun(t, stateDir, "run-upgr-0000002", time.Hour)
	foreign := sandboxopenshell.SandboxName("run-upgr-0000002")
	f := healthyOpenShell()
	f.answer = func(prog string, args []string) (extrun.ExecFacts, bool) {
		switch {
		case slices.Contains(args, "list"):
			return extrun.ExecFacts{Stdout: []byte(old.Name + "\n" + foreign + "\n"), PeakChildren: -1}, true
		case slices.Contains(args, "status"):
			return extrun.ExecFacts{Stdout: []byte(f.status), PeakChildren: -1}, true
		case slices.Contains(args, "get"):
			return extrun.ExecFacts{ExitCode: 1, Stderr: []byte(openShellNotFoundText), PeakChildren: -1}, true
		}
		return extrun.ExecFacts{PeakChildren: -1}, true
	}
	r, ex := f.runner()
	res := openShellSweep(context.Background(), r, stateDir, "0123456789abcdef", func(string) bool { return false }, time.Now)
	if slices.Contains(res.Reaped, foreign) {
		t.Fatalf("the box of a run with an unreadable plan was reaped: %+v", res)
	}
	for _, p := range ex.Calls() {
		if slices.Contains(p.Args, "delete") && slices.Contains(p.Args, foreign) {
			t.Fatalf("a delete was sent for the unreadable run's box: %v", p.Args)
		}
	}
	if !slices.Contains(res.Reaped, old.Name) {
		t.Fatalf("the abandoned readable run was not reaped: %+v", res)
	}
	if _, err := os.Stat(openShellRunDir(stateDir, "run-upgr-0000002")); err != nil {
		t.Fatalf("the unreadable run dir was removed: %v", err)
	}

	// The lifecycle's counts: recorded on any gateway; live only while held
	// or young (an old, unheld one is recorded, so an idle stop waits, but
	// it never blocks a restart forever on its own).
	if n := openShellRunsOn(stateDir, "sbo-anything"); n < 1 {
		t.Fatalf("an unreadable run dir is not counted as recorded: %d", n)
	}
	if n := openShellLiveRunsOn(stateDir, "sbo-anything"); n != 0 {
		t.Fatalf("an old unheld unreadable run counted live: %d", n)
	}
	writeOpenShellForeignRun(t, stateDir, "run-young-000003", 0)
	if n := openShellLiveRunsOn(stateDir, "sbo-anything"); n != 1 {
		t.Fatalf("a young unreadable run is not counted live: %d", n)
	}
}

// TestOpenShellPlanlessRunDirIsBounded (O5 audit finding O5-A4): a run dir
// with no plan file at all (a launch killed between making the dir and
// writing its plan) counts as recorded only while it is young or held, like
// the live count, so it never pins a managed gateway forever. A dir whose
// plan exists but cannot be read stays recorded whatever its age (the
// upgrade case, O5 sweep L1). Nothing is deleted.
func TestOpenShellPlanlessRunDirIsBounded(t *testing.T) {
	planless := func(t *testing.T, stateDir, runID string, age time.Duration) string {
		t.Helper()
		dir := openShellRunDir(stateDir, runID)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		at := time.Now().Add(-age)
		if err := os.Chtimes(dir, at, at); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	cases := []struct {
		name     string
		setup    func(t *testing.T, stateDir string) string
		recorded int
	}{
		{"old planless dir is debris", func(t *testing.T, s string) string { return planless(t, s, "run-noplan-00001", time.Hour) }, 0},
		{"young planless dir counts", func(t *testing.T, s string) string { return planless(t, s, "run-noplan-00002", 0) }, 1},
		{"old dir with an unreadable plan counts", func(t *testing.T, s string) string {
			return writeOpenShellForeignRun(t, s, "run-upgr-0000003", time.Hour)
		}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stateDir := t.TempDir()
			dir := tc.setup(t, stateDir)
			if n := openShellRunsOn(stateDir, "sbo-anything"); n != tc.recorded {
				t.Fatalf("recorded runs %d, want %d", n, tc.recorded)
			}
			if _, err := os.Stat(dir); err != nil {
				t.Fatalf("the run dir was removed: %v", err)
			}
		})
	}
}

// TestOpenShellUnreadableRunDirsSkipsLinksAndJunk: only real directories
// named like a run id count; a symlink or an odd name is never a run.
func TestOpenShellUnreadableRunDirsSkipsLinksAndJunk(t *testing.T) {
	stateDir := t.TempDir()
	runs := filepath.Join(stateDir, "runs")
	if err := os.MkdirAll(filepath.Join(runs, "x"), 0o700); err != nil { // too short for a run id
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(runs, "run-link-0000001")); err != nil {
		t.Fatal(err)
	}
	if got := openShellUnreadableRunDirs(stateDir); len(got) != 0 {
		t.Fatalf("junk counted as runs: %v", got)
	}
}

// TestOpenShellReadonlyHomeShowsNoMask (O5 sweep F-M1, adversarial row
// A13 for the row's own settings): under home_mode "readonly" the box
// binds the whole host home read-only, so a mask path or a configured
// state dir under the home would show through it; each refuses the launch
// naming its key. In tmpfs mode the same paths stay allowed, since nothing
// shows them.
func TestOpenShellReadonlyHomeShowsNoMask(t *testing.T) {
	cases := []struct {
		name string
		cfg  config.TerminalSandboxConfig
		key  string
	}{
		{"a mask path under the home", config.TerminalSandboxConfig{MaskPaths: []string{"/home/dev/.aws"}}, "mask_paths"},
		{"a state dir under the home", config.TerminalSandboxConfig{OpenShell: config.TerminalSandboxOpenShellConfig{StateDir: "/home/dev/osh-state"}}, "state_dir"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := openShellBindFixture()
			b.masks = openShellMasks(tc.cfg, nil)
			if _, err := openShellCompileInput(b); err != nil {
				t.Fatalf("tmpfs home refused an unbound mask: %v", err)
			}
			b.homeMode = "readonly"
			_, err := openShellCompileInput(b)
			if err == nil || !strings.Contains(err.Error(), tc.key) || !strings.Contains(err.Error(), "inside /home/dev,") {
				t.Fatalf("readonly home: %v, want a refusal naming %q and the home", err, tc.key)
			}
		})
	}
}

//go:build unix && !sbo_omit_terminals_sandbox_seatbelt && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestSweepStaleMacPlans pins D-MU7 with planted leftovers: the plan of a
// run whose helper is gone is cleared with the run dirs it names; a fresh
// plan and a plan its helper still locks are kept; a planted symlink in
// place of a run dir is not followed; a dir outside Observer's run roots,
// or named after another run, is never removed.
func TestSweepStaleMacPlans(t *testing.T) {
	obs := t.TempDir()
	tmpRoot := filepath.Join(t.TempDir(), "obsbx-tmp")
	sockRoot := filepath.Join(t.TempDir(), "obsbx")
	outside := t.TempDir()
	for _, d := range []string{tmpRoot, sockRoot} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	roots := []string{tmpRoot, sockRoot}
	plans := filepath.Join(macStateDir(obs, seatbeltDriverName), "plans")
	if err := os.MkdirAll(plans, 0o700); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	mkRun := func(parent, run string) string {
		d := filepath.Join(parent, run)
		if err := os.MkdirAll(filepath.Join(d, "sub"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "sub", "f"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		return d
	}
	plant := func(run string, dirs macRunDirs, mtime time.Time) string {
		b, _ := json.Marshal(seatbeltPlanFile{Version: macPlanVersion, Dirs: dirs})
		p := filepath.Join(plans, run+".json")
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, mtime, mtime); err != nil {
			t.Fatal(err)
		}
		return p
	}
	exists := func(p string) bool { _, err := os.Lstat(p); return err == nil }

	// A: the helper was SIGKILLed.
	aTmp, aSock := mkRun(tmpRoot, "runA"), mkRun(sockRoot, "runA")
	aPlan := plant("runA", macRunDirs{TempDir: aTmp, SocketDir: aSock, SocketParent: sockRoot}, old)
	// B: just written, its helper not started yet.
	bTmp := mkRun(tmpRoot, "runB")
	bPlan := plant("runB", macRunDirs{TempDir: bTmp}, time.Now())
	// C: its helper is alive and holds the lock.
	cTmp := mkRun(tmpRoot, "runC")
	cPlan := plant("runC", macRunDirs{TempDir: cTmp}, old)
	release, err := lockMacPlan(cPlan)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	// D: a planted symlink where the run dir should be, pointing outside.
	victim := mkRun(outside, "victim")
	dLink := filepath.Join(tmpRoot, "runD")
	if err := os.Symlink(victim, dLink); err != nil {
		t.Fatal(err)
	}
	dPlan := plant("runD", macRunDirs{TempDir: dLink}, old)
	// E: a plan naming a dir outside every root, and one under a root but
	// named after another run.
	eOut := mkRun(outside, "runE")
	eOther := mkRun(tmpRoot, "someoneElse")
	ePlan := plant("runE", macRunDirs{TempDir: eOut, SocketDir: eOther}, old)

	n, err := sweepStaleMacPlans(obs, seatbeltDriverName, roots, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("cleared %d plans, want 3 (A, D, E)", n)
	}
	for _, p := range []string{aPlan, aTmp, aSock, dPlan, ePlan} {
		if exists(p) {
			t.Errorf("%s left behind", p)
		}
	}
	for _, p := range []string{bPlan, bTmp, cPlan, cTmp, victim, filepath.Join(victim, "sub", "f"), dLink, eOut, eOther} {
		if !exists(p) {
			t.Errorf("%s was removed", p)
		}
	}
}

//go:build !sbo_omit_terminals_sandbox_credentials && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
)

// TestCredSweepDeadRows drives credSweepDead over one run per sweep row
// (tracker F-055): a dead run's injection record and fresh ids go, every
// run a row keeps stays, and a name that is not a run's file is left.
func TestCredSweepDeadRows(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	old := now.Add(-time.Hour)
	for _, tc := range []struct {
		name string
		// setup prepares observerDir for runID beside its two files and
		// may return the files' time (zero: old).
		setup  func(t *testing.T, obs, runID string) time.Time
		held   bool
		remove bool
	}{
		{"dead run: both files removed", nil, false, true},
		{"young file kept", func(*testing.T, string, string) time.Time { return now.Add(-10 * time.Second) }, false, false},
		{"relay record kept (live, offered or held)", func(t *testing.T, obs, runID string) time.Time {
			credSweepWriteRelay(t, obs, runID)
			return time.Time{}
		}, false, false},
		{"helper holds its lock", func(t *testing.T, obs, runID string) time.Time {
			release, err := sandboxrelayd.HoldRun(obs, runID)
			if err != nil {
				t.Skipf("no liveness lock here: %v", err)
			}
			t.Cleanup(release)
			return time.Time{}
		}, false, false},
		{"hosted teardown record kept", func(t *testing.T, obs, runID string) time.Time {
			p := hostedRecordPath(obs, runID)
			if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
			return time.Time{}
		}, false, false},
		{"dead-run hold keeps it until the re-adoption table decides", nil, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			obs := t.TempDir()
			const runID = "runSENTINEL0000000000F055"
			at := old
			if tc.setup != nil {
				if got := tc.setup(t, obs, runID); !got.IsZero() {
					at = got
				}
			}
			files := credSweepWriteFiles(t, obs, runID, at)
			stray := filepath.Join(credRunsDir(obs), "not a run.txt")
			if err := os.WriteFile(stray, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			_ = os.Chtimes(stray, old, old)
			restoreNow, restoreHold := credNow, credSweepDeadRunHeld
			t.Cleanup(func() { credNow, credSweepDeadRunHeld = restoreNow, restoreHold })
			credNow = func() time.Time { return now }
			credSweepDeadRunHeld = func(_, id string) bool { return tc.held && id == runID }

			credSweepDead(obs)

			for _, p := range files {
				_, err := os.Lstat(p)
				if gone := os.IsNotExist(err); gone != tc.remove {
					t.Fatalf("%s: removed=%v, want %v", p, gone, tc.remove)
				}
			}
			if _, err := os.Lstat(stray); err != nil {
				t.Fatalf("a file that is not a run's was touched: %v", err)
			}
		})
	}
}

// TestCredSweepRunsAfterRelaySweep pins the wiring: the relay daemon's
// sweep (sandboxrelayd.Daemon.OnSweep) runs the sweep hooks, which carry
// credSweepDead, so a dead run's files go without a daemon restart.
func TestCredSweepRunsAfterRelaySweep(t *testing.T) {
	obs := t.TempDir()
	const runID = "runSENTINEL0000000000F055b"
	files := credSweepWriteFiles(t, obs, runID, time.Now().Add(-time.Hour))
	d := &sandboxrelayd.Daemon{ObserverDir: obs, OnSweep: func() { runSandboxRelaySweepHooks(obs) }}
	d.Sweep()
	for _, p := range files {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Fatalf("%s survived the relay sweep: %v", p, err)
		}
	}
}

// credSweepWriteFiles writes runID's injection record and fresh ids with
// modification time at, and returns their paths.
func credSweepWriteFiles(t *testing.T, obs, runID string, at time.Time) []string {
	t.Helper()
	var out []string
	for _, p := range []string{credRunPath(obs, runID), credFreshPath(obs, runID)} {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(`{"v":1}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, at, at); err != nil {
			t.Fatal(err)
		}
		out = append(out, p)
	}
	return out
}

// credSweepWriteRelay writes a relay record for runID.
func credSweepWriteRelay(t *testing.T, obs, runID string) {
	t.Helper()
	rec, err := sandboxrelayd.NewRunRecord(sandboxrelayd.RunRecord{RunID: runID, Tool: "claude-code", ProjectRoot: obs, WorkspaceDir: obs, Roots: []string{obs}})
	if err != nil {
		t.Fatal(err)
	}
	if err := sandboxrelayd.WriteRun(obs, rec); err != nil {
		t.Fatal(err)
	}
}

// TestCredSweepAsksTheHoldOncePerRun (audit FU11-A3): a dead run with a
// file in both runs/ and fresh/ asks the dead-run hold once in one sweep
// (the hold logs its own decision line when it lets a kept run go).
func TestCredSweepAsksTheHoldOncePerRun(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	obs := t.TempDir()
	const runID = "runSENTINEL0000000000A3"
	files := credSweepWriteFiles(t, obs, runID, now.Add(-time.Hour))
	restoreNow, restoreHold := credNow, credSweepDeadRunHeld
	t.Cleanup(func() { credNow, credSweepDeadRunHeld = restoreNow, restoreHold })
	credNow = func() time.Time { return now }
	asks := 0
	credSweepDeadRunHeld = func(string, string) bool { asks++; return false }
	credSweepDead(obs)
	if asks != 1 {
		t.Fatalf("the hold was asked %d times for one run, want 1", asks)
	}
	for _, p := range files {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Fatalf("%s survived: %v", p, err)
		}
	}
}

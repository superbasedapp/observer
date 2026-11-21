package sandboxrelayd

import (
	"os"
	"testing"
)

// TestSweepCallsOnSweepAfterPrune pins Daemon.OnSweep (tracker F-055): it
// runs on every sweep, after the dead helpers' records were pruned, so a
// sweep of what those runs left elsewhere sees them gone.
func TestSweepCallsOnSweepAfterPrune(t *testing.T) {
	obs := t.TempDir()
	const runID = "runSENTINELonsweep"
	rec, err := NewRunRecord(RunRecord{RunID: runID, Tool: "claude-code", ProjectRoot: obs, WorkspaceDir: obs, Roots: []string{obs}})
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteRun(obs, rec); err != nil {
		t.Fatal(err)
	}
	release, err := HoldRun(obs, runID)
	if err != nil {
		t.Skipf("no liveness lock here: %v", err)
	}
	// A helper that dies leaves its lock file behind with nobody holding it.
	DropRunLock(obs, runID)
	_ = release
	calls, recordSeen := 0, true
	d := &Daemon{ObserverDir: obs, OnSweep: func() {
		calls++
		_, err := ReadRun(obs, runID)
		recordSeen = err == nil
	}}
	d.Sweep()
	if calls != 1 {
		t.Fatalf("OnSweep calls = %d, want 1", calls)
	}
	if recordSeen {
		t.Fatal("OnSweep ran before the dead helper's record was pruned")
	}
}

// TestDeadRunHeldAsksTheHold pins the exported accessor: it answers what
// the installed hold answers, and false with none.
func TestDeadRunHeldAsksTheHold(t *testing.T) {
	t.Cleanup(func() { SetDeadRunHold(nil) })
	for _, tc := range []struct {
		name string
		hold func(string, string) bool
		want bool
	}{
		{"no hold", nil, false},
		{"hold keeps", func(string, string) bool { return true }, true},
		{"hold lets go", func(string, string) bool { return false }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			SetDeadRunHold(tc.hold)
			if got := DeadRunHeld(os.TempDir(), "runSENTINEL"); got != tc.want {
				t.Fatalf("DeadRunHeld = %v, want %v", got, tc.want)
			}
		})
	}
}

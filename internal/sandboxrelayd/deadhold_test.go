package sandboxrelayd

import (
	"os"
	"testing"
)

// TestPruneDeadRunRecordsAsksTheHold (tracker F-045): a dead helper's run
// the installed hold names keeps its record and lock file through every
// prune; the others are pruned as before; with no hold installed every
// dead run is pruned. One case per answer of the hold.
func TestPruneDeadRunRecordsAsksTheHold(t *testing.T) {
	cases := []struct {
		name    string
		hold    func(observerDir, runID string) bool
		wantGot []string // the runs pruned
	}{
		{"no hold installed", nil, []string{"run-held", "run-other"}},
		{"the hold keeps one run", func(_, id string) bool { return id == "run-held" }, []string{"run-other"}},
		{"the hold keeps none", func(string, string) bool { return false }, []string{"run-held", "run-other"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			obs := t.TempDir()
			ws := t.TempDir()
			for _, id := range []string{"run-held", "run-other"} {
				rec, err := NewRunRecord(RunRecord{RunID: id, Tool: "claude-code", ProjectRoot: ws, WorkspaceDir: ws, Roots: []string{ws}})
				if err != nil {
					t.Fatal(err)
				}
				if err := WriteRun(obs, rec); err != nil {
					t.Fatal(err)
				}
				// A lock file nobody holds: the helper is gone.
				if err := os.WriteFile(alivePath(obs, id), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			SetDeadRunHold(c.hold)
			defer SetDeadRunHold(nil)
			pruned, err := PruneDeadRunRecords(obs)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]bool{}
			for _, r := range pruned {
				got[r.RunID] = true
			}
			if len(got) != len(c.wantGot) {
				t.Fatalf("pruned %v, want %v", pruned, c.wantGot)
			}
			for _, id := range c.wantGot {
				if !got[id] {
					t.Fatalf("pruned %v, want %v", pruned, c.wantGot)
				}
			}
			for _, id := range []string{"run-held", "run-other"} {
				_, rerr := ReadRun(obs, id)
				_, aerr := os.Lstat(alivePath(obs, id))
				if kept := !got[id]; kept != (rerr == nil) || kept != (aerr == nil) {
					t.Fatalf("%s: record err %v, lock err %v, kept %v", id, rerr, aerr, kept)
				}
			}
		})
	}
}

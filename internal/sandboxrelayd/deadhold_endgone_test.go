//go:build linux

package sandboxrelayd

import (
	"os"
	"sync"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
)

// TestEndGoneKeepsAHeldRunsRecord (lane FU10 fix round 1, audit FU10-A1):
// in the live SIGKILL case the daemon holds state for the run, so the path
// that removed a re-adoptable run's record was endGone, reached from the
// sweep and from a later run's session claim (sessionMayBind). With the
// dead-run hold naming the run, both paths keep its record and lock file
// for the re-adoption step, while the daemon still releases its state
// (EndRun, OnRunEnd). Without the `!deadRunHeld` check in endGone this
// test fails on both rows: PruneDeadRunRecords skips the held run, then
// endGone removes the record and the lock file.
func TestEndGoneKeepsAHeldRunsRecord(t *testing.T) {
	cases := []struct {
		name string
		// end reaches endGone for the run whose helper died.
		end func(t *testing.T, h *bindHarness, d *Daemon, other RunRecord, ws string)
	}{
		{"the daemon's sweep", func(t *testing.T, _ *bindHarness, d *Daemon, _ RunRecord, _ string) {
			if n := d.Sweep(); n != 1 {
				t.Fatalf("the sweep ended %d runs, want 1", n)
			}
		}},
		{"another run's claim of the dead run's session", func(t *testing.T, h *bindHarness, _ *Daemon, other RunRecord, ws string) {
			if r := h.send(t, other, sandboxrelay.HookRequest{Stdin: []byte(`{"cwd":"` + ws + `","session_id":"s-held"}`)}).Refused; r != "" {
				t.Fatalf("the other run was refused the dead run's session: %q", r)
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tr := newBindTree(t)
			var mu sync.Mutex
			ended := map[string]int{}
			d := &Daemon{SweepInterval: -1, OnRunEnd: func(rec RunRecord) {
				mu.Lock()
				ended[rec.RunID]++
				mu.Unlock()
			}}
			held, other := bindRun(t, "run-held", tr), bindRun(t, "run-other", tr)
			h := startBindHarness(t, d, held, other)
			// The run speaks for a session, so the daemon holds its state.
			if r := h.send(t, held, sandboxrelay.HookRequest{Stdin: []byte(`{"cwd":"` + tr.ws + `","session_id":"s-held"}`)}).Refused; r != "" {
				t.Fatalf("the run's own session: %q", r)
			}
			if _, ok := d.Run(held.RunID); !ok {
				t.Fatal("the daemon holds no state for the run")
			}
			// Its helper dies (SIGKILL): the lock file stays, held by nobody.
			if err := os.WriteFile(alivePath(h.obs, held.RunID), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			SetDeadRunHold(func(_, id string) bool { return id == held.RunID })
			defer SetDeadRunHold(nil)

			c.end(t, h, d, other, tr.ws)
			d.FlushHealth()

			if _, err := ReadRun(h.obs, held.RunID); err != nil {
				t.Fatalf("endGone removed a held run's record: %v", err)
			}
			if _, err := os.Lstat(alivePath(h.obs, held.RunID)); err != nil {
				t.Fatalf("endGone removed a held run's lock file: %v", err)
			}
			if _, ok := d.Run(held.RunID); ok {
				t.Fatal("the daemon kept its state for a run whose helper died")
			}
			mu.Lock()
			n := ended[held.RunID]
			mu.Unlock()
			if n != 1 {
				t.Fatalf("OnRunEnd fired %d times for the run, want 1", n)
			}
		})
	}
}

package store

import (
	"context"
	"testing"
	"time"
)

// TestTerminalRunSealFailureKeepsTheRun (audit finding F6): when the seal
// write fails after the run row was committed, InsertTerminalRun still
// reports success (the row is there), retries the seal, and the run reads
// unsealed; once the write works again a later run is sealed.
func TestTerminalRunSealFailureKeepsTheRun(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	prev := sealRetryWaits
	sealRetryWaits = []time.Duration{time.Millisecond, time.Millisecond}
	t.Cleanup(func() { sealRetryWaits = prev; s.SetTerminalRunSealer(nil) })
	calls := 0
	s.SetTerminalRunSealer(func(context.Context, string) (TerminalRunSeal, bool) {
		calls++
		return TerminalRunSeal{KeyID: "k1", PublicKey: "pub", Sig: "sig"}, true
	})
	if _, err := s.db.ExecContext(ctx, `CREATE TRIGGER seal_fails BEFORE UPDATE OF evidence_seal_sig ON terminal_run
		BEGIN SELECT RAISE(ABORT, 'seal write refused'); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertTerminalRun(ctx, sealTestRun("run-f6")); err != nil {
		t.Fatalf("a committed run reported a failed insert: %v", err)
	}
	if calls != 3 {
		t.Fatalf("the seal was tried %d times, want the first try and two retries", calls)
	}
	seal, err := s.TerminalRunSealOf(ctx, "run-f6")
	if err != nil || seal.KeyID != "" {
		t.Fatalf("the run is not there unsealed: %+v %v", seal, err)
	}
	if _, err := s.db.ExecContext(ctx, `DROP TRIGGER seal_fails`); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertTerminalRun(ctx, sealTestRun("run-f6b")); err != nil {
		t.Fatal(err)
	}
	if seal, _ := s.TerminalRunSealOf(ctx, "run-f6b"); seal.KeyID != "k1" {
		t.Fatalf("a working seal write did not seal: %+v", seal)
	}
}

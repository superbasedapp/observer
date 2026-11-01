package sandboxremote

import (
	"testing"
	"time"
)

// TestLedgerSettleReportsAndSettlePlanned (live run 2, finding F-B): Settle
// says what it charged and whether it found an open reservation, never more
// than reserved; SettlePlanned closes a reservation at its planned minutes
// with a note; neither touches a settled entry or another run.
func TestLedgerSettleReportsAndSettlePlanned(t *testing.T) {
	var l Ledger
	l.Reserve("e2b", "2026-10-23", "a", 10)
	l.Reserve("e2b", "2026-10-23", "b", 10)
	l.Reserve("e2b", "2026-10-23", "c", 10)
	if m, ok := l.Settle("a", 150*time.Second); !ok || m != 3 {
		t.Errorf("settle a: %d %v", m, ok)
	}
	if m, ok := l.Settle("b", 3*time.Hour); !ok || m != 10 {
		t.Errorf("settle b past its timeout: %d %v", m, ok)
	}
	if _, ok := l.Settle("a", time.Minute); ok {
		t.Error("a settled entry was settled again")
	}
	if m, ok := l.SettlePlanned("c", "start unknown"); !ok || m != 10 {
		t.Errorf("settle planned c: %d %v", m, ok)
	}
	if _, ok := l.SettlePlanned("missing", "x"); ok {
		t.Error("a run with no reservation was settled")
	}
	for _, e := range l.Entries {
		if !e.Settled {
			t.Errorf("%s not settled", e.RunID)
		}
		if (e.RunID == "c") != (e.Note == "start unknown") {
			t.Errorf("%s note %q", e.RunID, e.Note)
		}
	}
	if got := l.Used("e2b", "2026-10-23"); got != 23 {
		t.Errorf("used %d, want 23", got)
	}
}

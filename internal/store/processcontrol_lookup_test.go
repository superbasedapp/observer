package store

import (
	"context"
	"testing"
	"time"
)

// TestLookupProcessControlStop exercises the read seam against rows written
// through the real writer (InsertNodeProcessControlAudit) — the round-trip a
// hand-built guard_events row would not catch (e.g. a JSON key rename in
// nodeProcessControlReasonMetadata silently breaking this seam's view type).
func TestLookupProcessControlStop(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	launchedAt := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)

	write := func(t *testing.T, st *Store, ts time.Time, pid int, status, reason, ruleID string) {
		t.Helper()
		audit := nodeProcessControlAuditFixture(ts)
		audit.PID = pid
		audit.Status = status
		audit.Reason = reason
		audit.RuleID = ruleID
		if err := st.InsertNodeProcessControlAudit(ctx, audit); err != nil {
			t.Fatalf("InsertNodeProcessControlAudit: %v", err)
		}
	}

	t.Run("no rows at all", func(t *testing.T) {
		t.Parallel()
		st, _ := newTestStore(t)
		_, found, err := st.LookupProcessControlStop(ctx, 4242, launchedAt)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if found {
			t.Fatal("expected no match against an empty table")
		}
	})

	t.Run("matches on pid within the window", func(t *testing.T) {
		t.Parallel()
		st, _ := newTestStore(t)
		write(t, st, launchedAt.Add(1*time.Minute), 5555, "terminated",
			"daily spend accounting is unavailable; cannot verify the configured budget", "B-602")

		stop, found, err := st.LookupProcessControlStop(ctx, 5555, launchedAt)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !found {
			t.Fatal("expected a match")
		}
		if stop.RuleID != "B-602" {
			t.Errorf("RuleID = %q, want B-602", stop.RuleID)
		}
		if stop.Decision != "terminated" {
			t.Errorf("Decision = %q, want terminated", stop.Decision)
		}
		if stop.Reason != "daily spend accounting is unavailable; cannot verify the configured budget" {
			t.Errorf("Reason = %q, unexpected", stop.Reason)
		}
		if !stop.At.Equal(launchedAt.Add(1 * time.Minute)) {
			t.Errorf("At = %v, want %v", stop.At, launchedAt.Add(1*time.Minute))
		}
	})

	t.Run("pid mismatch never matches", func(t *testing.T) {
		t.Parallel()
		st, _ := newTestStore(t)
		write(t, st, launchedAt.Add(1*time.Minute), 6001, "killed", "unrelated", "B-621")

		_, found, err := st.LookupProcessControlStop(ctx, 9999, launchedAt)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if found {
			t.Fatal("expected no match for a different pid")
		}
	})

	t.Run("a row before the window is excluded (recycled pid)", func(t *testing.T) {
		t.Parallel()
		st, _ := newTestStore(t)
		// A stop for the SAME pid, but from an unrelated process that ran
		// and exited before this terminal run even launched, must not be
		// attributed to the new run.
		write(t, st, launchedAt.Add(-10*time.Minute), 7000, "terminated", "unrelated prior process", "B-602")

		_, found, err := st.LookupProcessControlStop(ctx, 7000, launchedAt)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if found {
			t.Fatal("expected the pre-window row to be excluded")
		}
	})

	t.Run("newest matching row wins", func(t *testing.T) {
		t.Parallel()
		st, _ := newTestStore(t)
		write(t, st, launchedAt.Add(1*time.Minute), 8000, "policy_unavailable", "first attempt", "B-602")
		write(t, st, launchedAt.Add(2*time.Minute), 8000, "terminated", "second attempt", "B-602")

		stop, found, err := st.LookupProcessControlStop(ctx, 8000, launchedAt)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !found {
			t.Fatal("expected a match")
		}
		if stop.Decision != "terminated" || stop.Reason != "second attempt" {
			t.Errorf("got decision=%q reason=%q, want the newest row (terminated/second attempt)", stop.Decision, stop.Reason)
		}
	})

	t.Run("non-positive pid never queries", func(t *testing.T) {
		t.Parallel()
		st, _ := newTestStore(t)
		_, found, err := st.LookupProcessControlStop(ctx, 0, launchedAt)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if found {
			t.Fatal("expected no match for pid 0")
		}
	})

	t.Run("a non-process-control guard event is ignored", func(t *testing.T) {
		t.Parallel()
		st, _ := newTestStore(t)
		if _, err := st.InsertGuardEvents(ctx, []GuardEventRow{{
			TS:       launchedAt.Add(1 * time.Minute),
			RuleID:   "R-101",
			Category: "destructive",
			Decision: "deny",
			Reason:   `{"pid":9000}`,
		}}); err != nil {
			t.Fatalf("InsertGuardEvents: %v", err)
		}
		_, found, err := st.LookupProcessControlStop(ctx, 9000, launchedAt)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if found {
			t.Fatal("expected an unrelated-category guard event to be ignored")
		}
	})
}

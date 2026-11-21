package store

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// TestRepairGuardAnchorsInterrupted: a run cancelled mid-search reports
// what it has, flags it Interrupted, returns the context error and writes
// nothing even with Apply, and progress ran while it searched.
func TestRepairGuardAnchorsInterrupted(t *testing.T) {
	t.Parallel()
	s, database := newTestStore(t)
	ctx := context.Background()
	seedMixedAdapters(t, s)
	ids := guardActionIDs(t, database, "c1", 2)
	if _, err := s.InsertGuardEvents(ctx, []GuardEventRow{
		anchoredGuardRow(ids[0], "R-150", t0Guard),
		anchoredGuardRow(ids[1], "R-150", t0Guard.Add(time.Second)),
	}); err != nil {
		t.Fatal(err)
	}
	breakLikePre177(t, database, 1) // provable at once
	breakLikePre177(t, database, 2)
	// Row 2 was also edited, so no id proves it and its search over an
	// enormous range only ends with the context.
	if _, err := database.Exec(`UPDATE guard_events SET reason = 'edited' WHERE id = 2`); err != nil {
		t.Fatal(err)
	}
	deadline, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	var ticks atomic.Int64
	report, err := s.RepairGuardAnchors(deadline, GuardAnchorRepairOptions{
		Apply: true, Ceiling: 1 << 50,
		Progress: func(GuardAnchorProgress) { ticks.Add(1) }, ProgressEvery: 10 * time.Millisecond,
	})
	if !errors.Is(err, context.DeadlineExceeded) || !report.Interrupted || report.Applied ||
		report.Candidates != 2 || report.Proven != 1 {
		t.Fatalf("RepairGuardAnchors = (%+v, %v), want an interrupted report with row 1 proven", report, err)
	}
	if ticks.Load() == 0 {
		t.Error("no progress while searching")
	}
	rows, err := database.Query(`SELECT action_anchor FROM guard_events`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var anchor *int64
		if err := rows.Scan(&anchor); err != nil || anchor != nil {
			t.Fatalf("action_anchor = %v (%v), want NULL: an interrupted run writes nothing", anchor, err)
		}
	}
}

// TestGuardAnchorProgressTicks: the progress callback runs on its interval
// with the live counts and never after stop returns.
func TestGuardAnchorProgressTicks(t *testing.T) {
	t.Parallel()
	var done, proven, unproven, hashed atomic.Int64
	done.Store(3)
	proven.Store(2)
	unproven.Store(1)
	hashed.Store(99)
	var calls atomic.Int64
	got := make(chan GuardAnchorProgress, 1)
	stop := startGuardAnchorProgress(GuardAnchorRepairOptions{
		ProgressEvery: time.Millisecond,
		Progress: func(p GuardAnchorProgress) {
			calls.Add(1)
			select {
			case got <- p:
			default:
			}
		},
	}, 10, time.Now(), &done, &proven, &unproven, &hashed)
	p := <-got
	stop()
	stop() // idempotent
	if p.Done != 3 || p.Candidates != 10 || p.Proven != 2 || p.Unproven != 1 || p.Hashed != 99 {
		t.Fatalf("progress = %+v", p)
	}
	after := calls.Load()
	time.Sleep(10 * time.Millisecond)
	if calls.Load() != after {
		t.Fatal("progress called after stop")
	}
	// A nil callback starts nothing.
	startGuardAnchorProgress(GuardAnchorRepairOptions{}, 0, time.Now(), &done, &proven, &unproven, &hashed)()
}

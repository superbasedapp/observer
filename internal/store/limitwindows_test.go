package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// t0LimitWindows anchors the limit-window fixtures at MIDDAY UTC so the test
// never straddles a date boundary on a machine whose local clock is near
// midnight (the utc-midnight test class).
var t0LimitWindows = time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)

// limitSnapshotFixture returns a snapshot carrying only request-scoped
// headers. Window-bearing cases override Window5hUtil / Window7dUtil.
func limitSnapshotFixture(observed time.Time) models.LimitSnapshot {
	reqRemaining := int64(42)
	return models.LimitSnapshot{
		ScopeHash:    "scope-a",
		Provider:     "anthropic",
		ObservedAt:   observed,
		ReqRemaining: &reqRemaining,
	}
}

// limWin boxes a utilization fraction for the nullable window columns.
func limWin(v float64) *float64 { return &v }

// TestLatestLimitWindowsUsesPartialIndex pins migration 123: the guard poll's
// only read of limit_snapshots must be served by
// idx_limit_snapshots_window, not by a full table scan plus a temp b-tree
// sort. Migration 049 shipped the table with one index whose leading column
// this query never constrains, so on the operator's live node (178k rows) the
// SCAN + TEMP B-TREE ran past the 3 s poll deadline on every poll.
//
// The assertion is on the plan, not on wall-clock time: a timing assertion
// would be flaky on a small fixture, and the plan is the actual invariant.
func TestLatestLimitWindowsUsesPartialIndex(t *testing.T) {
	t.Parallel()
	s, database := newTestStore(t)
	ctx := context.Background()

	// Enough rows that SQLite's planner has a reason to prefer the index,
	// and a realistic mix: most snapshots carry no window at all.
	for i := 0; i < 200; i++ {
		snap := limitSnapshotFixture(t0LimitWindows.Add(time.Duration(i) * time.Minute))
		if i%10 == 0 {
			snap.Window5hUtil = limWin(0.1)
		}
		if err := s.InsertLimitSnapshot(ctx, snap); err != nil {
			t.Fatalf("InsertLimitSnapshot: %v", err)
		}
	}
	if _, err := database.ExecContext(ctx, `ANALYZE`); err != nil {
		t.Fatalf("ANALYZE: %v", err)
	}

	rows, err := database.QueryContext(ctx, `
		EXPLAIN QUERY PLAN
		SELECT window_5h_util, window_7d_util
		  FROM limit_snapshots
		 WHERE window_5h_util IS NOT NULL OR window_7d_util IS NOT NULL
		 ORDER BY observed_at DESC, id DESC LIMIT 1`)
	if err != nil {
		t.Fatalf("EXPLAIN QUERY PLAN: %v", err)
	}
	defer rows.Close()

	var plan []string
	for rows.Next() {
		var id, parent, notused int
		var detail string
		if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatalf("scan plan row: %v", err)
		}
		plan = append(plan, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("plan rows: %v", err)
	}
	if len(plan) == 0 {
		t.Fatal("EXPLAIN QUERY PLAN returned no rows")
	}
	joined := strings.Join(plan, " | ")
	if !strings.Contains(joined, "idx_limit_snapshots_window") {
		t.Fatalf("plan does not use idx_limit_snapshots_window: %s", joined)
	}
	// An index SCAN is the WIN here, not the defect: with the partial index
	// ordered (observed_at DESC, id DESC) SQLite walks its first entry and
	// stops at LIMIT 1. What must never come back is a scan of the TABLE
	// itself — the pre-123 plan, which read every row.
	for _, detail := range plan {
		if !strings.Contains(detail, "limit_snapshots") {
			continue
		}
		if strings.HasPrefix(detail, "SCAN") && !strings.Contains(detail, "USING") {
			t.Fatalf("plan still full-scans the limit_snapshots table: %s", joined)
		}
	}
	if strings.Contains(strings.ToUpper(joined), "TEMP B-TREE") {
		t.Fatalf("plan still sorts via a temp b-tree: %s", joined)
	}
}

// TestLatestLimitWindowsCorrectness is the behaviour half: the newest
// WINDOWED row wins even when newer window-less rows exist, and a table with
// no windowed row at all reports ok=false rather than zero-valued windows.
func TestLatestLimitWindowsCorrectness(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	tests := []struct {
		name   string
		snaps  []models.LimitSnapshot
		wantOK bool
		want5h float64
		want7d float64
	}{
		{
			name:   "no rows at all",
			wantOK: false,
		},
		{
			name: "only window-less rows",
			snaps: []models.LimitSnapshot{
				limitSnapshotFixture(t0LimitWindows),
				limitSnapshotFixture(t0LimitWindows.Add(time.Hour)),
			},
			wantOK: false,
		},
		{
			name: "newest windowed row wins over older windowed rows",
			snaps: []models.LimitSnapshot{
				func() models.LimitSnapshot {
					s := limitSnapshotFixture(t0LimitWindows)
					s.Window5hUtil, s.Window7dUtil = limWin(0.11), limWin(0.22)
					return s
				}(),
				func() models.LimitSnapshot {
					s := limitSnapshotFixture(t0LimitWindows.Add(2 * time.Hour))
					s.Window5hUtil, s.Window7dUtil = limWin(0.77), limWin(0.88)
					return s
				}(),
			},
			wantOK: true,
			want5h: 0.77,
			want7d: 0.88,
		},
		{
			name: "newer window-less rows are skipped",
			snaps: []models.LimitSnapshot{
				func() models.LimitSnapshot {
					s := limitSnapshotFixture(t0LimitWindows)
					s.Window5hUtil, s.Window7dUtil = limWin(0.33), limWin(0.44)
					return s
				}(),
				limitSnapshotFixture(t0LimitWindows.Add(3 * time.Hour)),
				limitSnapshotFixture(t0LimitWindows.Add(4 * time.Hour)),
			},
			wantOK: true,
			want5h: 0.33,
			want7d: 0.44,
		},
		{
			name: "a half-populated window still counts",
			snaps: []models.LimitSnapshot{
				func() models.LimitSnapshot {
					s := limitSnapshotFixture(t0LimitWindows.Add(time.Hour))
					s.Window7dUtil = limWin(0.66)
					return s
				}(),
			},
			wantOK: true,
			want5h: 0,
			want7d: 0.66,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, _ := newTestStore(t)
			for _, snap := range tc.snaps {
				if err := s.InsertLimitSnapshot(ctx, snap); err != nil {
					t.Fatalf("InsertLimitSnapshot: %v", err)
				}
			}
			got5h, got7d, ok, err := s.LatestLimitWindows(ctx)
			if err != nil {
				t.Fatalf("LatestLimitWindows: %v", err)
			}
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !tc.wantOK {
				return
			}
			if got5h != tc.want5h || got7d != tc.want7d {
				t.Fatalf("windows = (%v, %v), want (%v, %v)", got5h, got7d, tc.want5h, tc.want7d)
			}
		})
	}
}

package store

import (
	"context"
	"database/sql"
	"math"
	"reflect"
	"testing"
	"time"
)

// TestGuardAnchorDistanceBucket: each bound is inclusive.
func TestGuardAnchorDistanceBucket(t *testing.T) {
	t.Parallel()
	cases := []struct {
		d    int64
		want int
	}{{0, 0}, {1, 1}, {10, 1}, {11, 2}, {100, 2}, {1_000_000, 6}, {1_000_001, 7}, {math.MaxInt64, 7}}
	for _, tc := range cases {
		if got := guardAnchorDistanceBucket(tc.d); got != tc.want {
			t.Errorf("guardAnchorDistanceBucket(%d) = %d, want %d", tc.d, got, tc.want)
		}
	}
}

// TestRepairGuardAnchorsRadiusAndWorkers: on a real store the bounded
// search proves the near rows, reports the far one with the radius reason,
// and every worker count gives the same report.
func TestRepairGuardAnchorsRadiusAndWorkers(t *testing.T) {
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
	breakLikePre177(t, database, 2)
	// Row 3: hashed with an action id far above everything else, then cleared.
	far := ids[1] + 5_000
	row := sealedGuardRow(guardEventFixture("c1", "R-152", t0Guard.Add(2*time.Second)), "", far)
	var prev string
	if err := database.QueryRow(`SELECT chain_hash FROM guard_events WHERE id = 2`).Scan(&prev); err != nil {
		t.Fatal(err)
	}
	row = sealedGuardRow(row, prev, far)
	insertRawGuardRow(t, database, 3, row, nil)
	ceiling := far + 10
	var first GuardAnchorRepairReport
	for i, workers := range []int{1, 2, 4} {
		report, err := s.RepairGuardAnchors(ctx, GuardAnchorRepairOptions{Ceiling: ceiling, Radius: 1_000, Workers: workers})
		if err != nil {
			t.Fatal(err)
		}
		if report.Candidates != 2 || report.Proven != 1 || report.UnprovenCount != 1 ||
			report.UnprovenByReason[GuardAnchorOutsideRadius] != 1 || len(report.Unproven) != 1 || report.Unproven[0].ID != 3 {
			t.Fatalf("workers %d: report = %+v", workers, report)
		}
		if u := report.Unproven[0]; u.Hint != ids[1] || u.Lo != max(1, ids[1]-1_000) || u.Hi != ids[1]+1_000 {
			t.Fatalf("workers %d: unproven walk = %+v, want around %d", workers, u, ids[1])
		}
		if i == 0 {
			first = report
			continue
		}
		if report.Tries != first.Tries || report.Proven != first.Proven {
			t.Fatalf("workers %d: tries %d proven %d, workers 1: tries %d proven %d",
				workers, report.Tries, report.Proven, first.Tries, first.Proven)
		}
	}
	whole, err := s.RepairGuardAnchors(ctx, GuardAnchorRepairOptions{Ceiling: ceiling, Apply: true})
	if err != nil {
		t.Fatal(err)
	}
	if whole.Proven != 2 || whole.Repaired != 2 {
		t.Fatalf("--radius 0 report = %+v, want both rows proven and written", whole)
	}
	var got int64
	if err := database.QueryRow(`SELECT action_anchor FROM guard_events WHERE id = 3`).Scan(&got); err != nil || got != far {
		t.Fatalf("row 3 action_anchor = %d (%v), want %d", got, err, far)
	}
}

// insertRawGuardRow writes row verbatim as guard_events id (chain columns
// as given), with action_anchor set to anchor (nil: NULL).
func insertRawGuardRow(t *testing.T, database *sql.DB, id int64, row GuardEventRow, anchor *int64) {
	t.Helper()
	if _, err := database.Exec(`INSERT INTO guard_events (id, ts, session_id, tool, event_kind, rule_id, category, severity,
		decision, degraded_from, enforced, source, reason, target_hash, target_excerpt, taint_origin, chain_prev, chain_hash, chain_v, action_anchor)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, row.tsStored, row.SessionID, row.Tool, row.EventKind, row.RuleID, row.Category, row.Severity,
		row.Decision, row.DegradedFrom, row.Source, row.Reason, row.TargetHash, row.TargetExcerpt, row.TaintOrigin,
		row.ChainPrev, row.ChainHash, row.chainVersion(), anchor); err != nil {
		t.Fatal(err)
	}
}

// TestRepairGuardAnchorsRepeatsSkipAndRetry pins the repeat handling on the
// node's shape (one row repeated, every repeat hashed with the same action
// id): with a radius, a window an identical earlier row came up empty in is
// not searched again, and once a later repeat is proven the retry pass
// proves the earlier ones with one hash each. Rows "A" share content and
// action id 5,000; "known" rows still carry their anchor.
func TestRepairGuardAnchorsRepeatsSkipAndRetry(t *testing.T) {
	t.Parallel()
	type spec struct {
		content string // "A" or a known row's rule id
		known   int64  // the anchor a known row still carries; 0 for an "A" candidate
	}
	const anchorA = 5_000
	cases := []struct {
		name         string
		rows         []spec
		wantProven   int
		wantReasons  map[string]int
		wantTries    int64
		wantUnproven []int64
	}{
		{
			name: "a later repeat comes into range: every repeat proven",
			// Row 1 searches around the next known anchor (4,700) and misses;
			// rows 2 and 4 skip that same window; row 6 searches around 4,950
			// and proves 5,000; the retry pass proves rows 1, 2 and 4.
			rows:       []spec{{"A", 0}, {"A", 0}, {"R-1", 4_700}, {"A", 0}, {"R-2", 4_950}, {"A", 0}},
			wantProven: 4, wantReasons: map[string]int{},
			wantTries: 401 + 100 + 3,
		},
		{
			name:       "no repeat ever in range: the first misses, the repeats say why",
			rows:       []spec{{"A", 0}, {"A", 0}, {"R-1", 4_700}},
			wantProven: 0,
			wantReasons: map[string]int{
				GuardAnchorOutsideRadius: 1, GuardAnchorRepeatMissed: 1,
			},
			wantTries:    401,
			wantUnproven: []int64{1, 2},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, database := newTestStore(t)
			ctx := context.Background()
			prev := ""
			for i, sp := range tc.rows {
				base := guardEventFixture("x", "R-150", t0Guard)
				anchor := int64(anchorA)
				var stored *int64
				if sp.known != 0 {
					base = guardEventFixture("y", sp.content, t0Guard)
					anchor = sp.known
					stored = &anchor
				}
				row := sealedGuardRow(base, prev, anchor)
				insertRawGuardRow(t, database, int64(i+1), row, stored)
				prev = row.ChainHash
			}
			for _, workers := range []int{1, 3} {
				report, err := s.RepairGuardAnchors(ctx, GuardAnchorRepairOptions{Ceiling: 10_000, Radius: 200, Workers: workers})
				if err != nil {
					t.Fatal(err)
				}
				var unproven []int64
				for _, u := range report.Unproven {
					unproven = append(unproven, u.ID)
				}
				if report.Proven != tc.wantProven || report.Tries != tc.wantTries ||
					!reflect.DeepEqual(report.UnprovenByReason, tc.wantReasons) || !reflect.DeepEqual(unproven, tc.wantUnproven) {
					t.Fatalf("workers %d: report = %+v", workers, report)
				}
			}
			applied, err := s.RepairGuardAnchors(ctx, GuardAnchorRepairOptions{Ceiling: 10_000, Radius: 200, Apply: true})
			if err != nil || applied.Repaired != tc.wantProven {
				t.Fatalf("apply = (%+v, %v), want %d written", applied, err, tc.wantProven)
			}
			if tc.wantProven == 0 {
				return
			}
			verify, err := s.VerifyGuardChain(ctx)
			if err != nil || !verify.OK {
				t.Fatalf("VerifyGuardChain after apply = (%+v, %v)", verify, err)
			}
		})
	}
}

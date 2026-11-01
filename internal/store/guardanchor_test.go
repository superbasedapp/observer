package store

import (
	"context"
	"database/sql"
	"reflect"
	"strings"
	"testing"
	"time"
)

// guardActionIDs returns the ids of the first n actions of a session, in id
// order.
func guardActionIDs(t *testing.T, database *sql.DB, session string, n int) []int64 {
	t.Helper()
	rows, err := database.QueryContext(context.Background(),
		`SELECT id FROM actions WHERE session_id = ? ORDER BY id LIMIT ?`, session, n)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if len(ids) != n {
		t.Fatalf("session %s: %d actions, want %d", session, len(ids), n)
	}
	return ids
}

// anchoredGuardRow is a guard row anchored to action id.
func anchoredGuardRow(id int64, rule string, ts time.Time) GuardEventRow {
	ev := guardEventFixture("z1", rule, ts)
	ev.ActionID = &id
	return ev
}

// TestGuardChainSurvivesActionMaintenance pins GUARD-CHAIN-1: removing an
// action that carries a guard flag clears guard_events.action_id (so the
// foreign key holds) and leaves the audit chain verifying, because the
// chain hashes action_anchor, which maintenance never touches.
func TestGuardChainSurvivesActionMaintenance(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		// remove deletes the action behind the first guard row the way one
		// maintenance writer does.
		remove func(t *testing.T, s *Store, database *sql.DB, action int64)
	}{
		{
			name: "component purge of the action's adapter",
			remove: func(t *testing.T, s *Store, _ *sql.DB, _ int64) {
				ctx := context.Background()
				plan, err := s.CreateComponentPurgePlan(ctx, ComponentPurgeSpec{Kind: PurgeInteractive, Component: "adapter.zed", CatalogVersion: 1})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := s.ExecuteComponentPurgePlan(ctx, plan.ID, nil, time.Time{}); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			// The statement retention.deleteActionsOlder and migration 079
			// run before deleting the action (internal/retention has its own
			// end-to-end case).
			name: "retention / migration 079 anchor clear",
			remove: func(t *testing.T, _ *Store, database *sql.DB, action int64) {
				for _, q := range []string{
					`UPDATE guard_events SET action_id = NULL WHERE action_id IN (?)`,
					`DELETE FROM action_excerpts WHERE rowid IN (SELECT id FROM action_excerpts_content WHERE c0 IN (?))`,
					`DELETE FROM failure_context WHERE action_id IN (?)`,
					`DELETE FROM actions WHERE id IN (?)`,
				} {
					if _, err := database.Exec(q, action); err != nil {
						t.Fatalf("%s: %v", q, err)
					}
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, database := newTestStore(t)
			ctx := context.Background()
			seedMixedAdapters(t, s)
			zed := guardActionIDs(t, database, "z1", 1)[0]
			kept := guardActionIDs(t, database, "c1", 1)[0]
			if _, err := s.InsertGuardEvents(ctx, []GuardEventRow{
				anchoredGuardRow(zed, "R-150", t0Guard),
				guardEventFixture("z1", "R-110", t0Guard.Add(time.Second)), // hook row, no anchor
				anchoredGuardRow(kept, "R-152", t0Guard.Add(2*time.Second)),
			}); err != nil {
				t.Fatal(err)
			}

			tc.remove(t, s, database, zed)

			var gone int
			if err := database.QueryRow(`SELECT COUNT(*) FROM actions WHERE id = ?`, zed).Scan(&gone); err != nil || gone != 0 {
				t.Fatalf("action %d still present (%d, %v)", zed, gone, err)
			}
			var actionID, anchor sql.NullInt64
			if err := database.QueryRow(`SELECT action_id, action_anchor FROM guard_events ORDER BY id LIMIT 1`).Scan(&actionID, &anchor); err != nil {
				t.Fatal(err)
			}
			if actionID.Valid || !anchor.Valid || anchor.Int64 != zed {
				t.Fatalf("first row action_id=%v action_anchor=%v, want NULL and %d", actionID, anchor, zed)
			}
			report, err := s.VerifyGuardChain(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if !report.OK || report.Checked != 3 {
				t.Fatalf("VerifyGuardChain after maintenance = %+v, want OK across 3 rows", report)
			}
		})
	}
}

// TestVerifyGuardChain_AnchorTamper: the anchor split must not open a new
// way to edit a row silently.
func TestVerifyGuardChain_AnchorTamper(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		tamper string // %d is the other action's id
		detail string
	}{
		{"action_id re-pointed at another action", `UPDATE guard_events SET action_id = ? WHERE id = 1`, guardBreakRepointed},
		{"anchor and action_id moved together", `UPDATE guard_events SET action_id = ?, action_anchor = ? WHERE id = 1`, guardBreakRewritten},
		{"anchor moved, action_id cleared", `UPDATE guard_events SET action_id = NULL, action_anchor = ? WHERE id = 1`, guardBreakRewritten},
		{"anchor cleared with action_id", `UPDATE guard_events SET action_id = NULL, action_anchor = NULL WHERE id = 1`, guardBreakRewritten},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, database := newTestStore(t)
			ctx := context.Background()
			seedMixedAdapters(t, s)
			ids := guardActionIDs(t, database, "z1", 2)
			if _, err := s.InsertGuardEvents(ctx, []GuardEventRow{
				anchoredGuardRow(ids[0], "R-150", t0Guard),
				anchoredGuardRow(ids[0], "R-152", t0Guard.Add(time.Second)),
			}); err != nil {
				t.Fatal(err)
			}
			args := make([]any, strings.Count(tc.tamper, "?"))
			for i := range args {
				args[i] = ids[1]
			}
			if _, err := database.Exec(tc.tamper, args...); err != nil {
				t.Fatal(err)
			}
			report, err := s.VerifyGuardChain(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if report.OK || report.FirstDivergenceID != 1 || !strings.Contains(report.Detail, tc.detail) {
				t.Fatalf("VerifyGuardChain = %+v, want divergence at 1 (%s)", report, tc.detail)
			}
		})
	}
}

// TestVerifyGuardChain_LegacyRowWithoutAnchor: a row whose action_anchor is
// NULL but whose action_id is set (written by a binary that predates
// migration 197) still hashes its action_id.
func TestVerifyGuardChain_LegacyRowWithoutAnchor(t *testing.T) {
	t.Parallel()
	s, database := newTestStore(t)
	ctx := context.Background()
	seedMixedAdapters(t, s)
	id := guardActionIDs(t, database, "z1", 1)[0]
	if _, err := s.InsertGuardEvents(ctx, []GuardEventRow{anchoredGuardRow(id, "R-150", t0Guard)}); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE guard_events SET action_anchor = NULL`); err != nil {
		t.Fatal(err)
	}
	if report, err := s.VerifyGuardChain(ctx); err != nil || !report.OK {
		t.Fatalf("VerifyGuardChain = (%+v, %v), want OK", report, err)
	}
}

// breakLikePre177 reproduces what maintenance did before migration 197: the
// row loses its action id entirely.
func breakLikePre177(t *testing.T, database *sql.DB, guardID int64) {
	t.Helper()
	if _, err := database.Exec(`UPDATE guard_events SET action_id = NULL, action_anchor = NULL WHERE id = ?`, guardID); err != nil {
		t.Fatal(err)
	}
}

// TestRepairGuardAnchors: the repair restores exactly the ids the stored
// hashes prove, and nothing else.
func TestRepairGuardAnchors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		// damage is applied to the 5-row chain (ids 1-5: anchored, anchored,
		// hook, anchored, anchored).
		damage        func(t *testing.T, database *sql.DB)
		ceiling       int64
		wantCand      int
		wantProven    int
		wantUnproven  []int64
		wantVerifyOK  bool
		wantDivergeAt int64
		wantBreaks    map[string]int
	}{
		{
			name:         "intact chain: nothing to do",
			damage:       func(*testing.T, *sql.DB) {},
			wantVerifyOK: true,
		},
		{
			name: "anchors cleared by old maintenance are proven and restored",
			damage: func(t *testing.T, database *sql.DB) {
				breakLikePre177(t, database, 1)
				breakLikePre177(t, database, 2)
				breakLikePre177(t, database, 5)
			},
			wantCand: 3, wantProven: 3, wantVerifyOK: true,
		},
		{
			name: "a cleared row whose content was also edited is not repaired",
			damage: func(t *testing.T, database *sql.DB) {
				breakLikePre177(t, database, 1)
				breakLikePre177(t, database, 4)
				if _, err := database.Exec(`UPDATE guard_events SET decision = 'allow' WHERE id = 4`); err != nil {
					t.Fatal(err)
				}
			},
			wantCand: 2, wantProven: 1, wantUnproven: []int64{4}, wantDivergeAt: 4,
			wantBreaks: map[string]int{guardBreakRewritten: 1},
		},
		{
			name: "an edited row that still has its anchor is not a candidate",
			damage: func(t *testing.T, database *sql.DB) {
				if _, err := database.Exec(`UPDATE guard_events SET reason = 'edited' WHERE id = 2`); err != nil {
					t.Fatal(err)
				}
			},
			wantDivergeAt: 2, wantBreaks: map[string]int{guardBreakRewritten: 1},
		},
		{
			name: "a deleted row stays a broken link",
			damage: func(t *testing.T, database *sql.DB) {
				breakLikePre177(t, database, 5)
				if _, err := database.Exec(`DELETE FROM guard_events WHERE id = 3`); err != nil {
					t.Fatal(err)
				}
			},
			wantCand: 1, wantProven: 1, wantDivergeAt: 4,
			wantBreaks: map[string]int{guardBreakLink: 1},
		},
		{
			name: "an id beyond the ceiling is not found",
			damage: func(t *testing.T, database *sql.DB) {
				breakLikePre177(t, database, 1)
			},
			ceiling:  1,
			wantCand: 1, wantUnproven: []int64{1}, wantDivergeAt: 1,
			wantBreaks: map[string]int{guardBreakRewritten: 1},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, database := newTestStore(t)
			ctx := context.Background()
			seedMixedAdapters(t, s)
			ids := guardActionIDs(t, database, "c1", 4)
			if _, err := s.InsertGuardEvents(ctx, []GuardEventRow{
				anchoredGuardRow(ids[0], "R-150", t0Guard),
				anchoredGuardRow(ids[1], "R-150", t0Guard.Add(time.Second)),
				guardEventFixture("z1", "R-110", t0Guard.Add(2*time.Second)),
				anchoredGuardRow(ids[2], "R-152", t0Guard.Add(3*time.Second)),
				anchoredGuardRow(ids[3], "R-101", t0Guard.Add(4*time.Second)),
			}); err != nil {
				t.Fatal(err)
			}
			var want map[int64]sql.NullInt64
			snapshot := func() map[int64]sql.NullInt64 {
				out := map[int64]sql.NullInt64{}
				rows, err := database.Query(`SELECT id, action_anchor FROM guard_events`)
				if err != nil {
					t.Fatal(err)
				}
				defer rows.Close()
				for rows.Next() {
					var id int64
					var a sql.NullInt64
					if err := rows.Scan(&id, &a); err != nil {
						t.Fatal(err)
					}
					out[id] = a
				}
				return out
			}
			want = snapshot()
			tc.damage(t, database)
			damaged := snapshot()

			dry, err := s.RepairGuardAnchors(ctx, GuardAnchorRepairOptions{Ceiling: tc.ceiling})
			if err != nil {
				t.Fatal(err)
			}
			if dry.Candidates != tc.wantCand || dry.Proven != tc.wantProven || !reflect.DeepEqual(dry.Unproven, tc.wantUnproven) {
				t.Fatalf("dry run = %+v, want candidates %d proven %d unproven %v", dry, tc.wantCand, tc.wantProven, tc.wantUnproven)
			}
			if dry.Applied || !reflect.DeepEqual(snapshot(), damaged) {
				t.Fatal("dry run wrote")
			}

			applied, err := s.RepairGuardAnchors(ctx, GuardAnchorRepairOptions{Apply: true, Ceiling: tc.ceiling})
			if err != nil {
				t.Fatal(err)
			}
			if applied.Repaired != tc.wantProven {
				t.Fatalf("Repaired = %d, want %d", applied.Repaired, tc.wantProven)
			}
			// Every proven row got back exactly its original anchor.
			after := snapshot()
			for id, a := range after {
				if a.Valid && a != want[id] {
					t.Errorf("row %d anchor = %v, want %v", id, a, want[id])
				}
			}
			report, err := s.VerifyGuardChain(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if report.OK != tc.wantVerifyOK || report.FirstDivergenceID != tc.wantDivergeAt {
				t.Fatalf("VerifyGuardChain after repair = %+v, want OK=%v divergence %d", report, tc.wantVerifyOK, tc.wantDivergeAt)
			}
			if !reflect.DeepEqual(report.Breaks, tc.wantBreaks) {
				t.Fatalf("Breaks = %v, want %v", report.Breaks, tc.wantBreaks)
			}
		})
	}
}

// TestRepairGuardAnchors_SkipsRowChangedAfterSearch: Apply re-proves each
// row under the write lock, so a row whose hash no longer matches is left
// alone.
func TestRepairGuardAnchors_SkipsRowChangedAfterSearch(t *testing.T) {
	t.Parallel()
	s, database := newTestStore(t)
	ctx := context.Background()
	seedMixedAdapters(t, s)
	id := guardActionIDs(t, database, "c1", 1)[0]
	if _, err := s.InsertGuardEvents(ctx, []GuardEventRow{anchoredGuardRow(id, "R-150", t0Guard)}); err != nil {
		t.Fatal(err)
	}
	breakLikePre177(t, database, 1)
	if _, err := database.Exec(`UPDATE guard_events SET reason = 'edited' WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	n, err := s.writeGuardAnchors(ctx, []guardAnchorFix{{id: 1, anchor: id}})
	if err != nil || n != 0 {
		t.Fatalf("writeGuardAnchors = (%d, %v), want (0, nil)", n, err)
	}
}

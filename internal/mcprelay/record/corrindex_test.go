// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package record

import (
	"context"
	"database/sql"
	"strings"
	"testing"
)

// explainPlan returns SQLite's EXPLAIN QUERY PLAN detail lines for q.
func explainPlan(t *testing.T, d *sql.DB, q string, args ...any) string {
	t.Helper()
	rows, err := d.QueryContext(context.Background(), "EXPLAIN QUERY PLAN "+q, args...)
	if err != nil {
		t.Fatalf("explain: %v\n%s", err, q)
	}
	defer func() { _ = rows.Close() }()
	var lines []string
	for rows.Next() {
		var id, parent, notused int
		var detail string
		if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatal(err)
		}
		lines = append(lines, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return strings.Join(lines, "\n")
}

// TestCorrelationReadsUseTheAnchorIndexes pins node migration 134 (lane PF1,
// lane IA Q2): the two decision reads ForCorrelation issues - the session
// anchor and the per-call action_ref anchor, each `ORDER BY seq DESC LIMIT` -
// SEARCH mcp_relay_record through the partial anchor indexes on the anchor
// instead of scanning the whole never-pruned chain. The session read needs no
// sort (seq is the rowid every index entry carries); the IN-list read sorts
// only the rows its index ranges matched. The query text is ForCorrelation's,
// built from the same recordColumns; a table populated with unanchored rows
// keeps the planner honest about the partial predicate.
func TestCorrelationReadsUseTheAnchorIndexes(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	for i := 0; i < 40; i++ {
		r := decision(int64(1000+i), "call-"+string(rune('a'+i%26))+string(rune('a'+i/26)))
		if i%4 == 0 {
			r.CodingSessionID, r.ActionRef = "sess-1", "toolu_"+string(rune('a'+i%26))
		}
		if _, err := s.Append(ctx, r); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name IN ('idx_mcprelayrec_codingsess', 'idx_mcprelayrec_actionref')
		AND sql LIKE '%WHERE%IS NOT NULL%'`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("partial anchor indexes present = %d %v, want 2 (migration 134)", n, err)
	}
	for _, tc := range []struct {
		name, q, index, anchor string
		args                   []any
	}{
		{"by session", `SELECT ` + recordColumns + ` FROM mcp_relay_record
			WHERE record_kind = 'decision' AND coding_session_id = ? ORDER BY seq DESC LIMIT ?`, "idx_mcprelayrec_codingsess", "coding_session_id", []any{"sess-1", 500}},
		{"by action_ref", `SELECT ` + recordColumns + ` FROM mcp_relay_record
			WHERE record_kind = 'decision' AND action_ref IN (` + placeholders(3) + `) ORDER BY seq DESC LIMIT ?`, "idx_mcprelayrec_actionref", "action_ref", []any{"toolu_a", "toolu_e", "toolu_i", 500}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan := explainPlan(t, s.db, tc.q, tc.args...)
			t.Logf("plan:\n%s", plan)
			if !strings.Contains(plan, "SEARCH mcp_relay_record USING INDEX "+tc.index+" ("+tc.anchor+"=") {
				t.Fatalf("plan does not SEARCH %s on %s:\n%s", tc.index, tc.anchor, plan)
			}
		})
	}
	// The read itself still returns exactly the anchored decisions.
	got, err := s.ForCorrelation(ctx, "sess-1", nil, 0)
	if err != nil || len(got) != 10 {
		t.Fatalf("ForCorrelation = %d rows %v, want 10", len(got), err)
	}
}

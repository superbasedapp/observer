package store

import (
	"context"
	"database/sql"
	"testing"
	"time"
)

// TestInsertSummaryCall pins the summary_calls insert seam: every column
// lands as given, the timestamp is stored as UTC RFC3339Nano, and an empty
// session id stores NULL.
func TestInsertSummaryCall(t *testing.T) {
	s, database := newTestStore(t)
	ctx := context.Background()
	at := time.Date(2026, 11, 21, 10, 30, 0, 123, time.FixedZone("x", 3600))
	if err := s.InsertSummaryCall(ctx, SummaryCallRow{
		SessionID: "sX", At: at, Model: "claude-haiku-4-5",
		InputTokens: 1000, OutputTokens: 200, CacheReadTokens: 30, CacheCreationTokens: 40,
		CostUSD: 0.0016,
	}); err != nil {
		t.Fatalf("InsertSummaryCall: %v", err)
	}
	if err := s.InsertSummaryCall(ctx, SummaryCallRow{At: at, Model: "m"}); err != nil {
		t.Fatalf("InsertSummaryCall (no session): %v", err)
	}

	rows, err := database.QueryContext(ctx, `SELECT session_id, timestamp, model, input_tokens, output_tokens,
		cache_read_tokens, cache_creation_tokens, cost_usd FROM summary_calls ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	type got struct {
		session      sql.NullString
		ts, model    string
		in, out      int64
		cread, ccrea int64
		cost         float64
	}
	var all []got
	for rows.Next() {
		var g got
		if err := rows.Scan(&g.session, &g.ts, &g.model, &g.in, &g.out, &g.cread, &g.ccrea, &g.cost); err != nil {
			t.Fatal(err)
		}
		all = append(all, g)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("rows = %d, want 2", len(all))
	}
	want := got{
		session: sql.NullString{String: "sX", Valid: true},
		ts:      "2026-11-21T09:30:00.000000123Z",
		model:   "claude-haiku-4-5",
		in:      1000,
		out:     200,
		cread:   30,
		ccrea:   40,
		cost:    0.0016,
	}
	if all[0] != want {
		t.Errorf("row 1 = %+v, want %+v", all[0], want)
	}
	if all[1].session.Valid {
		t.Errorf("row 2 session_id = %q, want NULL", all[1].session.String)
	}
}

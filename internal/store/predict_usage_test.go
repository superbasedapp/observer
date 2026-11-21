package store

import (
	"context"
	"testing"
	"time"
)

// TestLoadUsageRows pins the projection's usage seam: per (session, model)
// over the deduplicated substrate, the window bounds half-open, the tool
// filter, and a turn both the proxy and the transcript saw counted once.
func TestLoadUsageRows(t *testing.T) {
	st := newPredictTestStore(t)
	ctx := context.Background()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := st.db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	day := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
	exec(`INSERT INTO projects (id, root_path, created_at) VALUES (1, '/src/app', ?)`, timestamp(day))
	for _, s := range [][2]string{{"cc-1", "claude-code"}, {"cc-2", "claude-code"}, {"cx-1", "codex"}} {
		exec(`INSERT INTO sessions (id, project_id, tool, started_at) VALUES (?, 1, ?, ?)`, s[0], s[1], timestamp(day))
	}
	usage := func(sid, tool, model, ts string, in, cr, cw, out int64, cost float64, ev string) {
		t.Helper()
		exec(`INSERT INTO token_usage (session_id, timestamp, tool, model, input_tokens, cache_read_tokens, cache_creation_tokens, output_tokens,
			estimated_cost_usd, source, reliability, source_event_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'jsonl', 'accurate', ?)`,
			sid, ts, tool, model, in, cr, cw, out, cost, ev)
	}
	usage("cc-1", "claude-code", "opus", "2026-11-09T01:00:00Z", 10, 1000, 100, 50, 0.5, "a")
	usage("cc-1", "claude-code", "opus", "2026-11-09T02:00:00Z", 20, 2000, 0, 60, 0.7, "b")
	usage("cc-1", "claude-code", "haiku", "2026-11-09T03:00:00Z", 5, 0, 0, 5, 0.01, "c")
	// Outside the window on both ends (the upper bound is exclusive).
	usage("cc-2", "claude-code", "opus", "2026-11-08T23:59:59Z", 999, 0, 0, 0, 9, "d")
	usage("cc-2", "claude-code", "opus", "2026-11-09T06:00:00Z", 999, 0, 0, 0, 9, "e")
	// Another tool.
	usage("cx-1", "codex", "gpt-x", "2026-11-09T01:00:00Z", 7, 0, 0, 7, 0.1, "f")
	// A proxy-only turn of cc-2 counts.
	exec(`INSERT INTO api_turns (session_id, timestamp, provider, model, input_tokens, output_tokens, cache_read_tokens, cache_creation_tokens, cost_usd)
		VALUES ('cc-2', '2026-11-09T04:00:00Z', 'anthropic', 'opus', 30, 40, 300, 3, 0.2)`)
	// An unattributed proxy turn belongs to no session.
	exec(`INSERT INTO api_turns (session_id, timestamp, provider, model, input_tokens, output_tokens, cost_usd)
		VALUES (NULL, '2026-11-09T04:00:00Z', 'anthropic', 'opus', 30, 40, 0.2)`)
	// A turn both captured counts once.
	exec(`INSERT INTO api_turns (session_id, timestamp, provider, model, input_tokens, output_tokens, cache_read_tokens, cost_usd)
		VALUES ('cc-2', '2026-11-09T05:00:00Z', 'anthropic', 'opus', 1, 2, 0, 0.05)`)
	usage("cc-2", "claude-code", "opus", "2026-11-09T05:00:01Z", 1, 0, 0, 2, 0.05, "twin")

	got, err := st.LoadUsageRows(ctx, []string{"claude-code"}, day, day.Add(6*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	type key struct{ sid, model string }
	by := map[key]int{}
	for i, r := range got {
		by[key{r.SessionID, r.Model}] = i
	}
	if len(got) != 3 {
		t.Fatalf("rows %+v, want cc-1/opus, cc-1/haiku, cc-2/opus", got)
	}
	o := got[by[key{"cc-1", "opus"}]]
	if o.Input != 30 || o.CacheRead != 3000 || o.CacheWrite != 100 || o.Output != 110 || o.Turns != 2 || o.Project != "/src/app" {
		t.Errorf("cc-1/opus %+v", o)
	}
	if o.CostUSD < 1.19 || o.CostUSD > 1.21 {
		t.Errorf("cc-1/opus cost %v, want 1.2", o.CostUSD)
	}
	c2 := got[by[key{"cc-2", "opus"}]]
	if c2.Input != 31 || c2.Output != 42 || c2.CacheRead != 300 || c2.CacheWrite != 3 || c2.Turns != 2 {
		t.Errorf("cc-2/opus %+v, want the proxy turn plus the twin once", c2)
	}

	all, err := st.LoadUsageRows(ctx, nil, day, day.Add(6*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 4 {
		t.Errorf("every tool: %d rows, want 4", len(all))
	}
	if none, err := st.LoadUsageRows(ctx, nil, day, day); err != nil || len(none) != 0 {
		t.Errorf("an empty range: %v %v", none, err)
	}
}

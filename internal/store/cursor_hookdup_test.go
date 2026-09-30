package store

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// Cursor 3.17.21 (session cc8322af, 2026-09-08) fired `stop` with the
// NEXT request's generation id but the SAME usage as the
// afterAgentResponse that closed the request. Grounded numbers. The store
// acts only on a PROVEN pair (review finding F3, 2026-09-26): the hook kind
// rides on TokenEvent.HookEvent, and counter equality alone never drops or
// deletes a row.
func TestCursorMislabelledStopDedup(t *testing.T) {
	t0 := time.Date(2026, 9, 8, 4, 36, 43, 395_000_000, time.UTC)
	mk := func(gen, kind string, ts time.Time, in int64) models.TokenEvent {
		return models.TokenEvent{
			SessionID: "cc8322af", ProjectRoot: "/repo", Timestamp: ts, Tool: models.ToolCursor,
			Model: "cursor-grok-4.6-high", Source: models.TokenSourceHook, Reliability: models.ReliabilityAccurate,
			SourceFile: "cursor:hook", SourceEventID: gen + ":stop", MessageID: gen, HookEvent: kind,
			InputTokens: in, OutputTokens: 53139, CacheReadTokens: 15524224,
		}
	}
	const aarKind, stopKind = "afterAgentResponse", "stop"
	aar := mk("52f30b63", aarKind, t0, 420473)
	stop := mk("93c94255", stopKind, t0.Add(1354*time.Millisecond), 420473)
	// The next request's REAL usage, delivered by its own afterAgentResponse.
	realNext := mk("93c94255", aarKind, t0.Add(40*time.Second), 7000)
	farDup := mk("aaaaaaaa", stopKind, t0.Add(10*time.Minute), 420473)
	// 30 s later with the identical tuple: beyond the 10 s window.
	nearDup := mk("cccccccc", stopKind, t0.Add(30*time.Second), 420473)
	other := mk("bbbbbbbb", stopKind, t0.Add(2*time.Second), 999)
	// A different model with the identical counters is not a restatement.
	otherModel := stop
	otherModel.Model = "claude-opus-5-5"

	// Two REAL consecutive requests whose counters happen to be equal:
	// each stop follows its OWN afterAgentResponse, inside 10 s.
	realA1 := mk("11111111", aarKind, t0, 420473)
	realA2 := mk("11111111", stopKind, t0.Add(400*time.Millisecond), 420473)
	realB1 := mk("22222222", aarKind, t0.Add(2*time.Second), 420473)
	realB2 := mk("22222222", stopKind, t0.Add(2400*time.Millisecond), 420473)

	cases := []struct {
		name      string
		seq       [][]models.TokenEvent // one Ingest per element
		wantKeep  []string
		wantInput int64
	}{
		{"afterAgentResponse first", [][]models.TokenEvent{{aar}, {stop}}, []string{"52f30b63"}, 420473},
		{"same batch, fire order", [][]models.TokenEvent{{aar, stop}}, []string{"52f30b63"}, 420473},
		{"then the next request's real usage lands on its own key", [][]models.TokenEvent{{aar}, {stop}, {realNext}}, []string{"52f30b63", "93c94255"}, 420473 + 7000},
		// A reversed race cannot be proven when it happens (no counter
		// equality alone); the next request's authoritative usage evicts
		// the squatter instead of MAX-merging into it.
		{"stop committed first, healed by the next request's usage", [][]models.TokenEvent{{stop}, {aar}, {realNext}}, []string{"52f30b63", "93c94255"}, 420473 + 7000},
		{"different tuple kept", [][]models.TokenEvent{{aar}, {other}}, []string{"52f30b63", "bbbbbbbb"}, 420473 + 999},
		{"different model kept", [][]models.TokenEvent{{aar}, {otherModel}}, []string{"52f30b63", "93c94255"}, 2 * 420473},
		{"outside the window kept (10 min)", [][]models.TokenEvent{{aar}, {farDup}}, []string{"52f30b63", "aaaaaaaa"}, 2 * 420473},
		{"outside the 10 s window kept (30 s)", [][]models.TokenEvent{{aar}, {nearDup}}, []string{"52f30b63", "cccccccc"}, 2 * 420473},
		{"replay re-insert stays deduped", [][]models.TokenEvent{{aar}, {stop}, {stop}, {aar}}, []string{"52f30b63"}, 420473},
		{"two real requests with equal counters both survive", [][]models.TokenEvent{{realA1}, {realA2}, {realB1}, {realB2}}, []string{"11111111", "22222222"}, 2 * 420473},
		{"two real requests with equal counters, one batch", [][]models.TokenEvent{{realA1, realA2, realB1, realB2}}, []string{"11111111", "22222222"}, 2 * 420473},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st, _ := newTestStore(t)
			ctx := context.Background()
			for _, batch := range tc.seq {
				if _, err := st.Ingest(ctx, nil, batch, IngestOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			rows, err := st.db.QueryContext(ctx, `SELECT message_id FROM token_usage WHERE session_id = 'cc8322af' ORDER BY message_id`)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for rows.Next() {
				var m string
				_ = rows.Scan(&m)
				got = append(got, m)
			}
			rows.Close()
			if len(got) != len(tc.wantKeep) {
				t.Fatalf("kept %v, want %v", got, tc.wantKeep)
			}
			for i := range got {
				if got[i] != tc.wantKeep[i] {
					t.Fatalf("kept %v, want %v", got, tc.wantKeep)
				}
			}
			var sum int64
			_ = st.db.QueryRowContext(ctx, `SELECT SUM(input_tokens) FROM token_usage WHERE session_id = 'cc8322af'`).Scan(&sum)
			if sum != tc.wantInput {
				t.Fatalf("input sum = %d, want %d", sum, tc.wantInput)
			}
		})
	}
}

// TestProvenRestatementRemovesOnlyAnExactSquatter pins the adapter-proven
// rule (TokenEvent.Restates): the event is never written, and a row already
// stored under its key is removed ONLY while it carries exactly the restated
// usage and the restated row is present. The historical rows of f91f2ffd
// (2026-08-17) are the grounded squatter shape. Nothing is removed on
// counter equality alone: without a Restates proof the same two rows stay.
func TestProvenRestatementRemovesOnlyAnExactSquatter(t *testing.T) {
	seed := func(t *testing.T, bInput int64) *Store {
		t.Helper()
		st, db := newTestStore(t)
		ctx := context.Background()
		for _, q := range []string{
			`INSERT INTO projects (id, root_path, created_at) VALUES (1, '/repo', '2026-08-17T00:00:00Z')`,
			`INSERT INTO sessions (id, tool, started_at, project_id) VALUES ('f91f', 'cursor', '2026-08-17T21:00:00Z', 1)`,
		} {
			if _, err := db.ExecContext(ctx, q); err != nil {
				t.Fatal(err)
			}
		}
		for _, r := range []struct {
			id, ts string
			in     int64
		}{{"49d5d505", "2026-08-17T21:22:11.094541746Z", 8371}, {"648fba3b", "2026-08-17T21:22:11.901704699Z", bInput}} {
			if _, err := db.ExecContext(ctx, `INSERT INTO token_usage (session_id, timestamp, tool, model, input_tokens, output_tokens, cache_read_tokens, cache_creation_tokens, source, reliability, source_file, source_event_id, message_id)
				VALUES ('f91f', ?, 'cursor', 'default', ?, 4753, 0, 0, 'hook', 'accurate', 'cursor:hook', ?, ?)`, r.ts, r.in, r.id+":stop", r.id); err != nil {
				t.Fatal(err)
			}
		}
		return st
	}
	count := func(t *testing.T, st *Store) int {
		t.Helper()
		var n int
		_ = st.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM token_usage WHERE session_id = 'f91f'`).Scan(&n)
		return n
	}
	stop := models.TokenEvent{
		SessionID: "f91f", ProjectRoot: "/repo", Tool: models.ToolCursor, Model: "default",
		Source: models.TokenSourceHook, Reliability: models.ReliabilityAccurate, SourceFile: "cursor:hook",
		SourceEventID: "648fba3b:stop", MessageID: "648fba3b", HookEvent: "stop",
		Timestamp:   time.Date(2026, 8, 17, 21, 22, 11, 901_704_699, time.UTC),
		InputTokens: 8371, OutputTokens: 4753,
	}
	ctx := context.Background()

	t.Run("proven exact squatter is removed", func(t *testing.T) {
		st := seed(t, 8371)
		proven := stop
		proven.Restates = "49d5d505"
		res, err := st.Ingest(ctx, nil, []models.TokenEvent{proven}, IngestOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if res.TokenRestatementsRemoved != 1 || count(t, st) != 1 {
			t.Fatalf("removed %d, rows %d; want the squatter removed and 49d5d505 kept", res.TokenRestatementsRemoved, count(t, st))
		}
		if res, _ := st.Ingest(ctx, nil, []models.TokenEvent{proven}, IngestOptions{}); res.TokenRestatementsRemoved != 0 || count(t, st) != 1 {
			t.Fatalf("re-run removed %d, rows %d; want an idempotent no-op", res.TokenRestatementsRemoved, count(t, st))
		}
	})
	t.Run("a row that no longer carries the restated usage is kept", func(t *testing.T) {
		st := seed(t, 9000) // absorbed real usage: not a pure restatement any more
		proven := stop
		proven.Restates = "49d5d505"
		res, err := st.Ingest(ctx, nil, []models.TokenEvent{proven}, IngestOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if res.TokenRestatementsRemoved != 0 || count(t, st) != 2 {
			t.Fatalf("removed %d, rows %d; want nothing removed", res.TokenRestatementsRemoved, count(t, st))
		}
	})
	t.Run("counter equality alone removes nothing", func(t *testing.T) {
		st := seed(t, 8371)
		// The same stop WITHOUT a proof: its own key is occupied, so the
		// live stop rule does not fire either, and the two rows stay.
		res, err := st.Ingest(ctx, nil, []models.TokenEvent{stop}, IngestOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if res.TokenRestatementsRemoved != 0 || count(t, st) != 2 {
			t.Fatalf("removed %d, rows %d; want both rows kept without a proof", res.TokenRestatementsRemoved, count(t, st))
		}
	})
}

// The mislabelled stop carries the NEXT generation's key. If it were
// written, the next request's real usage would MAX-merge into it. It
// must be skipped before the upsert so the key stays free.
func TestCursorMislabelledStopNeverSquatsNextKey(t *testing.T) {
	st, _ := newTestStore(t)
	ctx := context.Background()
	t0 := time.Date(2026, 9, 8, 4, 36, 43, 0, time.UTC)
	base := models.TokenEvent{
		SessionID: "s", ProjectRoot: "/repo", Tool: models.ToolCursor, Model: "m",
		Source: models.TokenSourceHook, Reliability: models.ReliabilityAccurate, SourceFile: "cursor:hook",
	}
	a := base
	a.MessageID, a.SourceEventID, a.Timestamp, a.HookEvent = "A", "A:stop", t0, "afterAgentResponse"
	a.InputTokens, a.OutputTokens, a.CacheReadTokens = 420473, 53139, 15524224
	mis := a
	mis.MessageID, mis.SourceEventID, mis.Timestamp, mis.HookEvent = "B", "B:stop", t0.Add(time.Second), "stop"
	realB := base
	realB.MessageID, realB.SourceEventID, realB.Timestamp, realB.HookEvent = "B", "B:stop", t0.Add(90*time.Second), "afterAgentResponse"
	realB.InputTokens, realB.OutputTokens, realB.CacheReadTokens = 7000, 900, 400000
	// One batch, log order — the replay shape.
	if _, err := st.Ingest(ctx, nil, []models.TokenEvent{a, mis, realB}, IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	var in, out int64
	if err := st.db.QueryRowContext(ctx, `SELECT input_tokens, output_tokens FROM token_usage WHERE source_event_id = 'B:stop'`).Scan(&in, &out); err != nil {
		t.Fatal(err)
	}
	if in != 7000 || out != 900 {
		t.Fatalf("B row = %d/%d, want the real 7000/900 (no MAX-merge with the mislabelled restatement)", in, out)
	}
}

// TestSessionHasActionsOutside pins the transcript-check predicate the
// Cursor hooks-log replay consults (S10-CURSOR review finding 3): only
// an activity row from ANOTHER source counts; the replay's own
// `cursor:hook` rows and the ignored store.db row kinds do not.
func TestSessionHasActionsOutside(t *testing.T) {
	ctx := context.Background()
	ts := time.Date(2026, 9, 19, 14, 0, 0, 0, time.UTC)
	mk := func(sid, file, id, typ string) models.ToolEvent {
		return models.ToolEvent{
			SessionID: sid, ProjectRoot: "/repo", Timestamp: ts, Tool: models.ToolCursor,
			SourceFile: file, SourceEventID: id, ActionType: typ, Target: id, Success: true,
		}
	}
	st, _ := newTestStore(t)
	if _, err := st.Ingest(ctx, []models.ToolEvent{
		mk("hook-only", "cursor:hook", "g1:before", models.ActionReadFile),
		mk("storedb-only", "/c/store.db", "sys", models.ActionSystemPrompt),
		mk("storedb-only", "/c/store.db", "ctx", models.ActionPromptContext),
		mk("transcript", "/c/t.jsonl", "turn1", models.ActionReadFile),
	}, nil, IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		sid  string
		want bool
	}{
		{"hook-only", false},
		{"storedb-only", false},
		{"transcript", true},
		{"unknown", false},
	}
	for _, tc := range cases {
		got, err := st.SessionHasActionsOutside(ctx, tc.sid, "cursor:hook", models.ActionSystemPrompt, models.ActionPromptContext)
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Errorf("SessionHasActionsOutside(%s) = %v, want %v", tc.sid, got, tc.want)
		}
	}
}

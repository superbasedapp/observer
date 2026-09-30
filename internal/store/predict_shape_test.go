package store

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/predict"
)

// seedRow is one turn row to plant in the fixture. Source picks the table:
// "proxy" → api_turns, "jsonl" → token_usage.
type seedRow struct {
	source        string
	ts            string
	model         string
	input         int64
	output        int64
	cacheRead     int64
	cacheCreation int64
	// eventID is api_turns.request_id for a proxy row and
	// token_usage.source_event_id for a JSONL row — the exact-match
	// dedup key.
	eventID string
	// promptID is api_turns.prompt_id (migration 139) for a proxy row.
	promptID string
	// reasoning is token_usage.reasoning_tokens for a JSONL row (the
	// transcript's output is NET of it; the proxy's is gross).
	reasoning int64
}

// TestLoadSessionShape_TurnSubstrate is the regression pin for the
// predict-substrate defect: LoadSessionShape read token_usage EXCLUSIVELY,
// so a session the proxy captured but no adapter ever transcribed reported
// no model / no prefix / no samples — while the session-detail endpoint,
// reading the same session's api_turns, simultaneously rendered real turn
// and token totals for it. The panel contradicted itself.
//
// The "proxy_only_live_shape" row is modelled on the live session that
// surfaced this (claude-code launched from the dashboard terminal in a
// directory with no ~/.claude/projects transcript): cache-heavy Anthropic
// turns, a single user_prompt boundary, zero token_usage rows, forever.
func TestLoadSessionShape_TurnSubstrate(t *testing.T) {
	tests := []struct {
		name string
		// sessionModel is sessions.model (usually empty for claude-code).
		sessionModel string
		rows         []seedRow
		promptTimes  []string

		wantModel   string
		wantPrefix  int64
		wantSamples []predict.TurnSample
		wantTPM     []int
	}{
		{
			// THE REGRESSION CASE. Proxy-only, cache-heavy, one prompt.
			// Pre-fix: model "", prefix 0, zero samples.
			name:         "proxy_only_live_shape",
			sessionModel: "",
			rows: []seedRow{
				{source: "proxy", ts: "2026-08-28T08:24:04.051306009Z", model: "claude-sonnet-5", input: 1171, output: 14},
				{source: "proxy", ts: "2026-08-28T08:24:04.138803319Z", model: "claude-sonnet-5", input: 2, output: 107, cacheCreation: 68540},
				{source: "proxy", ts: "2026-08-28T08:24:07.140221662Z", model: "claude-sonnet-5", input: 2, output: 204, cacheRead: 68540, cacheCreation: 172},
				{source: "proxy", ts: "2026-08-28T08:24:10.482755136Z", model: "claude-sonnet-5", input: 504, output: 13, cacheRead: 68712, cacheCreation: 204},
			},
			promptTimes: []string{"2026-08-28T08:24:02.693636247Z"},
			wantModel:   "claude-sonnet-5",
			wantPrefix:  68712,
			wantSamples: []predict.TurnSample{
				{FreshInput: 1171, Output: 14},
				{FreshInput: 2, Output: 107},
				{FreshInput: 0, Output: 204},
				{FreshInput: 0, Output: 13},
			},
			wantTPM: []int{4},
		},
		{
			// Legacy path must be untouched: JSONL-only sessions behave
			// exactly as before the union landed.
			name: "jsonl_only_unchanged",
			rows: []seedRow{
				{source: "jsonl", ts: "2026-08-28T09:00:00Z", model: "claude-sonnet-5", input: 900, output: 40, eventID: "msg_a"},
				{source: "jsonl", ts: "2026-08-28T09:00:10Z", model: "claude-sonnet-5", input: 5000, output: 60, cacheRead: 4800, eventID: "msg_b"},
			},
			promptTimes: []string{"2026-08-28T08:59:00Z"},
			wantModel:   "claude-sonnet-5",
			wantPrefix:  4800,
			wantSamples: []predict.TurnSample{
				{FreshInput: 900, Output: 40},
				{FreshInput: 200, Output: 60},
			},
			wantTPM: []int{2},
		},
		{
			// Dedup gate 1: the adapter mirrors the upstream message id,
			// so source_event_id == request_id. One turn, not two.
			name: "both_sources_deduped_by_event_id",
			rows: []seedRow{
				{source: "proxy", ts: "2026-08-28T10:00:00Z", model: "claude-sonnet-5", input: 700, output: 25, cacheRead: 600, eventID: "msg_dup"},
				{source: "jsonl", ts: "2026-08-28T10:00:00Z", model: "claude-sonnet-5", input: 700, output: 25, cacheRead: 600, eventID: "msg_dup"},
			},
			promptTimes: []string{"2026-08-28T09:59:00Z"},
			wantModel:   "claude-sonnet-5",
			wantPrefix:  600,
			wantSamples: []predict.TurnSample{{FreshInput: 100, Output: 25}},
			wantTPM:     []int{1},
		},
		{
			// Dedup gate 2: ids differ (codex "tk:…" vs proxy "resp_…"),
			// so only the token-shape match recognises the same turn.
			name: "both_sources_deduped_by_token_shape",
			rows: []seedRow{
				{source: "proxy", ts: "2026-08-28T11:00:00Z", model: "gpt-5.6-sol", input: 1200, output: 80, cacheRead: 900, cacheCreation: 0, eventID: "resp_abc"},
				{source: "jsonl", ts: "2026-08-28T11:00:09Z", model: "gpt-5.6-sol", input: 1200, output: 80, cacheRead: 900, cacheCreation: 0, eventID: "tk:file:L12"},
			},
			promptTimes: []string{"2026-08-28T10:59:00Z"},
			wantModel:   "gpt-5.6-sol",
			wantPrefix:  900,
			wantSamples: []predict.TurnSample{{FreshInput: 300, Output: 80}},
			wantTPM:     []int{1},
		},
		{
			// Partial coverage — the case the session-detail endpoint was
			// fixed for in 2026-04. Proxy caught one turn, the adapter
			// caught a DIFFERENT one. Both must survive; neither source is
			// dropped wholesale.
			name: "partial_overlap_keeps_both",
			rows: []seedRow{
				{source: "proxy", ts: "2026-08-28T12:00:00Z", model: "claude-sonnet-5", input: 400, output: 10, cacheRead: 300, eventID: "resp_1"},
				{source: "jsonl", ts: "2026-08-28T12:00:30Z", model: "claude-sonnet-5", input: 9000, output: 55, cacheRead: 8000, eventID: "msg_2"},
			},
			promptTimes: []string{"2026-08-28T11:59:00Z"},
			wantModel:   "claude-sonnet-5",
			wantPrefix:  8000,
			wantSamples: []predict.TurnSample{
				{FreshInput: 100, Output: 10},
				{FreshInput: 1000, Output: 55},
			},
			wantTPM: []int{2},
		},
		{
			// sessions.model, when set, still wins over the fallback.
			name:         "session_model_wins",
			sessionModel: "claude-opus-5",
			rows: []seedRow{
				{source: "proxy", ts: "2026-08-28T13:00:00Z", model: "claude-sonnet-5", input: 100, output: 5},
			},
			wantModel:   "claude-opus-5",
			wantSamples: []predict.TurnSample{{FreshInput: 100, Output: 5}},
		},
		{
			// Honest empty: no turn rows in EITHER table.
			name:        "no_turns_anywhere",
			rows:        nil,
			promptTimes: []string{"2026-08-28T14:00:00Z"},
			wantModel:   "",
			wantPrefix:  0,
			wantSamples: nil,
			wantTPM:     nil,
		},
		{
			// Zero-token rows are still skipped from the samples (an
			// errored turn is not an observation), but must not break the
			// model/prefix reads around them.
			name: "zero_token_row_skipped",
			rows: []seedRow{
				{source: "proxy", ts: "2026-08-28T15:00:00Z", model: "claude-sonnet-5", input: 0, output: 0},
				{source: "proxy", ts: "2026-08-28T15:00:05Z", model: "claude-sonnet-5", input: 800, output: 20, cacheRead: 700},
			},
			promptTimes: []string{"2026-08-28T14:59:00Z"},
			wantModel:   "claude-sonnet-5",
			wantPrefix:  700,
			wantSamples: []predict.TurnSample{{FreshInput: 100, Output: 20}},
			wantTPM:     []int{1},
		},
		{
			// Prompt-id grouping (migration 139) is EXACT and wins over
			// timestamp bucketing: the one user_prompt boundary would bucket
			// all five turns into a single message, but the client said
			// they served two prompts. Groups come back in first-seen order,
			// and a zero-token row does not count toward its prompt.
			name: "prompt_id_groups_win",
			rows: []seedRow{
				{source: "proxy", ts: "2026-08-28T16:00:01Z", model: "claude-sonnet-5", input: 100, output: 5, promptID: "p-a"},
				{source: "proxy", ts: "2026-08-28T16:00:02Z", model: "claude-sonnet-5", input: 100, output: 5, promptID: "p-a"},
				{source: "proxy", ts: "2026-08-28T16:00:03Z", model: "claude-sonnet-5", input: 100, output: 5, promptID: "p-a"},
				{source: "proxy", ts: "2026-08-28T16:00:04Z", model: "claude-sonnet-5", input: 0, output: 0, promptID: "p-b"},
				{source: "proxy", ts: "2026-08-28T16:00:05Z", model: "claude-sonnet-5", input: 100, output: 5, promptID: "p-b"},
				{source: "proxy", ts: "2026-08-28T16:00:06Z", model: "claude-sonnet-5", input: 100, output: 5, promptID: "p-b"},
			},
			promptTimes: []string{"2026-08-28T16:00:00Z"},
			wantModel:   "claude-sonnet-5",
			wantSamples: []predict.TurnSample{
				{FreshInput: 100, Output: 5},
				{FreshInput: 100, Output: 5},
				{FreshInput: 100, Output: 5},
				{FreshInput: 100, Output: 5},
				{FreshInput: 100, Output: 5},
			},
			wantTPM: []int{3, 2},
		},
		{
			// Prompt ids also cover a session with NO user_prompt actions
			// at all - the ~68% the timestamp path cannot bucket.
			name: "prompt_id_without_user_prompt_actions",
			rows: []seedRow{
				{source: "proxy", ts: "2026-08-28T17:00:01Z", model: "claude-sonnet-5", input: 100, output: 5, promptID: "p-1"},
				{source: "proxy", ts: "2026-08-28T17:00:02Z", model: "claude-sonnet-5", input: 100, output: 5, promptID: "p-2"},
			},
			wantModel: "claude-sonnet-5",
			wantSamples: []predict.TurnSample{
				{FreshInput: 100, Output: 5},
				{FreshInput: 100, Output: 5},
			},
			wantTPM: []int{1, 1},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := newPredictTestStore(t)
			ctx := context.Background()
			seedShapeSession(t, st, "sess-1", tc.sessionModel, tc.rows, tc.promptTimes)

			got, err := st.LoadSessionShape(ctx, "sess-1")
			if err != nil {
				t.Fatalf("LoadSessionShape: %v", err)
			}
			if got.Model != tc.wantModel {
				t.Errorf("Model = %q, want %q", got.Model, tc.wantModel)
			}
			if got.PrefixTokens != tc.wantPrefix {
				t.Errorf("PrefixTokens = %d, want %d", got.PrefixTokens, tc.wantPrefix)
			}
			if len(got.TurnSamples) != len(tc.wantSamples) {
				t.Fatalf("TurnSamples len = %d, want %d (%+v)", len(got.TurnSamples), len(tc.wantSamples), got.TurnSamples)
			}
			for i, w := range tc.wantSamples {
				if got.TurnSamples[i] != w {
					t.Errorf("TurnSamples[%d] = %+v, want %+v", i, got.TurnSamples[i], w)
				}
			}
			if len(got.TurnsPerMessage) != len(tc.wantTPM) {
				t.Fatalf("TurnsPerMessage = %v, want %v", got.TurnsPerMessage, tc.wantTPM)
			}
			for i, w := range tc.wantTPM {
				if got.TurnsPerMessage[i] != w {
					t.Errorf("TurnsPerMessage[%d] = %d, want %d", i, got.TurnsPerMessage[i], w)
				}
			}
			if got.ObservedMessages != len(tc.wantTPM) {
				t.Errorf("ObservedMessages = %d, want %d", got.ObservedMessages, len(tc.wantTPM))
			}
		})
	}
}

// TestLoadSessionShape_DedupFollowsDerive pins the predictor substrate onto
// the one session rule, sessionmsg.DeriveVerdicts (lane R2-PARITY-2). The
// old SQL NOT EXISTS compared the transcript's RAW output with the proxy's
// gross output, so a codex-shaped reasoning-split twin survived and the turn
// was sampled twice; and it dropped EVERY same-shape transcript row, where
// Derive claims one twin per proxy row.
func TestLoadSessionShape_DedupFollowsDerive(t *testing.T) {
	st := newPredictTestStore(t)
	seedShapeSession(t, st, "sess-d", "gpt-5.4", []seedRow{
		{source: "proxy", ts: "2026-08-28T10:00:00Z", model: "gpt-5.4", input: 1000, output: 300, eventID: "resp_1"},
		// The same turn from the transcript: output net of 50 reasoning.
		{source: "jsonl", ts: "2026-08-28T10:00:05Z", model: "gpt-5.4", input: 1000, output: 250, reasoning: 50, eventID: "tk:L1"},
		// A distinct transcript-only turn with the proxy turn's exact shape:
		// one proxy row claims ONE twin, so this one must stay.
		{source: "jsonl", ts: "2026-08-28T10:20:00Z", model: "gpt-5.4", input: 1000, output: 250, reasoning: 50, eventID: "tk:L2"},
	}, nil)
	got, err := st.LoadSessionShape(context.Background(), "sess-d")
	if err != nil {
		t.Fatalf("LoadSessionShape: %v", err)
	}
	// The proxy row carries its twin's visible output (the header's output
	// bucket), then the transcript-only turn.
	want := []predict.TurnSample{{FreshInput: 1000, Output: 250}, {FreshInput: 1000, Output: 250}}
	if len(got.TurnSamples) != len(want) {
		t.Fatalf("TurnSamples = %+v, want %+v (twin once, second turn kept)", got.TurnSamples, want)
	}
	for i := range want {
		if got.TurnSamples[i] != want[i] {
			t.Errorf("TurnSamples[%d] = %+v, want %+v", i, got.TurnSamples[i], want[i])
		}
	}
}

// TestLoadToolProjectPrior_CountsProxyOnlySessions pins the sibling half
// of the same defect: the cross-session fan-out prior gated on
// EXISTS(token_usage), so proxy-only sessions were invisible to it and a
// proxy-heavy node fell below the 3-session floor and silently dropped to
// the static default tier.
func TestLoadToolProjectPrior_CountsProxyOnlySessions(t *testing.T) {
	st := newPredictTestStore(t)
	ctx := context.Background()

	// Three comparable proxy-only sessions, each 2 user prompts and 4
	// proxy turns ⇒ avg fan-out 2.
	for _, id := range []string{"p1", "p2", "p3"} {
		rows := []seedRow{
			{source: "proxy", ts: "2026-08-20T10:00:01Z", model: "claude-sonnet-5", input: 100, output: 10},
			{source: "proxy", ts: "2026-08-20T10:00:02Z", model: "claude-sonnet-5", input: 100, output: 10},
			{source: "proxy", ts: "2026-08-20T10:00:11Z", model: "claude-sonnet-5", input: 100, output: 10},
			{source: "proxy", ts: "2026-08-20T10:00:12Z", model: "claude-sonnet-5", input: 100, output: 10},
		}
		seedShapeSession(t, st, id, "", rows,
			[]string{"2026-08-20T10:00:00Z", "2026-08-20T10:00:10Z"})
	}

	prior, err := st.LoadToolProjectPrior(ctx, "claude-code", 1, 0)
	if err != nil {
		t.Fatalf("LoadToolProjectPrior: %v", err)
	}
	if len(prior) != 3 {
		t.Fatalf("prior = %v, want 3 samples (proxy-only sessions must count)", prior)
	}
	for i, v := range prior {
		if v != 2 {
			t.Errorf("prior[%d] = %d, want 2 (4 turns / 2 prompts)", i, v)
		}
	}
}

// TestLoadToolProjectPrior_UsesPromptIDs pins the prior's prompt-id rung:
// sessions whose proxied turns carry prompt ids join the prior even with no
// user_prompt actions, at tagged turns / distinct prompt ids.
func TestLoadToolProjectPrior_UsesPromptIDs(t *testing.T) {
	st := newPredictTestStore(t)
	ctx := context.Background()

	// Three sessions, each 6 tagged turns over 2 prompts => fan-out 3.
	// No user_prompt actions anywhere.
	for _, id := range []string{"q1", "q2", "q3"} {
		var rows []seedRow
		for i, pid := range []string{"a", "a", "a", "b", "b", "b"} {
			rows = append(rows, seedRow{
				source: "proxy", ts: "2026-08-20T10:00:0" + string(rune('1'+i)) + "Z",
				model: "claude-sonnet-5", input: 100, output: 10, promptID: id + "-" + pid,
			})
		}
		seedShapeSession(t, st, id, "", rows, nil)
	}

	prior, err := st.LoadToolProjectPrior(ctx, "claude-code", 1, 0)
	if err != nil {
		t.Fatalf("LoadToolProjectPrior: %v", err)
	}
	if len(prior) != 3 {
		t.Fatalf("prior = %v, want 3 samples (prompt-id sessions must count)", prior)
	}
	for i, v := range prior {
		if v != 3 {
			t.Errorf("prior[%d] = %d, want 3 (6 tagged turns / 2 prompt ids)", i, v)
		}
	}
}

// seedShapeSession plants one session plus its turn rows and user_prompt
// boundaries. Session ids share project 1 / tool claude-code so the prior
// test's scoping works.
func seedShapeSession(t *testing.T, st *Store, id, model string, rows []seedRow, promptTimes []string) {
	t.Helper()
	ctx := context.Background()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := st.db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("seed %q: %v", q, err)
		}
	}
	exec(`INSERT OR IGNORE INTO projects (id, root_path, created_at)
	      VALUES (1, '/tmp/shape', '2026-08-01T00:00:00Z')`)
	var m any
	if model != "" {
		m = model
	}
	exec(`INSERT INTO sessions (id, project_id, tool, model, started_at)
	      VALUES (?, 1, 'claude-code', ?, '2026-08-28T08:00:00Z')`, id, m)

	for i, r := range rows {
		switch r.source {
		case "proxy":
			var reqID, promptID any
			if r.eventID != "" {
				reqID = r.eventID
			}
			if r.promptID != "" {
				promptID = r.promptID
			}
			exec(`INSERT INTO api_turns
			        (session_id, timestamp, provider, model, request_id,
			         input_tokens, output_tokens, cache_read_tokens, cache_creation_tokens,
			         prompt_id)
			      VALUES (?, ?, 'anthropic', ?, ?, ?, ?, ?, ?, ?)`,
				id, r.ts, r.model, reqID, r.input, r.output, r.cacheRead, r.cacheCreation, promptID)
		case "jsonl":
			exec(`INSERT INTO token_usage
			        (session_id, timestamp, tool, model, source, source_file, source_event_id,
			         input_tokens, output_tokens, cache_read_tokens, cache_creation_tokens, reasoning_tokens)
			      VALUES (?, ?, 'claude-code', ?, 'jsonl', ?, ?, ?, ?, ?, ?, ?)`,
				id, r.ts, r.model, id+"-file", r.eventID,
				r.input, r.output, r.cacheRead, r.cacheCreation, r.reasoning)
		default:
			t.Fatalf("row %d: unknown source %q", i, r.source)
		}
	}
	for _, ts := range promptTimes {
		exec(`INSERT INTO actions (session_id, project_id, timestamp, tool, action_type, success)
		      VALUES (?, 1, ?, 'claude-code', 'user_prompt', 1)`, id, ts)
	}
}

// TestInsertAPITurn_PersistsPromptID pins the store half of migration 139:
// the proxy's prompt id lands in api_turns.prompt_id, and an absent one is
// NULL (so the predictor's prompt-id rung stays empty for untagged turns).
func TestInsertAPITurn_PersistsPromptID(t *testing.T) {
	st := newPredictTestStore(t)
	ctx := context.Background()
	seedShapeSession(t, st, "sess-p", "", nil, nil)
	for _, pid := range []string{"4b8f1c2e-9d3a-4f6b-8e21-7c5d0a9b3e14", ""} {
		if _, err := st.InsertAPITurn(ctx, models.APITurn{
			SessionID: "sess-p", Timestamp: time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC),
			Provider: "anthropic", Model: "claude-sonnet-5", RequestID: "req-" + pid,
			InputTokens: 10, OutputTokens: 2, PromptID: pid,
		}); err != nil {
			t.Fatalf("InsertAPITurn: %v", err)
		}
	}
	rows, err := st.db.QueryContext(ctx, `SELECT prompt_id FROM api_turns WHERE session_id = 'sess-p' ORDER BY id`)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	defer rows.Close()
	var got []sql.NullString
	for rows.Next() {
		var v sql.NullString
		if err := rows.Scan(&v); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got = append(got, v)
	}
	if len(got) != 2 {
		t.Fatalf("rows = %d, want 2", len(got))
	}
	if !got[0].Valid || got[0].String != "4b8f1c2e-9d3a-4f6b-8e21-7c5d0a9b3e14" {
		t.Errorf("tagged turn prompt_id = %+v, want the uuid", got[0])
	}
	if got[1].Valid {
		t.Errorf("untagged turn prompt_id = %q, want NULL", got[1].String)
	}
}

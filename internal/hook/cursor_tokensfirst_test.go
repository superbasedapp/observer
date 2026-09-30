package hook

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter/cursor"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// orderSink records each Ingest call's shape and makes any call that
// carries ACTION rows slow — the 2026-09-19 8be96a3f shape, where the
// action write (InsertActions + FTS) ate the whole hook deadline and the
// token row, bundled behind it, was never written.
type orderSink struct {
	fakeSink
	calls       []string
	actionDelay time.Duration
}

func (o *orderSink) Ingest(ctx context.Context, events []models.ToolEvent, tokens []models.TokenEvent, opts store.IngestOptions) (store.IngestResult, error) {
	shape := "actions"
	if len(events) == 0 {
		shape = "tokens"
	}
	if len(events) > 0 && len(tokens) > 0 {
		shape = "mixed"
	}
	o.calls = append(o.calls, shape)
	if len(events) > 0 && o.actionDelay > 0 {
		select {
		case <-time.After(o.actionDelay):
		case <-ctx.Done():
			return store.IngestResult{}, ctx.Err()
		}
	}
	return o.fakeSink.Ingest(ctx, events, tokens, opts)
}

func TestProcessCursorEvent_TokensFirstAndSurviveSlowActionWrite(t *testing.T) {
	cases := []struct {
		name  string
		event string
		body  string
	}{
		{
			name:  "afterAgentResponse",
			event: cursor.EventAfterAgentResponse,
			body: `{"conversation_id":"c1","generation_id":"g1","model":"cursor-grok-4.6-high",
				"text":"done","workspace_roots":["/r"],
				"input_tokens":2783511,"output_tokens":21724,"cache_read_tokens":2529792,"cache_write_tokens":0}`,
		},
		{
			name:  "afterAgentResponse empty text still carries usage",
			event: cursor.EventAfterAgentResponse,
			body: `{"conversation_id":"c1","generation_id":"g2","model":"cursor-grok-4.6-high",
				"text":"","workspace_roots":["/r"],
				"input_tokens":100,"output_tokens":5,"cache_read_tokens":40,"cache_write_tokens":0}`,
		},
		{
			name:  "stop",
			event: cursor.EventStop,
			body: `{"conversation_id":"c1","generation_id":"g3","model":"cursor-grok-4.6-high",
				"status":"completed","workspace_roots":["/r"],
				"input_tokens":2783511,"output_tokens":21724,"cache_read_tokens":2529792,"cache_write_tokens":0}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sink := &orderSink{actionDelay: 200 * time.Millisecond}
			var stdout, stderr bytes.Buffer
			// 5ms configured deadline: every ACTION write times out, as on
			// the live 27 GB DB; the token write must still land.
			HandleCursorEvent(tc.event, sink, nil, strings.NewReader(tc.body), &stdout, &stderr, 5*time.Millisecond)
			if len(sink.calls) == 0 || sink.calls[0] != "tokens" {
				t.Fatalf("first Ingest call = %v, want a token-only call first", sink.calls)
			}
			for _, c := range sink.calls {
				if c == "mixed" {
					t.Fatalf("tokens bundled with actions: calls=%v", sink.calls)
				}
			}
			if len(sink.tokens) != 1 {
				t.Fatalf("token rows = %d, want 1 (stderr=%q)", len(sink.tokens), stderr.String())
			}
			if tc.name != "afterAgentResponse empty text still carries usage" && sink.tokens[0].InputTokens != 2783511-2529792 {
				t.Fatalf("input = %d, want net %d", sink.tokens[0].InputTokens, 2783511-2529792)
			}
		})
	}
}

func TestCursorRootlessConversationGetsSyntheticRootButGuardSeesNone(t *testing.T) {
	// Cursor Cloud Agent (bc-…) payload, verbatim shape from Cursor
	// 3.21.13: workspace_roots is empty.
	body := `{"conversation_id":"bc-4e387d38-4596-4b70-8ca8-5c1f2db7290a","generation_id":"bc-4e387d38-4596-4b70-8ca8-5c1f2db7290a",
		"model":"claude-4.5-sonnet","subagent_id":"call-1","subagent_type":"computerUse",
		"hook_event_name":"subagentStart","workspace_roots":[]}`
	sink := &fakeSink{}
	var stdout, stderr bytes.Buffer
	HandleCursorEvent(cursor.EventSubagentStart, sink, nil, strings.NewReader(body), &stdout, &stderr, 250*time.Millisecond)
	if len(sink.called) != 1 || sink.called[0].ProjectRoot != cursor.SyntheticProjectRoot {
		t.Fatalf("rows=%+v stderr=%q, want one row under %q", sink.called, stderr.String(), cursor.SyntheticProjectRoot)
	}

	shell := `{"conversation_id":"bc-x","generation_id":"g","command":"rm -rf /tmp/x","workspace_roots":[]}`
	if ev, ok := BuildCursorEvent(cursor.EventBeforeShellCommand, []byte(shell), nil); ok && ev.ProjectRoot != "" {
		t.Fatalf("guard ProjectRoot = %q, want empty for a root-less conversation", ev.ProjectRoot)
	}
}

// TestCursorRootlessEventKeepsFolderSessionProject pins S10-CURSOR review
// finding 5 against the REAL store: store.UpsertSession overwrites
// project_id with the incoming event's project, so a root-less payload
// (`workspace_roots: []`) for a conversation the store already knows
// under a folder must resolve to that folder, never flip it (or its new
// rows) onto the "[cursor]" placeholder.
func TestCursorRootlessEventKeepsFolderSessionProject(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "o.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	st := store.New(database)
	run := func(event, body string) {
		t.Helper()
		var stdout, stderr bytes.Buffer
		HandleCursorEvent(event, st, nil, strings.NewReader(body), &stdout, &stderr, 5*time.Second)
		if stderr.Len() > 0 {
			t.Logf("%s stderr: %s", event, stderr.String())
		}
	}
	const conv = "c0ffee00-0000-4000-8000-000000000001"
	run(cursor.EventBeforeReadFile, `{"conversation_id":"`+conv+`","generation_id":"g1","hook_event_name":"beforeReadFile",
		"file_path":"/repo/a.go","content":"package a","workspace_roots":["/repo"]}`)
	run(cursor.EventBeforeReadFile, `{"conversation_id":"`+conv+`","generation_id":"g2","hook_event_name":"beforeReadFile",
		"file_path":"/repo/b.go","content":"package b","workspace_roots":[]}`)
	run(cursor.EventStop, `{"conversation_id":"`+conv+`","generation_id":"g2","hook_event_name":"stop","status":"completed",
		"model":"cursor-grok-4.6-high","workspace_roots":[],
		"input_tokens":1000,"output_tokens":10,"cache_read_tokens":400,"cache_write_tokens":0}`)

	root, err := st.ProjectRootForSession(ctx, conv)
	if err != nil {
		t.Fatal(err)
	}
	if root != "/repo" {
		t.Fatalf("session project = %q, want the folder /repo kept", root)
	}
	var onPlaceholder, actions, tokens int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM actions a JOIN projects p ON p.id = a.project_id
		WHERE a.session_id = ? AND p.root_path = ?`, conv, cursor.SyntheticProjectRoot).Scan(&onPlaceholder); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM actions WHERE session_id = ?`, conv).Scan(&actions); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM token_usage WHERE session_id = ?`, conv).Scan(&tokens); err != nil {
		t.Fatal(err)
	}
	if onPlaceholder != 0 || actions != 2 || tokens != 1 {
		t.Fatalf("placeholder rows=%d actions=%d tokens=%d, want 0/2/1", onPlaceholder, actions, tokens)
	}
}

// TestCursorReadOutcomeUpdatesItsRow drives the Read pair through the
// real store: before Codex pass-2 finding 5 every Read postToolUse
// touched 0 rows (its id hashed an empty file_path).
func TestCursorReadOutcomeUpdatesItsRow(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "o.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	st := store.New(database)
	var stdout, stderr bytes.Buffer
	HandleCursorEvent(cursor.EventBeforeReadFile, st, nil, strings.NewReader(`{"conversation_id":"c-read","generation_id":"g1",
		"hook_event_name":"beforeReadFile","file_path":"/repo/a.go","content":"package a","workspace_roots":["/repo"]}`),
		&stdout, &stderr, 5*time.Second)
	HandleCursorEvent(cursor.EventPostToolUse, st, nil, strings.NewReader(`{"conversation_id":"c-read","generation_id":"g1",
		"hook_event_name":"postToolUse","tool_name":"Read","tool_input":{"file_path":"/repo/a.go"},
		"tool_output":"package a","duration":1401.838,"cursor_version":"3.20.21","tool_use_id":"call-1"}`),
		&stdout, &stderr, 5*time.Second)
	if strings.Contains(stderr.String(), "touched 0 rows") {
		t.Fatalf("Read outcome missed its row: %s", stderr.String())
	}
	var dur int64
	if err := database.QueryRowContext(ctx, `SELECT COALESCE(duration_ms, 0) FROM actions WHERE session_id = 'c-read'`).Scan(&dur); err != nil {
		t.Fatal(err)
	}
	if dur != 1401 {
		t.Fatalf("duration_ms = %d, want 1401 (ms on 3.20.21, applied to the before row)", dur)
	}
}

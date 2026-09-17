package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/adapter/claudecode"
	"github.com/marmutapp/superbased-observer/internal/adapter/cursor"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/scrub"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/watcher"
)

// TestBackfillCacheTier_RecoversNullColumns simulates the pre-migration-008
// state: token_usage rows with NULL cache_creation_1h_tokens that should
// have been tagged 1h tier per the JSONL. The backfill must:
//
//  1. Scan the JSONL, extract the 1h subset per msg id.
//  2. UPDATE token_usage where the column IS NULL.
//  3. Leave already-populated rows untouched.
//  4. Report the count of recovered tokens.
func TestBackfillCacheTier_RecoversNullColumns(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "obs.db")
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	// Seed a session and three token_usage rows:
	//   row A: NULL cw_1h, msg_a in JSONL says ephemeral_1h = 100k → backfill should fill in 100k
	//   row B: explicit cw_1h=50k already, msg_b in JSONL says ephemeral_1h = 50k → IS-NULL guard skips
	//   row C: NULL cw_1h, msg_c JSONL has ephemeral_1h=0 (5m only) → backfill leaves alone
	if _, err := database.ExecContext(ctx,
		`INSERT INTO projects (id, root_path, created_at) VALUES (1, '/tmp/test', '2026-04-23T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	_, err = database.ExecContext(ctx,
		`INSERT INTO sessions (id, tool, started_at, project_id) VALUES ('sA', 'claude-code', '2026-04-23T00:00:00Z', 1)`)
	if err != nil {
		t.Fatal(err)
	}
	for _, tu := range []struct {
		eid  string
		cw1h sql.NullInt64
	}{
		{"msg_a", sql.NullInt64{}},                           // NULL — should backfill
		{"msg_b", sql.NullInt64{Int64: 50_000, Valid: true}}, // explicit — should NOT touch
		{"msg_c", sql.NullInt64{}},                           // NULL but JSONL has 0 — should leave alone
	} {
		_, err := database.ExecContext(ctx,
			`INSERT INTO token_usage (session_id, source_file, source_event_id, timestamp, tool, model,
				input_tokens, output_tokens, cache_creation_tokens, cache_creation_1h_tokens,
				source, reliability)
			 VALUES ('sA', 'f', ?, '2026-04-23T00:00:01Z', 'claude-code', 'claude-opus-4-7',
				10, 100, 100000, ?, 'jsonl', 'unreliable')`,
			tu.eid, tu.cw1h)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Build a fake Claude Code projects dir with one JSONL.
	projects := filepath.Join(root, "projects", "fake")
	if err := os.MkdirAll(projects, 0o755); err != nil {
		t.Fatal(err)
	}
	jsonl := filepath.Join(projects, "sA.jsonl")
	body := strings.Join([]string{
		// msg_a: 1h subset = 100,000 (this is what the backfill must surface)
		`{"sessionId":"sA","message":{"id":"msg_a","usage":{"cache_creation_input_tokens":100000,"cache_creation":{"ephemeral_5m_input_tokens":0,"ephemeral_1h_input_tokens":100000}}}}`,
		// msg_b: 1h = 50,000 — but token_usage row is already populated so nothing to do
		`{"sessionId":"sA","message":{"id":"msg_b","usage":{"cache_creation_input_tokens":50000,"cache_creation":{"ephemeral_5m_input_tokens":0,"ephemeral_1h_input_tokens":50000}}}}`,
		// msg_c: ephemeral_1h = 0 → backfill must skip (no correction needed)
		`{"sessionId":"sA","message":{"id":"msg_c","usage":{"cache_creation_input_tokens":100000,"cache_creation":{"ephemeral_5m_input_tokens":100000,"ephemeral_1h_input_tokens":0}}}}`,
		"",
	}, "\n")
	if err := os.WriteFile(jsonl, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := backfillCacheTier(ctx, database, projects, 0)
	if err != nil {
		t.Fatalf("backfillCacheTier: %v", err)
	}

	if res.FilesScanned != 1 {
		t.Errorf("FilesScanned: got %d want 1", res.FilesScanned)
	}
	// Only msg_a and msg_b have ephemeral_1h > 0 → examined; msg_c skipped.
	if res.MsgIDsExamined != 2 {
		t.Errorf("MsgIDsExamined: got %d want 2 (msg_a + msg_b; msg_c skipped because 1h=0)", res.MsgIDsExamined)
	}
	// Only msg_a actually triggered a row update — msg_b was already populated.
	if res.TokenUsageUpdated != 1 {
		t.Errorf("TokenUsageUpdated: got %d want 1", res.TokenUsageUpdated)
	}
	if res.TokensRecovered != 100_000 {
		t.Errorf("TokensRecovered: got %d want 100000", res.TokensRecovered)
	}

	// Verify the resulting state of the three rows.
	for _, tc := range []struct {
		eid      string
		wantCW1H sql.NullInt64
	}{
		{"msg_a", sql.NullInt64{Int64: 100_000, Valid: true}},
		{"msg_b", sql.NullInt64{Int64: 50_000, Valid: true}},
		{"msg_c", sql.NullInt64{}}, // still NULL — no JSONL data triggered correction
	} {
		var got sql.NullInt64
		err := database.QueryRowContext(ctx,
			`SELECT cache_creation_1h_tokens FROM token_usage WHERE source_event_id = ?`, tc.eid).Scan(&got)
		if err != nil {
			t.Fatalf("query %s: %v", tc.eid, err)
		}
		if got.Valid != tc.wantCW1H.Valid || got.Int64 != tc.wantCW1H.Int64 {
			t.Errorf("%s: cache_creation_1h_tokens = %+v, want %+v", tc.eid, got, tc.wantCW1H)
		}
	}

	// Idempotency: a second run should have zero updates.
	res2, err := backfillCacheTier(ctx, database, projects, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res2.TokenUsageUpdated != 0 {
		t.Errorf("second-run idempotency: TokenUsageUpdated = %d, want 0", res2.TokenUsageUpdated)
	}
}

func TestBackfillCodexMessageIDAndModel(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "obs.db")
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	if _, err := database.ExecContext(ctx,
		`INSERT INTO projects (id, root_path, created_at) VALUES (1, '/tmp/test', '2026-04-29T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, tool, model, started_at, project_id) VALUES ('thread-1', 'codex', 'gpt-5.4', '2026-04-29T00:00:00Z', 1)`); err != nil {
		t.Fatal(err)
	}
	userSourceID := "user:rollout-2026-04-29T00-00-00-thread.jsonl:L3:" + shortHash("Check status")

	if _, err := database.ExecContext(ctx,
		`INSERT INTO actions (session_id, project_id, timestamp, action_type, success, tool, source_file, source_event_id, raw_tool_name, target)
		 VALUES ('thread-1', 1, '2026-04-29T00:00:01Z', 'user_prompt', 1, 'codex', 'rollout', ?, 'user_message', 'Check status')`, userSourceID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO actions (session_id, project_id, timestamp, action_type, success, tool, source_file, source_event_id, raw_tool_name, target)
		 VALUES ('thread-1', 1, '2026-04-29T00:00:02Z', 'run_command', 1, 'codex', 'rollout', 'call_1', 'exec_command_end', 'pwd')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO token_usage (session_id, timestamp, tool, source_file, source_event_id, input_tokens, output_tokens, cache_read_tokens, source, reliability)
		 VALUES ('thread-1', '2026-04-29T00:00:03Z', 'codex', 'rollout', 'tk:rollout-2026-04-29T00-00-00-thread.jsonl:L5', 12, 3, 5, 'jsonl', 'approximate')`); err != nil {
		t.Fatal(err)
	}

	sessions := filepath.Join(root, "sessions", "2026", "04", "29")
	if err := os.MkdirAll(sessions, 0o755); err != nil {
		t.Fatal(err)
	}
	jsonl := filepath.Join(sessions, "rollout-2026-04-29T00-00-00-thread.jsonl")
	body := strings.Join([]string{
		`{"timestamp":"2026-04-29T00:00:01.000Z","type":"session_meta","payload":{"id":"thread-1","cwd":"D:\\programsx\\partner-names","git_branch":"main"}}`,
		`{"timestamp":"2026-04-29T00:00:01.050Z","type":"event_msg","payload":{"type":"task_started","turn_id":"turn-1"}}`,
		`{"timestamp":"2026-04-29T00:00:01.100Z","type":"event_msg","payload":{"type":"user_message","message":"Check status\n"}}`,
		`{"timestamp":"2026-04-29T00:00:02.000Z","type":"event_msg","payload":{"type":"exec_command_end","call_id":"call_1","turn_id":"turn-1","command":["pwd"],"cwd":"D:\\programsx\\partner-names","aggregated_output":"D:\\programsx\\partner-names\n","exit_code":0,"duration":{"secs":0,"nanos":1000},"status":"completed"}}`,
		`{"timestamp":"2026-04-29T00:00:03.000Z","type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":12,"cached_input_tokens":5,"output_tokens":3,"reasoning_output_tokens":1,"total_tokens":15}}}}`,
		`{"timestamp":"2026-04-29T00:00:03.500Z","type":"turn_context","payload":{"turn_id":"turn-1","cwd":"D:\\programsx\\partner-names","model":"gpt-5.4","git_branch":"main"}}`,
		``,
	}, "\n")
	if err := os.WriteFile(jsonl, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := backfillCodexMessageID(ctx, database, filepath.Join(root, "sessions"), 0)
	if err != nil {
		t.Fatalf("backfillCodexMessageID: %v", err)
	}
	if res.ActionsUpdated != 2 {
		t.Fatalf("ActionsUpdated: got %d want 2", res.ActionsUpdated)
	}
	if res.TokenUsageUpdated != 2 {
		t.Fatalf("TokenUsageUpdated: got %d want 2", res.TokenUsageUpdated)
	}

	var msgID, model string
	if err := database.QueryRowContext(ctx,
		`SELECT message_id FROM actions WHERE source_event_id = 'call_1'`).Scan(&msgID); err != nil {
		t.Fatal(err)
	}
	if msgID != "turn-1" {
		t.Fatalf("call_1 backfill: message_id=%q", msgID)
	}
	if err := database.QueryRowContext(ctx,
		`SELECT message_id, model FROM token_usage WHERE source_event_id = 'tk:rollout-2026-04-29T00-00-00-thread.jsonl:L5'`).Scan(&msgID, &model); err != nil {
		t.Fatal(err)
	}
	if msgID != "turn-1" || model != "gpt-5.4" {
		t.Fatalf("token backfill: message_id=%q model=%q", msgID, model)
	}
}

func TestBackfillCursorMessageID(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "obs.db")
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	if _, err := database.ExecContext(ctx,
		`INSERT INTO projects (id, root_path, created_at) VALUES (1, '/tmp/test', '2026-04-29T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, tool, started_at, project_id) VALUES ('cursor-session', 'cursor', '2026-04-29T00:00:00Z', 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO actions (session_id, project_id, timestamp, action_type, success, tool, source_file, source_event_id, raw_tool_name, target)
		 VALUES ('cursor-session', 1, '2026-04-29T00:00:01Z', 'user_prompt', 1, 'cursor', 'cursor:hook', 'gen-123:beforeSubmitPrompt', 'beforeSubmitPrompt', 'hello')`); err != nil {
		t.Fatal(err)
	}

	res, err := backfillCursorMessageID(ctx, database)
	if err != nil {
		t.Fatalf("backfillCursorMessageID: %v", err)
	}
	if res.ActionsUpdated != 1 {
		t.Fatalf("ActionsUpdated: got %d want 1", res.ActionsUpdated)
	}

	var msgID string
	if err := database.QueryRowContext(ctx,
		`SELECT message_id FROM actions WHERE source_event_id = 'gen-123:beforeSubmitPrompt'`).Scan(&msgID); err != nil {
		t.Fatal(err)
	}
	if msgID != "user:gen-123" {
		t.Fatalf("message_id = %q want user:gen-123", msgID)
	}
}

func TestBackfillCursorHookUsage(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "obs.db")
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	if _, err := database.ExecContext(ctx,
		`INSERT INTO projects (id, root_path, created_at) VALUES (1, '/repo', '2026-04-29T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, tool, started_at, project_id) VALUES ('cursor-session', 'cursor', '2026-04-29T00:00:00Z', 1)`); err != nil {
		t.Fatal(err)
	}

	logs := filepath.Join(root, "logs", "20260429T190737", "window1", "output_20260429T190743")
	if err := os.MkdirAll(logs, 0o755); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(logs, "cursor.hooks.workspaceId-test.log")
	body := strings.Join([]string{
		"INPUT:",
		`{"conversation_id":"cursor-session","generation_id":"gen-123","hook_event_name":"stop","workspace_roots":["/repo"],"model":"default","input_tokens":100,"output_tokens":20,"cache_read_tokens":50,"cache_write_tokens":0}`,
		"OUTPUT:",
		`{"permission":"allow","continue":true}`,
		"",
	}, "\n")
	if err := os.WriteFile(logPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := backfillCursorHookUsage(ctx, database, filepath.Join(root, "logs"), 0)
	if err != nil {
		t.Fatalf("backfillCursorHookUsage: %v", err)
	}
	if res.FilesScanned != 1 || res.TokenUsageUpdated != 1 {
		t.Fatalf("unexpected summary: %+v", res)
	}

	var model string
	var input, output int64
	if err := database.QueryRowContext(ctx,
		`SELECT model, input_tokens, output_tokens FROM token_usage WHERE source_event_id = ?`,
		"gen-123:"+cursor.EventStop).Scan(&model, &input, &output); err != nil {
		t.Fatal(err)
	}
	// input_tokens is NET non-cached: fixture's gross 100 with
	// cache_read_tokens=50 → 50. See cursor.BuildStopTokenEvent.
	if model != "default" || input != 50 || output != 20 {
		t.Fatalf("token row mismatch: model=%q in=%d out=%d (want in=50 net of 50 cached)", model, input, output)
	}
	if err := database.QueryRowContext(ctx,
		`SELECT model FROM sessions WHERE id = 'cursor-session'`).Scan(&model); err != nil {
		t.Fatal(err)
	}
	if model != "default" {
		t.Fatalf("session model = %q", model)
	}
}

func TestBackfillCursorTranscriptActions(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "obs.db")
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	if _, err := database.ExecContext(ctx,
		`INSERT INTO projects (id, root_path, created_at) VALUES (1, '/repo', '2026-04-29T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, tool, model, started_at, project_id) VALUES ('cursor-session', 'cursor', 'default', '2026-04-29T00:00:00Z', 1)`); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		msg string
		ts  string
	}{
		{"gen-1", "2026-04-29T00:00:10Z"},
		{"gen-2", "2026-04-29T00:00:20Z"},
	} {
		if _, err := database.ExecContext(ctx,
			`INSERT INTO token_usage (session_id, timestamp, tool, model, source_file, source_event_id, message_id, input_tokens, output_tokens, source, reliability)
			 VALUES ('cursor-session', ?, 'cursor', 'default', 'cursor:hook', ?, ?, 10, 5, 'hook', 'accurate')`,
			row.ts, row.msg+":"+cursor.EventStop, row.msg); err != nil {
			t.Fatal(err)
		}
	}

	transcriptDir := filepath.Join(root, "projects", "demo", "agent-transcripts", "cursor-session")
	if err := os.MkdirAll(transcriptDir, 0o755); err != nil {
		t.Fatal(err)
	}
	transcriptPath := filepath.Join(transcriptDir, "cursor-session.jsonl")
	body := strings.Join([]string{
		`{"role":"user","message":{"content":[{"type":"text","text":"one"}]}}`,
		`{"role":"assistant","message":{"content":[{"type":"text","text":"scan"},{"type":"tool_use","name":"Glob","input":{"glob_pattern":"*"}}]}}`,
		`{"role":"user","message":{"content":[{"type":"text","text":"two"}]}}`,
		`{"role":"assistant","message":{"content":[{"type":"text","text":"read"},{"type":"tool_use","name":"ReadFile","input":{"path":"d:\\repo\\README.md"}}]}}`,
		"",
	}, "\n")
	if err := os.WriteFile(transcriptPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := backfillCursorTranscriptActions(ctx, database, filepath.Join(root, "projects"), 0)
	if err != nil {
		t.Fatalf("backfillCursorTranscriptActions: %v", err)
	}
	// Each assistant turn emits 1 cursor.assistant_text row (text part)
	// plus 1 tool_use row = 2 actions per turn, 4 total across the two
	// generations covered by token_usage. The pre-v1.4.49 expected count
	// was 2 (tool_use only); v1.4.49 doubles it via the new emission.
	if res.ActionsUpdated != 4 {
		t.Fatalf("ActionsUpdated: got %d want 4 (2 turns × {assistant_text + tool_use})", res.ActionsUpdated)
	}
	var count int
	if err := database.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM actions WHERE tool = 'cursor' AND message_id IN ('gen-1','gen-2')`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 4 {
		t.Fatalf("action count = %d want 4", count)
	}
}

// TestBackfillsAllPrepareCleanlyOnEmptyDB is a defensive smoke test:
// every backfill function must compile its prepared statements
// against the canonical post-migrations schema. Pre-fix this would
// have caught the `actions.tool_output` and `actions.model` column-
// existence bugs at test time instead of at the user's terminal.
//
// Each backfill is run against a freshly-migrated DB with no rows;
// it must not error and must report zero updates.
func TestBackfillsAllPrepareCleanlyOnEmptyDB(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "obs.db")
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	// Empty source dirs — every JSONL-walking pass should report zero
	// files scanned and zero rows updated.
	emptyDir := filepath.Join(root, "empty")
	if err := os.MkdirAll(emptyDir, 0o755); err != nil {
		t.Fatal(err)
	}

	if _, err := backfillIsSidechain(ctx, database, emptyDir, 0); err != nil {
		t.Errorf("backfillIsSidechain: %v", err)
	}
	if _, err := backfillCacheTier(ctx, database, emptyDir, 0); err != nil {
		t.Errorf("backfillCacheTier: %v", err)
	}
	if _, err := backfillMessageID(ctx, database, emptyDir, 0); err != nil {
		t.Errorf("backfillMessageID: %v", err)
	}
	if _, err := backfillCodexMessageID(ctx, database, emptyDir, 0); err != nil {
		t.Errorf("backfillCodexMessageID: %v", err)
	}
	if _, err := backfillCursorMessageID(ctx, database); err != nil {
		t.Errorf("backfillCursorMessageID: %v", err)
	}
	if _, err := backfillCursorHookUsage(ctx, database, emptyDir, 0); err != nil {
		t.Errorf("backfillCursorHookUsage: %v", err)
	}
	if _, err := backfillCursorTranscriptActions(ctx, database, emptyDir, 0); err != nil {
		t.Errorf("backfillCursorTranscriptActions: %v", err)
	}
	if _, err := backfillOpenCodeMessageID(ctx, database); err != nil {
		t.Errorf("backfillOpenCodeMessageID: %v", err)
	}
	if _, err := backfillOpenCodeParts(ctx, database); err != nil {
		t.Errorf("backfillOpenCodeParts: %v", err)
	}
	if _, err := backfillOpenClawActionTypes(ctx, database); err != nil {
		t.Errorf("backfillOpenClawActionTypes: %v", err)
	}
	if _, err := backfillOpenClawModel(ctx, database); err != nil {
		t.Errorf("backfillOpenClawModel: %v", err)
	}
	if _, err := backfillOpenClawProjectRoot(ctx, database, []string{emptyDir}, 0); err != nil {
		t.Errorf("backfillOpenClawProjectRoot: %v", err)
	}
	if _, err := backfillOpenClawReasoning(ctx, database, emptyDir, 0); err != nil {
		t.Errorf("backfillOpenClawReasoning: %v", err)
	}
	if _, err := backfillOpenClawSessionID(ctx, database, []string{emptyDir}, 0); err != nil {
		t.Errorf("backfillOpenClawSessionID: %v", err)
	}
	if _, err := backfillCodexReasoning(ctx, database, emptyDir, 0); err != nil {
		t.Errorf("backfillCodexReasoning: %v", err)
	}
	if _, err := backfillCodexProjectRoot(ctx, database, []string{emptyDir}, 0); err != nil {
		t.Errorf("backfillCodexProjectRoot: %v", err)
	}
	if _, err := backfillCursorModel(ctx, database); err != nil {
		t.Errorf("backfillCursorModel: %v", err)
	}
	if _, err := backfillCopilotMessageID(ctx, database); err != nil {
		t.Errorf("backfillCopilotMessageID: %v", err)
	}
	if _, err := backfillPiMessageID(ctx, database); err != nil {
		t.Errorf("backfillPiMessageID: %v", err)
	}
	if _, err := backfillOpenCodeTokens(ctx, database); err != nil {
		t.Errorf("backfillOpenCodeTokens: %v", err)
	}
	if _, err := backfillClaudeCodeUserPrompts(ctx, database, emptyDir, 0); err != nil {
		t.Errorf("backfillClaudeCodeUserPrompts: %v", err)
	}
	if _, err := backfillClaudeCodeAPIErrors(ctx, database, emptyDir, 0); err != nil {
		t.Errorf("backfillClaudeCodeAPIErrors: %v", err)
	}
	if _, err := backfillCursorUserPrompts(ctx, database, emptyDir, 0); err != nil {
		t.Errorf("backfillCursorUserPrompts: %v", err)
	}
	if _, err := backfillCursorSubagents(ctx, database, emptyDir, 0); err != nil {
		t.Errorf("backfillCursorSubagents: %v", err)
	}
	if _, err := store.New(database).BackfillTaskItems(ctx, 0); err != nil {
		t.Errorf("BackfillTaskItems: %v", err)
	}
}

// TestBackfillClaudeCodeUserPrompts pins the recovery pass: re-runs
// the claudecode adapter on every JSONL file under projectsDir and
// inserts user_prompt action rows for sessions that were ingested
// before the adapter started emitting them. Idempotent via the
// (source_file, source_event_id) UNIQUE index.
func TestBackfillClaudeCodeUserPrompts(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "obs.db")
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	// Build a tiny Claude Code project tree with one session JSONL
	// carrying a user prompt + an assistant tool call.
	projects := filepath.Join(root, "projects", "demo")
	if err := os.MkdirAll(projects, 0o755); err != nil {
		t.Fatal(err)
	}
	jsonl := filepath.Join(projects, "sess-X.jsonl")
	body := strings.Join([]string{
		`{"sessionId":"sess-X","cwd":"/tmp","timestamp":"2026-04-30T00:00:00Z","uuid":"u-prompt","message":{"role":"user","content":[{"type":"text","text":"hello there"}]}}`,
		`{"sessionId":"sess-X","cwd":"/tmp","timestamp":"2026-04-30T00:00:01Z","uuid":"u-asst","message":{"id":"msg_a","role":"assistant","model":"claude-sonnet-4-5","content":[{"type":"tool_use","id":"toolu_1","name":"Read","input":{"file_path":"/x.go"}}]}}`,
	}, "\n")
	if err := os.WriteFile(jsonl, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	// Seed observer.db with a session + the assistant's Read action,
	// but NOT the user_prompt — simulating a pre-fix ingest.
	if _, err := database.ExecContext(ctx,
		`INSERT INTO projects (id, root_path, created_at) VALUES (1, '/tmp', '2026-04-30T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, tool, started_at, project_id) VALUES ('sess-X', 'claude-code', '2026-04-30T00:00:00Z', 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO actions (session_id, project_id, timestamp, action_type, tool, source_file, source_event_id)
		 VALUES ('sess-X', 1, '2026-04-30T00:00:01Z', 'read_file', 'claude-code', ?, 'toolu_1')`, jsonl); err != nil {
		t.Fatal(err)
	}

	res, err := backfillClaudeCodeUserPrompts(ctx, database, projects, 0)
	if err != nil {
		t.Fatalf("backfillClaudeCodeUserPrompts: %v", err)
	}
	if res.FilesScanned != 1 {
		t.Errorf("FilesScanned = %d, want 1", res.FilesScanned)
	}
	if res.UserEventsFound != 1 {
		t.Errorf("UserEventsFound = %d, want 1", res.UserEventsFound)
	}
	if res.ActionsInserted != 1 {
		t.Errorf("ActionsInserted = %d, want 1", res.ActionsInserted)
	}

	var actionType, msgID sql.NullString
	if err := database.QueryRowContext(ctx,
		`SELECT action_type, message_id FROM actions WHERE source_event_id = 'u-prompt'`).
		Scan(&actionType, &msgID); err != nil {
		t.Fatal(err)
	}
	if actionType.String != models.ActionUserPrompt {
		t.Errorf("action_type = %q, want %q", actionType.String, models.ActionUserPrompt)
	}
	if msgID.String != "user:u-prompt" {
		t.Errorf("message_id = %q, want user:u-prompt", msgID.String)
	}

	// Idempotency: re-running must not duplicate rows. Per the
	// v1.4.28 ON CONFLICT DO UPDATE for actions.duration_ms, the
	// ActionsInserted counter now reports "rows touched" rather
	// than "actually new rows" — assert against the table-level
	// row count instead.
	var beforeCount int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM actions`).Scan(&beforeCount); err != nil {
		t.Fatal(err)
	}
	if _, err := backfillClaudeCodeUserPrompts(ctx, database, projects, 0); err != nil {
		t.Fatal(err)
	}
	var afterCount int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM actions`).Scan(&afterCount); err != nil {
		t.Fatal(err)
	}
	if afterCount != beforeCount {
		t.Errorf("second run added rows: before=%d after=%d", beforeCount, afterCount)
	}
}

// TestBackfillCursorSubagents pins the v1.4.21 sidechain ingest:
// agent-transcripts/<parent>/subagents/<sub>.jsonl is walked, parsed
// via the cursor adapter's transcript path, and emitted as ToolEvents
// with IsSidechain=true under the parent session_id. Tests both the
// session-id linkage and the sidechain flag landing on inserted rows.
func TestBackfillCursorSubagents(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "obs.db")
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	// Build a tiny cursor project tree with one parent transcript and
	// one subagent transcript inside it.
	parentSessionID := "parent-sess"
	subUUID := "sub-AAA"
	transcriptDir := filepath.Join(root, "projects", "demo", "agent-transcripts", parentSessionID)
	subagentDir := filepath.Join(transcriptDir, "subagents")
	if err := os.MkdirAll(subagentDir, 0o755); err != nil {
		t.Fatal(err)
	}
	subPath := filepath.Join(subagentDir, subUUID+".jsonl")
	body := strings.Join([]string{
		`{"role":"user","message":{"content":[{"type":"text","text":"<user_query>research X</user_query>"}]}}`,
		`{"role":"assistant","message":{"content":[{"type":"text","text":"On it."},{"type":"tool_use","name":"WebFetch","input":{"url":"https://example.com"}}]}}`,
	}, "\n")
	if err := os.WriteFile(subPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	// Seed parent project + session — backfill skips files whose
	// parent session_id has no DB entry (no projectRoot to attribute).
	if _, err := database.ExecContext(ctx,
		`INSERT INTO projects (id, root_path, created_at) VALUES (1, '/tmp/demo', '2026-05-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, tool, started_at, project_id) VALUES (?, 'cursor', '2026-05-01T00:00:00Z', 1)`, parentSessionID); err != nil {
		t.Fatal(err)
	}

	res, err := backfillCursorSubagents(ctx, database, filepath.Join(root, "projects"), 0)
	if err != nil {
		t.Fatalf("backfillCursorSubagents: %v", err)
	}
	if res.FilesScanned != 1 {
		t.Errorf("FilesScanned = %d, want 1", res.FilesScanned)
	}
	if res.EventsBuilt != 3 {
		// 1 user_prompt + 1 cursor.assistant_text + 1 WebFetch tool_use
		t.Errorf("EventsBuilt = %d, want 3", res.EventsBuilt)
	}
	if res.ActionsInserted != 3 {
		t.Errorf("ActionsInserted = %d, want 3", res.ActionsInserted)
	}

	// All inserted rows must carry IsSidechain=1 and the parent SessionID.
	var sidechainCount, otherCount int
	if err := database.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM actions WHERE session_id = ? AND is_sidechain = 1`, parentSessionID).Scan(&sidechainCount); err != nil {
		t.Fatal(err)
	}
	if sidechainCount != 3 {
		t.Errorf("sidechain rows: %d want 3", sidechainCount)
	}
	if err := database.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM actions WHERE session_id = ? AND is_sidechain = 0`, parentSessionID).Scan(&otherCount); err != nil {
		t.Fatal(err)
	}
	if otherCount != 0 {
		t.Errorf("non-sidechain rows for parent: %d want 0", otherCount)
	}

	// Idempotency: re-running must not duplicate rows. v1.4.28's
	// ON CONFLICT DO UPDATE for actions.duration_ms shifted the
	// inserted-counter semantics to "rows touched"; check the
	// table-level row count instead.
	var beforeCount int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM actions`).Scan(&beforeCount); err != nil {
		t.Fatal(err)
	}
	if _, err := backfillCursorSubagents(ctx, database, filepath.Join(root, "projects"), 0); err != nil {
		t.Fatal(err)
	}
	var afterCount int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM actions`).Scan(&afterCount); err != nil {
		t.Fatal(err)
	}
	if afterCount != beforeCount {
		t.Errorf("second run added rows: before=%d after=%d", beforeCount, afterCount)
	}
}

// TestBackfillClaudeCodeAPIErrors pins the v1.4.20 recovery pass for
// upstream API failures: re-runs the adapter on every JSONL, picks
// out the api_error events the previous adapter version would have
// dropped, and ingests them. Idempotent via the
// (source_file, source_event_id) UNIQUE index — a second run is a
// no-op.
func TestBackfillClaudeCodeAPIErrors(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "obs.db")
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	// Build a tiny Claude Code project tree with one session JSONL
	// carrying an assistant turn + a system/api_error record after.
	projects := filepath.Join(root, "projects", "demo")
	if err := os.MkdirAll(projects, 0o755); err != nil {
		t.Fatal(err)
	}
	jsonl := filepath.Join(projects, "sess-err.jsonl")
	body := strings.Join([]string{
		`{"sessionId":"sess-err","cwd":"/tmp","timestamp":"2026-04-30T00:00:00Z","uuid":"u-asst","message":{"id":"msg_a","role":"assistant","model":"claude-sonnet-4-5","content":[{"type":"text","text":"thinking..."}]}}`,
		`{"sessionId":"sess-err","cwd":"/tmp","timestamp":"2026-04-30T00:00:01Z","uuid":"u-err","type":"system","subtype":"api_error","level":"error","error":{"status":400,"requestID":"req_011test","error":{"type":"invalid_request_error","message":"Output blocked by content filtering policy"}}}`,
	}, "\n") + "\n"
	if err := os.WriteFile(jsonl, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	// Seed observer.db with a session row but NOT the api_error action
	// (simulating a pre-fix ingest where the system record was dropped).
	if _, err := database.ExecContext(ctx,
		`INSERT INTO projects (id, root_path, created_at) VALUES (1, '/tmp', '2026-04-30T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, tool, started_at, project_id) VALUES ('sess-err', 'claude-code', '2026-04-30T00:00:00Z', 1)`); err != nil {
		t.Fatal(err)
	}

	res, err := backfillClaudeCodeAPIErrors(ctx, database, projects, 0)
	if err != nil {
		t.Fatalf("backfillClaudeCodeAPIErrors: %v", err)
	}
	if res.FilesScanned != 1 {
		t.Errorf("FilesScanned = %d, want 1", res.FilesScanned)
	}
	if res.APIErrorsFound != 1 {
		t.Errorf("APIErrorsFound = %d, want 1", res.APIErrorsFound)
	}
	if res.ActionsInserted != 1 {
		t.Errorf("ActionsInserted = %d, want 1", res.ActionsInserted)
	}

	var actionType, target, errorMessage, rawTool sql.NullString
	if err := database.QueryRowContext(ctx,
		`SELECT action_type, target, error_message, raw_tool_name
		 FROM actions WHERE source_event_id = 'u-err'`).
		Scan(&actionType, &target, &errorMessage, &rawTool); err != nil {
		t.Fatal(err)
	}
	if actionType.String != models.ActionAPIError {
		t.Errorf("action_type = %q, want %q", actionType.String, models.ActionAPIError)
	}
	if target.String != "req_011test" {
		t.Errorf("target = %q, want req_011test (request_id)", target.String)
	}
	if !strings.Contains(errorMessage.String, "content filtering") {
		t.Errorf("error_message = %q, want substring 'content filtering'", errorMessage.String)
	}
	if rawTool.String != "invalid_request_error" {
		t.Errorf("raw_tool_name = %q, want invalid_request_error (upstream error class)", rawTool.String)
	}

	// Idempotency: re-running must not duplicate rows. v1.4.28's
	// ON CONFLICT DO UPDATE for actions.duration_ms shifted the
	// inserted-counter semantics to "rows touched"; check the
	// table-level row count instead.
	var beforeCount int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM actions`).Scan(&beforeCount); err != nil {
		t.Fatal(err)
	}
	if _, err := backfillClaudeCodeAPIErrors(ctx, database, projects, 0); err != nil {
		t.Fatal(err)
	}
	var afterCount int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM actions`).Scan(&afterCount); err != nil {
		t.Fatal(err)
	}
	if afterCount != beforeCount {
		t.Errorf("second run added rows: before=%d after=%d", beforeCount, afterCount)
	}
}

// TestBackfillOpenCodeTokens pins the opencode-tokens recovery pass:
// re-runs the adapter against opencode.db and ingests any token rows
// that were missing from observer's DB. The user-reported case was a
// 'say hi' session whose actions were ingested but whose assistant
// message had data.tokens populated (input=9868, output=35) and
// observer's token_usage was empty.
func TestBackfillOpenCodeTokens(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "obs.db")
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	// Seed observer.db: project + an opencode session + one action so
	// the backfill discovers the source_file path. No token row.
	ocPath := filepath.Join(root, "opencode.db")
	if _, err := database.ExecContext(ctx,
		`INSERT INTO projects (id, root_path, created_at) VALUES (1, '/tmp/test', '2026-04-30T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, tool, started_at, project_id) VALUES ('ses_say_hi', 'opencode', '2026-04-30T00:00:00Z', 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO actions (session_id, project_id, timestamp, action_type, tool, source_file, source_event_id)
		 VALUES ('ses_say_hi', 1, '2026-04-30T00:00:01Z', 'task_complete', 'opencode', ?, 'complete:msg_assistant')`,
		ocPath); err != nil {
		t.Fatal(err)
	}

	// Seed opencode.db: the source schema with one assistant message
	// carrying real token data — the user-reported shape.
	ocDB, err := sql.Open("sqlite", ocPath)
	if err != nil {
		t.Fatal(err)
	}
	stmts := []string{
		`CREATE TABLE session (id TEXT PRIMARY KEY, directory TEXT NOT NULL, time_updated INTEGER NOT NULL)`,
		`CREATE TABLE message (id TEXT PRIMARY KEY, session_id TEXT NOT NULL, time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL, data TEXT NOT NULL)`,
		`CREATE TABLE part (id TEXT PRIMARY KEY, message_id TEXT NOT NULL, session_id TEXT NOT NULL, time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL, data TEXT NOT NULL)`,
		`INSERT INTO session(id, directory, time_updated) VALUES ('ses_say_hi', '/tmp/oc', 3000)`,
		`INSERT INTO message(id, session_id, time_created, time_updated, data) VALUES
			('msg_assistant', 'ses_say_hi', 2900, 3000,
			 '{"role":"assistant","modelID":"big-pickle","providerID":"opencode","time":{"created":2900,"completed":3000},"finish":"stop","tokens":{"input":9868,"output":35,"reasoning":0,"cache":{"read":0,"write":0}},"cost":0}')`,
	}
	for _, s := range stmts {
		if _, err := ocDB.Exec(s); err != nil {
			ocDB.Close()
			t.Fatalf("seed opencode.db: %v", err)
		}
	}
	ocDB.Close()

	// Verify observer.db has zero opencode token rows before the backfill.
	var before int
	if err := database.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM token_usage WHERE tool='opencode'`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if before != 0 {
		t.Fatalf("setup: expected 0 opencode token rows before backfill, got %d", before)
	}

	res, err := backfillOpenCodeTokens(ctx, database)
	if err != nil {
		t.Fatalf("backfillOpenCodeTokens: %v", err)
	}
	if res.DBsScanned != 1 {
		t.Errorf("DBsScanned = %d, want 1", res.DBsScanned)
	}
	if res.TokenRowsExtracted != 1 {
		t.Errorf("TokenRowsExtracted = %d, want 1", res.TokenRowsExtracted)
	}
	if res.TokenRowsInserted != 1 {
		t.Errorf("TokenRowsInserted = %d, want 1", res.TokenRowsInserted)
	}

	// Verify the actual values landed.
	var (
		input, output sql.NullInt64
		msgID         sql.NullString
	)
	if err := database.QueryRowContext(ctx,
		`SELECT input_tokens, output_tokens, message_id FROM token_usage WHERE tool='opencode' AND session_id='ses_say_hi'`).
		Scan(&input, &output, &msgID); err != nil {
		t.Fatal(err)
	}
	if input.Int64 != 9868 {
		t.Errorf("input_tokens = %d, want 9868", input.Int64)
	}
	if output.Int64 != 35 {
		t.Errorf("output_tokens = %d, want 35", output.Int64)
	}
	if msgID.String != "msg_assistant" {
		t.Errorf("message_id = %q, want msg_assistant", msgID.String)
	}

	// Idempotency: second run produces no duplicate row. The metric
	// reports "rows touched" since v1.4.27 (when token_usage moved from
	// INSERT OR IGNORE to ON CONFLICT DO UPDATE for the model column,
	// to let adapter improvements propagate to existing rows). Real
	// idempotence is the post-condition row count, not the metric.
	if _, err := backfillOpenCodeTokens(ctx, database); err != nil {
		t.Fatal(err)
	}
	var rows int
	_ = database.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM token_usage WHERE tool='opencode' AND session_id='ses_say_hi'`).Scan(&rows)
	if rows != 1 {
		t.Errorf("post second-run rows: got %d want 1", rows)
	}
}

// TestBackfillCopilotMessageID pins the copilot message-id pass.
// User-message lines yield 'user:<spanId>'; tool / agent_response /
// llm_request rows yield 'assistant:<parentSpanId | spanId>'.
func TestBackfillCopilotMessageID(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "obs.db")
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	logPath := filepath.Join(root, "main.jsonl")
	body := strings.Join([]string{
		`{"ts":1,"sid":"sess-1","type":"user_message","spanId":"u1","attrs":{"content":"hi"}}`,
		`{"ts":2,"sid":"sess-1","type":"tool_call","name":"manage_todo_list","spanId":"tool-1","parentSpanId":"u1","attrs":{}}`,
		`{"ts":3,"sid":"sess-1","type":"llm_request","name":"chat","spanId":"llm-1","parentSpanId":"u1","attrs":{"model":"oswe","inputTokens":10,"outputTokens":2}}`,
		"",
	}, "\n")
	if err := os.WriteFile(logPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := database.ExecContext(ctx,
		`INSERT INTO projects (id, root_path, created_at) VALUES (1, '/tmp/test', '2026-04-30T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, tool, started_at, project_id) VALUES ('sess-1', 'copilot', '2026-04-30T00:00:00Z', 1)`); err != nil {
		t.Fatal(err)
	}
	for _, eid := range []string{"u1", "tool-1", "llm-1"} {
		_, err := database.ExecContext(ctx,
			`INSERT INTO actions (session_id, project_id, timestamp, action_type, tool, source_file, source_event_id)
			 VALUES ('sess-1', 1, '2026-04-30T00:00:01Z', 'user_prompt', 'copilot', ?, ?)`, logPath, eid)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO token_usage (session_id, timestamp, tool, source_file, source_event_id, source, reliability)
		 VALUES ('sess-1', '2026-04-30T00:00:01Z', 'copilot', ?, 'llm-1', 'jsonl', 'approximate')`, logPath); err != nil {
		t.Fatal(err)
	}

	res, err := backfillCopilotMessageID(ctx, database)
	if err != nil {
		t.Fatalf("backfillCopilotMessageID: %v", err)
	}
	if res.FilesScanned != 1 {
		t.Errorf("FilesScanned = %d, want 1", res.FilesScanned)
	}
	if res.ActionsUpdated != 3 {
		t.Errorf("ActionsUpdated = %d, want 3", res.ActionsUpdated)
	}
	if res.TokenUsageUpdated != 1 {
		t.Errorf("TokenUsageUpdated = %d, want 1", res.TokenUsageUpdated)
	}
	for _, c := range []struct {
		eid, want string
	}{
		{"u1", "user:u1"},
		{"tool-1", "assistant:u1"},
		{"llm-1", "assistant:u1"},
	} {
		var got sql.NullString
		if err := database.QueryRowContext(ctx,
			`SELECT message_id FROM actions WHERE source_event_id = ?`, c.eid).Scan(&got); err != nil {
			t.Fatalf("query %s: %v", c.eid, err)
		}
		if got.String != c.want {
			t.Errorf("%s: message_id = %q, want %q", c.eid, got.String, c.want)
		}
	}

	res2, _ := backfillCopilotMessageID(ctx, database)
	if res2.ActionsUpdated != 0 || res2.TokenUsageUpdated != 0 {
		t.Errorf("second run not idempotent: actions=%d tokens=%d",
			res2.ActionsUpdated, res2.TokenUsageUpdated)
	}
}

// TestBackfillPiMessageID pins the pi message-id pass. User rows
// yield 'user:<id>'; assistant rows yield <id>; tool calls within an
// assistant message inherit the assistant's id; usage rows match
// 'usage:<id>'.
func TestBackfillPiMessageID(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "obs.db")
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	sessPath := filepath.Join(root, "session.jsonl")
	body := strings.Join([]string{
		`{"id":"u1","message":{"role":"user","content":[{"type":"text","text":"hi"}]}}`,
		`{"id":"a1","message":{"role":"assistant","content":[{"type":"toolUse","id":"tool_x","name":"read"}]}}`,
		"",
	}, "\n")
	if err := os.WriteFile(sessPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := database.ExecContext(ctx,
		`INSERT INTO projects (id, root_path, created_at) VALUES (1, '/tmp/test', '2026-04-30T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, tool, started_at, project_id) VALUES ('p1', 'pi', '2026-04-30T00:00:00Z', 1)`); err != nil {
		t.Fatal(err)
	}
	for _, eid := range []string{"u1", "tool_x"} {
		_, err := database.ExecContext(ctx,
			`INSERT INTO actions (session_id, project_id, timestamp, action_type, tool, source_file, source_event_id)
			 VALUES ('p1', 1, '2026-04-30T00:00:01Z', 'user_prompt', 'pi', ?, ?)`, sessPath, eid)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO token_usage (session_id, timestamp, tool, source_file, source_event_id, source, reliability)
		 VALUES ('p1', '2026-04-30T00:00:01Z', 'pi', ?, 'usage:a1', 'jsonl', 'approximate')`, sessPath); err != nil {
		t.Fatal(err)
	}

	res, err := backfillPiMessageID(ctx, database)
	if err != nil {
		t.Fatalf("backfillPiMessageID: %v", err)
	}
	if res.FilesScanned != 1 {
		t.Errorf("FilesScanned = %d, want 1", res.FilesScanned)
	}
	if res.ActionsUpdated != 2 {
		t.Errorf("ActionsUpdated = %d, want 2 (user prompt + tool inside assistant)", res.ActionsUpdated)
	}
	if res.TokenUsageUpdated != 1 {
		t.Errorf("TokenUsageUpdated = %d, want 1", res.TokenUsageUpdated)
	}
	for _, c := range []struct {
		eid, want string
	}{
		{"u1", "user:u1"},
		{"tool_x", "a1"}, // tool call inherits the assistant's id
	} {
		var got sql.NullString
		if err := database.QueryRowContext(ctx,
			`SELECT message_id FROM actions WHERE source_event_id = ?`, c.eid).Scan(&got); err != nil {
			t.Fatalf("query %s: %v", c.eid, err)
		}
		if got.String != c.want {
			t.Errorf("%s: message_id = %q, want %q", c.eid, got.String, c.want)
		}
	}

	res2, _ := backfillPiMessageID(ctx, database)
	if res2.ActionsUpdated != 0 || res2.TokenUsageUpdated != 0 {
		t.Errorf("second run not idempotent: actions=%d tokens=%d",
			res2.ActionsUpdated, res2.TokenUsageUpdated)
	}
}

// TestBackfillOpenCodeParts pins the fixed opencode-parts pass:
// duration_ms and message_id land on the actions row, and tool
// output is indexed into action_excerpts (not into a non-existent
// actions.tool_output column).
func TestBackfillOpenCodeParts(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "obs.db")
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	// Seed a project + session + an opencode tool action that points at
	// our fake opencode.db.
	ocDBPath := filepath.Join(root, "opencode.db")
	if _, err := database.ExecContext(ctx,
		`INSERT INTO projects (id, root_path, created_at) VALUES (1, '/tmp/test', '2026-04-30T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, tool, started_at, project_id) VALUES ('s1', 'opencode', '2026-04-30T00:00:00Z', 1)`); err != nil {
		t.Fatal(err)
	}
	var actionID int64
	r, err := database.ExecContext(ctx,
		`INSERT INTO actions (session_id, project_id, timestamp, action_type, raw_tool_name, target, tool, source_file, source_event_id)
		 VALUES ('s1', 1, '2026-04-30T00:00:01Z', 'run_command', 'bash', 'npm start', 'opencode', ?, 'part:prt_1')`, ocDBPath)
	if err != nil {
		t.Fatal(err)
	}
	actionID, _ = r.LastInsertId()

	// Build the fake opencode.db with one tool part carrying the data
	// we want backfilled.
	ocDB, err := sql.Open("sqlite", ocDBPath)
	if err != nil {
		t.Fatal(err)
	}
	stmts := []string{
		`CREATE TABLE part (id TEXT PRIMARY KEY, message_id TEXT, data TEXT NOT NULL)`,
		`INSERT INTO part (id, message_id, data) VALUES
			('prt_1', 'msg_a', '{"type":"tool","state":{"output":"boom","metadata":{"output":"boom","exit":1},"time":{"start":2200,"end":2500}}}')`,
	}
	for _, s := range stmts {
		if _, err := ocDB.Exec(s); err != nil {
			ocDB.Close()
			t.Fatalf("seed opencode.db: %v", err)
		}
	}
	ocDB.Close()

	res, err := backfillOpenCodeParts(ctx, database)
	if err != nil {
		t.Fatalf("backfillOpenCodeParts: %v", err)
	}
	if res.PartsExamined != 1 {
		t.Errorf("PartsExamined = %d, want 1", res.PartsExamined)
	}
	if res.DurationUpdated != 1 {
		t.Errorf("DurationUpdated = %d, want 1", res.DurationUpdated)
	}
	if res.MessageIDUpdated != 1 {
		t.Errorf("MessageIDUpdated = %d, want 1", res.MessageIDUpdated)
	}
	if res.ToolOutputUpdated != 1 {
		t.Errorf("ToolOutputUpdated = %d, want 1", res.ToolOutputUpdated)
	}

	// Verify the persisted state.
	var (
		duration sql.NullInt64
		msgID    sql.NullString
	)
	if err := database.QueryRowContext(ctx,
		`SELECT duration_ms, message_id FROM actions WHERE id = ?`, actionID).Scan(&duration, &msgID); err != nil {
		t.Fatal(err)
	}
	if duration.Int64 != 300 {
		t.Errorf("duration_ms = %d, want 300", duration.Int64)
	}
	if msgID.String != "msg_a" {
		t.Errorf("message_id = %q, want msg_a", msgID.String)
	}
	// Excerpt landed in action_excerpts (FTS5).
	var excerptCount int
	if err := database.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM action_excerpts WHERE action_id = ?`, actionID).Scan(&excerptCount); err != nil {
		t.Fatal(err)
	}
	if excerptCount != 1 {
		t.Errorf("action_excerpts rows for action_id=%d: got %d, want 1", actionID, excerptCount)
	}

	// Idempotency: second run skips the already-indexed excerpt and the
	// already-populated columns.
	res2, err := backfillOpenCodeParts(ctx, database)
	if err != nil {
		t.Fatal(err)
	}
	if res2.DurationUpdated != 0 || res2.MessageIDUpdated != 0 || res2.ToolOutputUpdated != 0 {
		t.Errorf("second run not idempotent: duration=%d msgID=%d output=%d",
			res2.DurationUpdated, res2.MessageIDUpdated, res2.ToolOutputUpdated)
	}
}

// TestBackfillOpenClawModel pins the fixed openclaw-model pass: model
// is lifted from sessions.json aliases onto SESSION rows (not actions
// — there's no actions.model column).
func TestBackfillOpenClawModel(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "obs.db")
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	// Mock the openclaw on-disk layout: tasks/runs.sqlite + sibling
	// agents/<a>/sessions/sessions.json.
	tasksDir := filepath.Join(root, ".openclaw", "tasks")
	agentsDir := filepath.Join(root, ".openclaw", "agents", "main", "sessions")
	if err := os.MkdirAll(tasksDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(agentsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	runsPath := filepath.Join(tasksDir, "runs.sqlite")
	ocDB, err := sql.Open("sqlite", runsPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ocDB.Exec(`CREATE TABLE task_runs (
		task_id TEXT PRIMARY KEY,
		child_session_key TEXT,
		owner_key TEXT NOT NULL,
		requester_session_key TEXT,
		run_id TEXT,
		source_id TEXT
	)`); err != nil {
		ocDB.Close()
		t.Fatalf("create runs.sqlite: %v", err)
	}
	if _, err := ocDB.Exec(`INSERT INTO task_runs VALUES
		('task_1', 'agent:main:obs-smoke', 'agent:main:obs-smoke', '', '', '')`); err != nil {
		ocDB.Close()
		t.Fatalf("seed task_runs: %v", err)
	}
	ocDB.Close()
	if err := os.WriteFile(filepath.Join(agentsDir, "sessions.json"), []byte(`{
		"agent:main:obs-smoke": {
			"sessionId": "agent:main:obs-smoke",
			"modelProvider": "anthropic",
			"model": "claude-sonnet-4-5",
			"systemPromptReport": {"workspaceDir":"/tmp/ws","provider":"anthropic","model":"claude-sonnet-4-5"}
		}
	}`), 0o644); err != nil {
		t.Fatal(err)
	}

	// Seed observer DB: project + openclaw session with empty model + an
	// action pointing at runs.sqlite so the backfill discovers the path.
	if _, err := database.ExecContext(ctx,
		`INSERT INTO projects (id, root_path, created_at) VALUES (1, '/tmp/test', '2026-04-30T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, tool, model, started_at, project_id)
		 VALUES ('agent:main:obs-smoke', 'openclaw', '', '2026-04-30T00:00:00Z', 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO actions (session_id, project_id, timestamp, action_type, tool, source_file, source_event_id)
		 VALUES ('agent:main:obs-smoke', 1, '2026-04-30T00:00:01Z', 'user_prompt', 'openclaw', ?, 'task:task_1:prompt')`,
		runsPath); err != nil {
		t.Fatal(err)
	}

	res, err := backfillOpenClawModel(ctx, database)
	if err != nil {
		t.Fatalf("backfillOpenClawModel: %v", err)
	}
	if res.AliasesLoaded == 0 {
		t.Errorf("AliasesLoaded = 0, want > 0")
	}
	if res.SessionsUpdated != 1 {
		t.Errorf("SessionsUpdated = %d, want 1", res.SessionsUpdated)
	}
	var got sql.NullString
	if err := database.QueryRowContext(ctx,
		`SELECT model FROM sessions WHERE id = 'agent:main:obs-smoke'`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got.String != "anthropic/claude-sonnet-4-5" {
		t.Errorf("session model = %q, want anthropic/claude-sonnet-4-5", got.String)
	}

	res2, _ := backfillOpenClawModel(ctx, database)
	if res2.SessionsUpdated != 0 {
		t.Errorf("second run not idempotent: %d", res2.SessionsUpdated)
	}
}

// TestBackfillOpenCodeMessageID pins the SQL-only opencode message_id
// pass: the upstream id is already in source_event_id (with a prefix);
// strip the prefix and write to message_id where empty.
func TestBackfillOpenCodeMessageID(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "obs.db")
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	if _, err := database.ExecContext(ctx,
		`INSERT INTO projects (id, root_path, created_at) VALUES (1, '/tmp/test', '2026-04-30T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, tool, started_at, project_id) VALUES ('ses_1', 'opencode', '2026-04-30T00:00:00Z', 1)`); err != nil {
		t.Fatal(err)
	}
	// Three actions: a user prompt (message:), a completion (complete:),
	// and a tool part (part:) — only the first two are touched by this
	// SQL-only pass; the part row is left for backfillOpenCodeParts.
	for _, a := range []struct {
		actionType string
		sourceID   string
		expectMID  string // "" means leave alone
	}{
		{"user_prompt", "message:msg_user", "user:msg_user"},
		{"task_complete", "complete:msg_done", "msg_done"},
		{"read_file", "part:prt_x", ""}, // not handled by SQL-only — stays empty
	} {
		_, err := database.ExecContext(ctx,
			`INSERT INTO actions (session_id, project_id, timestamp, action_type, tool, source_file, source_event_id)
			 VALUES ('ses_1', 1, '2026-04-30T00:00:01Z', ?, 'opencode', '/tmp/oc/opencode.db', ?)`,
			a.actionType, a.sourceID)
		if err != nil {
			t.Fatal(err)
		}
	}
	// One token_usage row with `tokens:` prefix.
	if _, err := database.ExecContext(ctx,
		`INSERT INTO token_usage (session_id, timestamp, tool, model, source_file, source_event_id, source, reliability)
		 VALUES ('ses_1', '2026-04-30T00:00:02Z', 'opencode', 'big-pickle', '/tmp/oc/opencode.db', 'tokens:msg_done', 'jsonl', 'approximate')`); err != nil {
		t.Fatal(err)
	}

	res, err := backfillOpenCodeMessageID(ctx, database)
	if err != nil {
		t.Fatalf("backfillOpenCodeMessageID: %v", err)
	}
	if res.ActionsUpdated != 2 {
		t.Errorf("ActionsUpdated = %d, want 2 (user prompt + completion)", res.ActionsUpdated)
	}
	if res.TokenUsageUpdated != 1 {
		t.Errorf("TokenUsageUpdated = %d, want 1", res.TokenUsageUpdated)
	}

	// Verify per-row state.
	for _, c := range []struct {
		eid      string
		wantMsg  string
		isAction bool
	}{
		{"message:msg_user", "user:msg_user", true},
		{"complete:msg_done", "msg_done", true},
		{"part:prt_x", "", true}, // untouched
		{"tokens:msg_done", "msg_done", false},
	} {
		var got sql.NullString
		var query string
		if c.isAction {
			query = `SELECT message_id FROM actions WHERE source_event_id = ?`
		} else {
			query = `SELECT message_id FROM token_usage WHERE source_event_id = ?`
		}
		if err := database.QueryRowContext(ctx, query, c.eid).Scan(&got); err != nil {
			t.Fatalf("query %s: %v", c.eid, err)
		}
		if got.String != c.wantMsg {
			t.Errorf("%s: message_id = %q, want %q", c.eid, got.String, c.wantMsg)
		}
	}

	// Idempotency.
	res2, err := backfillOpenCodeMessageID(ctx, database)
	if err != nil {
		t.Fatal(err)
	}
	if res2.ActionsUpdated != 0 || res2.TokenUsageUpdated != 0 {
		t.Errorf("second run not idempotent: actions=%d tokens=%d", res2.ActionsUpdated, res2.TokenUsageUpdated)
	}
}

// TestBackfillOpenClawActionTypes pins the SQL-only openclaw retag:
// historical sessions_spawn/process/canvas-style rows pick up the
// refined action_type now emitted by the adapter.
func TestBackfillOpenClawActionTypes(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "obs.db")
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	if _, err := database.ExecContext(ctx,
		`INSERT INTO projects (id, root_path, created_at) VALUES (1, '/tmp/test', '2026-04-30T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, tool, started_at, project_id) VALUES ('ses_1', 'openclaw', '2026-04-30T00:00:00Z', 1)`); err != nil {
		t.Fatal(err)
	}
	for i, a := range []struct {
		rawName    string
		actionType string
	}{
		{"sessions_spawn", "mcp_call"},       // → spawn_subagent
		{"process", "unknown"},               // → run_command
		{"canvas", "unknown"},                // → mcp_call
		{"sessions_list", "mcp_call"},        // leave
		{"sessions_spawn", "spawn_subagent"}, // already correct, leave
		{"read", "read_file"},                // unrelated, leave
	} {
		_, err := database.ExecContext(ctx,
			`INSERT INTO actions (session_id, project_id, timestamp, action_type, raw_tool_name, tool, source_file, source_event_id)
			 VALUES ('ses_1', 1, '2026-04-30T00:00:01Z', ?, ?, 'openclaw', '/tmp/runs.sqlite', ?)`,
			a.actionType, a.rawName, fmt.Sprintf("%s:seed:%d", a.rawName, i))
		if err != nil {
			t.Fatal(err)
		}
	}

	res, err := backfillOpenClawActionTypes(ctx, database)
	if err != nil {
		t.Fatalf("backfillOpenClawActionTypes: %v", err)
	}
	if res.ActionsUpdated != 3 {
		t.Errorf("ActionsUpdated = %d, want 3 (sessions_spawn + process + canvas)", res.ActionsUpdated)
	}

	// Verify only the targeted rows were retagged.
	var spawnCount int
	if err := database.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM actions WHERE raw_tool_name='sessions_spawn' AND action_type='spawn_subagent'`).Scan(&spawnCount); err != nil {
		t.Fatal(err)
	}
	if spawnCount != 2 {
		t.Errorf("spawn_subagent count = %d, want 2 (the retagged + the already-correct)", spawnCount)
	}
	var processCount int
	if err := database.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM actions WHERE raw_tool_name='process' AND action_type='run_command'`).Scan(&processCount); err != nil {
		t.Fatal(err)
	}
	if processCount != 1 {
		t.Errorf("process run_command count = %d, want 1", processCount)
	}
	var canvasCount int
	if err := database.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM actions WHERE raw_tool_name='canvas' AND action_type='mcp_call'`).Scan(&canvasCount); err != nil {
		t.Fatal(err)
	}
	if canvasCount != 1 {
		t.Errorf("canvas mcp_call count = %d, want 1", canvasCount)
	}
	var sessionsListCount int
	if err := database.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM actions WHERE raw_tool_name='sessions_list' AND action_type='mcp_call'`).Scan(&sessionsListCount); err != nil {
		t.Fatal(err)
	}
	if sessionsListCount != 1 {
		t.Errorf("sessions_list mcp_call count = %d, want 1 (must NOT be retagged)", sessionsListCount)
	}

	res2, _ := backfillOpenClawActionTypes(ctx, database)
	if res2.ActionsUpdated != 0 {
		t.Errorf("second run not idempotent: %d", res2.ActionsUpdated)
	}
}

// TestBackfillOpenClawProjectRoot_ReattributesAliasSessions pins the
// audit B3 repair path: sessions.json carries the authoritative
// workspaceDir, so historical openclaw rows that collapsed under a
// placeholder / wrong project can be reattached to the real workspace.
func TestBackfillOpenClawProjectRoot_ReattributesAliasSessions(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "obs.db")
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	if _, err := database.ExecContext(ctx,
		`INSERT INTO projects (root_path, created_at) VALUES ('[openclaw]', '2026-04-30T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	var wrongPID int64
	if err := database.QueryRowContext(ctx,
		`SELECT id FROM projects WHERE root_path = '[openclaw]'`).Scan(&wrongPID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(
		ctx,
		`INSERT INTO sessions (id, project_id, tool, started_at) VALUES ('observer-smoke', ?, 'openclaw', '2026-04-30T00:00:00Z')`, wrongPID,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(
		ctx,
		`INSERT INTO actions (session_id, project_id, timestamp, action_type, raw_tool_name, tool, source_file, source_event_id)
		 VALUES ('observer-smoke', ?, '2026-04-30T00:00:01Z', 'task_complete', 'sessions.status', 'openclaw', 'fake', 'session:observer-smoke:complete')`, wrongPID,
	); err != nil {
		t.Fatal(err)
	}

	realProject := filepath.Join(root, "real-openclaw-project")
	if err := os.MkdirAll(realProject, 0o755); err != nil {
		t.Fatal(err)
	}
	agentsDir := filepath.Join(root, ".openclaw", "agents", "main", "sessions")
	if err := os.MkdirAll(agentsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(agentsDir, "sessions.json"), []byte(`{
		"agent:main:explicit:observer-smoke": {
			"sessionId": "observer-smoke",
			"systemPromptReport": {
				"sessionKey": "agent:main:explicit:observer-smoke",
				"workspaceDir": `+jsonString(realProject)+`
			}
		}
	}`), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := backfillOpenClawProjectRoot(ctx, database, []string{filepath.Join(root, ".openclaw", "agents")}, 0)
	if err != nil {
		t.Fatalf("backfillOpenClawProjectRoot: %v", err)
	}
	if res.FilesScanned != 1 {
		t.Errorf("FilesScanned = %d, want 1", res.FilesScanned)
	}
	if res.SessionsReattributed != 1 {
		t.Errorf("SessionsReattributed = %d, want 1", res.SessionsReattributed)
	}
	if res.ActionsUpdated != 1 {
		t.Errorf("ActionsUpdated = %d, want 1", res.ActionsUpdated)
	}

	var newPID int64
	if err := database.QueryRowContext(ctx,
		`SELECT project_id FROM sessions WHERE id = 'observer-smoke'`).Scan(&newPID); err != nil {
		t.Fatal(err)
	}
	if newPID == wrongPID {
		t.Fatalf("session still attached to placeholder project")
	}
	var newRoot string
	if err := database.QueryRowContext(ctx,
		`SELECT root_path FROM projects WHERE id = ?`, newPID).Scan(&newRoot); err != nil {
		t.Fatal(err)
	}
	if newRoot != realProject {
		t.Errorf("project root = %q, want %q", newRoot, realProject)
	}

	res2, err := backfillOpenClawProjectRoot(ctx, database, []string{filepath.Join(root, ".openclaw", "agents")}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res2.SessionsReattributed != 0 || res2.ActionsUpdated != 0 {
		t.Errorf("second run not idempotent: %+v", res2)
	}
}

// TestBackfillOpenClawSessionID pins the audit B2 repair path:
// sessions.json historically used the raw sessionId while JSONL and
// task_runs used the alias/session-key. The backfill merges the raw-id
// rows onto the canonical alias session.
func TestBackfillOpenClawSessionID(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "obs.db")
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	if _, err := database.ExecContext(ctx,
		`INSERT INTO projects (id, root_path, created_at) VALUES (1, '/tmp/test', '2026-04-30T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, tool, model, started_at, project_id) VALUES
		 ('observer-smoke', 'openclaw', '', '2026-04-30T00:00:00Z', 1),
		 ('agent:main:explicit:observer-smoke', 'openclaw', 'anthropic/claude-sonnet-4-5', '2026-04-30T00:00:05Z', 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO actions (session_id, project_id, timestamp, action_type, raw_tool_name, tool, source_file, source_event_id)
		 VALUES
		 ('observer-smoke', 1, '2026-04-30T00:00:01Z', 'task_complete', 'sessions.status', 'openclaw', 'fake', 'session:observer-smoke:complete'),
		 ('agent:main:explicit:observer-smoke', 1, '2026-04-30T00:00:02Z', 'read_file', 'read', 'openclaw', 'fake', 'tool:existing')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO token_usage (session_id, timestamp, tool, model, input_tokens, output_tokens, source, reliability, source_file, source_event_id)
		 VALUES ('observer-smoke', '2026-04-30T00:00:03Z', 'openclaw', 'anthropic/claude-sonnet-4-5', 10, 2, 'jsonl', 'approximate', 'fake', 'tokens:observer-smoke')`); err != nil {
		t.Fatal(err)
	}

	agentsDir := filepath.Join(root, ".openclaw", "agents", "main", "sessions")
	if err := os.MkdirAll(agentsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(agentsDir, "sessions.json"), []byte(`{
		"agent:main:explicit:observer-smoke": {
			"sessionId": "observer-smoke",
			"systemPromptReport": {
				"sessionKey": "agent:main:explicit:observer-smoke"
			}
		}
	}`), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := backfillOpenClawSessionID(ctx, database, []string{filepath.Join(root, ".openclaw", "agents")}, 0)
	if err != nil {
		t.Fatalf("backfillOpenClawSessionID: %v", err)
	}
	if res.AliasFilesScanned != 1 {
		t.Errorf("AliasFilesScanned = %d, want 1", res.AliasFilesScanned)
	}
	if res.SessionRowsMerged != 1 {
		t.Errorf("SessionRowsMerged = %d, want 1", res.SessionRowsMerged)
	}
	if res.ActionsUpdated != 1 {
		t.Errorf("ActionsUpdated = %d, want 1", res.ActionsUpdated)
	}
	if res.TokenUsageUpdated != 1 {
		t.Errorf("TokenUsageUpdated = %d, want 1", res.TokenUsageUpdated)
	}
	if res.SessionsDeleted != 1 {
		t.Errorf("SessionsDeleted = %d, want 1", res.SessionsDeleted)
	}

	var oldCount int
	if err := database.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sessions WHERE id = 'observer-smoke'`).Scan(&oldCount); err != nil {
		t.Fatal(err)
	}
	if oldCount != 0 {
		t.Errorf("legacy session row still present: %d", oldCount)
	}
	var movedActions int
	if err := database.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM actions WHERE session_id = 'agent:main:explicit:observer-smoke'`).Scan(&movedActions); err != nil {
		t.Fatal(err)
	}
	if movedActions != 2 {
		t.Errorf("canonical action count = %d, want 2", movedActions)
	}
	var movedTokens int
	if err := database.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM token_usage WHERE session_id = 'agent:main:explicit:observer-smoke'`).Scan(&movedTokens); err != nil {
		t.Fatal(err)
	}
	if movedTokens != 1 {
		t.Errorf("canonical token count = %d, want 1", movedTokens)
	}

	res2, err := backfillOpenClawSessionID(ctx, database, []string{filepath.Join(root, ".openclaw", "agents")}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res2.SessionRowsMerged != 0 || res2.ActionsUpdated != 0 || res2.TokenUsageUpdated != 0 || res2.SessionsDeleted != 0 {
		t.Errorf("second run not idempotent: %+v", res2)
	}
}

// TestBackfillCursorModel pins the SQL-only cursor session-model copy:
// session rows whose model is empty pick up the model from a matching
// token_usage row. (Actions has no model column; per-action model is
// always derived by joining to token_usage.)
func TestBackfillCursorModel(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "obs.db")
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	if _, err := database.ExecContext(ctx,
		`INSERT INTO projects (id, root_path, created_at) VALUES (1, '/tmp/test', '2026-04-30T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	// Three cursor sessions:
	//   c1: empty model + matching token row → should pick up
	//   c2: empty model + no token row → stays empty
	//   c3: already has model → IS NULL/empty guard skips it
	for _, s := range []struct {
		id, model string
	}{{"c1", ""}, {"c2", ""}, {"c3", "gpt-5"}} {
		_, err := database.ExecContext(ctx,
			`INSERT INTO sessions (id, tool, model, started_at, project_id)
			 VALUES (?, 'cursor', ?, '2026-04-30T00:00:00Z', 1)`, s.id, s.model)
		if err != nil {
			t.Fatal(err)
		}
	}
	// Token row for c1 only.
	if _, err := database.ExecContext(ctx,
		`INSERT INTO token_usage (session_id, timestamp, tool, model, source_file, source_event_id, message_id, input_tokens, output_tokens, source, reliability)
		 VALUES ('c1', '2026-04-30T00:00:00Z', 'cursor', 'claude-sonnet-4-5', 'cursor:hook', 'gen-1:stop', 'gen-1', 10, 5, 'hook', 'accurate')`); err != nil {
		t.Fatal(err)
	}
	// Token row for c3 with a different model — must NOT overwrite c3's existing model.
	if _, err := database.ExecContext(ctx,
		`INSERT INTO token_usage (session_id, timestamp, tool, model, source_file, source_event_id, message_id, input_tokens, output_tokens, source, reliability)
		 VALUES ('c3', '2026-04-30T00:00:00Z', 'cursor', 'claude-haiku-4-5', 'cursor:hook', 'gen-3:stop', 'gen-3', 10, 5, 'hook', 'accurate')`); err != nil {
		t.Fatal(err)
	}

	res, err := backfillCursorModel(ctx, database)
	if err != nil {
		t.Fatalf("backfillCursorModel: %v", err)
	}
	if res.SessionsUpdated != 1 {
		t.Errorf("SessionsUpdated = %d, want 1 (only c1)", res.SessionsUpdated)
	}
	for _, c := range []struct {
		id, want string
	}{
		{"c1", "claude-sonnet-4-5"}, // lifted
		{"c2", ""},                  // no token row
		{"c3", "gpt-5"},             // existing preserved
	} {
		var got sql.NullString
		if err := database.QueryRowContext(ctx,
			`SELECT model FROM sessions WHERE id = ?`, c.id).Scan(&got); err != nil {
			t.Fatalf("query %s: %v", c.id, err)
		}
		if got.String != c.want {
			t.Errorf("session %s: model = %q, want %q", c.id, got.String, c.want)
		}
	}

	res2, _ := backfillCursorModel(ctx, database)
	if res2.SessionsUpdated != 0 {
		t.Errorf("second run not idempotent: %d", res2.SessionsUpdated)
	}
}

// TestBackfillSessionModels pins the --session-models CLI wiring over
// store.BackfillSessionModels: the rollup is ADAPTER-AGNOSTIC (unlike
// --cursor-model), fills only an empty sessions.model, takes the NEWEST
// model-bearing token row, leaves a session with no such row alone, and
// is idempotent on a second run.
func TestBackfillSessionModels(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "obs.db")
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	if _, err := database.ExecContext(ctx,
		`INSERT INTO projects (id, root_path, created_at) VALUES (1, '/tmp/test', '2026-04-30T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	for _, s := range []struct{ id, tool, model string }{
		{"s1", "codex", ""},        // empty + token rows → filled with the newest
		{"s2", "cline", ""},        // empty + no token row → untouched
		{"s3", "cowork", "opus-4"}, // already set → never overwritten
	} {
		if _, err := database.ExecContext(ctx,
			`INSERT INTO sessions (id, tool, model, started_at, project_id)
			 VALUES (?, ?, ?, '2026-04-30T00:00:00Z', 1)`, s.id, s.tool, s.model); err != nil {
			t.Fatal(err)
		}
	}
	for _, tk := range []struct{ session, model, ts, evt string }{
		{"s1", "gpt-5-mini", "2026-04-30T00:00:00Z", "s1-a"},
		{"s1", "gpt-5", "2026-04-30T01:00:00Z", "s1-b"}, // newest wins
		{"s3", "haiku-4-5", "2026-04-30T02:00:00Z", "s3-a"},
	} {
		if _, err := database.ExecContext(ctx,
			`INSERT INTO token_usage (session_id, timestamp, tool, model, source_file, source_event_id, input_tokens, output_tokens, source, reliability)
			 VALUES (?, ?, 'codex', ?, '/tmp/x.jsonl', ?, 10, 5, 'jsonl', 'estimated')`,
			tk.session, tk.ts, tk.model, tk.evt); err != nil {
			t.Fatal(err)
		}
	}

	res, err := backfillSessionModels(ctx, database)
	if err != nil {
		t.Fatalf("backfillSessionModels: %v", err)
	}
	if res.SessionsUpdated != 1 {
		t.Errorf("SessionsUpdated = %d, want 1 (only s1)", res.SessionsUpdated)
	}
	for _, c := range []struct{ id, want string }{
		{"s1", "gpt-5"},
		{"s2", ""},
		{"s3", "opus-4"},
	} {
		var got sql.NullString
		if err := database.QueryRowContext(ctx,
			`SELECT model FROM sessions WHERE id = ?`, c.id).Scan(&got); err != nil {
			t.Fatalf("query %s: %v", c.id, err)
		}
		if got.String != c.want {
			t.Errorf("session %s: model = %q, want %q", c.id, got.String, c.want)
		}
	}

	again, err := backfillSessionModels(ctx, database)
	if err != nil {
		t.Fatal(err)
	}
	if again.SessionsUpdated != 0 {
		t.Errorf("second run not idempotent: %d", again.SessionsUpdated)
	}
}

// TestBackfillCodexReasoning pins the codex agent_message → preceding_reasoning
// pass: agent_message text per turn lands on every action row with
// the matching message_id (turn_id).
func TestBackfillCodexReasoning(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "obs.db")
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	if _, err := database.ExecContext(ctx,
		`INSERT INTO projects (id, root_path, created_at) VALUES (1, '/tmp/test', '2026-04-30T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, tool, started_at, project_id) VALUES ('thread-3', 'codex', '2026-04-30T00:00:00Z', 1)`); err != nil {
		t.Fatal(err)
	}
	// Two action rows for turn-3, one for turn-4.
	for _, a := range []struct {
		eid, mid string
	}{
		{"call_1", "turn-3"},
		{"call_2", "turn-3"},
		{"call_3", "turn-4"},
	} {
		_, err := database.ExecContext(ctx,
			`INSERT INTO actions (session_id, project_id, timestamp, action_type, tool, source_file, source_event_id, message_id)
			 VALUES ('thread-3', 1, '2026-04-30T00:00:01Z', 'read_file', 'codex', 'fake', ?, ?)`, a.eid, a.mid)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Build a fake codex sessions tree with one rollout file.
	sessionsDir := filepath.Join(root, "codex-sessions")
	if err := os.MkdirAll(sessionsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	rollout := filepath.Join(sessionsDir, "rollout-thread-3.jsonl")
	body := strings.Join([]string{
		`{"timestamp":"2026-04-30T00:00:01.000Z","type":"session_meta","payload":{"id":"thread-3","cwd":"/x","model":"gpt-5","git_branch":"main"}}`,
		`{"timestamp":"2026-04-30T00:00:01.050Z","type":"event_msg","payload":{"type":"task_started","turn_id":"turn-3"}}`,
		`{"timestamp":"2026-04-30T00:00:01.100Z","type":"event_msg","payload":{"type":"agent_message","turn_id":"turn-3","message":"I'll inspect main.go and run the tests."}}`,
		`{"timestamp":"2026-04-30T00:00:02.000Z","type":"event_msg","payload":{"type":"task_started","turn_id":"turn-4"}}`,
		`{"timestamp":"2026-04-30T00:00:02.100Z","type":"event_msg","payload":{"type":"agent_message","turn_id":"turn-4","message":"Now I'll patch the bug."}}`,
		"",
	}, "\n")
	if err := os.WriteFile(rollout, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := backfillCodexReasoning(ctx, database, sessionsDir, 0)
	if err != nil {
		t.Fatalf("backfillCodexReasoning: %v", err)
	}
	if res.TurnsCaptured != 2 {
		t.Errorf("TurnsCaptured = %d, want 2", res.TurnsCaptured)
	}
	if res.ActionsUpdated != 3 {
		t.Errorf("ActionsUpdated = %d, want 3 (two turn-3 rows + one turn-4)", res.ActionsUpdated)
	}
	for _, c := range []struct {
		eid, want string
	}{
		{"call_1", "I'll inspect main.go and run the tests."},
		{"call_2", "I'll inspect main.go and run the tests."},
		{"call_3", "Now I'll patch the bug."},
	} {
		var got sql.NullString
		if err := database.QueryRowContext(ctx,
			`SELECT preceding_reasoning FROM actions WHERE source_event_id = ?`, c.eid).Scan(&got); err != nil {
			t.Fatalf("query %s: %v", c.eid, err)
		}
		if got.String != c.want {
			t.Errorf("%s: preceding_reasoning = %q, want %q", c.eid, got.String, c.want)
		}
	}

	// Idempotency.
	res2, _ := backfillCodexReasoning(ctx, database, sessionsDir, 0)
	if res2.ActionsUpdated != 0 {
		t.Errorf("second run not idempotent: %d", res2.ActionsUpdated)
	}
}

// TestBackfillCodexProjectRoot_ReattributesWindowsCwd pins the
// v1.4.28 fix: codex sessions whose cwd was a Windows-style path
// (captured by codex on Windows, parsed by an observer in WSL2) were
// misattributed to whichever project lay on the path
// filepath.Abs+findGitRoot ended up walking — typically observer's
// own repo. The backfill re-reads the rollout's session_meta cwd,
// translates via crossmount, resolves the new project, and updates
// every action row + the session row to point at the new project_id.
func TestBackfillCodexProjectRoot_ReattributesWindowsCwd(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "obs.db")
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	// Seed a "wrong" project (simulating observer's own repo) and
	// attach one session + two actions to it. This is the post-bug
	// state: the codex adapter resolved cwd "C:\\proj-x" as a
	// relative path, walked up, and landed on the test process's
	// nearest .git — typically a useless attribution.
	if _, err := database.ExecContext(
		ctx,
		`INSERT INTO projects (root_path, created_at) VALUES ('/wrong/observer-cwd', '2026-04-30T00:00:00Z')`,
	); err != nil {
		t.Fatal(err)
	}
	var wrongPID int64
	if err := database.QueryRowContext(
		ctx,
		`SELECT id FROM projects WHERE root_path = '/wrong/observer-cwd'`,
	).Scan(&wrongPID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(
		ctx,
		`INSERT INTO sessions (id, project_id, tool, started_at) VALUES ('s-cx-1', ?, 'codex', '2026-04-30T00:00:00Z')`, wrongPID,
	); err != nil {
		t.Fatal(err)
	}
	for _, eid := range []string{"call_1", "call_2"} {
		if _, err := database.ExecContext(
			ctx,
			`INSERT INTO actions (session_id, project_id, timestamp, action_type, tool, source_file, source_event_id)
			 VALUES ('s-cx-1', ?, '2026-04-30T00:00:01Z', 'read_file', 'codex', 'fake', ?)`,
			wrongPID, eid,
		); err != nil {
			t.Fatal(err)
		}
	}

	// Build a synthetic codex rollout whose session_meta.cwd is a
	// Windows-style path. The /mnt/c equivalent must exist on this
	// host so git.Resolve can return a stable Root — point it at a
	// non-git directory under t.TempDir, then symlink-style fake
	// the /mnt/c lookup by giving the rollout a cwd whose
	// translation matches a real local path.
	realProject := filepath.Join(root, "real-proj") // /tmp/.../real-proj
	if err := os.MkdirAll(realProject, 0o755); err != nil {
		t.Fatal(err)
	}
	// Use a forward-slash cwd pointing at the real project's mount
	// equivalent: a path that, after TranslateForeignPath, equals
	// realProject. Easiest synthetic: pretend realProject's path is
	// the post-translation form of a Windows path. We can't fake the
	// translation table, so instead test the realistic scenario by
	// using a Linux-form cwd directly — TranslateForeignPath is a
	// no-op on Linux paths so the backfill still runs the rest of
	// the pipeline (UpsertProject + UPDATE) and verifies
	// reattribution end-to-end.
	sessionsDir := filepath.Join(root, "codex-sessions")
	if err := os.MkdirAll(sessionsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	rollout := filepath.Join(sessionsDir, "rollout-s-cx-1.jsonl")
	body := strings.Join([]string{
		`{"timestamp":"2026-04-30T00:00:01.000Z","type":"session_meta","payload":{"id":"s-cx-1","cwd":` + jsonString(realProject) + `,"model":"gpt-5"}}`,
		"",
	}, "\n")
	if err := os.WriteFile(rollout, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := backfillCodexProjectRoot(ctx, database, []string{sessionsDir}, 0)
	if err != nil {
		t.Fatalf("backfillCodexProjectRoot: %v", err)
	}
	if res.FilesScanned != 1 {
		t.Errorf("FilesScanned = %d, want 1", res.FilesScanned)
	}
	if res.SessionsReattributed != 1 {
		t.Errorf("SessionsReattributed = %d, want 1", res.SessionsReattributed)
	}
	if res.ActionsUpdated != 2 {
		t.Errorf("ActionsUpdated = %d, want 2 (two seeded actions)", res.ActionsUpdated)
	}

	// Verify the session is now attached to the real project, not
	// the wrong one.
	var newPID int64
	if err := database.QueryRowContext(
		ctx,
		`SELECT project_id FROM sessions WHERE id = 's-cx-1'`,
	).Scan(&newPID); err != nil {
		t.Fatal(err)
	}
	if newPID == wrongPID {
		t.Errorf("session still attached to wrong project: pid=%d", newPID)
	}
	var newRoot string
	if err := database.QueryRowContext(
		ctx,
		`SELECT root_path FROM projects WHERE id = ?`, newPID,
	).Scan(&newRoot); err != nil {
		t.Fatal(err)
	}
	if newRoot != realProject {
		t.Errorf("new project root = %q, want %q", newRoot, realProject)
	}

	// Idempotency.
	res2, _ := backfillCodexProjectRoot(ctx, database, []string{sessionsDir}, 0)
	if res2.SessionsReattributed != 0 || res2.ActionsUpdated != 0 {
		t.Errorf("second run not idempotent: %+v", res2)
	}
}

// gitAvailableForBackfill skips a test when the git binary isn't on PATH,
// mirroring internal/git's own gitAvailable helper (unexported there, so
// this package needs its own copy).
func gitAvailableForBackfill(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git binary not available")
	}
}

// initRepoWithRemote creates a real git repo with one commit and an
// "origin" remote, so a backfill call site's git.Resolve sees a real
// info.Remote to normalize (B3 reattribution residual).
func initRepoWithRemote(t *testing.T, remoteURL string) string {
	t.Helper()
	gitAvailableForBackfill(t)
	dir := t.TempDir()
	for _, args := range [][]string{
		{"init"},
		{"symbolic-ref", "HEAD", "refs/heads/main"},
		{"config", "user.email", "test@example.com"},
		{"config", "user.name", "test"},
		{"remote", "add", "origin", remoteURL},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("# repo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"add", "-A"},
		{"commit", "-m", "init"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	return dir
}

// TestBackfillProjectRootReattribution_CarriesNormalizedRemote is the B3
// residual regression test: cmd/observer/backfill.go's five re-attribution
// call sites (codex, claudecode, cowork, openclaw, antigravity) used to
// hardcode "" for store.UpsertProject's remote argument even when the
// resolved cwd sat inside a real git working tree with an "origin" remote
// available — so a backfill-driven reattribution could never populate
// projects.git_remote the way a live parse does. This exercises the codex
// and claudecode paths (both call git.Resolve directly) end-to-end and
// asserts the stored git_remote is the SAME normalized form git.NormalizeRemote
// produces for the live adapters.
func TestBackfillProjectRootReattribution_CarriesNormalizedRemote(t *testing.T) {
	ctx := context.Background()
	remoteURL := "git@github.com:acme/widget.git"
	wantRemote := git.NormalizeRemote(remoteURL) // "github.com/acme/widget"

	t.Run("codex", func(t *testing.T) {
		root := t.TempDir()
		dbPath := filepath.Join(root, "obs.db")
		database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
		if err != nil {
			t.Fatal(err)
		}
		defer database.Close()

		realProject := initRepoWithRemote(t, remoteURL)

		sessionsDir := filepath.Join(root, "codex-sessions")
		if err := os.MkdirAll(sessionsDir, 0o755); err != nil {
			t.Fatal(err)
		}
		rollout := filepath.Join(sessionsDir, "rollout-s-cx-remote.jsonl")
		body := strings.Join([]string{
			`{"timestamp":"2026-04-30T00:00:01.000Z","type":"session_meta","payload":{"id":"s-cx-remote","cwd":` + jsonString(realProject) + `,"model":"gpt-5"}}`,
			"",
		}, "\n")
		if err := os.WriteFile(rollout, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}

		res, err := backfillCodexProjectRoot(ctx, database, []string{sessionsDir}, 0)
		if err != nil {
			t.Fatalf("backfillCodexProjectRoot: %v", err)
		}
		if res.FilesScanned != 1 {
			t.Fatalf("FilesScanned = %d, want 1", res.FilesScanned)
		}

		var gotRemote string
		if err := database.QueryRowContext(
			ctx,
			`SELECT git_remote FROM projects WHERE root_path = ?`, realProject,
		).Scan(&gotRemote); err != nil {
			t.Fatal(err)
		}
		if gotRemote != wantRemote {
			t.Errorf("projects.git_remote = %q, want %q", gotRemote, wantRemote)
		}
	})

	t.Run("claudecode", func(t *testing.T) {
		root := t.TempDir()
		dbPath := filepath.Join(root, "obs.db")
		database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
		if err != nil {
			t.Fatal(err)
		}
		defer database.Close()

		realProject := initRepoWithRemote(t, remoteURL)

		projectsDir := filepath.Join(root, "claude-projects")
		if err := os.MkdirAll(projectsDir, 0o755); err != nil {
			t.Fatal(err)
		}
		transcript := filepath.Join(projectsDir, "s-cc-remote.jsonl")
		body := strings.Join([]string{
			`{"sessionId":"s-cc-remote","cwd":` + jsonString(realProject) + `,"type":"user","message":{"role":"user","content":"hi"},"timestamp":"2026-04-30T00:00:01.000Z"}`,
			"",
		}, "\n")
		if err := os.WriteFile(transcript, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}

		res, err := backfillClaudecodeProjectRoot(ctx, database, []string{projectsDir}, 0)
		if err != nil {
			t.Fatalf("backfillClaudecodeProjectRoot: %v", err)
		}
		if res.FilesScanned != 1 {
			t.Fatalf("FilesScanned = %d, want 1", res.FilesScanned)
		}

		var gotRemote string
		if err := database.QueryRowContext(
			ctx,
			`SELECT git_remote FROM projects WHERE root_path = ?`, realProject,
		).Scan(&gotRemote); err != nil {
			t.Fatal(err)
		}
		if gotRemote != wantRemote {
			t.Errorf("projects.git_remote = %q, want %q", gotRemote, wantRemote)
		}
	})
}

// codexForkDedupRolloutBody builds a synthetic codex fork/subagent
// rollout mirroring the real 0.144 replay shape: an owning session_meta
// (fork markers), a replayed parent session_meta, a replayed
// task_started governing two replayed token_count bursts (lines 4 + 5),
// then the first LIVE task_started + a live token_count (line 7). The
// fork-replay detector flags lines 4 and 5, so their token_usage rows
// (source_event_id tk:<base>:L4 / :L5) are the historical duplicates the
// backfill deletes; the live row (:L7) must survive.
func codexForkDedupRolloutBody() string {
	const (
		ownerCreateTS = "2026-07-16T20:32:04.469Z"
		replayStartAt = 1784231668 // 19:54:28Z — earlier ⇒ replayed
		liveStartAt   = 1784233924 // == owner second ⇒ live
	)
	return strings.Join([]string{
		fmt.Sprintf(`{"timestamp":"2026-07-16T20:32:04.545Z","type":"session_meta","payload":{"id":"child-sess","session_id":"child-sess","forked_from_id":"parent-sess","parent_thread_id":"parent-sess","thread_source":"subagent","timestamp":%q,"cwd":"/w","model":"gpt-5.6","git_branch":"main"}}`, ownerCreateTS),
		`{"timestamp":"2026-07-16T20:32:04.545Z","type":"session_meta","payload":{"id":"parent-sess","session_id":"parent-sess","timestamp":"2026-07-16T19:54:11.583Z","cwd":"/w","model":"gpt-5.6"}}`,
		fmt.Sprintf(`{"timestamp":"2026-07-16T20:32:04.545Z","type":"event_msg","payload":{"type":"task_started","turn_id":"turn-replay","started_at":%d}}`, replayStartAt),
		`{"timestamp":"2026-07-16T20:32:04.546Z","type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":300000,"cached_input_tokens":0,"output_tokens":100,"reasoning_output_tokens":0,"total_tokens":300100},"total_token_usage":{"input_tokens":600000,"cached_input_tokens":0,"output_tokens":200,"reasoning_output_tokens":0,"total_tokens":600200}}}}`,
		`{"timestamp":"2026-07-16T20:32:04.547Z","type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":70699,"cached_input_tokens":0,"output_tokens":100,"reasoning_output_tokens":0,"total_tokens":70799},"total_token_usage":{"input_tokens":670699,"cached_input_tokens":0,"output_tokens":300,"reasoning_output_tokens":0,"total_tokens":670999}}}}`,
		fmt.Sprintf(`{"timestamp":"2026-07-16T20:32:04.646Z","type":"event_msg","payload":{"type":"task_started","turn_id":"turn-live","started_at":%d}}`, liveStartAt),
		`{"timestamp":"2026-07-16T20:32:04.647Z","type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":17398,"cached_input_tokens":0,"output_tokens":237,"reasoning_output_tokens":88,"total_tokens":17635},"total_token_usage":{"input_tokens":688097,"cached_input_tokens":0,"output_tokens":537,"reasoning_output_tokens":88,"total_tokens":688634}}}}`,
		``,
	}, "\n")
}

// TestBackfillCodexForkDedup pins the --codex-fork-dedup pass: it must
// (a) dry-run by default (match + tally, delete nothing), (b) delete
// exactly the replayed rows under --apply while preserving the live row,
// (c) be a no-op on a second --apply, (d) skip source_files whose
// rollout is gone from disk, and (e) backfill session lineage under
// --apply (but not on a dry run).
func TestBackfillCodexForkDedup(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "obs.db")
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	if _, err := database.ExecContext(ctx,
		`INSERT INTO projects (id, root_path, created_at) VALUES (1, '/w', '2026-07-16T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	// The forked (child) session — starts with NO lineage so we can
	// assert the backfill fills it in. A second session owns the
	// missing-file row.
	for _, sid := range []string{"child-sess", "gone-sess"} {
		if _, err := database.ExecContext(ctx,
			`INSERT INTO sessions (id, tool, started_at, project_id) VALUES (?, 'codex', '2026-07-16T20:32:04Z', 1)`, sid); err != nil {
			t.Fatal(err)
		}
	}

	// The on-disk fork rollout. base becomes the source_event_id prefix.
	sessionsDir := filepath.Join(root, "codex-sessions")
	if err := os.MkdirAll(sessionsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	rollout := filepath.Join(sessionsDir, "rollout-child.jsonl")
	if err := os.WriteFile(rollout, []byte(codexForkDedupRolloutBody()), 0o644); err != nil {
		t.Fatal(err)
	}
	base := filepath.Base(rollout)

	// Seed token_usage: two replayed rows (L4 + L5), one live row (L7),
	// all under the on-disk file, plus one row under a file that no
	// longer exists on disk (must be skipped, never matched).
	insTok := func(sid, srcFile, eid string, in, out, cacheRead int64) {
		t.Helper()
		if _, err := database.ExecContext(ctx,
			`INSERT INTO token_usage (session_id, timestamp, tool, model, input_tokens, output_tokens, cache_read_tokens, source, source_file, source_event_id)
			 VALUES (?, '2026-07-16T20:32:04Z', 'codex', 'gpt-5.6', ?, ?, ?, 'measured', ?, ?)`,
			sid, in, out, cacheRead, srcFile, eid); err != nil {
			t.Fatal(err)
		}
	}
	insTok("child-sess", rollout, "tk:"+base+":L4", 100, 10, 5)    // replayed
	insTok("child-sess", rollout, "tk:"+base+":L5", 200, 20, 15)   // replayed
	insTok("child-sess", rollout, "tk:"+base+":L7", 17398, 237, 0) // live — keep
	missingFile := filepath.Join(root, "gone", "rollout-gone.jsonl")
	insTok("gone-sess", missingFile, "tk:rollout-gone.jsonl:L4", 999, 99, 9)

	countRows := func() int {
		t.Helper()
		var n int
		if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM token_usage`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	rowExists := func(eid string) bool {
		t.Helper()
		var n int
		if err := database.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM token_usage WHERE source_event_id = ?`, eid).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n > 0
	}
	lineage := func() (string, string, string) {
		t.Helper()
		var ffi, pti, ts sql.NullString
		if err := database.QueryRowContext(ctx,
			`SELECT forked_from_id, parent_thread_id, thread_source FROM sessions WHERE id = 'child-sess'`).
			Scan(&ffi, &pti, &ts); err != nil {
			t.Fatal(err)
		}
		return ffi.String, pti.String, ts.String
	}

	if countRows() != 4 {
		t.Fatalf("seed: got %d token_usage rows, want 4", countRows())
	}

	// (a) Dry run: match + tally, delete nothing, write no lineage.
	dry, err := backfillCodexForkDedup(ctx, database, false /*apply*/, 0, nil)
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if dry.RowsMatched != 2 {
		t.Errorf("dry RowsMatched = %d, want 2", dry.RowsMatched)
	}
	if dry.RowsDeleted != 0 {
		t.Errorf("dry RowsDeleted = %d, want 0", dry.RowsDeleted)
	}
	if dry.InputTokens != 300 || dry.OutputTokens != 30 || dry.CacheReadTokens != 20 {
		t.Errorf("dry token sums = in %d/out %d/cr %d, want 300/30/20",
			dry.InputTokens, dry.OutputTokens, dry.CacheReadTokens)
	}
	if dry.SessionsTouched != 1 {
		t.Errorf("dry SessionsTouched = %d, want 1", dry.SessionsTouched)
	}
	if dry.FilesScanned != 1 {
		t.Errorf("dry FilesScanned = %d, want 1", dry.FilesScanned)
	}
	if dry.FilesMissing != 1 {
		t.Errorf("dry FilesMissing = %d, want 1 (rollout-gone.jsonl)", dry.FilesMissing)
	}
	if dry.LineageBackfilled != 1 {
		t.Errorf("dry LineageBackfilled = %d, want 1", dry.LineageBackfilled)
	}
	if countRows() != 4 {
		t.Errorf("dry run mutated the DB: %d rows, want 4", countRows())
	}
	if ffi, _, _ := lineage(); ffi != "" {
		t.Errorf("dry run wrote lineage: forked_from_id=%q, want empty", ffi)
	}

	// (b) Apply: delete exactly the two replayed rows; keep live +
	// missing-file rows; write lineage.
	got, err := backfillCodexForkDedup(ctx, database, true /*apply*/, 0, nil)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got.RowsMatched != 2 || got.RowsDeleted != 2 {
		t.Errorf("apply RowsMatched/Deleted = %d/%d, want 2/2", got.RowsMatched, got.RowsDeleted)
	}
	if countRows() != 2 {
		t.Errorf("after apply: %d rows, want 2 (live + missing-file)", countRows())
	}
	if rowExists("tk:"+base+":L4") || rowExists("tk:"+base+":L5") {
		t.Error("replayed rows survived --apply")
	}
	if !rowExists("tk:" + base + ":L7") {
		t.Error("live row was deleted by --apply")
	}
	if !rowExists("tk:rollout-gone.jsonl:L4") {
		t.Error("missing-file row was deleted by --apply")
	}
	if ffi, pti, ts := lineage(); ffi != "parent-sess" || pti != "parent-sess" || ts != "subagent" {
		t.Errorf("lineage after apply = %q/%q/%q, want parent-sess/parent-sess/subagent", ffi, pti, ts)
	}
	if got.LineageBackfilled != 1 {
		t.Errorf("apply LineageBackfilled = %d, want 1 (first stamp changed a row)", got.LineageBackfilled)
	}

	// (c) Second apply is a no-op — including an HONEST lineage counter:
	// the session is already stamped, so SetSessionLineage changes no
	// row and LineageBackfilled must be 0 (finding #8, test f).
	again, err := backfillCodexForkDedup(ctx, database, true /*apply*/, 0, nil)
	if err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if again.RowsMatched != 0 || again.RowsDeleted != 0 {
		t.Errorf("second apply not idempotent: matched=%d deleted=%d", again.RowsMatched, again.RowsDeleted)
	}
	if again.LineageBackfilled != 0 {
		t.Errorf("second apply LineageBackfilled = %d, want 0 (already stamped — honest counter)", again.LineageBackfilled)
	}
	if countRows() != 2 {
		t.Errorf("second apply mutated rows: %d, want 2", countRows())
	}

	// (g) Post-apply DRY-RUN is honest too: the session exists but
	// already carries identical lineage, so the read-only change-check
	// counts nothing (finding: dry-run must mirror SetSessionLineage's
	// change semantics, not tally every lineage-bearing file).
	postDry, err := backfillCodexForkDedup(ctx, database, false /*apply*/, 0, nil)
	if err != nil {
		t.Fatalf("post-apply dry run: %v", err)
	}
	if postDry.LineageBackfilled != 0 {
		t.Errorf("post-apply dry LineageBackfilled = %d, want 0 (session already stamped)", postDry.LineageBackfilled)
	}
}

// TestLastPathSegment pins finding #5's separator-aware basename: it
// must strip after the last '/' OR '\\' regardless of host OS, so a
// Windows-captured source_file matches on a Linux observer.
func TestLastPathSegment(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ in, want string }{
		{`/home/u/.codex/sessions/rollout-x.jsonl`, "rollout-x.jsonl"},
		{`C:\Users\dev\.codex\sessions\rollout-x.jsonl`, "rollout-x.jsonl"},
		{`/mnt/c/Users/dev/mixed\rollout-x.jsonl`, "rollout-x.jsonl"},
		{`rollout-x.jsonl`, "rollout-x.jsonl"},
		{``, ""},
	} {
		if got := lastPathSegment(tc.in); got != tc.want {
			t.Errorf("lastPathSegment(%q) = %q; want %q", tc.in, got, tc.want)
		}
	}
}

// TestBackfillCodexForkDedupWindowsBasename pins finding #5 end-to-end:
// a token_usage row whose source_file is a Windows-style path (captured
// on Windows, its source_event_id built from the Windows basename) must
// still match on a Linux observer. filepath.Base would return the whole
// backslash string and never match; lastPathSegment recovers the
// trailing basename. Also pins finding #8's report completeness
// (reasoning / web_search / estimated_cost sums).
func TestBackfillCodexForkDedupWindowsBasename(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "obs.db")
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	if _, err := database.ExecContext(ctx,
		`INSERT INTO projects (id, root_path, created_at) VALUES (1, '/w', '2026-07-16T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, tool, started_at, project_id) VALUES ('child-sess', 'codex', '2026-07-16T20:32:04Z', 1)`); err != nil {
		t.Fatal(err)
	}

	// Create the on-disk rollout whose full path embeds backslash
	// separators in its final component — so filepath.Base (Linux) sees
	// the whole "C:\...\rollout-win.jsonl" string while lastPathSegment
	// recovers "rollout-win.jsonl", exactly the Windows-capture shape.
	diskDir := t.TempDir()
	winBase := "rollout-win.jsonl"
	winComponent := `C:\Users\dev\.codex\sessions\` + winBase
	winPath := filepath.Join(diskDir, winComponent)
	if err := os.WriteFile(winPath, []byte(codexForkDedupRolloutBody()), 0o644); err != nil {
		t.Fatal(err)
	}

	// Seed rows keyed by the WINDOWS basename (what a Windows-side parse
	// wrote), stored under the Windows-style source_file. Include
	// reasoning / web_search / estimated_cost so the report sums are
	// exercised. Replayed lines are L4 + L5; L7 is live.
	insTok := func(eid string, in, out, cacheRead, reason, web int64, cost float64) {
		t.Helper()
		if _, err := database.ExecContext(ctx,
			`INSERT INTO token_usage (session_id, timestamp, tool, model, input_tokens, output_tokens, cache_read_tokens, reasoning_tokens, web_search_requests, estimated_cost_usd, source, source_file, source_event_id)
			 VALUES ('child-sess', '2026-07-16T20:32:04Z', 'codex', 'gpt-5.6', ?, ?, ?, ?, ?, ?, 'measured', ?, ?)`,
			in, out, cacheRead, reason, web, cost, winPath, eid); err != nil {
			t.Fatal(err)
		}
	}
	insTok("tk:"+winBase+":L4", 100, 10, 5, 7, 1, 0.02)    // replayed
	insTok("tk:"+winBase+":L5", 200, 20, 15, 9, 2, 0.03)   // replayed
	insTok("tk:"+winBase+":L7", 17398, 237, 0, 88, 0, 0.5) // live — keep

	dry, err := backfillCodexForkDedup(ctx, database, false /*apply*/, 0, nil)
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if dry.RowsMatched != 2 {
		t.Fatalf("RowsMatched = %d, want 2 (windows-basename rows must match)", dry.RowsMatched)
	}
	if dry.ReasoningTokens != 16 {
		t.Errorf("ReasoningTokens = %d, want 16 (7+9)", dry.ReasoningTokens)
	}
	if dry.WebSearchRequests != 3 {
		t.Errorf("WebSearchRequests = %d, want 3 (1+2)", dry.WebSearchRequests)
	}
	if dry.EstimatedCostUSD < 0.0499 || dry.EstimatedCostUSD > 0.0501 {
		t.Errorf("EstimatedCostUSD = %v, want ~0.05 (0.02+0.03)", dry.EstimatedCostUSD)
	}

	// Apply deletes exactly the two replayed rows; the live row survives.
	got, err := backfillCodexForkDedup(ctx, database, true /*apply*/, 0, nil)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got.RowsDeleted != 2 {
		t.Errorf("RowsDeleted = %d, want 2", got.RowsDeleted)
	}
	var live int
	if err := database.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM token_usage WHERE source_event_id = ?`, "tk:"+winBase+":L7").Scan(&live); err != nil {
		t.Fatal(err)
	}
	if live != 1 {
		t.Errorf("live row survived count = %d, want 1", live)
	}
}

// jsonString quotes s for inclusion as a JSON string literal in test
// fixtures. Avoids manual escaping of backslashes in Windows-style
// paths the test corpus exercises.
func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// TestBackfillDryRun_SnapshotAndRedirect pins the contract for the
// Issue #3 follow-up `observer backfill --dry-run` flow:
//
//  1. setupBackfillDryRun creates a snapshot of the live DB via
//     VACUUM INTO (atomic, no live-DB mutation).
//  2. Sets OBSERVER_OBSERVER_DB_PATH so downstream config.Load
//     calls route to the snapshot.
//  3. The cleanup func restores the prior env value and deletes
//     the snapshot + any -wal / -shm siblings.
//
// We don't exercise the full backfill pipeline here (that's covered
// by the per-pass tests above); we just verify the setup/teardown
// contract.
func TestBackfillDryRun_SnapshotAndRedirect(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	livePath := filepath.Join(root, "live.db")

	// Build a non-trivial live DB so VACUUM INTO actually copies
	// content (zero-row DBs round-trip but exercise less of the
	// path).
	live, err := dbtemplate.Open(ctx, db.Options{Path: livePath})
	if err != nil {
		t.Fatalf("open live: %v", err)
	}
	if _, err := live.ExecContext(ctx,
		`INSERT INTO projects (id, root_path, created_at)
		 VALUES (1, '/tmp/p', '2026-05-19T00:00:00Z')`); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	if err := live.Close(); err != nil {
		t.Fatalf("close live: %v", err)
	}

	// Build a minimal config TOML pointing at livePath.
	configPath := filepath.Join(root, "config.toml")
	if err := os.WriteFile(
		configPath,
		[]byte(fmt.Sprintf(`[observer]
db_path = %q
log_level = "warn"

[observer.watch]
poll_interval_seconds = 2
max_file_size_mb = 64
enabled_adapters = ["claude-code"]

[observer.scrubber]
enabled = true

[observer.proxy]
enabled = false

[observer.mcp]
enabled = false
`, livePath)),
		0o644,
	); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// Capture prior env value so we can verify restoration.
	const envKey = "OBSERVER_OBSERVER_DB_PATH"
	priorValue, priorSet := os.LookupEnv(envKey)
	if priorSet {
		t.Cleanup(func() { _ = os.Setenv(envKey, priorValue) })
	} else {
		t.Cleanup(func() { _ = os.Unsetenv(envKey) })
	}

	var out strings.Builder
	snapshotPath, cleanup, err := setupBackfillDryRun(ctx, configPath, &out)
	if err != nil {
		t.Fatalf("setupBackfillDryRun: %v", err)
	}

	// Snapshot must exist on disk and be a valid SQLite DB with the
	// seeded project row.
	if _, err := os.Stat(snapshotPath); err != nil {
		t.Fatalf("snapshot not on disk: %v", err)
	}
	snap, err := dbtemplate.Open(ctx, db.Options{Path: snapshotPath})
	if err != nil {
		t.Fatalf("open snapshot: %v", err)
	}
	var count int
	if err := snap.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM projects WHERE root_path='/tmp/p'`,
	).Scan(&count); err != nil {
		t.Fatalf("query snapshot: %v", err)
	}
	snap.Close()
	if count != 1 {
		t.Errorf("snapshot row count = %d, want 1", count)
	}

	// Env override must be set to the snapshot path.
	if got := os.Getenv(envKey); got != snapshotPath {
		t.Errorf("env override = %q, want %q", got, snapshotPath)
	}

	// Banner must mention "DRY RUN" so operators don't miss the flag.
	if !strings.Contains(out.String(), "DRY RUN") {
		t.Errorf("output missing DRY RUN banner: %q", out.String())
	}
	if !strings.Contains(out.String(), snapshotPath) {
		t.Errorf("output missing snapshot path: %q", out.String())
	}

	// Cleanup must restore prior env and remove the snapshot file.
	cleanup()
	if priorSet {
		if got := os.Getenv(envKey); got != priorValue {
			t.Errorf("post-cleanup env = %q, want prior %q", got, priorValue)
		}
	} else {
		if _, set := os.LookupEnv(envKey); set {
			t.Errorf("post-cleanup env was set, expected unset")
		}
	}
	if _, err := os.Stat(snapshotPath); !os.IsNotExist(err) {
		t.Errorf("snapshot file still present after cleanup: %v", err)
	}
}

// TestBackfillDryRun_RefusesOverwrite verifies the snapshot helper
// errors out if the destination file already exists, rather than
// silently clobbering it. Defensive — the destination is a temp file
// keyed on time.Now().UnixNano() so collisions are vanishingly
// unlikely in practice, but the guard prevents a sufficiently
// adversarial $TMPDIR from being weaponized.
func TestBackfillDryRun_RefusesOverwrite(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	src := filepath.Join(root, "src.db")
	dst := filepath.Join(root, "dst.db")

	// Build a valid source DB.
	live, err := dbtemplate.Open(ctx, db.Options{Path: src})
	if err != nil {
		t.Fatal(err)
	}
	live.Close()

	// Pre-create the destination so the overwrite guard fires.
	if err := os.WriteFile(dst, []byte("pre-existing"), 0o644); err != nil {
		t.Fatal(err)
	}

	err = snapshotSQLiteDB(ctx, src, dst)
	if err == nil {
		t.Fatal("expected error on pre-existing destination, got nil")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error text: %v (want 'already exists')", err)
	}
}

// --- observer backfill --content ---
//
// TestBackfillContent_GatedOff exercises `--content` through the real cobra
// command: contentCaptureBlockReason short-circuits before buildWatcher is
// ever called, so the test never touches anything outside its own temp dir
// and is safe to run as written.
//
// The two gate-OPEN tests below (CaptureParity, Idempotent) deliberately do
// NOT go through the cobra command / buildWatcher. buildWatcher registers
// EVERY adapter via adapterdefaults.Adapters(), and claude-code's default
// WatchPaths() walks crossmount.AllHomes() — which on a WSL2 host
// unconditionally scans /mnt/c/Users for a Windows-side ~/.claude/projects
// tree (internal/platform/crossmount/crossmount.go::wslWindowsHomes; no env
// var or config knob disables it, by design — the doc comment there says as
// much — and t.Setenv("HOME", ...) only redirects the *native* home
// candidate, not this one). On a machine with a real Windows Claude Code
// install, a naive cobra-level test therefore reads and parses the
// OPERATOR'S OWN live session history during `go test`: an earlier draft of
// this test parsed 56 real transcripts instead of the 1-file fixture it
// asked for, and failed its exact files_processed assertion because of it.
//
// The two tests below instead hand-build the exact same production chain
// (wireContentCapture -> registry -> watcher.New -> Rescan ->
// Store.Ingest -> captureMessageContent) via runScopedContentRescan, using
// claudecode.NewWithOptions(scrub.New(), watchRoot) — an EXPLICIT watch
// root, which Adapter.WatchPaths() returns verbatim instead of consulting
// crossmount.AllHomes(). Same adapter, same watcher, same store seam
// production uses; only the registry's adapter LIST differs (one adapter
// with an explicit root, vs adapterdefaults.Adapters()'s full ~37-adapter
// default registry) — a test-hermeticity substitution, not a second
// implementation of the rescan logic. The CLI-level flag/gate/message
// wiring itself is covered by TestBackfillContent_GatedOff (blocked
// branch); the unblocked branch in backfill.go's --content block is a
// two-line composition of buildWatcher + Rescan + fmt.Sprintf over pieces
// already pinned here and in content_capture_wire_test.go /
// internal/store/messagecontent_test.go.

// contentFixtureSession writes one Claude Code session JSONL (a user prompt
// + an assistant text reply) predating the message-content producer
// (263a3cadc) under <tmp>/projects/demo/sess-content.jsonl — simulating
// exactly the historical-session gap --content exists to close — and
// returns the projects directory, suitable as an adapter's explicit
// watchRoot.
func contentFixtureSession(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	projects := filepath.Join(root, "projects", "demo")
	if err := os.MkdirAll(projects, 0o755); err != nil {
		t.Fatal(err)
	}
	body := strings.Join([]string{
		`{"sessionId":"sess-content","cwd":"/tmp","timestamp":"2026-05-12T00:00:00Z","uuid":"u-prompt","message":{"role":"user","content":[{"type":"text","text":"hello there"}]}}`,
		`{"sessionId":"sess-content","cwd":"/tmp","timestamp":"2026-05-12T00:00:01Z","uuid":"u-asst","message":{"id":"msg_1","role":"assistant","model":"claude-sonnet-4-5","content":[{"type":"text","text":"hi there"}]}}`,
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(projects, "sess-content.jsonl"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(root, "projects")
}

// runScopedContentRescan hand-builds the same wireContentCapture ->
// registry -> watcher.New -> Rescan chain `observer backfill --content`
// composes in backfill.go, scoped to a single claude-code adapter with an
// explicit watchRoot (see the package comment above for why this bypasses
// buildWatcher). Content sharing is turned on exactly as
// [org_client.share] full_content = true resolves via
// contentCapturePosture/wireContentCapture — the same production seam,
// asserted open first so a regression there fails loudly instead of
// silently producing zero rows.
func runScopedContentRescan(t *testing.T, ctx context.Context, dbPath, watchRoot string) watcher.ScanResult {
	t.Helper()
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	st := store.New(database)
	cfg := config.Config{OrgClient: config.OrgClientConfig{
		Share: config.OrgClientShareConfig{FullContent: true},
	}}
	if reason := contentCaptureBlockReason(cfg); reason != "" {
		t.Fatalf("fixture cfg should leave the content-capture gate open, got block reason: %q", reason)
	}
	wireContentCapture(cfg, st)

	reg := adapter.NewRegistry()
	reg.Register(claudecode.NewWithOptions(scrub.New(), watchRoot))
	w := watcher.New(st, reg, watcher.Options{Allow: []string{"claude-code"}})

	res, err := w.Rescan(ctx)
	if err != nil {
		t.Fatalf("Rescan: %v", err)
	}
	return res
}

// runBackfillContent invokes `observer backfill --content --config
// configPath` through the real cobra command and returns its combined
// stdout/stderr. Only used by TestBackfillContent_GatedOff — see the
// package comment above for why the gate-open tests use
// runScopedContentRescan instead.
func runBackfillContent(t *testing.T, configPath string) string {
	t.Helper()
	var out strings.Builder
	cmd := newBackfillCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--content", "--config", configPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("backfill --content: %v", err)
	}
	return out.String()
}

// countOTelContentRows opens dbPath and returns the total otel_content row
// count.
func countOTelContentRows(t *testing.T, ctx context.Context, dbPath string) int {
	t.Helper()
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var n int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM otel_content`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestBackfillContent_GatedOff pins the honest no-op contract for
// `observer backfill --content` when the node's content-capture gate is
// closed — the default posture, no [org_client.share] section at all. It
// must not populate otel_content, and must print a message naming the
// specific blocking config key rather than a bare "did nothing"
// (CLAUDE.md's honest-disabled-copy convention).
//
// Mutation-proof target: deleting the
//
//	if reason := contentCaptureBlockReason(gateCfg); reason != "" { ... }
//
// gate check in backfill.go's --content block (so it always falls through
// to buildWatcher+Rescan) makes this test fail by name — the skip message
// disappears from stdout and/or otel_content gains rows it must not have on
// a metadata-only node.
func TestBackfillContent_GatedOff(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "obs.db")

	configPath := filepath.Join(root, "config.toml")
	if err := os.WriteFile(configPath, []byte(fmt.Sprintf(`[observer]
db_path = %q
log_level = "warn"

[observer.watch]
poll_interval_seconds = 2
max_file_size_mb = 64
enabled_adapters = ["claude-code"]

[observer.scrubber]
enabled = true

[observer.proxy]
enabled = false

[observer.mcp]
enabled = false
`, dbPath)), 0o644); err != nil {
		t.Fatal(err)
	}

	out := runBackfillContent(t, configPath)

	if !strings.Contains(out, "content backfill skipped:") {
		t.Errorf("output missing skip message: %q", out)
	}
	if !strings.Contains(out, "[org_client.share]") {
		t.Errorf("skip message must name the blocking key: %q", out)
	}

	if n := countOTelContentRows(t, ctx, dbPath); n != 0 {
		t.Errorf("otel_content rows = %d, want 0 (gate was closed)", n)
	}
}

// TestBackfillContent_CaptureParity backfills a fixture session predating
// the message-content producer and verifies the --content chain (see
// runScopedContentRescan) reproduces exactly the otel_content rows live
// ingest would have written for the same transcript: one kindPrompt row for
// the user turn and one kindAssistant row for the reply — parsed through
// the adapter's own real parser (internal/adapter/claudecode), not a second
// hand-rolled implementation.
func TestBackfillContent_CaptureParity(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "obs.db")
	watchRoot := contentFixtureSession(t)

	res := runScopedContentRescan(t, ctx, dbPath, watchRoot)
	if res.FilesProcessed != 1 || res.Errors != 0 {
		t.Fatalf("ScanResult = %+v, want FilesProcessed=1 Errors=0", res)
	}

	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	rows, err := database.QueryContext(ctx,
		`SELECT kind, content FROM otel_content WHERE session_id = 'sess-content' ORDER BY kind`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[string]string{}
	for rows.Next() {
		var kind, content string
		if err := rows.Scan(&kind, &content); err != nil {
			t.Fatal(err)
		}
		got[kind] = content
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"assistant": "hi there", "prompt": "hello there"}
	if len(got) != len(want) {
		t.Fatalf("otel_content rows = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("otel_content[%q] = %q, want %q", k, got[k], v)
		}
	}
}

// TestBackfillContent_Idempotent runs the --content chain (see
// runScopedContentRescan) twice over the same unmodified session file and
// asserts the otel_content row count is identical both times: the table's
// (content_hash, kind, request_id, tool_use_id) UNIQUE key — tool_use_id
// carrying a session-scoped event key — must absorb the re-parse via ON
// CONFLICT DO NOTHING rather than duplicating rows.
//
// Mutation-proof target: dropping InsertOTelContent's ON CONFLICT clause
// (or un-scoping eventContentKey back to a bare per-event id) makes this
// test fail by name — the second run's count comes back doubled instead of
// unchanged.
func TestBackfillContent_Idempotent(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "obs.db")
	watchRoot := contentFixtureSession(t)

	runScopedContentRescan(t, ctx, dbPath, watchRoot)
	first := countOTelContentRows(t, ctx, dbPath)
	if first == 0 {
		t.Fatal("first rescan produced 0 otel_content rows; fixture not being captured")
	}

	runScopedContentRescan(t, ctx, dbPath, watchRoot)
	second := countOTelContentRows(t, ctx, dbPath)

	if second != first {
		t.Errorf("otel_content rows after 2nd rescan = %d, want %d (unchanged — re-parse must not duplicate)", second, first)
	}
}

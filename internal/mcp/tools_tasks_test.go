package mcp

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// tasksTestServer builds a server with the given [tasks].enabled value
// and, when seed is true, one claude-code session carrying a completed
// TodoWrite task (via BackfillTaskItems, ignoring the enabled gate at
// seed time — production wiring, not this seam, is what respects it).
func tasksTestServer(t *testing.T, tasksEnabled, seed bool) *Server {
	t.Helper()
	return tasksTestServerWithConfig(t, config.TasksConfig{
		Enabled:               tasksEnabled,
		MatchMode:             "exact",
		ConcurrentAttribution: "shared",
	}, seed)
}

// tasksTestServerWithConfig is tasksTestServer's fuller sibling for
// tests that need to control match_mode/concurrent_attribution/
// include_sidechains directly (FIX-A: get_session_tasks must apply
// these from the Tasks config it was built with, not a store
// instance's TasksOptions()).
func tasksTestServerWithConfig(t *testing.T, cfg config.TasksConfig, seed bool) *Server {
	t.Helper()
	dir := t.TempDir()
	database, err := db.Open(context.Background(), db.Options{Path: filepath.Join(dir, "obs.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { database.Close() })

	if seed {
		ctx := context.Background()
		var projectID int64
		if err := database.QueryRowContext(ctx,
			`INSERT INTO projects (root_path, created_at) VALUES ('/tmp/mcp-tasks', '2026-06-09T00:00:00Z') RETURNING id`).
			Scan(&projectID); err != nil {
			t.Fatal(err)
		}
		if _, err := database.ExecContext(ctx,
			`INSERT INTO sessions (id, tool, project_id, model, started_at)
			 VALUES ('sMCP', 'claude-code', ?, 'claude-opus-4-8', '2026-06-09T00:00:00Z')`, projectID); err != nil {
			t.Fatal(err)
		}
		if _, err := database.ExecContext(ctx,
			`INSERT INTO actions (session_id, project_id, timestamp, action_type, tool, raw_tool_name, raw_tool_input, source_file, source_event_id)
			 VALUES ('sMCP', ?, '2026-06-09T00:01:00Z', 'todo_update', 'claude-code', 'TodoWrite', '{"todos":[{"content":"Fix the bug","status":"completed"}]}', 'f.jsonl', 'e0')`,
			projectID); err != nil {
			t.Fatal(err)
		}
		st := store.New(database)
		if _, err := st.BackfillTaskItems(ctx, 0); err != nil {
			t.Fatalf("BackfillTaskItems: %v", err)
		}
	}

	s, err := New(Options{DB: database, ServerName: "test", ServerVersion: "0", Tasks: cfg})
	if err != nil {
		t.Fatalf("mcp.New: %v", err)
	}
	return s
}

func TestGetSessionTasksTool_ReportsCompletedTask(t *testing.T) {
	s := tasksTestServer(t, true, true)
	out := callTool(t, s, "get_session_tasks", map[string]any{"session_id": "sMCP"})

	hasTasks, _ := out["has_tasks"].(bool)
	if !hasTasks {
		t.Fatalf("expected has_tasks=true, got %+v", out)
	}
	items, _ := out["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("got %d items, want 1: %+v", len(items), out)
	}
	item := items[0].(map[string]any)
	if item["status"] != "completed" {
		t.Errorf("status = %v, want completed", item["status"])
	}
}

func TestGetSessionTasksTool_DisabledByConfig(t *testing.T) {
	s := tasksTestServer(t, false, true)
	out := callTool(t, s, "get_session_tasks", map[string]any{"session_id": "sMCP"})

	if enabled, ok := out["enabled"].(bool); !ok || enabled {
		t.Fatalf("expected enabled=false, got %+v", out)
	}
}

func TestGetSessionTasksTool_EmptyStateForSessionWithoutTasks(t *testing.T) {
	s := tasksTestServer(t, true, false)
	// No session row at all is fine — LoadTaskItems just returns nothing.
	out := callTool(t, s, "get_session_tasks", map[string]any{"session_id": "sNoSuchSession"})

	hasTasks, ok := out["has_tasks"].(bool)
	if !ok || hasTasks {
		t.Fatalf("expected has_tasks=false, got %+v", out)
	}
}

func TestGetSessionTasksTool_RequiresSessionID(t *testing.T) {
	s := tasksTestServer(t, true, false)
	msg := callToolExpectError(t, s, "get_session_tasks", map[string]any{})
	if msg == "" {
		t.Fatal("expected an error when session_id is omitted")
	}
}

func TestGetSessionTasksTool_RegisteredAndListed(t *testing.T) {
	s := tasksTestServer(t, true, false)
	if _, ok := s.tools["get_session_tasks"]; !ok {
		t.Fatal("get_session_tasks not registered — expected it always-on like cache_status")
	}
}

// seedConcurrentTasksSession seeds a session with two tasks that go
// in_progress SIMULTANEOUSLY (one TodoWrite snapshot listing both),
// then one token_usage row while both are still open — the
// [tasks].concurrent_attribution fork point: "shared" buckets that row
// into the session's shared total, "none" drops it into between_tasks
// instead. Returns the opened database so the caller can build a
// Server against it with whichever config it wants to exercise.
func seedConcurrentTasksSession(t *testing.T, sessionID string) *sql.DB {
	t.Helper()
	dir := t.TempDir()
	database, err := db.Open(context.Background(), db.Options{Path: filepath.Join(dir, "obs.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { database.Close() })

	ctx := context.Background()
	var projectID int64
	if err := database.QueryRowContext(ctx,
		`INSERT INTO projects (root_path, created_at) VALUES ('/tmp/mcp-tasks-concurrent', '2026-06-09T00:00:00Z') RETURNING id`).
		Scan(&projectID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, tool, project_id, model, started_at)
		 VALUES (?, 'claude-code', ?, 'claude-opus-4-8', '2026-06-09T00:00:00Z')`, sessionID, projectID); err != nil {
		t.Fatal(err)
	}
	// t=0: both tasks go in_progress in the same snapshot call.
	if _, err := database.ExecContext(ctx,
		`INSERT INTO actions (session_id, project_id, timestamp, action_type, tool, raw_tool_name, raw_tool_input, source_file, source_event_id)
		 VALUES (?, ?, '2026-06-09T00:00:00Z', 'todo_update', 'claude-code', 'TodoWrite',
		         '{"todos":[{"content":"Task A","status":"in_progress"},{"content":"Task B","status":"in_progress"}]}',
		         'f.jsonl', 'e0')`,
		sessionID, projectID); err != nil {
		t.Fatal(err)
	}
	// t=1: a token row while both tasks are still open.
	if _, err := database.ExecContext(ctx,
		`INSERT INTO token_usage (session_id, timestamp, tool, model, input_tokens, output_tokens, source, source_file, source_event_id)
		 VALUES (?, '2026-06-09T00:01:00Z', 'claude-code', 'claude-opus-4-8', 1000, 500, 'watcher', 'tok.jsonl', ?)`,
		sessionID, "tok-"+sessionID); err != nil {
		t.Fatal(err)
	}
	st := store.New(database)
	if _, err := st.BackfillTaskItems(ctx, 0); err != nil {
		t.Fatalf("BackfillTaskItems: %v", err)
	}
	return database
}

// TestGetSessionTasksTool_ConcurrentAttributionOptionReachesReport is
// the FIX-A regression test: get_session_tasks must apply
// [tasks].concurrent_attribution from the config this server was
// constructed with, not from a fresh store.New(db)'s (never-configured)
// Store.TasksOptions() — the bug was that every read surface built its
// own ephemeral store, so concurrent_attribution/include_sidechains
// were silently inert everywhere except the long-lived daemon store.
func TestGetSessionTasksTool_ConcurrentAttributionOptionReachesReport(t *testing.T) {
	t.Run("shared", func(t *testing.T) {
		database := seedConcurrentTasksSession(t, "sConcShared")
		s, err := New(Options{DB: database, ServerName: "test", ServerVersion: "0", Tasks: config.TasksConfig{
			Enabled: true, MatchMode: "exact", ConcurrentAttribution: "shared",
		}})
		if err != nil {
			t.Fatalf("mcp.New: %v", err)
		}
		out := callTool(t, s, "get_session_tasks", map[string]any{"session_id": "sConcShared"})
		shared := out["shared"].(map[string]any)
		sharedTokens := shared["tokens"].(map[string]any)
		if sharedTokens["input_tokens"].(float64) != 1000 {
			t.Errorf("shared.tokens.input_tokens = %v, want 1000 (concurrent_attribution=shared)", sharedTokens["input_tokens"])
		}
		between := out["between_tasks"].(map[string]any)
		betweenTokens := between["tokens"].(map[string]any)
		if betweenTokens["input_tokens"].(float64) != 0 {
			t.Errorf("between_tasks.tokens.input_tokens = %v, want 0 (concurrent_attribution=shared)", betweenTokens["input_tokens"])
		}
	})

	t.Run("none", func(t *testing.T) {
		database := seedConcurrentTasksSession(t, "sConcNone")
		s, err := New(Options{DB: database, ServerName: "test", ServerVersion: "0", Tasks: config.TasksConfig{
			Enabled: true, MatchMode: "exact", ConcurrentAttribution: "none",
		}})
		if err != nil {
			t.Fatalf("mcp.New: %v", err)
		}
		out := callTool(t, s, "get_session_tasks", map[string]any{"session_id": "sConcNone"})
		shared := out["shared"].(map[string]any)
		sharedTokens := shared["tokens"].(map[string]any)
		if sharedTokens["input_tokens"].(float64) != 0 {
			t.Errorf("shared.tokens.input_tokens = %v, want 0 (concurrent_attribution=none)", sharedTokens["input_tokens"])
		}
		between := out["between_tasks"].(map[string]any)
		betweenTokens := between["tokens"].(map[string]any)
		if betweenTokens["input_tokens"].(float64) != 1000 {
			t.Errorf("between_tasks.tokens.input_tokens = %v, want 1000 (concurrent_attribution=none) — the option did not reach the report", betweenTokens["input_tokens"])
		}
	})
}

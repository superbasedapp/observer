package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/compression/indexing"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
)

// importTestForeign builds a foreign observer.db carrying one project
// with one session, two keyed actions (one with tool output), one
// legacy NULL-key action, token usage (keyed + legacy), one api_turn
// with request_id and one without, an effort row, and a failure row —
// every merge branch exercised.
func importTestForeign(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "foreign.db")
	fdb, err := dbtemplate.Open(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer fdb.Close()
	now := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)

	mustExec := func(q string, args ...any) {
		t.Helper()
		if _, err := fdb.Exec(q, args...); err != nil {
			t.Fatalf("seed foreign: %v\n%s", err, q)
		}
	}
	mustExec(`INSERT INTO projects (root_path, name, created_at) VALUES ('/f-proj', 'f-proj', ?)`, now)
	mustExec(`INSERT INTO sessions (id, project_id, tool, started_at) VALUES ('f-sess', 1, 'claude-code', ?)`, now)
	mustExec(`INSERT INTO actions (session_id, project_id, timestamp, action_type, target, success, tool,
		source_file, source_event_id, raw_tool_name, raw_tool_output)
		VALUES ('f-sess', 1, ?, 'run_command', 'go test ./...', 0, 'claude-code',
		'/foreign/sess.jsonl', 'evt-1', 'Bash', 'FAIL: TestThing — connection refused')`, now)
	mustExec(`INSERT INTO actions (session_id, project_id, timestamp, action_type, target, success, tool,
		source_file, source_event_id)
		VALUES ('f-sess', 1, ?, 'read_file', 'main.go', 1, 'claude-code',
		'/foreign/sess.jsonl', 'evt-2')`, now)
	mustExec(`INSERT INTO actions (session_id, project_id, timestamp, action_type, target, success, tool,
		source_file, source_event_id)
		VALUES ('f-sess', 1, ?, 'edit_file', 'legacy.go', 1, 'claude-code',
		'/foreign/legacy.jsonl', NULL)`, now)
	mustExec(`INSERT INTO token_usage (session_id, timestamp, tool, model, input_tokens, output_tokens,
		source, source_file, source_event_id)
		VALUES ('f-sess', ?, 'claude-code', 'claude-opus-4-8', 100, 50, 'jsonl',
		'/foreign/sess.jsonl', 'tok-1')`, now)
	mustExec(`INSERT INTO token_usage (session_id, timestamp, tool, model, input_tokens, output_tokens,
		source, source_file, source_event_id)
		VALUES ('f-sess', ?, 'claude-code', 'claude-opus-4-8', 7, 3, 'hook',
		'/foreign/legacy.jsonl', NULL)`, now)
	mustExec(`INSERT INTO api_turns (session_id, project_id, timestamp, provider, model, request_id,
		input_tokens, output_tokens)
		VALUES ('f-sess', 1, ?, 'anthropic', 'claude-opus-4-8', 'req-abc', 100, 50)`, now)
	mustExec(`INSERT INTO api_turns (session_id, timestamp, provider, model, request_id,
		input_tokens, output_tokens)
		VALUES ('f-sess', ?, 'anthropic', 'claude-opus-4-8', NULL, 9, 4)`, now)
	mustExec(`INSERT INTO claudecode_effort (session_id, tool_use_id, effort_level, event_name, received_at)
		VALUES ('f-sess', 'toolu_f1', 'high', 'PreToolUse', ?)`, now)
	mustExec(`INSERT INTO failure_context (action_id, session_id, project_id, timestamp, command_hash,
		command_summary, exit_code, retry_count, eventually_succeeded)
		VALUES (1, 'f-sess', 1, ?, 'hash-1', 'go test ./...', 1, 0, 0)`, now)
	return path
}

func importCount(t *testing.T, database *sql.DB, table, where string, args ...any) int64 {
	t.Helper()
	q := "SELECT COUNT(*) FROM " + table
	if where != "" {
		q += " WHERE " + where
	}
	var n int64
	if err := database.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// TestImportFrom pins the merge: project ids remap through root_path
// (the local DB gets a decoy project first so ids diverge), every
// table lands, prior_action_id never crosses databases, imported
// outputs become searchable, and a second run inserts nothing.
func TestImportFrom(t *testing.T) {
	ctx := context.Background()
	s, database := newTestStore(t)
	foreign := importTestForeign(t)

	// Decoy local project so foreign project_id=1 ≠ local id.
	if _, err := s.UpsertProject(ctx, "/local-existing", ""); err != nil {
		t.Fatal(err)
	}

	ix := indexing.New(database, 0)
	res, err := s.ImportFrom(ctx, foreign, ImportOptions{Indexer: ix})
	if err != nil {
		t.Fatalf("ImportFrom: %v", err)
	}

	for _, tc := range []struct {
		label    string
		got      ImportTableResult
		inserted int64
	}{
		{"projects", res.Projects, 1},
		{"sessions", res.Sessions, 1},
		{"actions", res.Actions, 3},
		{"token_usage", res.TokenUsage, 2},
		{"api_turns", res.APITurns, 2},
		{"effort", res.Effort, 1},
		{"failure_context", res.FailureContext, 1},
	} {
		if tc.got.Inserted != tc.inserted {
			t.Errorf("%s inserted = %d, want %d", tc.label, tc.got.Inserted, tc.inserted)
		}
	}
	if res.ExcerptsIndexed != 1 {
		t.Errorf("excerpts indexed = %d, want 1", res.ExcerptsIndexed)
	}

	// Project remap: the imported session points at the LOCAL id for
	// /f-proj, not the foreign's id 1 (which here is /local-existing).
	var sessProj int64
	if err := database.QueryRow(`SELECT project_id FROM sessions WHERE id = 'f-sess'`).Scan(&sessProj); err != nil {
		t.Fatal(err)
	}
	var fProj int64
	if err := database.QueryRow(`SELECT id FROM projects WHERE root_path = '/f-proj'`).Scan(&fProj); err != nil {
		t.Fatal(err)
	}
	if sessProj != fProj || fProj == 1 {
		t.Errorf("session project_id = %d, want remapped %d (≠ foreign raw id 1)", sessProj, fProj)
	}
	if n := importCount(t, database, "actions", "prior_action_id IS NOT NULL"); n != 0 {
		t.Errorf("%d imported actions carry a cross-database prior_action_id", n)
	}
	// The failure row re-attached to the REMAPPED action id.
	var failAction int64
	if err := database.QueryRow(`SELECT action_id FROM failure_context LIMIT 1`).Scan(&failAction); err != nil {
		t.Fatal(err)
	}
	var wantAction int64
	if err := database.QueryRow(`SELECT id FROM actions WHERE source_event_id = 'evt-1'`).Scan(&wantAction); err != nil {
		t.Fatal(err)
	}
	if failAction != wantAction {
		t.Errorf("failure action_id = %d, want %d", failAction, wantAction)
	}
	// Imported output is searchable.
	hits, err := ix.Search(ctx, `"connection refused"`, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 {
		t.Errorf("search hits = %d, want 1", len(hits))
	}

	// Idempotency: the same import again inserts zero everywhere.
	res2, err := s.ImportFrom(ctx, foreign, ImportOptions{Indexer: ix})
	if err != nil {
		t.Fatalf("second ImportFrom: %v", err)
	}
	for _, tc := range []struct {
		label string
		got   ImportTableResult
	}{
		{"projects", res2.Projects},
		{"sessions", res2.Sessions},
		{"actions", res2.Actions},
		{"token_usage", res2.TokenUsage},
		{"api_turns", res2.APITurns},
		{"effort", res2.Effort},
		{"failure_context", res2.FailureContext},
	} {
		if tc.got.Inserted != 0 {
			t.Errorf("re-import %s inserted = %d, want 0", tc.label, tc.got.Inserted)
		}
	}
	if res2.ExcerptsIndexed != 0 {
		t.Errorf("re-import excerpts = %d, want 0", res2.ExcerptsIndexed)
	}
}

// TestImportFromDryRun pins the dry-run contract: exact counts, zero
// writes, no FTS rows.
func TestImportFromDryRun(t *testing.T) {
	ctx := context.Background()
	s, database := newTestStore(t)
	foreign := importTestForeign(t)

	res, err := s.ImportFrom(ctx, foreign, ImportOptions{DryRun: true, Indexer: indexing.New(database, 0)})
	if err != nil {
		t.Fatalf("ImportFrom dry-run: %v", err)
	}
	if res.Actions.Inserted != 3 || res.Sessions.Inserted != 1 {
		t.Errorf("dry-run counts: actions=%d sessions=%d, want 3/1", res.Actions.Inserted, res.Sessions.Inserted)
	}
	if res.ExcerptsIndexed != 0 {
		t.Errorf("dry-run indexed %d excerpts, want 0", res.ExcerptsIndexed)
	}
	for _, table := range []string{"sessions", "actions", "token_usage", "api_turns", "claudecode_effort", "failure_context", "action_excerpts"} {
		if n := importCount(t, database, table, ""); n != 0 {
			t.Errorf("dry-run left %d rows in %s", n, table)
		}
	}
	if n := importCount(t, database, "projects", ""); n != 0 {
		t.Errorf("dry-run left %d projects", n)
	}
}

// TestImportFromOverlap pins the partial-overlap case: rows already
// present locally (same idempotency keys) are skipped, new foreign
// rows land.
func TestImportFromOverlap(t *testing.T) {
	ctx := context.Background()
	s, database := newTestStore(t)
	foreign := importTestForeign(t)
	now := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)

	// Pre-seed the local DB with the same project/session and ONE of
	// the keyed actions.
	if _, err := database.Exec(`INSERT INTO projects (root_path, name, created_at) VALUES ('/f-proj', 'f-proj', ?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO sessions (id, project_id, tool, started_at) VALUES ('f-sess', 1, 'claude-code', ?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO actions (session_id, project_id, timestamp, action_type, target, success, tool,
		source_file, source_event_id) VALUES ('f-sess', 1, ?, 'run_command', 'go test ./...', 0, 'claude-code',
		'/foreign/sess.jsonl', 'evt-1')`, now); err != nil {
		t.Fatal(err)
	}

	res, err := s.ImportFrom(ctx, foreign, ImportOptions{})
	if err != nil {
		t.Fatalf("ImportFrom: %v", err)
	}
	if res.Projects.Inserted != 0 || res.Sessions.Inserted != 0 {
		t.Errorf("overlap: projects=%d sessions=%d inserted, want 0/0", res.Projects.Inserted, res.Sessions.Inserted)
	}
	if res.Actions.Inserted != 2 {
		t.Errorf("overlap: actions inserted = %d, want 2 (evt-1 already local)", res.Actions.Inserted)
	}
	if n := importCount(t, database, "actions", "source_event_id = 'evt-1'"); n != 1 {
		t.Errorf("evt-1 rows = %d, want exactly 1", n)
	}
}

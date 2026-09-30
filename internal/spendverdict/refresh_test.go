package spendverdict

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db"
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	d, err := db.Open(context.Background(), db.Options{Path: filepath.Join(t.TempDir(), "observer.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func mustExec(t *testing.T, d *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := d.ExecContext(context.Background(), q, args...); err != nil {
		t.Fatalf("exec: %v\n%s", err, q)
	}
}

func count(t *testing.T, d *sql.DB, q string, args ...any) int {
	t.Helper()
	var n int
	if err := d.QueryRowContext(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatalf("count: %v\n%s", err, q)
	}
	return n
}

// seedTwin writes session sid with one proxy turn and its shape twin (the
// transcript copy: same model / input / cache, output net of reasoning).
func seedTwin(t *testing.T, d *sql.DB, sid string) {
	t.Helper()
	mustExec(t, d, `INSERT OR IGNORE INTO projects (id, root_path, created_at) VALUES (1, '/repo', '2026-09-01T00:00:00Z')`)
	mustExec(t, d, `INSERT INTO sessions (id, project_id, tool, model, started_at)
		VALUES (?, 1, 'claude-code', 'claude-x', '2026-09-01T10:00:00Z')`, sid)
	mustExec(t, d, `INSERT INTO api_turns (session_id, timestamp, provider, model, request_id,
		input_tokens, output_tokens, cache_read_tokens, cache_creation_tokens, cost_usd)
		VALUES (?, '2026-09-01T10:00:01Z', 'anthropic', 'claude-x', 'req-'||?, 100, 30, 5, 2, 0.01)`, sid, sid)
	mustExec(t, d, `INSERT INTO token_usage (session_id, timestamp, tool, model, source_event_id,
		input_tokens, output_tokens, reasoning_tokens, cache_read_tokens, cache_creation_tokens,
		source, reliability)
		VALUES (?, '2026-09-01T10:00:02Z', 'claude-code', 'claude-x', 'msg-'||?, 100, 20, 10, 5, 2,
		'jsonl', 'estimated')`, sid, sid)
}

// TestRefresh_TriggerQueuesAndDerives: a row write queues its session; Refresh
// stores Derive's verdicts (the twin is not counted, the proxy row carries the
// twin's visible output + reasoning) and clears the queue.
func TestRefresh_TriggerQueuesAndDerives(t *testing.T) {
	ctx := context.Background()
	d := openTestDB(t)
	if _, err := Refresh(ctx, d, Options{}); err != nil { // consume the version backfill
		t.Fatalf("Refresh: %v", err)
	}
	seedTwin(t, d, "s1")
	if n := count(t, d, `SELECT COUNT(*) FROM spend_verdict_dirty WHERE session_id = 's1'`); n != 1 {
		t.Fatalf("dirty = %d, want 1 (triggers queue the session)", n)
	}
	n, err := Refresh(ctx, d, Options{})
	if err != nil || n != 1 {
		t.Fatalf("Refresh = %d, %v; want 1, nil", n, err)
	}
	if p, _ := Pending(ctx, d); p != 0 {
		t.Fatalf("pending = %d after Refresh, want 0", p)
	}
	if n := count(t, d, `SELECT COUNT(*) FROM spend_verdict_token WHERE session_id = 's1' AND shadow = 0`); n != 1 {
		t.Fatalf("token verdicts = %d, want the twin (1)", n)
	}
	var out, reasoning, counted int
	if err := d.QueryRowContext(ctx, `SELECT output_tokens, reasoning_tokens, counted FROM spend_verdict_proxy WHERE session_id = 's1'`).
		Scan(&out, &reasoning, &counted); err != nil {
		t.Fatalf("proxy verdict: %v", err)
	}
	if out != 20 || reasoning != 10 || counted != 1 {
		t.Fatalf("proxy verdict = out %d reasoning %d counted %d, want 20/10/1", out, reasoning, counted)
	}
	if rev := count(t, d, `SELECT rev FROM spend_verdict_state`); rev < 1 {
		t.Fatalf("rev = %d, want bumped", rev)
	}
}

// TestRefresh_UpsertOnQueuedSessionDoesNotAbort pins the trigger shape: an
// UPSERT on a session already queued must not fail on the queue's primary key
// (SQLite overrides a trigger's OR IGNORE with the firing statement's
// conflict clause, which is why the triggers use WHERE NOT EXISTS).
func TestRefresh_UpsertOnQueuedSessionDoesNotAbort(t *testing.T) {
	d := openTestDB(t)
	seedTwin(t, d, "s1")
	mustExec(t, d, `INSERT INTO sessions (id, project_id, tool, model, started_at)
		VALUES ('s1', 1, 'claude-code', 'claude-y', '2026-09-01T10:00:00Z')
		ON CONFLICT (id) DO UPDATE SET model = excluded.model`)
	if n := count(t, d, `SELECT COUNT(*) FROM spend_verdict_dirty WHERE session_id = 's1'`); n != 1 {
		t.Fatalf("dirty = %d, want 1", n)
	}
}

// TestRefresh_RuleVersionBackfill: stored verdicts older than RuleVersion are
// recomputed - every candidate session is queued once, then drained.
func TestRefresh_RuleVersionBackfill(t *testing.T) {
	ctx := context.Background()
	d := openTestDB(t)
	seedTwin(t, d, "s1")
	seedTwin(t, d, "s2")
	if _, err := Refresh(ctx, d, Options{}); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	// Simulate verdicts written by an older rule, with the queue drained.
	mustExec(t, d, `DELETE FROM spend_verdict_token`)
	mustExec(t, d, `DELETE FROM spend_verdict_proxy`)
	mustExec(t, d, `UPDATE spend_verdict_state SET rule_version = ?`, RuleVersion-1)
	n, err := Refresh(ctx, d, Options{})
	if err != nil || n != 2 {
		t.Fatalf("Refresh = %d, %v; want both sessions re-derived", n, err)
	}
	if v := count(t, d, `SELECT rule_version FROM spend_verdict_state`); v != RuleVersion {
		t.Fatalf("rule_version = %d, want %d", v, RuleVersion)
	}
	if n := count(t, d, `SELECT COUNT(*) FROM spend_verdict_token`); n != 2 {
		t.Fatalf("token verdicts = %d, want 2", n)
	}
	// Idempotent once current.
	if n, err := Refresh(ctx, d, Options{}); err != nil || n != 0 {
		t.Fatalf("second Refresh = %d, %v; want 0, nil", n, err)
	}
}

// TestRefresh_MovedRowReStamped: a token row the node moves to another session
// re-queues BOTH sessions; after Refresh the old session holds no verdict for
// it and the new session's derivation decides it afresh (here: it is the new
// session's only row, so it counts).
func TestRefresh_MovedRowReStamped(t *testing.T) {
	ctx := context.Background()
	d := openTestDB(t)
	seedTwin(t, d, "s1")
	mustExec(t, d, `INSERT INTO sessions (id, project_id, tool, model, started_at)
		VALUES ('s2', 1, 'claude-code', 'claude-x', '2026-09-01T11:00:00Z')`)
	if _, err := Refresh(ctx, d, Options{}); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if n := count(t, d, `SELECT COUNT(*) FROM spend_verdict_token`); n != 1 {
		t.Fatalf("token verdicts before the move = %d, want 1", n)
	}
	mustExec(t, d, `UPDATE token_usage SET session_id = 's2' WHERE session_id = 's1'`)
	if n := count(t, d, `SELECT COUNT(*) FROM spend_verdict_dirty`); n != 2 {
		t.Fatalf("dirty after the move = %d, want both sessions", n)
	}
	if _, err := Refresh(ctx, d, Options{}); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if n := count(t, d, `SELECT COUNT(*) FROM spend_verdict_token`); n != 0 {
		t.Fatalf("token verdicts after the move = %d, want 0 (the row now counts in s2)", n)
	}
	if n := count(t, d, `SELECT COUNT(*) FROM spend_verdict_proxy WHERE session_id = 's1'`); n != 0 {
		t.Fatalf("s1's proxy row keeps a twin verdict after its twin moved away")
	}
}

// TestRefresh_MissingTablesIsANoOp: a schema without the verdict tables (an
// older binary's database) is not an error.
func TestRefresh_MissingTablesIsANoOp(t *testing.T) {
	d, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "bare.db"))
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer d.Close()
	if n, err := Refresh(context.Background(), d, Options{}); err != nil || n != 0 {
		t.Fatalf("Refresh = %d, %v; want 0, nil", n, err)
	}
}

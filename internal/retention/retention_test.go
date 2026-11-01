package retention

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"

	"github.com/marmutapp/superbased-observer/internal/compression/indexing"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// fakeNow lets tests anchor "now" so age cutoffs are deterministic.
var fakeNow = time.Date(2026, 4, 16, 12, 0, 0, 0, time.UTC)

func init() {
	nowUTC = func() time.Time { return fakeNow }
}

// seed builds a db with a few sessions of varying ages and returns it,
// the path, and the store for additional inserts.
func seed(t *testing.T) (string, *store.Store) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "obs.db")
	d, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	st := store.New(d)

	// 3 sessions at -200d, -90d, -10d.
	ages := []time.Duration{-200 * 24 * time.Hour, -90 * 24 * time.Hour, -10 * 24 * time.Hour}
	idx := indexing.New(d, 0)
	for i, age := range ages {
		ts := fakeNow.Add(age)
		ev := models.ToolEvent{
			SourceFile: "f", SourceEventID: makeID(i),
			SessionID:   "sess-" + makeID(i),
			ProjectRoot: "/repo",
			Timestamp:   ts,
			Tool:        models.ToolClaudeCode,
			ActionType:  models.ActionRunCommand,
			Target:      "go test",
			Success:     i == 1, // mid-age succeeds, others fail
			ErrorMessage: func() string {
				if i == 1 {
					return ""
				}
				return "FAIL"
			}(),
			ToolOutput: "PASS some test output content",
		}
		if _, err := st.Ingest(context.Background(), []models.ToolEvent{ev}, nil, store.IngestOptions{
			RecordFailures: true,
			Indexer:        idx,
		}); err != nil {
			t.Fatalf("Ingest %d: %v", i, err)
		}
	}
	return dbPath, st
}

func makeID(i int) string {
	return string(rune('a' + i))
}

func TestRun_AgePruning(t *testing.T) {
	dbPath, st := seed(t)

	// Cap MaxAgeDays at 100 → only the -200d action gets pruned.
	d := openExisting(t, dbPath)
	p := New(d)
	res, err := p.Run(context.Background(), Options{
		MaxAgeDays: 100,
		DBPath:     dbPath,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ActionsDeleted != 1 {
		t.Errorf("actions deleted: %d (want 1)", res.ActionsDeleted)
	}
	if res.OrphanedSessionsDeleted != 1 {
		t.Errorf("orphaned sessions deleted: %d (want 1)", res.OrphanedSessionsDeleted)
	}
	if res.ExcerptsDeleted != 1 {
		t.Errorf("excerpts deleted: %d (want 1)", res.ExcerptsDeleted)
	}
	if res.FailureContextDeleted != 1 {
		t.Errorf("failure_context deleted: %d (want 1 — the -200d failure)", res.FailureContextDeleted)
	}
	// Verify remaining counts.
	n, _ := st.CountActions(context.Background())
	if n != 2 {
		t.Errorf("remaining actions: %d (want 2)", n)
	}
}

func TestRun_NoAgeCapKeepsEverything(t *testing.T) {
	dbPath, _ := seed(t)
	d := openExisting(t, dbPath)
	p := New(d)
	res, err := p.Run(context.Background(), Options{
		MaxAgeDays: 0, // disabled
		DBPath:     dbPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.ActionsDeleted != 0 {
		t.Errorf("expected 0 actions deleted with disabled age cap: %d", res.ActionsDeleted)
	}
}

func TestRun_FileStateAge(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "obs.db")
	d, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	// Insert a project and an old + recent file_state row directly so we
	// don't need to drive the freshness pipeline.
	_, _ = d.ExecContext(context.Background(),
		`INSERT INTO projects (root_path, created_at) VALUES ('/r', ?)`,
		fakeNow.Format(time.RFC3339Nano))
	var pid int64
	_ = d.QueryRowContext(context.Background(), `SELECT id FROM projects WHERE root_path='/r'`).Scan(&pid)

	stale := fakeNow.AddDate(0, 0, -45).Format(time.RFC3339Nano)
	recent := fakeNow.AddDate(0, 0, -5).Format(time.RFC3339Nano)
	_, _ = d.ExecContext(context.Background(),
		`INSERT INTO file_state (project_id, file_path, content_hash, file_mtime, file_size_bytes, last_action_type, last_seen_at)
		 VALUES (?, 'a.go', 'h', ?, 0, 'read_file', ?)`, pid, stale, stale)
	_, _ = d.ExecContext(context.Background(),
		`INSERT INTO file_state (project_id, file_path, content_hash, file_mtime, file_size_bytes, last_action_type, last_seen_at)
		 VALUES (?, 'b.go', 'h', ?, 0, 'read_file', ?)`, pid, recent, recent)

	p := New(d)
	res, err := p.Run(context.Background(), Options{DBPath: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	if res.FileStateDeleted != 1 {
		t.Errorf("file_state deleted: %d (want 1 — the 45-day-old row)", res.FileStateDeleted)
	}
}

func TestRun_ObserverLogPruning(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "obs.db")
	d, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	old := fakeNow.AddDate(0, 0, -45).Format(time.RFC3339Nano)
	young := fakeNow.AddDate(0, 0, -5).Format(time.RFC3339Nano)
	_, _ = d.ExecContext(context.Background(),
		`INSERT INTO observer_log (timestamp, level, component, message) VALUES (?, 'info', 'x', 'old')`, old)
	_, _ = d.ExecContext(context.Background(),
		`INSERT INTO observer_log (timestamp, level, component, message) VALUES (?, 'info', 'x', 'young')`, young)

	p := New(d)
	res, err := p.Run(context.Background(), Options{
		ObserverLogMaxAgeDays: 30,
		DBPath:                dbPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.LogEntriesDeleted != 1 {
		t.Errorf("log entries deleted: %d (want 1)", res.LogEntriesDeleted)
	}
}

func TestRun_NilDBErrors(t *testing.T) {
	p := New(nil)
	if _, err := p.Run(context.Background(), Options{}); err == nil {
		t.Error("expected error for nil DB")
	}
}

func TestRun_FileStateLastActionIDNulledWhenActionDeleted(t *testing.T) {
	dbPath, _ := seed(t)
	d := openExisting(t, dbPath)
	p := New(d)

	if _, err := p.Run(context.Background(), Options{
		MaxAgeDays: 100,
		DBPath:     dbPath,
	}); err != nil {
		t.Fatal(err)
	}
	// All file_state rows should now have last_action_id NULL or pointing
	// to actions that still exist.
	var orphaned int
	if err := d.QueryRowContext(
		context.Background(),
		`SELECT COUNT(*) FROM file_state fs
		 WHERE fs.last_action_id IS NOT NULL
		   AND fs.last_action_id NOT IN (SELECT id FROM actions)`,
	).Scan(&orphaned); err != nil {
		t.Fatal(err)
	}
	if orphaned != 0 {
		t.Errorf("found %d file_state rows with dangling last_action_id", orphaned)
	}
}

// TestRun_OrphanedSessions_TokenUsageReferencePreserved guards a real
// foreign-key bug from the live install: sessions whose actions had all
// aged out but whose token_usage rows still existed (subagent compaction
// turns emit usage with no tool_use blocks — see PROGRESS.md decision log
// 2026-04-16) tripped the FK constraint when the orphan predicate looked
// only at the actions table. The pruner must keep those sessions.
func TestRun_OrphanedSessions_TokenUsageReferencePreserved(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "obs.db")
	d, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	st := store.New(d)

	// Seed one session that has only token_usage (no actions).
	tokenOnly := models.TokenEvent{
		SourceFile:    "j",
		SourceEventID: "tok-1",
		SessionID:     "sess-tokens-only",
		ProjectRoot:   "/repo",
		Timestamp:     fakeNow.Add(-5 * 24 * time.Hour),
		Tool:          models.ToolClaudeCode,
		Model:         "claude-sonnet-4-5",
		InputTokens:   1000,
		OutputTokens:  200,
		Source:        models.TokenSourceJSONL,
		Reliability:   models.ReliabilityApproximate,
	}
	if _, err := st.Ingest(context.Background(), nil, []models.TokenEvent{tokenOnly}, store.IngestOptions{}); err != nil {
		t.Fatalf("Ingest tokens-only: %v", err)
	}
	// Sanity: session row landed.
	var n int
	if err := d.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM sessions WHERE id = 'sess-tokens-only'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("setup: expected 1 sess-tokens-only row, got %d", n)
	}

	// Run retention. The orphan predicate must not touch the session
	// because token_usage still references it.
	p := New(d)
	res, err := p.Run(context.Background(), Options{
		MaxAgeDays: 365, // doesn't apply to this 5-day-old data
		DBPath:     dbPath,
	})
	if err != nil {
		t.Fatalf("Run: %v (FK probably tripped — orphan predicate too narrow)", err)
	}
	if res.OrphanedSessionsDeleted != 0 {
		t.Errorf("OrphanedSessionsDeleted: %d (want 0 — session has token_usage)", res.OrphanedSessionsDeleted)
	}
	if err := d.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM sessions WHERE id = 'sess-tokens-only'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("session was deleted despite token_usage reference (count=%d)", n)
	}
}

// TestRun_ChildActionRefsNulledNotBlocked guards the FK-787 regression from
// the live install (2026-06-18): later migrations added more nullable
// action_id FKs to actions with no ON DELETE CASCADE — retrieval_signals
// (014), guard_events (040), process_runs + process_events (044). The
// pruner cleaned only action_excerpts / failure_context / file_state, so a
// surviving reference in any of the newer tables tripped "FOREIGN KEY
// constraint failed (787)" and aborted the whole DELETE, leaving actions
// un-pruned. deleteActionsOlder must null those refs first; the rows
// themselves must survive (audit chain / K43 long tail / process-obs own
// retention horizon).
func TestRun_ChildActionRefsNulledNotBlocked(t *testing.T) {
	dbPath, _ := seed(t)
	d := openExisting(t, dbPath)
	ctx := context.Background()

	// The -200d action belongs to session "sess-a"; it ages out at
	// MaxAgeDays=100 (fakeNow - 100d).
	var aid int64
	if err := d.QueryRowContext(ctx,
		`SELECT id FROM actions WHERE session_id='sess-a'`).Scan(&aid); err != nil {
		t.Fatalf("find old action: %v", err)
	}

	now := fakeNow.Format(time.RFC3339Nano)
	mustExec := func(q string, args ...any) {
		t.Helper()
		if _, err := d.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("seed child row: %v\n%s", err, q)
		}
	}
	// One referencing row in each of the four previously-uncleaned tables.
	mustExec(`INSERT INTO retrieval_signals (action_id, signal_type, signal_at) VALUES (?, 'search_hit', ?)`, aid, now)
	mustExec(`INSERT INTO guard_events (ts, action_id, rule_id, enforced, chain_prev, chain_hash) VALUES (?, ?, 'R-1', 0, '', 'h')`, now, aid)
	mustExec(`INSERT INTO process_runs (process_key, pid, action_id, attribution_source, attribution_confidence, started_at, last_seen_at)
	          VALUES ('pk-1', 123, ?, 'env_token', 'high', ?, ?)`, aid, now, now)
	mustExec(`INSERT INTO process_events (process_key, timestamp, event_type, action_id) VALUES ('pk-1', ?, 'exec', ?)`, now, aid)

	// Prune the -200d action. Before the fix this returned the 787 error.
	p := New(d)
	if _, err := p.Run(ctx, Options{MaxAgeDays: 100, DBPath: dbPath}); err != nil {
		t.Fatalf("Run tripped the FK-787 regression: %v", err)
	}

	// The action is pruned; each child row survives with action_id nulled.
	var n int
	if err := d.QueryRowContext(ctx, `SELECT COUNT(*) FROM actions WHERE id=?`, aid).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("old action not pruned (count=%d)", n)
	}
	for _, c := range []struct{ name, rowsQ, dangQ string }{
		{"retrieval_signals", `SELECT COUNT(*) FROM retrieval_signals`, `SELECT COUNT(*) FROM retrieval_signals WHERE action_id IS NOT NULL`},
		{"guard_events", `SELECT COUNT(*) FROM guard_events`, `SELECT COUNT(*) FROM guard_events WHERE action_id IS NOT NULL`},
		{"process_runs", `SELECT COUNT(*) FROM process_runs`, `SELECT COUNT(*) FROM process_runs WHERE action_id IS NOT NULL`},
		{"process_events", `SELECT COUNT(*) FROM process_events`, `SELECT COUNT(*) FROM process_events WHERE action_id IS NOT NULL`},
	} {
		var rows, dangling int
		if err := d.QueryRowContext(ctx, c.rowsQ).Scan(&rows); err != nil {
			t.Fatal(err)
		}
		if err := d.QueryRowContext(ctx, c.dangQ).Scan(&dangling); err != nil {
			t.Fatal(err)
		}
		if rows != 1 {
			t.Errorf("%s: row count=%d (want 1 — row preserved, not deleted)", c.name, rows)
		}
		if dangling != 0 {
			t.Errorf("%s: %d rows still reference the pruned action (want 0 — nulled)", c.name, dangling)
		}
	}
}

// TestRun_GuardChainSurvivesActionPrune pins GUARD-CHAIN-1 end to end:
// pruning an action that carries a guard flag nulls the flag's action_id
// (the FK) and the guard audit chain still verifies, because the chain
// hashes the action_anchor column, which retention never touches.
func TestRun_GuardChainSurvivesActionPrune(t *testing.T) {
	dbPath, st := seed(t)
	d := openExisting(t, dbPath)
	ctx := context.Background()

	var old, fresh int64
	if err := d.QueryRowContext(ctx, `SELECT id FROM actions WHERE session_id='sess-a'`).Scan(&old); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRowContext(ctx, `SELECT id FROM actions WHERE session_id='sess-c'`).Scan(&fresh); err != nil {
		t.Fatal(err)
	}
	flag := func(action int64, rule string, ts time.Time) store.GuardEventRow {
		return store.GuardEventRow{
			TS: ts, SessionID: "sess-a", ActionID: &action, Tool: models.ToolClaudeCode,
			EventKind: "shell_exec", RuleID: rule, Decision: "flag", TargetHash: "h",
		}
	}
	if _, err := st.InsertGuardEvents(ctx, []store.GuardEventRow{
		flag(old, "R-101", fakeNow.Add(-time.Hour)),
		flag(fresh, "R-110", fakeNow.Add(-time.Minute)),
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := New(d).Run(ctx, Options{MaxAgeDays: 100, DBPath: dbPath}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	var actionID, anchor sql.NullInt64
	if err := d.QueryRowContext(ctx,
		`SELECT action_id, action_anchor FROM guard_events WHERE rule_id = 'R-101'`).Scan(&actionID, &anchor); err != nil {
		t.Fatal(err)
	}
	if actionID.Valid || anchor.Int64 != old {
		t.Fatalf("pruned flag action_id=%v action_anchor=%v, want NULL and %d", actionID, anchor, old)
	}
	report, err := store.New(d).VerifyGuardChain(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !report.OK || report.Checked != 2 {
		t.Fatalf("VerifyGuardChain after the action prune = %+v, want OK across 2 rows", report)
	}
}

// openExisting reopens a DB at path so we can re-create the *sql.DB after
// the seed test cleanup. Avoids leaking handles between subtests.
func openExisting(t *testing.T, path string) *sql.DB {
	t.Helper()
	d, err := dbtemplate.Open(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

// TestShrinkToCap_FloorProtectsRecentActions pins the size-cap floor fix:
// when the DB is over max_db_size_mb because the BULK is in a non-actions
// table (token_usage), the size loop must NOT delete recent actions
// (within sizeCapActionFloorDays) chasing an unreachable cap — it stops
// and sets SizeCapUnmet instead. Pre-fix it deleted the whole actions
// table (operator's 68K→90 incident).
func TestShrinkToCap_FloorProtectsRecentActions(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "big.db")
	d, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer d.Close()
	ctx := context.Background()

	var projectID int64
	if err := d.QueryRowContext(ctx,
		`INSERT INTO projects (root_path, created_at) VALUES ('/r', '2026-01-01T00:00:00Z') RETURNING id`).
		Scan(&projectID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ExecContext(ctx,
		`INSERT INTO sessions (id, tool, project_id, started_at) VALUES ('s1','claude-code',?,?)`,
		projectID, fakeNow.Add(-5*24*time.Hour).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	// A few RECENT actions (within the 30-day floor relative to fakeNow).
	recentTS := fakeNow.Add(-5 * 24 * time.Hour).Format(time.RFC3339Nano)
	for i := 0; i < 5; i++ {
		if _, err := d.ExecContext(ctx,
			`INSERT INTO actions (session_id, project_id, timestamp, action_type, tool, source_file, source_event_id)
			 VALUES ('s1',?,?,'run_command','claude-code','f',?)`,
			projectID, recentTS, makeID(i)); err != nil {
			t.Fatal(err)
		}
	}
	// Inflate token_usage (the non-actions bulk) past a 1MB cap.
	pad := make([]byte, 1200)
	for i := range pad {
		pad[i] = 'x'
	}
	padStr := string(pad)
	for i := 0; i < 1500; i++ {
		if _, err := d.ExecContext(ctx,
			`INSERT INTO token_usage (session_id, timestamp, tool, source, source_file) VALUES ('s1',?, 'claude-code','jsonl',?)`,
			recentTS, padStr); err != nil {
			t.Fatal(err)
		}
	}
	_, _ = d.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`)
	_, _ = d.ExecContext(ctx, `VACUUM`)

	p := New(d)
	res, err := p.Run(ctx, Options{MaxDBSizeMB: 1, DBPath: dbPath})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Recent actions must survive (floor protected them).
	var n int
	if err := d.QueryRowContext(ctx, `SELECT COUNT(*) FROM actions`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Errorf("recent actions = %d, want 5 (floor must protect them); pre-fix this was 0", n)
	}
	if !res.SizeCapUnmet {
		t.Errorf("SizeCapUnmet should be set when the bulk is non-actions and cap is unreachable")
	}
}

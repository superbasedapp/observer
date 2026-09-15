package store

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// seedPushData inserts one project, one session, two actions, one api_turn,
// and one token_usage row, returning the project id.
func seedPushData(t *testing.T, s *Store, db *sql.DB) int64 {
	t.Helper()
	ctx := context.Background()
	pid, err := s.UpsertProject(ctx, "/tmp/proj", "git@example.com:acme/app.git")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	if err := s.UpsertSession(ctx, models.Session{
		ID: "s1", ProjectID: pid, Tool: models.ToolClaudeCode, Model: "claude",
		StartedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("UpsertSession: %v", err)
	}
	if _, err := s.InsertActions(ctx, []models.Action{
		{
			SessionID: "s1", ProjectID: pid, Timestamp: time.Now().UTC(),
			ActionType: models.ActionReadFile, Target: "a.go", Success: true,
			Tool: models.ToolClaudeCode, SourceFile: "f.jsonl", SourceEventID: "e1",
		},
		{
			SessionID: "s1", ProjectID: pid, Timestamp: time.Now().UTC(),
			ActionType: models.ActionRunCommand, Target: "go test", Success: false,
			Tool: models.ToolClaudeCode, SourceFile: "f.jsonl", SourceEventID: "e2",
		},
	}); err != nil {
		t.Fatalf("InsertActions: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO api_turns(session_id, project_id, timestamp, provider, model, request_id,
		    input_tokens, output_tokens) VALUES('s1', ?, ?, 'anthropic', 'claude', 'req1', 100, 50)`,
		pid, time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("insert api_turn: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO token_usage(session_id, timestamp, tool, model, input_tokens, output_tokens,
		    source, source_file, source_event_id) VALUES('s1', ?, 'claude-code', 'claude', 100, 50,
		    'proxy', 'f.jsonl', 'tu1')`,
		time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("insert token_usage: %v", err)
	}
	return pid
}

func TestSelectUnpushedSince_MapsAndStamps(t *testing.T) {
	s, db := newTestStore(t)
	seedPushData(t, s, db)
	ctx := context.Background()

	batch, err := s.SelectUnpushedSince(ctx, PushCursor{}, 1<<20, "org-1", "dev@acme.example", ShareOptions{FullContent: true}, ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince: %v", err)
	}
	if got := batch.RowCount(); got != 5 { // 1 session + 2 actions + 1 turn + 1 token
		t.Fatalf("RowCount = %d, want 5", got)
	}
	// Every row stamped with the enrolled identity.
	for _, r := range batch.Sessions {
		if r.OrgID != "org-1" || r.UserEmail != "dev@acme.example" {
			t.Fatalf("session not stamped: %+v", r)
		}
	}
	// Session mapping carries project root + git remote.
	if batch.Sessions[0].ProjectRoot != "/tmp/proj" || batch.Sessions[0].GitRemote != "git@example.com:acme/app.git" {
		t.Fatalf("session project mapping wrong: %+v", batch.Sessions[0])
	}
	// Action success/sidechain bool mapping.
	if !batch.Actions[0].Success || batch.Actions[1].Success {
		t.Fatalf("action success mapping wrong: %+v", batch.Actions)
	}
	if batch.Actions[0].SourceFile != "f.jsonl" || batch.Actions[0].SourceEventID != "e1" {
		t.Fatalf("action dedup key not mapped: %+v", batch.Actions[0])
	}
	// api_turn + token_usage project_root via join.
	if batch.APITurns[0].ProjectRoot != "/tmp/proj" || batch.APITurns[0].RequestID != "req1" {
		t.Fatalf("api_turn mapping wrong: %+v", batch.APITurns[0])
	}
	if batch.TokenUsage[0].ProjectRoot != "/tmp/proj" || batch.TokenUsage[0].SourceEventID != "tu1" {
		t.Fatalf("token_usage mapping wrong: %+v", batch.TokenUsage[0])
	}
}

func TestSelectUnpushedSince_CursorAdvances(t *testing.T) {
	s, db := newTestStore(t)
	seedPushData(t, s, db)
	ctx := context.Background()

	first, err := s.SelectUnpushedSince(ctx, PushCursor{}, 1<<20, "o", "u", ShareOptions{FullContent: true}, ScopeOptions{})
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	if first.Empty() {
		t.Fatal("first batch empty")
	}
	// Re-reading from the returned cursor yields no new ROW-LEVEL data. The
	// windowed-recompute aggregates (and, under shipsRawContent, the
	// session-scoped enterprise wires — here the seeded run_command's
	// command-bytes verbosity row) legitimately ride every push and are
	// server-upsert-idempotent, so they are deliberately NOT part of this
	// cursor assertion (they never gate cursor progress).
	second, err := s.SelectUnpushedSince(ctx, first.Cursor, 1<<20, "o", "u", ShareOptions{FullContent: true}, ScopeOptions{})
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if got := second.RowCount(); got != 0 {
		t.Fatalf("second batch row count = %d, want 0 (cursor did not advance)", got)
	}
	if second.Cursor != first.Cursor {
		t.Fatalf("cursor moved on an empty re-read: %+v -> %+v", first.Cursor, second.Cursor)
	}
}

func TestSelectUnpushedSince_BudgetForwardProgress(t *testing.T) {
	s, db := newTestStore(t)
	seedPushData(t, s, db)
	ctx := context.Background()

	// maxBytes=1 forces the budget guard immediately; the first row must
	// still be included (forward progress) and nothing beyond it.
	batch, err := s.SelectUnpushedSince(ctx, PushCursor{}, 1, "o", "u", ShareOptions{FullContent: true}, ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince: %v", err)
	}
	if batch.RowCount() != 1 {
		t.Fatalf("budget=1 RowCount = %d, want exactly 1", batch.RowCount())
	}
	if len(batch.Sessions) != 1 {
		t.Fatalf("expected the single row to be the first session, got %+v", batch)
	}
}

func TestSelectUnpushedSince_ScopeAllowlistFiltersByRoot(t *testing.T) {
	s, db := newTestStore(t)
	seedPushData(t, s, db) // seeds project "/tmp/proj"
	ctx := context.Background()

	// Allowlist contains a non-existent root → no project IDs match →
	// SelectUnpushedSince returns an empty batch.
	batch, err := s.SelectUnpushedSince(ctx, PushCursor{}, 1<<20, "o", "u",
		ShareOptions{FullContent: true},
		ScopeOptions{ProjectRootAllowlist: []string{"/no/such/project"}})
	if err != nil {
		t.Fatalf("SelectUnpushedSince scoped (no match): %v", err)
	}
	if !batch.Empty() {
		t.Fatalf("expected empty batch when allowlist has no DB match, got %d rows", batch.RowCount())
	}

	// Allowlist with the actual root → existing rows ship as before.
	batch, err = s.SelectUnpushedSince(ctx, PushCursor{}, 1<<20, "o", "u",
		ShareOptions{FullContent: true},
		ScopeOptions{ProjectRootAllowlist: []string{"/tmp/proj"}})
	if err != nil {
		t.Fatalf("SelectUnpushedSince scoped (match): %v", err)
	}
	if batch.RowCount() != 5 {
		t.Fatalf("expected 5 rows when allowlist matches /tmp/proj, got %d", batch.RowCount())
	}
}

func TestSelectUnpushedSince_ScopeDenylistStripsRoot(t *testing.T) {
	s, db := newTestStore(t)
	seedPushData(t, s, db)
	ctx := context.Background()

	// Denylisting the only seeded project → empty batch.
	batch, err := s.SelectUnpushedSince(ctx, PushCursor{}, 1<<20, "o", "u",
		ShareOptions{FullContent: true},
		ScopeOptions{ProjectRootDenylist: []string{"/tmp/proj"}})
	if err != nil {
		t.Fatalf("SelectUnpushedSince denylist: %v", err)
	}
	if !batch.Empty() {
		t.Fatalf("expected empty batch when denylist covers the only project, got %d rows", batch.RowCount())
	}
}

func TestPushCursor_RoundTripAndMaxIDs(t *testing.T) {
	s, db := newTestStore(t)
	seedPushData(t, s, db)
	ctx := context.Background()

	// Default (never pushed) reads as zero.
	c0, err := s.LoadPushCursor(ctx)
	if err != nil || (c0 != PushCursor{}) {
		t.Fatalf("LoadPushCursor default = %+v, %v; want zero", c0, err)
	}
	// CurrentMaxIDs reflects seeded rows.
	mx, err := s.CurrentMaxIDs(ctx)
	if err != nil {
		t.Fatalf("CurrentMaxIDs: %v", err)
	}
	if mx.Actions != 2 || mx.APITurns != 1 || mx.TokenUsage != 1 || mx.Sessions < 1 {
		t.Fatalf("CurrentMaxIDs = %+v", mx)
	}
	// Round-trip persistence.
	if err := s.SavePushCursor(ctx, mx); err != nil {
		t.Fatalf("SavePushCursor: %v", err)
	}
	got, err := s.LoadPushCursor(ctx)
	if err != nil {
		t.Fatalf("LoadPushCursor: %v", err)
	}
	if got != mx {
		t.Fatalf("LoadPushCursor = %+v, want %+v", got, mx)
	}
}

func TestRecordPush_AndLastPushLog(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	if last, err := s.LastPushLog(ctx); err != nil || last != nil {
		t.Fatalf("LastPushLog (none) = %+v, %v; want nil, nil", last, err)
	}
	if err := s.RecordPush(ctx, 10, 2048, "ok", ""); err != nil {
		t.Fatalf("RecordPush ok: %v", err)
	}
	if err := s.RecordPush(ctx, 0, 0, "failed", "boom"); err != nil {
		t.Fatalf("RecordPush failed: %v", err)
	}
	last, err := s.LastPushLog(ctx)
	if err != nil {
		t.Fatalf("LastPushLog: %v", err)
	}
	if last == nil || last.Status != "failed" || last.Error != "boom" {
		t.Fatalf("LastPushLog = %+v, want failed/boom", last)
	}
}

// TestPushBreaker_RoundTripAndExpiry pins the persisted oversized-batch circuit
// (Task 7 H2). It exists because the daemon that OPENS the circuit is a
// different process from the dashboard / `observer org push-status` that must
// report it: in-memory state would leave a parked push loop invisible.
func TestPushBreaker_RoundTripAndExpiry(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	// No record → not paused.
	got, err := s.LoadPushBreaker(ctx)
	if err != nil || got != nil {
		t.Fatalf("LoadPushBreaker on a fresh store = %+v, %v; want nil, nil", got, err)
	}

	until := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	if err := s.OpenPushBreaker(ctx, until, "serialized_bytes=250000000 limit_bytes=1048576"); err != nil {
		t.Fatalf("OpenPushBreaker: %v", err)
	}
	got, err = s.LoadPushBreaker(ctx)
	if err != nil {
		t.Fatalf("LoadPushBreaker: %v", err)
	}
	if got == nil {
		t.Fatal("open circuit reads back as nil — the pause would be invisible to the dashboard")
	}
	if !got.Until.Equal(until) {
		t.Errorf("Until = %v, want %v", got.Until, until)
	}
	if !strings.Contains(got.Reason, "limit_bytes=1048576") {
		t.Errorf("Reason = %q, want the serialized-vs-limit diagnostic", got.Reason)
	}

	// An ELAPSED park reads as closed: the retry is imminent, so reporting it
	// as still-paused would be dishonest.
	if err := s.OpenPushBreaker(ctx, time.Now().UTC().Add(-time.Minute), "old"); err != nil {
		t.Fatalf("OpenPushBreaker (elapsed): %v", err)
	}
	got, err = s.LoadPushBreaker(ctx)
	if err != nil || got != nil {
		t.Fatalf("elapsed circuit = %+v, %v; want nil, nil", got, err)
	}

	// Clear is idempotent and really clears.
	if err := s.OpenPushBreaker(ctx, until, "again"); err != nil {
		t.Fatalf("OpenPushBreaker (again): %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := s.ClearPushBreaker(ctx); err != nil {
			t.Fatalf("ClearPushBreaker[%d]: %v", i, err)
		}
	}
	if got, err := s.LoadPushBreaker(ctx); err != nil || got != nil {
		t.Fatalf("after clear = %+v, %v; want nil, nil", got, err)
	}
}

// TestClearLastPushStateClearsPushBreaker pins that a re-enrol does not carry a
// stale pause banner from the previous enrolment.
func TestClearLastPushStateClearsPushBreaker(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	if err := s.OpenPushBreaker(ctx, time.Now().UTC().Add(time.Hour), "too large"); err != nil {
		t.Fatalf("OpenPushBreaker: %v", err)
	}
	if err := s.ClearLastPushState(ctx); err != nil {
		t.Fatalf("ClearLastPushState: %v", err)
	}
	if got, err := s.LoadPushBreaker(ctx); err != nil || got != nil {
		t.Fatalf("push breaker survived a re-enrol reset: %+v, %v", got, err)
	}
}

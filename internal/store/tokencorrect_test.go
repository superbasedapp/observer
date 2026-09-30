package store

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestCorrectTokenEvents pins the correcting path a fixed adapter needs
// because InsertTokenEvents' upsert is MAX-monotone: the live Crush case
// (session 30bc155f) stored a multi-step session's last-step snapshot
// 8975/5 before the parser learned those counters are not billed tokens;
// the fixed parse emits 0/0 + Crush's own $0.0863, and only this seam
// can lower the stored row. It also pins the org-propagation contract:
// an update re-queues the row (migration 140), a removal records a
// correction tombstone (migration 141, no retention marker), and a
// second run changes and queues nothing. A zero-cost ONE-step row the
// fixed parser still emits with its real counts is left alone.
func TestCorrectTokenEvents(t *testing.T) {
	ctx := context.Background()
	s, database := newTestStore(t)
	pid, err := s.UpsertProject(ctx, "/repo/crushy", "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	for _, id := range []string{"ses_multi", "ses_flatmulti", "ses_flat", "ses_ok", "ses_gone"} {
		if err := s.UpsertSession(ctx, models.Session{ID: id, ProjectID: pid, Tool: models.ToolCrush, StartedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	const src = "/repo/crushy/.crush/crush.db"
	stale := func(sess string, in, out int64, cost float64) models.TokenEvent {
		return models.TokenEvent{
			SourceFile: src, SourceEventID: "tokens:" + sess, SessionID: sess,
			Tool: models.ToolCrush, Model: "gpt-5.4-mini", Timestamp: now,
			InputTokens: in, OutputTokens: out, EstimatedCostUSD: cost,
			Source: models.TokenSourceJSONL, Reliability: models.ReliabilityApproximate,
		}
	}
	if _, err := s.InsertTokenEvents(ctx, []models.TokenEvent{
		stale("ses_multi", 8975, 5, 0.0863), // multi-step snapshot, pre-fix
		stale("ses_flatmulti", 9500, 30, 0), // zero-cost multi-step snapshot, pre-fix
		stale("ses_flat", 9120, 40, 0),      // zero-cost one-step: real counts
		stale("ses_ok", 21749, 5, 0.0544),   // already correct
		stale("ses_gone", 500, 10, 0.001),   // session the tool deleted
		// A row from another source file: never in scope.
		{
			SourceFile: "/other/crush.db", SourceEventID: "tokens:ses_multi", SessionID: "ses_multi",
			Tool: models.ToolCrush, Timestamp: now, InputTokens: 7, OutputTokens: 7,
		},
	}); err != nil {
		t.Fatal(err)
	}
	// Enrolled node: floors at 0 so every row above is "shipped".
	if _, err := database.Exec(`INSERT INTO schema_meta (key, value) VALUES ('org_push_floor_token_usage', '0')`); err != nil {
		t.Fatal(err)
	}

	// The fixed parse: ses_multi now 0/0 + cost; ses_flatmulti (no tokens,
	// no cost) emits nothing; ses_flat keeps its real counts; ses_ok is
	// unchanged. ses_gone is NOT observed (the tool deleted it).
	fresh := []models.TokenEvent{
		stale("ses_multi", 0, 0, 0.0863), stale("ses_flat", 9120, 40, 0), stale("ses_ok", 21749, 5, 0.0544),
	}
	observed := []string{"ses_multi", "ses_flatmulti", "ses_flat", "ses_ok"}

	got, err := s.CorrectTokenEvents(ctx, models.ToolCrush, src, observed, fresh)
	if err != nil {
		t.Fatal(err)
	}
	if want := (TokenCorrection{Examined: 4, Updated: 1, Deleted: 1}); got != want {
		t.Errorf("first run = %+v, want %+v", got, want)
	}

	type row struct {
		in, out int64
		cost    float64
	}
	read := func(file, sess string) (row, bool) {
		var r row
		err := database.QueryRow(`SELECT input_tokens, output_tokens, estimated_cost_usd FROM token_usage
			WHERE source_file = ? AND source_event_id = ?`, file, "tokens:"+sess).Scan(&r.in, &r.out, &r.cost)
		if err == sql.ErrNoRows {
			return r, false
		}
		if err != nil {
			t.Fatal(err)
		}
		return r, true
	}
	if r, ok := read(src, "ses_multi"); !ok || r.in != 0 || r.out != 0 || r.cost != 0.0863 {
		t.Errorf("ses_multi = %+v (present=%v), want 0/0 $0.0863", r, ok)
	}
	if _, ok := read(src, "ses_flatmulti"); ok {
		t.Error("ses_flatmulti's zero-cost last-step snapshot survived the correction")
	}
	if r, ok := read(src, "ses_flat"); !ok || r.in != 9120 || r.out != 40 {
		t.Errorf("ses_flat = %+v (present=%v), want its real 9120/40 kept", r, ok)
	}
	if r, ok := read(src, "ses_ok"); !ok || r.in != 21749 || r.out != 5 {
		t.Errorf("ses_ok = %+v, want untouched 21749/5", r)
	}
	if r, ok := read(src, "ses_gone"); !ok || r.in != 500 {
		t.Errorf("ses_gone = %+v (present=%v): an unobserved session must never be touched", r, ok)
	}
	if r, ok := read("/other/crush.db", "ses_multi"); !ok || r.in != 7 {
		t.Errorf("other source file's row = %+v, want untouched", r)
	}

	// Org propagation: the update is queued for re-send, the removal is a
	// CORRECTION tombstone.
	count := func(q string, args ...any) int {
		var n int
		if err := database.QueryRow(q, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := count(`SELECT COUNT(*) FROM org_push_changes WHERE tbl = 'token_usage'`); n != 1 {
		t.Errorf("queued re-sends = %d, want 1 (the updated ses_multi row)", n)
	}
	if n := count(`SELECT COUNT(*) FROM org_push_deletions WHERE tbl = 'token_usage' AND k2 = 'tokens:ses_flatmulti'`); n != 1 {
		t.Errorf("tombstones for ses_flatmulti = %d, want 1 (a correction, not retention)", n)
	}
	rev := count(`SELECT rev FROM org_push_rev WHERE k = 1`)

	// Idempotent: the same parse again changes and queues nothing.
	again, err := s.CorrectTokenEvents(ctx, models.ToolCrush, src, observed, fresh)
	if err != nil {
		t.Fatal(err)
	}
	if want := (TokenCorrection{Examined: 3}); again != want {
		t.Errorf("second run = %+v, want %+v", again, want)
	}
	if n := count(`SELECT rev FROM org_push_rev WHERE k = 1`); n != rev {
		t.Errorf("org_push_rev moved %d -> %d on an idempotent re-run", rev, n)
	}

	// A fresh event with no stored row is reported, never inserted here.
	miss, err := s.CorrectTokenEvents(ctx, models.ToolCrush, src, []string{"ses_new"},
		[]models.TokenEvent{stale("ses_new", 1, 1, 0.01)})
	if err != nil {
		t.Fatal(err)
	}
	if miss.Missing != 1 || miss.Updated+miss.Deleted != 0 {
		t.Errorf("missing-row run = %+v, want Missing=1 and no writes", miss)
	}
	if _, ok := read(src, "ses_new"); ok {
		t.Error("CorrectTokenEvents inserted a row; inserting is Ingest's job")
	}
}

// TestTokenSourceFiles pins the distinct, sorted, tool-scoped file list.
func TestTokenSourceFiles(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	pid, err := s.UpsertProject(ctx, "/repo/x", "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	if err := s.UpsertSession(ctx, models.Session{ID: "s1", ProjectID: pid, Tool: models.ToolCrush, StartedAt: now}); err != nil {
		t.Fatal(err)
	}
	ev := func(file, id, tool string) models.TokenEvent {
		return models.TokenEvent{SourceFile: file, SourceEventID: id, SessionID: "s1", Tool: tool, Timestamp: now, InputTokens: 1}
	}
	if _, err := s.InsertTokenEvents(ctx, []models.TokenEvent{
		ev("/b/crush.db", "t1", models.ToolCrush), ev("/a/crush.db", "t2", models.ToolCrush),
		ev("/a/crush.db", "t3", models.ToolCrush), ev("/c/x.jsonl", "t4", models.ToolClaudeCode),
	}); err != nil {
		t.Fatal(err)
	}
	got, err := s.TokenSourceFiles(ctx, models.ToolCrush)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "/a/crush.db" || got[1] != "/b/crush.db" {
		t.Errorf("TokenSourceFiles = %v, want [/a/crush.db /b/crush.db]", got)
	}
}

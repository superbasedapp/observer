package store

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/models"
)

func newPredictTestStore(t *testing.T) *Store {
	t.Helper()
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: t.TempDir() + "/p.db"})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	return New(database)
}

func f64(v float64) *float64 { return &v }
func i64(v int64) *int64     { return &v }

// TestLatestLimitWindows pins the §12.1 guard read: the newest row
// carrying a window wins across scopes/providers, rows without any
// window util are skipped, and an empty table reports ok=false.
func TestLatestLimitWindows(t *testing.T) {
	st := newPredictTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC)

	// No windows yet.
	if _, _, ok, err := st.LatestLimitWindows(ctx); err != nil || ok {
		t.Fatalf("empty windows: ok=%v err=%v, want ok=false", ok, err)
	}
	// An older windowed row, then a window-less straggler that must
	// NOT shadow it, then the newest windowed row that wins.
	must := func(s models.LimitSnapshot) {
		t.Helper()
		if err := st.InsertLimitSnapshot(ctx, s); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	must(models.LimitSnapshot{ScopeHash: "default", Provider: "anthropic", SessionID: "a", ObservedAt: now, Window5hUtil: f64(0.30), Window7dUtil: f64(0.20)})
	must(models.LimitSnapshot{ScopeHash: "default", Provider: "openai", SessionID: "b", ObservedAt: now.Add(2 * time.Minute), ReqRemaining: i64(5)})
	must(models.LimitSnapshot{ScopeHash: "default", Provider: "anthropic", SessionID: "c", ObservedAt: now.Add(time.Minute), Window5hUtil: f64(0.88)})

	u5, u7, ok, err := st.LatestLimitWindows(ctx)
	if err != nil || !ok {
		t.Fatalf("windows: ok=%v err=%v", ok, err)
	}
	if u5 != 0.88 {
		t.Errorf("util5h = %v, want 0.88 (newest windowed row)", u5)
	}
	if u7 != 0 {
		t.Errorf("util7d = %v, want 0 (newest row carried no 7d)", u7)
	}
}

func TestLimitSnapshot_RoundTrip(t *testing.T) {
	st := newPredictTestStore(t)
	ctx := context.Background()

	now := time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC)
	in := models.LimitSnapshot{
		ScopeHash:     "default",
		Provider:      "anthropic",
		SessionID:     "sX",
		ObservedAt:    now,
		Window5hUtil:  f64(0.42),
		Window5hReset: i64(now.Add(time.Hour).Unix()),
		Window7dUtil:  f64(0.13),
		ReqRemaining:  i64(987),
		Status:        "allowed",
		Raw:           "anthropic-ratelimit-unified-5h-utilization=42",
	}
	if err := st.InsertLimitSnapshot(ctx, in); err != nil {
		t.Fatalf("insert: %v", err)
	}
	// A newer snapshot should win the "latest" read.
	in2 := in
	in2.ObservedAt = now.Add(time.Minute)
	in2.Window5hUtil = f64(0.55)
	if err := st.InsertLimitSnapshot(ctx, in2); err != nil {
		t.Fatalf("insert 2: %v", err)
	}

	got, ok, err := st.LatestLimitSnapshot(ctx, "default", "anthropic")
	if err != nil || !ok {
		t.Fatalf("latest: ok=%v err=%v", ok, err)
	}
	if got.Window5hUtil == nil || *got.Window5hUtil != 0.55 {
		t.Errorf("latest 5h util = %v, want 0.55 (newest)", got.Window5hUtil)
	}
	if got.Window7dUtil == nil || *got.Window7dUtil != 0.13 {
		t.Errorf("7d util = %v", got.Window7dUtil)
	}
	if got.ReqRemaining == nil || *got.ReqRemaining != 987 {
		t.Errorf("req remaining = %v", got.ReqRemaining)
	}
	if got.Status != "allowed" {
		t.Errorf("status = %q", got.Status)
	}
}

func TestLimitSnapshot_NoneOK(t *testing.T) {
	st := newPredictTestStore(t)
	_, ok, err := st.LatestLimitSnapshot(context.Background(), "default", "anthropic")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if ok {
		t.Error("expected ok=false when no snapshot exists")
	}
}

func TestLimitSnapshot_NullablesPreserved(t *testing.T) {
	st := newPredictTestStore(t)
	ctx := context.Background()
	// classic-only snapshot: no window utilization at all.
	in := models.LimitSnapshot{
		ScopeHash:    "default",
		Provider:     "openai",
		ObservedAt:   time.Now().UTC(),
		TokRemaining: i64(120000),
	}
	if err := st.InsertLimitSnapshot(ctx, in); err != nil {
		t.Fatalf("insert: %v", err)
	}
	got, ok, err := st.LatestLimitSnapshot(ctx, "default", "openai")
	if err != nil || !ok {
		t.Fatalf("latest: ok=%v err=%v", ok, err)
	}
	if got.Window5hUtil != nil || got.Window7dUtil != nil {
		t.Error("absent window headers should round-trip as nil, not 0")
	}
	if got.TokRemaining == nil || *got.TokRemaining != 120000 {
		t.Errorf("tok remaining = %v, want 120000", got.TokRemaining)
	}
}

// TestLatestLimitSnapshotForTool_Attribution pins that the tool-attributed
// read only surfaces a window to the tool whose session produced it — the
// cline-cli cross-tool-leak fix — and that a null-session_id straggler
// doesn't join.
func TestLatestLimitSnapshotForTool_Attribution(t *testing.T) {
	st := newPredictTestStore(t)
	ctx := context.Background()

	var projectID int64
	if err := st.db.QueryRowContext(ctx,
		`INSERT INTO projects (root_path, created_at) VALUES ('/tmp/pred-attr', '2026-06-29T00:00:00Z') RETURNING id`).
		Scan(&projectID); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	// Two anthropic-provider sessions, different tools.
	for _, s := range []struct{ id, tool string }{
		{"cc1", "claude-code"},
		{"cl1", "cline-cli"},
	} {
		if _, err := st.db.ExecContext(ctx,
			`INSERT INTO sessions (id, tool, project_id, started_at) VALUES (?, ?, ?, '2026-06-29T00:00:00Z')`,
			s.id, s.tool, projectID); err != nil {
			t.Fatalf("seed session %s: %v", s.id, err)
		}
	}

	// Only claude-code observed a subscription window. Plus an early
	// straggler with no session_id that must not join to anyone.
	if err := st.InsertLimitSnapshot(ctx, models.LimitSnapshot{
		ScopeHash: "default", Provider: "anthropic", SessionID: "cc1",
		ObservedAt: time.Now().UTC(), Window5hUtil: f64(0.09), Window7dUtil: f64(0.65),
	}); err != nil {
		t.Fatalf("insert cc snapshot: %v", err)
	}
	if err := st.InsertLimitSnapshot(ctx, models.LimitSnapshot{
		ScopeHash: "default", Provider: "anthropic", // SessionID empty
		ObservedAt: time.Now().Add(time.Minute).UTC(), Window5hUtil: f64(0.99),
	}); err != nil {
		t.Fatalf("insert straggler: %v", err)
	}

	// claude-code resolves its own window.
	got, ok, err := st.LatestLimitSnapshotForTool(ctx, "anthropic", "claude-code")
	if err != nil || !ok {
		t.Fatalf("claude-code: ok=%v err=%v", ok, err)
	}
	if got.Window5hUtil == nil || *got.Window5hUtil != 0.09 {
		t.Errorf("claude-code 5h util = %v, want 0.09 (its own, not the 0.99 straggler)", got.Window5hUtil)
	}

	// cline-cli produced none → no window inherited.
	if _, ok, err := st.LatestLimitSnapshotForTool(ctx, "anthropic", "cline-cli"); err != nil || ok {
		t.Errorf("cline-cli should have no attributed window, got ok=%v err=%v", ok, err)
	}
}

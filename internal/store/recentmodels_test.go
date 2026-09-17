package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// newRecentModelsTestStore stands up a project + session (token_usage's
// FK requires both), mirroring the seedModelValueCorpus pattern in
// modelvalue_test.go.
func newRecentModelsTestStore(t *testing.T) (*Store, context.Context, int64) {
	t.Helper()
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "recentmodels_test.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	st := New(database)

	projectID, err := st.UpsertProject(ctx, "/repo/acme", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	if err := st.UpsertSession(ctx, models.Session{
		ID: "sess-rm", ProjectID: projectID, Tool: "claude-code",
		StartedAt: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("UpsertSession: %v", err)
	}
	return st, ctx, projectID
}

// ev is a small helper building a models.TokenEvent for token_usage
// seeding, keyed by a unique source_event_id (required by
// InsertTokenEvents' ON CONFLICT(source_file, source_event_id) upsert).
func ev(id, tool, model string, ts time.Time) models.TokenEvent {
	return models.TokenEvent{
		SourceFile: "fixture.jsonl", SourceEventID: id, SessionID: "sess-rm",
		ProjectRoot: "/repo/acme", Tool: tool, Model: model,
		Timestamp: ts, InputTokens: 10, OutputTokens: 5,
	}
}

func TestLoadRecentModelsForTool(t *testing.T) {
	t.Parallel()
	// LoadRecentModelsForTool computes its window cutoff from the real
	// time.Now() internally (it drives a live "recent models" picker, so
	// that's correct production behavior — see recentmodels.go). A fixture
	// "now" pinned to a hardcoded calendar literal drifts out of every
	// subtest's window as real time passes the literal + window, silently
	// turning every subtest into an empty-result read (indistinguishable
	// from — and coincidentally matching — the "no rows" subtest). Anchor
	// to real time instead so seeded offsets always land inside the window
	// being asserted against.
	now := time.Now().UTC()

	t.Run("orders by recency", func(t *testing.T) {
		t.Parallel()
		st, ctx, _ := newRecentModelsTestStore(t)
		if _, err := st.InsertTokenEvents(ctx, []models.TokenEvent{
			ev("a1", "claude-code", "claude-opus-4-8", now.Add(-3*time.Hour)),
			ev("a2", "claude-code", "claude-haiku-4-5", now.Add(-1*time.Hour)),
			ev("a3", "claude-code", "claude-sonnet-4-8", now.Add(-2*time.Hour)),
		}); err != nil {
			t.Fatalf("InsertTokenEvents: %v", err)
		}
		got, err := st.LoadRecentModelsForTool(ctx, "claude-code", 24*time.Hour, 12)
		if err != nil {
			t.Fatalf("LoadRecentModelsForTool: %v", err)
		}
		want := []string{"claude-haiku-4-5", "claude-sonnet-4-8", "claude-opus-4-8"}
		if len(got) != len(want) {
			t.Fatalf("len = %d, want %d; got %+v", len(got), len(want), got)
		}
		for i, m := range want {
			if got[i].Model != m {
				t.Errorf("got[%d].Model = %q, want %q (full: %+v)", i, got[i].Model, m, got)
			}
			if got[i].Count != 1 {
				t.Errorf("got[%d].Count = %d, want 1", i, got[i].Count)
			}
			if got[i].LastUsed == "" {
				t.Errorf("got[%d].LastUsed empty", i)
			}
		}
	})

	t.Run("groups and counts per model", func(t *testing.T) {
		t.Parallel()
		st, ctx, _ := newRecentModelsTestStore(t)
		if _, err := st.InsertTokenEvents(ctx, []models.TokenEvent{
			ev("b1", "claude-code", "claude-opus-4-8", now.Add(-3*time.Hour)),
			ev("b2", "claude-code", "claude-opus-4-8", now.Add(-2*time.Hour)),
			ev("b3", "claude-code", "claude-opus-4-8", now.Add(-1*time.Hour)),
		}); err != nil {
			t.Fatalf("InsertTokenEvents: %v", err)
		}
		got, err := st.LoadRecentModelsForTool(ctx, "claude-code", 24*time.Hour, 12)
		if err != nil {
			t.Fatalf("LoadRecentModelsForTool: %v", err)
		}
		if len(got) != 1 || got[0].Count != 3 {
			t.Fatalf("got = %+v, want a single row with Count=3", got)
		}
	})

	t.Run("limit caps results", func(t *testing.T) {
		t.Parallel()
		st, ctx, _ := newRecentModelsTestStore(t)
		if _, err := st.InsertTokenEvents(ctx, []models.TokenEvent{
			ev("c1", "claude-code", "model-a", now.Add(-4*time.Hour)),
			ev("c2", "claude-code", "model-b", now.Add(-3*time.Hour)),
			ev("c3", "claude-code", "model-c", now.Add(-2*time.Hour)),
			ev("c4", "claude-code", "model-d", now.Add(-1*time.Hour)),
		}); err != nil {
			t.Fatalf("InsertTokenEvents: %v", err)
		}
		got, err := st.LoadRecentModelsForTool(ctx, "claude-code", 24*time.Hour, 2)
		if err != nil {
			t.Fatalf("LoadRecentModelsForTool: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("len = %d, want 2; got %+v", len(got), got)
		}
		if got[0].Model != "model-d" || got[1].Model != "model-c" {
			t.Errorf("got = %+v, want [model-d, model-c] (most-recent-first, capped)", got)
		}
	})

	t.Run("excludes rows outside the window", func(t *testing.T) {
		t.Parallel()
		st, ctx, _ := newRecentModelsTestStore(t)
		if _, err := st.InsertTokenEvents(ctx, []models.TokenEvent{
			ev("d1", "claude-code", "model-old", now.Add(-48*time.Hour)),
			ev("d2", "claude-code", "model-recent", now.Add(-1*time.Hour)),
		}); err != nil {
			t.Fatalf("InsertTokenEvents: %v", err)
		}
		got, err := st.LoadRecentModelsForTool(ctx, "claude-code", 24*time.Hour, 12)
		if err != nil {
			t.Fatalf("LoadRecentModelsForTool: %v", err)
		}
		if len(got) != 1 || got[0].Model != "model-recent" {
			t.Fatalf("got = %+v, want only model-recent (model-old is outside the 24h window)", got)
		}
	})

	t.Run("excludes sentinel models", func(t *testing.T) {
		t.Parallel()
		st, ctx, _ := newRecentModelsTestStore(t)
		if _, err := st.InsertTokenEvents(ctx, []models.TokenEvent{
			ev("e1", "claude-code", "<synthetic>", now.Add(-1*time.Hour)),
			ev("e2", "claude-code", "claude-opus-4-8", now.Add(-2*time.Hour)),
		}); err != nil {
			t.Fatalf("InsertTokenEvents: %v", err)
		}
		got, err := st.LoadRecentModelsForTool(ctx, "claude-code", 24*time.Hour, 12)
		if err != nil {
			t.Fatalf("LoadRecentModelsForTool: %v", err)
		}
		if len(got) != 1 || got[0].Model != "claude-opus-4-8" {
			t.Fatalf("got = %+v, want only claude-opus-4-8 (sentinel '<synthetic>' excluded)", got)
		}
	})

	t.Run("excludes other tools", func(t *testing.T) {
		t.Parallel()
		st, ctx, projectID := newRecentModelsTestStore(t)
		if err := st.UpsertSession(ctx, models.Session{
			ID: "sess-rm-other", ProjectID: projectID, Tool: "codex",
			StartedAt: now.Add(-2 * time.Hour),
		}); err != nil {
			t.Fatalf("UpsertSession: %v", err)
		}
		other := ev("f1", "codex", "gpt-5-codex", now.Add(-1*time.Hour))
		other.SessionID = "sess-rm-other"
		if _, err := st.InsertTokenEvents(ctx, []models.TokenEvent{
			ev("f2", "claude-code", "claude-opus-4-8", now.Add(-1*time.Hour)),
			other,
		}); err != nil {
			t.Fatalf("InsertTokenEvents: %v", err)
		}
		got, err := st.LoadRecentModelsForTool(ctx, "claude-code", 24*time.Hour, 12)
		if err != nil {
			t.Fatalf("LoadRecentModelsForTool: %v", err)
		}
		if len(got) != 1 || got[0].Model != "claude-opus-4-8" {
			t.Fatalf("got = %+v, want only claude-opus-4-8 (codex row must be excluded)", got)
		}
	})

	t.Run("no rows returns empty, no error", func(t *testing.T) {
		t.Parallel()
		st, ctx, _ := newRecentModelsTestStore(t)
		got, err := st.LoadRecentModelsForTool(ctx, "claude-code", 24*time.Hour, 12)
		if err != nil {
			t.Fatalf("LoadRecentModelsForTool: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("got = %+v, want empty", got)
		}
	})
}

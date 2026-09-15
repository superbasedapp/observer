package store

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// seedRollupSession creates a project + session row directly (bypassing
// Ingest), mirroring how adapters like codex/cursor/cline/cowork leave
// sessions.model empty while their token_usage rows still carry a model.
func seedRollupSession(t *testing.T, s *Store, ctx context.Context, sessionID, root, model string) {
	t.Helper()
	pid, err := s.UpsertProject(ctx, root, "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	if err := s.UpsertSession(ctx, models.Session{
		ID:        sessionID,
		ProjectID: pid,
		Tool:      "codex",
		Model:     model,
		StartedAt: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("UpsertSession: %v", err)
	}
}

func rollupSessionModel(t *testing.T, s *Store, ctx context.Context, sessionID string) string {
	t.Helper()
	var model string
	if err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(model, '') FROM sessions WHERE id = ?`, sessionID,
	).Scan(&model); err != nil {
		t.Fatalf("query session model: %v", err)
	}
	return model
}

// TestIngestRollsUpEmptySessionModelFromNewestTokenRow pins the C8 fix
// end to end through the Ingest call site: a session created with an
// empty model (the codex/cursor/cline/cowork shape) picks up the model
// of its NEWEST token_usage row once tokens are ingested, even when an
// older row on the same session carries a different model.
func TestIngestRollsUpEmptySessionModelFromNewestTokenRow(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	seedRollupSession(t, s, ctx, "sess-empty", "/repo/empty", "")

	older := models.TokenEvent{
		SourceFile: "codex:transcript", SourceEventID: "tok-1",
		SessionID: "sess-empty", ProjectRoot: "",
		Timestamp: time.Date(2026, 9, 1, 12, 1, 0, 0, time.UTC),
		Tool:      "codex", Model: "gpt-4.1",
		InputTokens: 10, OutputTokens: 5,
		Source: models.TokenSourceHook, Reliability: models.ReliabilityAccurate,
	}
	newer := older
	newer.SourceEventID = "tok-2"
	newer.Timestamp = time.Date(2026, 9, 1, 12, 5, 0, 0, time.UTC)
	newer.Model = "gpt-5-codex"

	if _, err := s.Ingest(ctx, nil, []models.TokenEvent{older, newer}, IngestOptions{}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	if got := rollupSessionModel(t, s, ctx, "sess-empty"); got != "gpt-5-codex" {
		t.Errorf("sessions.model = %q, want %q (newest token row)", got, "gpt-5-codex")
	}
}

// TestIngestRollupPreservesExistingSessionModel guards the other half of
// the safety rule: a session whose model is already set (e.g. from a
// ToolEvent that DID carry one) must never be clobbered by the rollup,
// even when its token rows disagree.
func TestIngestRollupPreservesExistingSessionModel(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	seedRollupSession(t, s, ctx, "sess-set", "/repo/set", "claude-3-opus")

	tk := models.TokenEvent{
		SourceFile: "codex:transcript", SourceEventID: "tok-1",
		SessionID: "sess-set", ProjectRoot: "",
		Timestamp: time.Date(2026, 9, 1, 12, 5, 0, 0, time.UTC),
		Tool:      "codex", Model: "gpt-5-codex",
		InputTokens: 10, OutputTokens: 5,
		Source: models.TokenSourceHook, Reliability: models.ReliabilityAccurate,
	}
	if _, err := s.Ingest(ctx, nil, []models.TokenEvent{tk}, IngestOptions{}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	if got := rollupSessionModel(t, s, ctx, "sess-set"); got != "claude-3-opus" {
		t.Errorf("sessions.model = %q, want preserved %q", got, "claude-3-opus")
	}
}

// TestIngestRollupLeavesModelEmptyWhenTokenRowsCarryNone covers a session
// whose token rows exist but never resolved a model (Model == "" on every
// row) — the rollup must leave sessions.model empty rather than write an
// empty string over an empty string, or otherwise misbehave.
func TestIngestRollupLeavesModelEmptyWhenTokenRowsCarryNone(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	seedRollupSession(t, s, ctx, "sess-no-model", "/repo/no-model", "")

	tk := models.TokenEvent{
		SourceFile: "codex:transcript", SourceEventID: "tok-1",
		SessionID: "sess-no-model", ProjectRoot: "",
		Timestamp: time.Date(2026, 9, 1, 12, 5, 0, 0, time.UTC),
		Tool:      "codex", Model: "",
		InputTokens: 10, OutputTokens: 5,
		Source: models.TokenSourceHook, Reliability: models.ReliabilityAccurate,
	}
	if _, err := s.Ingest(ctx, nil, []models.TokenEvent{tk}, IngestOptions{}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	if got := rollupSessionModel(t, s, ctx, "sess-no-model"); got != "" {
		t.Errorf("sessions.model = %q, want empty", got)
	}
}

// TestRollupSessionModelsUnknownIDsAreNoOp calls rollupSessionModels
// directly with session ids that don't exist in the DB at all — the
// UPDATE matches zero rows and the call must return nil, not error.
func TestRollupSessionModelsUnknownIDsAreNoOp(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	if err := s.rollupSessionModels(ctx, []string{"", "ghost-1", "ghost-2", "ghost-1"}); err != nil {
		t.Fatalf("rollupSessionModels on unknown ids: %v", err)
	}
	if err := s.rollupSessionModels(ctx, nil); err != nil {
		t.Fatalf("rollupSessionModels on nil ids: %v", err)
	}
}

// TestBackfillSessionModelsFillsThenNoOps exercises the set-based
// BackfillSessionModels path (the intended `observer backfill
// --session-models` engine): it must fill every empty-model session that
// has a model-bearing token row in one pass, report that count, leave
// already-set or genuinely modelless sessions untouched, and report 0 on
// a second run since nothing is left to fill.
func TestBackfillSessionModelsFillsThenNoOps(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	// sess-a: empty model, one token row with a model -> should fill.
	seedRollupSession(t, s, ctx, "sess-a", "/repo/a", "")
	// sess-b: empty model, one token row with a model -> should fill.
	seedRollupSession(t, s, ctx, "sess-b", "/repo/b", "")
	// sess-c: already has a model -> must stay untouched.
	seedRollupSession(t, s, ctx, "sess-c", "/repo/c", "gpt-4.1")
	// sess-d: empty model, no token rows at all -> stays empty.
	seedRollupSession(t, s, ctx, "sess-d", "/repo/d", "")

	tokens := []models.TokenEvent{
		{
			SourceFile: "codex:transcript", SourceEventID: "a-1",
			SessionID: "sess-a", Tool: "codex", Model: "gpt-5-codex",
			Timestamp:   time.Date(2026, 9, 1, 12, 5, 0, 0, time.UTC),
			InputTokens: 10, OutputTokens: 5,
			Source: models.TokenSourceHook, Reliability: models.ReliabilityAccurate,
		},
		{
			SourceFile: "cline:transcript", SourceEventID: "b-1",
			SessionID: "sess-b", Tool: "cline", Model: "claude-3-sonnet",
			Timestamp:   time.Date(2026, 9, 1, 12, 5, 0, 0, time.UTC),
			InputTokens: 10, OutputTokens: 5,
			Source: models.TokenSourceHook, Reliability: models.ReliabilityAccurate,
		},
		{
			SourceFile: "cursor:transcript", SourceEventID: "c-1",
			SessionID: "sess-c", Tool: "cursor", Model: "gpt-4o",
			Timestamp:   time.Date(2026, 9, 1, 12, 5, 0, 0, time.UTC),
			InputTokens: 10, OutputTokens: 5,
			Source: models.TokenSourceHook, Reliability: models.ReliabilityAccurate,
		},
	}
	if _, err := s.InsertTokenEvents(ctx, tokens); err != nil {
		t.Fatalf("InsertTokenEvents: %v", err)
	}

	n, err := s.BackfillSessionModels(ctx)
	if err != nil {
		t.Fatalf("BackfillSessionModels: %v", err)
	}
	if n != 2 {
		t.Errorf("BackfillSessionModels rows affected = %d, want 2", n)
	}
	if got := rollupSessionModel(t, s, ctx, "sess-a"); got != "gpt-5-codex" {
		t.Errorf("sess-a model = %q, want %q", got, "gpt-5-codex")
	}
	if got := rollupSessionModel(t, s, ctx, "sess-b"); got != "claude-3-sonnet" {
		t.Errorf("sess-b model = %q, want %q", got, "claude-3-sonnet")
	}
	if got := rollupSessionModel(t, s, ctx, "sess-c"); got != "gpt-4.1" {
		t.Errorf("sess-c model = %q, want preserved %q", got, "gpt-4.1")
	}
	if got := rollupSessionModel(t, s, ctx, "sess-d"); got != "" {
		t.Errorf("sess-d model = %q, want empty (no token rows)", got)
	}

	n2, err := s.BackfillSessionModels(ctx)
	if err != nil {
		t.Fatalf("BackfillSessionModels (second run): %v", err)
	}
	if n2 != 0 {
		t.Errorf("BackfillSessionModels second run rows affected = %d, want 0", n2)
	}
}

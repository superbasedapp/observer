package store

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestLoadSessionQuality pins the read seam behind the session Quality card:
// unknown session → found=false; never-scored → Scored=false with every score
// nil (never a zero); a pre-migration-137 score → the persisted inputs with
// the breakdown/stamp still nil; a full score → every column round-tripped.
func TestLoadSessionQuality(t *testing.T) {
	t.Parallel()
	s, database := newTestStore(t)
	ctx := context.Background()

	root := t.TempDir()
	base := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	var events []models.ToolEvent
	for _, sid := range []string{"q-unscored", "q-legacy", "q-full"} {
		for i := 0; i < 2; i++ {
			events = append(events, models.ToolEvent{
				SourceFile: "f.jsonl", SourceEventID: sid + "-" + string(rune('a'+i)),
				SessionID: sid, ProjectRoot: root, Timestamp: base.Add(time.Duration(i) * time.Second),
				Tool: models.ToolClaudeCode, ActionType: models.ActionReadFile,
				Target: "a.go", Success: true,
			})
		}
	}
	if _, err := s.Ingest(ctx, events, nil, IngestOptions{}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if _, err := database.ExecContext(ctx, `UPDATE sessions SET
		quality_score = 0.61, redundancy_ratio = 0.2, error_rate = 0.1,
		onboarding_cost = 500, turns_to_first_edit = 3, retry_cost_tokens = 40
		WHERE id = 'q-legacy'`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `UPDATE sessions SET
		quality_score = 0.8, redundancy_ratio = 0.1, error_rate = 0,
		exploration_efficiency = 0.5, continuity_score = 0.09,
		onboarding_cost = 0, turns_to_first_edit = NULL, retry_cost_tokens = 0,
		stale_reads_wasteful = 1, stale_reads_necessary = 2, redundancy_ratio_wasteful = 0.05,
		scored_at = '2026-09-27T12:30:00Z', scored_action_count = 2
		WHERE id = 'q-full'`); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		id         string
		wantFound  bool
		wantScored bool
		check      func(t *testing.T, q SessionQuality)
	}{
		{id: "missing", wantFound: false},
		{id: "q-unscored", wantFound: true, wantScored: false, check: func(t *testing.T, q SessionQuality) {
			if q.QualityScore != nil || q.ErrorRate != nil || q.ScoredActionCount != nil || q.ScoredAt != "" {
				t.Errorf("unscored session carries score fields: %+v", q)
			}
		}},
		{id: "q-legacy", wantFound: true, wantScored: true, check: func(t *testing.T, q SessionQuality) {
			if q.QualityScore == nil || *q.QualityScore != 0.61 || q.OnboardingCost == nil || *q.OnboardingCost != 500 {
				t.Errorf("legacy inputs not read: %+v", q)
			}
			if q.ExplorationEfficiency != nil || q.ContinuityScore != nil || q.ScoredAt != "" || q.ScoredActionCount != nil {
				t.Errorf("pre-137 score must leave breakdown/stamp nil: %+v", q)
			}
		}},
		{id: "q-full", wantFound: true, wantScored: true, check: func(t *testing.T, q SessionQuality) {
			if q.ExplorationEfficiency == nil || *q.ExplorationEfficiency != 0.5 ||
				q.ContinuityScore == nil || q.ScoredAt != "2026-09-27T12:30:00Z" ||
				q.ScoredActionCount == nil || *q.ScoredActionCount != 2 {
				t.Errorf("full score not round-tripped: %+v", q)
			}
			if q.TurnsToFirstEdit != nil {
				t.Errorf("NULL turns_to_first_edit must stay nil, got %d", *q.TurnsToFirstEdit)
			}
			if q.StaleReadsWasteful == nil || *q.StaleReadsWasteful != 1 || q.RedundancyRatioWasteful == nil {
				t.Errorf("stale split not read: %+v", q)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			q, found, err := s.LoadSessionQuality(ctx, tc.id)
			if err != nil {
				t.Fatalf("LoadSessionQuality: %v", err)
			}
			if found != tc.wantFound {
				t.Fatalf("found=%v, want %v", found, tc.wantFound)
			}
			if !found {
				return
			}
			if q.Scored != tc.wantScored {
				t.Errorf("Scored=%v, want %v", q.Scored, tc.wantScored)
			}
			if q.CurrentActionCount != 2 {
				t.Errorf("CurrentActionCount=%d, want 2", q.CurrentActionCount)
			}
			if tc.check != nil {
				tc.check(t, q)
			}
		})
	}
}

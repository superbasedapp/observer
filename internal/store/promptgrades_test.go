package store

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/intelligence/alignment"
)

func TestSavePromptGradeUpsertsOnProjectActionTier(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	projectID, err := s.UpsertProject(ctx, "/repo/grades", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}

	at := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	row := PromptGradeRow{
		ProjectID: projectID,
		ActionID:  1,
		Tier:      "judge",
		Model:     "gpt-5-mini",
		Result: alignment.Result{
			Delivered:  []string{"retry"},
			Missed:     []string{"backoff"},
			Confidence: 0.7,
			Notes:      "first pass",
		},
		GradedAt: at,
	}
	if err := s.SavePromptGrade(ctx, row); err != nil {
		t.Fatalf("SavePromptGrade: %v", err)
	}

	got, err := s.LoadPromptGrades(ctx, projectID, []int64{1})
	if err != nil {
		t.Fatalf("LoadPromptGrades: %v", err)
	}
	first, ok := got[1]
	if !ok {
		t.Fatalf("action 1 missing from LoadPromptGrades result")
	}
	if first.Model != "gpt-5-mini" || first.Result.Confidence != 0.7 {
		t.Fatalf("first load = %+v", first)
	}

	// Re-save under the SAME (project, action, tier) with different
	// content — must REPLACE, not accumulate a second row.
	row.Model = "gpt-5.1"
	row.Result = alignment.Result{Delivered: []string{"retry", "backoff"}, Confidence: 0.9, Notes: "revised"}
	row.GradedAt = at.Add(time.Hour)
	if err := s.SavePromptGrade(ctx, row); err != nil {
		t.Fatalf("SavePromptGrade (re-save): %v", err)
	}

	got2, err := s.LoadPromptGrades(ctx, projectID, []int64{1})
	if err != nil {
		t.Fatalf("LoadPromptGrades (after re-save): %v", err)
	}
	second := got2[1]
	if second.Model != "gpt-5.1" || second.Result.Confidence != 0.9 || len(second.Result.Delivered) != 2 {
		t.Fatalf("re-saved row = %+v, want the REVISED content", second)
	}

	var n int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM project_prompt_grades WHERE project_id = ? AND action_id = ? AND tier = ?`,
		projectID, 1, "judge").Scan(&n); err != nil {
		t.Fatalf("count query: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected exactly 1 row after upsert, found %d", n)
	}
}

func TestLoadPromptGradesPrefersCloudOverJudge(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	projectID, err := s.UpsertProject(ctx, "/repo/grades2", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}

	at := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	if err := s.SavePromptGrade(ctx, PromptGradeRow{
		ProjectID: projectID, ActionID: 5, Tier: "judge", Model: "local-model",
		Result: alignment.Result{Notes: "judge tier", Confidence: 0.4}, GradedAt: at,
	}); err != nil {
		t.Fatalf("SavePromptGrade(judge): %v", err)
	}
	if err := s.SavePromptGrade(ctx, PromptGradeRow{
		ProjectID: projectID, ActionID: 5, Tier: "cloud", Model: "hosted-model",
		Result: alignment.Result{Notes: "cloud tier", Confidence: 0.95}, GradedAt: at.Add(time.Minute),
	}); err != nil {
		t.Fatalf("SavePromptGrade(cloud): %v", err)
	}
	// A DIFFERENT action graded only by the judge tier stays judge.
	if err := s.SavePromptGrade(ctx, PromptGradeRow{
		ProjectID: projectID, ActionID: 6, Tier: "judge", Model: "local-model",
		Result: alignment.Result{Notes: "judge only", Confidence: 0.5}, GradedAt: at,
	}); err != nil {
		t.Fatalf("SavePromptGrade(action 6): %v", err)
	}

	got, err := s.LoadPromptGrades(ctx, projectID, []int64{5, 6})
	if err != nil {
		t.Fatalf("LoadPromptGrades: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 actions, got %d: %+v", len(got), got)
	}
	if got[5].Tier != "cloud" || got[5].Result.Notes != "cloud tier" {
		t.Fatalf("action 5 should prefer the cloud tier, got %+v", got[5])
	}
	if got[6].Tier != "judge" || got[6].Result.Notes != "judge only" {
		t.Fatalf("action 6 should keep its sole judge grade, got %+v", got[6])
	}
}

func TestLoadPromptGradesEmptyInputs(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	got, err := s.LoadPromptGrades(ctx, 1, nil)
	if err != nil {
		t.Fatalf("LoadPromptGrades(nil ids): %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected an empty map, got %+v", got)
	}

	// A projectID/actionID pair that was never graded is simply ABSENT,
	// never a zero-valued entry.
	projectID, err := s.UpsertProject(ctx, "/repo/grades3", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	got2, err := s.LoadPromptGrades(ctx, projectID, []int64{999})
	if err != nil {
		t.Fatalf("LoadPromptGrades(ungraded action): %v", err)
	}
	if _, ok := got2[999]; ok {
		t.Fatalf("ungraded action 999 should be absent from the map, got %+v", got2[999])
	}
}

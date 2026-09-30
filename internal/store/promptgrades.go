package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/intelligence/alignment"
)

// Alignment-grading persistence, node-side (docs/plans/projects-page-roi-
// and-commit-alignment-plan-2026-09-21.md §2 R6, §3.6 tier J, §4 W5a).
//
// THIS FILE IS THE ONE OWNER of project_prompt_grades (agent migration
// 128) — CLAUDE.md module-boundary rule #4. Both the J tier
// (internal/intelligence/alignment, bound in
// cmd/observer/alignment_wire.go) and, later, the C tier (W5b's Cloud
// Intelligence grading) write through this seam under their own `tier`
// value ("judge" / "cloud"); neither imports internal/store itself.
//
// NODE-LOCAL: project_prompt_grades is never named in
// internal/store/orgpush.go — pinned in the forbidden-table sentinel
// (tests/invariant/privacy_test.go).

// tierPriority ranks the grading tiers so LoadPromptGrades can prefer the
// deeper-evidence grade when more than one tier has graded the same
// action (§3.6: cloud grading sees more evidence than the local/configured
// judge, which in turn is strictly more than the always-available local
// heuristic that never persists a row here at all). An unrecognized tier
// ranks below every known one, never above.
var tierPriority = map[string]int{
	"judge": 1,
	"cloud": 2,
}

// PromptGradeRow is one project_prompt_grades row: one alignment.Result,
// scoped to the (project, prompt action, tier) that produced it.
type PromptGradeRow struct {
	ProjectID int64
	ActionID  int64
	Tier      string
	Model     string
	Result    alignment.Result
	GradedAt  time.Time
}

// SavePromptGrade upserts one grading verdict, keyed on (project_id,
// action_id, tier) — re-grading the same prompt under the same tier
// replaces its prior verdict rather than accumulating history.
func (s *Store) SavePromptGrade(ctx context.Context, row PromptGradeRow) error {
	if strings.TrimSpace(row.Tier) == "" {
		return fmt.Errorf("store.SavePromptGrade: tier is required")
	}
	resultJSON, err := json.Marshal(row.Result)
	if err != nil {
		return fmt.Errorf("store.SavePromptGrade: marshal result: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO project_prompt_grades (project_id, action_id, tier, model, result_json, graded_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(project_id, action_id, tier) DO UPDATE SET
			model       = excluded.model,
			result_json = excluded.result_json,
			graded_at   = excluded.graded_at`,
		row.ProjectID, row.ActionID, row.Tier, row.Model, string(resultJSON), timestamp(row.GradedAt),
	)
	if err != nil {
		return fmt.Errorf("store.SavePromptGrade: upsert: %w", err)
	}
	return nil
}

// LoadPromptGrades returns the LATEST grade per action_id, across every
// tier that has graded it — preferring the deepest-evidence tier
// (tierPriority: cloud > judge) when an action was graded more than once.
// actionIDs not present in the table are simply absent from the returned
// map (never a zero-valued row), so callers can distinguish "not graded"
// from "graded with an empty verdict".
func (s *Store) LoadPromptGrades(ctx context.Context, projectID int64, actionIDs []int64) (map[int64]PromptGradeRow, error) {
	out := make(map[int64]PromptGradeRow)
	if len(actionIDs) == 0 {
		return out, nil
	}

	placeholders := make([]string, len(actionIDs))
	args := make([]any, 0, len(actionIDs)+1)
	args = append(args, projectID)
	for i, id := range actionIDs {
		placeholders[i] = "?"
		args = append(args, id)
	}

	//nolint:gosec // G201: the only formatted value is a generated `?` placeholder run; ids bind via args.
	query := fmt.Sprintf(`
		SELECT action_id, tier, model, result_json, graded_at
		  FROM project_prompt_grades
		 WHERE project_id = ? AND action_id IN (%s)`, strings.Join(placeholders, ","))

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store.LoadPromptGrades: query: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var actionID int64
		var tier, model, resultJSON, gradedAtStr string
		if err := rows.Scan(&actionID, &tier, &model, &resultJSON, &gradedAtStr); err != nil {
			return nil, fmt.Errorf("store.LoadPromptGrades: scan: %w", err)
		}
		var result alignment.Result
		if err := json.Unmarshal([]byte(resultJSON), &result); err != nil {
			return nil, fmt.Errorf("store.LoadPromptGrades: unmarshal result for action %d/%s: %w", actionID, tier, err)
		}
		row := PromptGradeRow{
			ProjectID: projectID,
			ActionID:  actionID,
			Tier:      tier,
			Model:     model,
			Result:    result,
			GradedAt:  parseCommitTime(gradedAtStr),
		}
		if existing, ok := out[actionID]; !ok || tierPriority[tier] > tierPriority[existing.Tier] {
			out[actionID] = row
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.LoadPromptGrades: rows: %w", err)
	}
	return out, nil
}

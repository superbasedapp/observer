-- 128_project_prompt_grades.sql — persisted alignment-grading verdicts,
-- node-side (docs/plans/projects-page-roi-and-commit-alignment-plan-2026-
-- 09-21.md §2 R6, §3.6 tier J, §4 W5a).
--
-- One row per (project, prompt action, tier) grading verdict: whether a
-- commit delivered what a developer's prompt asked an AI coding tool for.
-- Split from migration 127 (the commit-capture tables) because it is a
-- DIFFERENT concern that lands in a later wave — this table has no
-- relationship to the git-log scanner, it is written by the "J" judge
-- tier (internal/intelligence/alignment, bound in
-- cmd/observer/alignment_wire.go over the SAME chatCompletionsJudge the
-- eval/admission judges use) and, later, by the "C" Cloud Intelligence
-- tier (W5b, tier="cloud"). Multiple tiers may grade the same
-- (project_id, action_id) pair; result_json's shape is
-- internal/intelligence/alignment.Result marshaled as-is, and
-- internal/store/promptgrades.go::LoadPromptGrades picks the deepest-
-- evidence tier present per action when more than one exists.
--
-- model records which model produced the verdict (e.g. the
-- [observability.judge] model, or a cloud-side model id); empty for a
-- tier where that concept does not apply.
--
-- PRIVACY (R1/R12 posture, same as migration 127): this table is
-- NODE-LOCAL. A prompt's text and a commit's hunks are the evidence a
-- grading verdict is built from, so the verdict itself (delivered/missed/
-- extra/notes) is a DERIVED disclosure of the same sensitivity as the
-- conversation content it graded — never selected by
-- internal/store/orgpush.go::SelectUnpushedSince, and pinned in the
-- forbidden-table sentinel (tests/invariant/privacy_test.go). An org
-- projection is not planned; the C tier already has its own explicit,
-- consent-gated upload path (internal/cloudevidence), which is a
-- different mechanism entirely from the node/org push wire.
--
-- Timestamps are RFC3339 UTC strings, matching every other table in this
-- schema.

CREATE TABLE IF NOT EXISTS project_prompt_grades (
    project_id   INTEGER NOT NULL REFERENCES projects(id),
    action_id    INTEGER NOT NULL,
    tier         TEXT NOT NULL,
    model        TEXT NOT NULL DEFAULT '',
    result_json  TEXT NOT NULL,
    graded_at    TEXT NOT NULL,
    PRIMARY KEY (project_id, action_id, tier)
);

CREATE INDEX IF NOT EXISTS idx_project_prompt_grades_action
    ON project_prompt_grades(action_id);

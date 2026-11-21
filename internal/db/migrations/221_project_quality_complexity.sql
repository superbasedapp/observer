-- 221_project_quality_complexity.sql - the complexity metric's columns on
-- the Projects page's quality trend (docs/projects-page.md "Quality
-- metrics"; plan docs/plans/os-and-ci-vulnerability-scanning-plan-2026-11-04.md
-- section 14.10, item 8, M3L-4). Additive to migration 219's
-- project_quality_daily; internal/store/codequality.go stays its one writer.
--
-- Numbered 216 on main; renumbered to 221 when main merged into the release
-- line (plans decision log P-247), after 219, which creates its table.
-- Numbers 213, 214 and 216 are retired on both lines. SQLite has no ADD
-- COLUMN IF NOT EXISTS, so this is a node late step (lateSteps in
-- internal/db/db.go probes project_quality_daily.complexity_state): a
-- database that ran main's 216 adopts it, any other runs it.
--
-- NUMBERS AND STATES ONLY, like the rest of the row: no function name, no
-- path. complexity_state holds internal/codequality's closed State
-- vocabulary; rows written before this step read '' (not recorded), and
-- every numeric column is meaningful only when the state is 'measured'
-- (otherwise 0, read as NOT MEASURED, never as zero complexity).
--
-- NODE-LOCAL: project_quality_daily is pinned in the org-push forbidden-table
-- sentinel (tests/invariant/privacy_test.go). No server pair.
ALTER TABLE project_quality_daily ADD COLUMN complexity_state TEXT NOT NULL DEFAULT '';
-- functions and methods counted
ALTER TABLE project_quality_daily ADD COLUMN complexity_functions INTEGER NOT NULL DEFAULT 0;
-- of them, over codequality.ComplexityThreshold
ALTER TABLE project_quality_daily ADD COLUMN complexity_over INTEGER NOT NULL DEFAULT 0;
-- sum of the counted values (the mean is sum / functions)
ALTER TABLE project_quality_daily ADD COLUMN complexity_sum INTEGER NOT NULL DEFAULT 0;
ALTER TABLE project_quality_daily ADD COLUMN complexity_p90 INTEGER NOT NULL DEFAULT 0;
ALTER TABLE project_quality_daily ADD COLUMN complexity_max INTEGER NOT NULL DEFAULT 0;

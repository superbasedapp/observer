-- 219_project_quality_daily.sql - the Projects page's quality-metric trend
-- (docs/projects-page.md "Quality metrics"; plan
-- docs/plans/os-and-ci-vulnerability-scanning-plan-2026-11-04.md section
-- 14.10, item 8, M3L-2).
--
-- One row per project per UTC day: the last measurement of that day wins
-- (internal/store/codequality.go::UpsertProjectQualityDay is the one writer).
-- NUMBERS AND STATES ONLY: no report path, no source file path, no symbol
-- name. The coverage report files are read from the project, capped, and
-- never stored; the duplication figure is rolled up from the codeintel
-- index already on this node.
--
-- A *_state column holds internal/codequality's closed State vocabulary
-- ('measured', 'no_report', 'codeintel_off', ...). The numeric columns are
-- meaningful only when the matching state is 'measured'; otherwise they are
-- 0 and every reader treats the metric as NOT MEASURED, never as zero.
--
-- NODE-LOCAL: never selected by internal/store/orgpush.go, pinned in the
-- forbidden-table sentinel (tests/invariant/privacy_test.go). No server pair
-- (an org roll-up is out of scope, plan 14.10).
--
-- Numbered 214 on main; renumbered to 219 when main merged into the release
-- line (plans decision log P-247), because the release line had also used
-- 214. Numbers 213, 214 and 216 are retired on both lines. The table is
-- created only when missing, so a database that ran main's 214 runs this
-- step again harmlessly; 221 adds its complexity columns.
CREATE TABLE IF NOT EXISTS project_quality_daily (
    project_id            INTEGER NOT NULL REFERENCES projects(id),
    day                   TEXT    NOT NULL,            -- UTC YYYY-MM-DD
    measured_at           TEXT    NOT NULL,            -- RFC3339 UTC
    coverage_state        TEXT    NOT NULL DEFAULT '',
    coverage_lines        INTEGER NOT NULL DEFAULT 0,  -- instrumented lines, counted reports
    coverage_covered      INTEGER NOT NULL DEFAULT 0,
    coverage_reports      INTEGER NOT NULL DEFAULT 0,  -- reports counted
    coverage_report_at    TEXT    NOT NULL DEFAULT '', -- newest counted report's mtime
    dup_state             TEXT    NOT NULL DEFAULT '',
    dup_eligible_symbols  INTEGER NOT NULL DEFAULT 0,
    dup_cloned_symbols    INTEGER NOT NULL DEFAULT 0,
    dup_eligible_lines    INTEGER NOT NULL DEFAULT 0,
    dup_cloned_lines      INTEGER NOT NULL DEFAULT 0,
    dup_groups            INTEGER NOT NULL DEFAULT 0,
    dup_indexed_at        TEXT    NOT NULL DEFAULT '', -- newest codeintel indexed_at
    PRIMARY KEY (project_id, day)
);

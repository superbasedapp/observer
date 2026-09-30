-- 130_project_activity_indexes.sql — covering indexes for the Projects-page
-- rework's [since,until) activity scans (2026-09-22 Sol adversarial
-- REWORK findings #4 / #5, following 129's precedent).
--
-- WHY. internal/store/projectroi.go::LoadProjectSessions (finding #4)
-- replaces four correlated `EXISTS` subqueries (each planned against
-- migration 129's idx_actions_project_type_ts using only its LEADING
-- project_id column, since the sessions query filters no action_type —
-- effectively a per-project full scan filtered by timestamp row-by-row)
-- with ONE UNION of in-window activity session ids, including
-- summary_calls (previously missed entirely). internal/store/locread.go
-- (finding #5) adds LoadProjectLOCWindowed, an EXACT [since,until)
-- project LOC loader built on locDedupCTESQL with the window bound
-- spliced into BOTH collapse-rule CTE arms — bounding the dedup
-- computation itself to the window instead of grouping the whole
-- file_changes table before filtering (measured on this box's corpus:
-- an index-wide scan plus a temporary B-tree for the unbounded GROUP BY).
--
-- Both new access patterns filter `file_changes`/`actions` by
-- (project_id, <event-time column>) with NO action_type/actor predicate
-- narrow enough for an existing index to seek on — idx_file_changes_
-- project_created (migration 103) leads with created_at, not saved_at
-- (an INGEST-time column, not the EVENT-time column these queries need),
-- and idx_actions_project_type_ts (migration 129) leads with
-- action_type, which these queries don't bind.
--
--   idx_actions_project_ts            actions(project_id, timestamp,
--                                      session_id) — LoadProjectSessions'
--                                      actions arm (session_id rides
--                                      along as a covering column so the
--                                      UNION doesn't need a row lookup).
--   idx_file_changes_project_saved    file_changes(project_id, saved_at,
--                                      session_id) — LoadProjectSessions'
--                                      file_changes arm AND
--                                      LoadProjectLOCWindowed's
--                                      single-project ([since,until) with
--                                      a bound project id) case.
--   idx_file_changes_saved_at         file_changes(saved_at) —
--                                      LoadProjectLOCWindowed's
--                                      ALL-PROJECTS case (the Projects
--                                      LIST's one-query-not-N+1 read,
--                                      projectID=0: no project_id bind,
--                                      so a project_id-leading index
--                                      can't be seeked, but this one can).
--
-- Index-only: no column, no table, no wire shape change. NODE-LOCAL by
-- construction (actions/file_changes were already node-local); no
-- paired server migration, no privacy-sentinel change (no new table
-- name).

CREATE INDEX IF NOT EXISTS idx_actions_project_ts
    ON actions(project_id, timestamp, session_id);

CREATE INDEX IF NOT EXISTS idx_file_changes_project_saved
    ON file_changes(project_id, saved_at, session_id);

CREATE INDEX IF NOT EXISTS idx_file_changes_saved_at
    ON file_changes(saved_at);

-- 217_process_runs_service_root_idx.sql - the process capture summary's
-- service lookup (docs/plans/process-capture-budget-plan-2026-11-04.md §9.3,
-- GET /api/session/<id>/processes/summary).
--
-- The summary lists a session's service roots (capture_class 'service_root')
-- and totals the rows kept under each one (capture_class 'service'). Both
-- carry service_root_key; every other row (exemplars, legacy rows written
-- before the budget) has it NULL. Without this index the lookup walks every
-- one of the session's rows through idx_process_runs_session and fetches each
-- to test the class: on the measured 92,428-row session that is the whole
-- session per summary poll. The PARTIAL index holds only the service rows, a
-- few dozen per session, so the read is an index range scan over them. Queries
-- that want it repeat the predicate (service_root_key IS NOT NULL) verbatim so
-- SQLite's partial-index implication check matches.
--
-- NODE-LOCAL index only (process_runs is pinned out of orgpush.go by
-- tests/invariant/privacy_test.go): no column, no wire shape, no server pair.
--
-- Numbered 213 on main; renumbered to 217 when main merged into the release
-- line (plans decision log P-247), because the release line had also used
-- 213. Numbers 213, 214 and 216 are retired on both lines. The index is
-- IF NOT EXISTS, so a database that ran main's 213 runs this step again
-- harmlessly.
CREATE INDEX IF NOT EXISTS idx_process_runs_session_service
    ON process_runs(session_id, service_root_key)
    WHERE service_root_key IS NOT NULL;

-- 138_actions_timestamp_cover_idx.sql — covering index for the dashboard's
-- time-window analytics over `actions` (optimization review 2026-09-27,
-- docs/audits/optimization-review-2026-09-27.md, finding N2).
--
-- WHY. An `actions` row averages ~4.7 KB on a real corpus (raw_tool_input /
-- raw_tool_output / preceding_reasoning live in the row), so with 4 KB pages
-- almost every row spills into overflow pages, and the columns the
-- analytics read (`tool`, `is_sidechain`, ...) sit AFTER those large text
-- columns in the row. Every "last N days, grouped by tool/type" read therefore
-- paid one random row fetch plus an overflow-chain walk per action: on the
-- reference 936k-action / 21 GB node that was 1.3-2.4 s per query for
-- /api/tools, /api/tools/breakdown (two passes), /api/timeseries/actions,
-- /api/status/scoped, /api/discover's totals, and the unwindowed
-- /api/status per-tool scan (a full 4.5 GB table scan, 2.3 s warm / 21 s
-- cold). With this index each of those becomes an index-only range scan
-- (measured 0.05-0.9 s, see the audit's before/after table).
--
-- The leading column is `timestamp`, so this index SUBSUMES
-- idx_actions_timestamp(timestamp) from 001_initial.sql: every plan that
-- seeked or ordered on that index can use this one's prefix instead (same
-- ordering, same seek). It is dropped so the net per-insert index
-- maintenance on `actions` stays one index wider rather than one index more.
--
-- raw_tool_name rides along for /api/tools/breakdown's surface pass; it is a
-- short tool name (e.g. "Bash", "mcp__x__y"), not content. `target` is
-- deliberately NOT included (commands/paths are long and would triple the
-- index).
--
-- Index-only: no column, no table, no wire shape change. NODE-LOCAL by
-- construction (actions is node-local, migration 001); no paired server
-- migration, no privacy-sentinel change (no new table name).

CREATE INDEX IF NOT EXISTS idx_actions_ts_cover
    ON actions(timestamp, tool, action_type, raw_tool_name, session_id,
               project_id, success, is_native_tool, is_sidechain);

DROP INDEX IF EXISTS idx_actions_timestamp;

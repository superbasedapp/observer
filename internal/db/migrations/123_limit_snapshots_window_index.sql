-- 123_limit_snapshots_window_index.sql — the missing covering index for
-- store.LatestLimitWindows (the §12.1 B-610..B-613 limit rules' only read
-- of limit_snapshots).
--
-- That query is:
--
--   SELECT window_5h_util, window_7d_util FROM limit_snapshots
--    WHERE window_5h_util IS NOT NULL OR window_7d_util IS NOT NULL
--    ORDER BY observed_at DESC, id DESC LIMIT 1
--
-- and migration 049 gave the table exactly one index,
-- idx_limit_snapshots_scope (scope_hash, provider, observed_at DESC),
-- whose leading column the query does not constrain. EXPLAIN QUERY PLAN
-- therefore showed `SCAN limit_snapshots` + `USE TEMP B-TREE FOR ORDER BY`:
-- the whole table read and sorted to return one row. On the operator's live
-- node (178k rows) that ran past the guard poll's 3 s deadline on EVERY
-- poll — 185 `guard: limit-window lookup failed` lines in one daemon log.
--
-- The index is PARTIAL on exactly the query's WHERE clause, so it indexes
-- only the windowed rows (a minority: most snapshots carry request/token
-- headers but no subscription-window headers) and SQLite can satisfy both
-- the filter and the ORDER BY by walking its first entry. Writes pay for
-- one extra b-tree entry only on rows that actually carry a window.
--
-- NODE-LOCAL, like the table it indexes (migration 049): an index adds no
-- column, no wire shape and no row, so there is no paired server migration
-- and nothing changes for internal/store/orgpush.go.

CREATE INDEX IF NOT EXISTS idx_limit_snapshots_window
    ON limit_snapshots(observed_at DESC, id DESC)
    WHERE window_5h_util IS NOT NULL OR window_7d_util IS NOT NULL;

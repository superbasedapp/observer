-- 147_dashboard_read_indexes.sql — read-path indexes for the node dashboard
-- (node dashboard performance audit 2026-09-29,
-- docs/audits/node-dashboard-performance-audit-2026-09-29.md). Every number
-- below was measured on a VACUUM INTO copy of a real 27 GB node DB (990k
-- actions, 239k api_turns, 476k token_usage, 179k limit_snapshots) with the
-- daemon's own driver (modernc.org/sqlite), warm cache, identical result
-- digests before and after.
--
-- Index-only: no column, no table, no wire shape change. Every table here is
-- NODE-LOCAL; no paired server migration, no privacy-sentinel change (no new
-- table name).

-- (1) Excerpt lookup by action id. action_excerpts is an FTS5 table whose
-- action_id column is UNINDEXED, so `WHERE action_id IN (...)` (the session
-- Messages tab on every poll, the Actions page) was a FULL scan of every
-- excerpt: 450k rows / 351 MB, half the CPU of a Messages poll. FTS5 keeps its
-- stored columns in the ordinary shadow table action_excerpts_content (c0 is
-- the first declared column, action_id). An ordinary index on it lets the
-- reader resolve action ids to FTS rowids by seek and fetch those rows by
-- rowid equality (dashboard.loadActionExcerpts): 0.6-2.0 s -> 2-22 ms for 400
-- ids. SQLite maintains the index on every FTS5 insert / delete / rebuild
-- (FTS5 writes the shadow table with plain SQL), so every existing writer
-- keeps it consistent with no code change; dropping the virtual table drops
-- it together with the shadow table. 5 MB.
CREATE INDEX IF NOT EXISTS idx_action_excerpts_content_c0
    ON action_excerpts_content(c0);

-- (2) Per-session activity in a time window. The Sessions list (and the
-- Overview recent-sessions tile) filters every session through
-- `EXISTS (SELECT 1 FROM <t> WHERE session_id = s.id AND timestamp >= ?)` on
-- actions, api_turns and token_usage, three times per request (total,
-- scored_count, page). With only session_id-leading indexes each EXISTS walked
-- every row of an old session looking for a recent one: 1.9 s per COUNT on the
-- reference node, 7-26 s per /api/sessions request under load, and the page
-- polled it every 5 s. With (session_id, timestamp) each EXISTS is one seek:
-- 22-42 ms. The same indexes serve the session drawer's per-session loaders
-- (ORDER BY timestamp). Each subsumes the single-column session_id index on
-- the same table (same leading column, so every plan that seeked it can use
-- the prefix), which is dropped so the per-insert index count is unchanged.
-- 72 / 17 / 35 MB.
CREATE INDEX IF NOT EXISTS idx_actions_session_ts
    ON actions(session_id, timestamp);
DROP INDEX IF EXISTS idx_actions_session;

CREATE INDEX IF NOT EXISTS idx_api_turns_session_ts
    ON api_turns(session_id, timestamp);
DROP INDEX IF EXISTS idx_api_turns_session;

CREATE INDEX IF NOT EXISTS idx_token_usage_session_ts
    ON token_usage(session_id, timestamp);
DROP INDEX IF EXISTS idx_token_usage_session;

-- (3) Latest rate-limit snapshot per provider for a tool
-- (store.LatestLimitSnapshotForTool, behind the session drawer's limit gauge,
-- polled every 15 s). The ORDER BY observed_at DESC, id DESC LIMIT 1 had no
-- provider-leading index in that order, so every call sorted the whole table
-- (179k rows): 0.5-0.7 s. Walking this index newest-first stops at the first
-- row whose session matches the tool: ~1 ms. 5 MB.
CREATE INDEX IF NOT EXISTS idx_limit_snapshots_provider_observed
    ON limit_snapshots(provider, observed_at DESC, id DESC);

-- (4) Reads of one action type grouped / matched by target. /api/discover's
-- repeated-command pass (`action_type = 'run_command' AND timestamp >= ?`
-- GROUP BY target, project_id), its no-change-rerun pass, and the
-- stale-read / cross-tool passes (whose correlated EXISTS match
-- `action_type = 'read_file' AND target = ? AND session_id = ? AND
-- project_id = ? AND timestamp < ?`) could only seek idx_actions_type, so
-- every run_command in HISTORY (293k) paid a random row fetch into the 4.7 GB
-- actions table: 31-36 s for the repeated-commands pass alone, 147-156 s for
-- the whole endpoint, which also feeds /api/analysis/headline. With this
-- covering index the repeated-commands pass is an index-only scan of the type
-- (1.0 s) and every correlated stale-read probe is one seek on all five
-- columns (the whole stale-read pass 0.17-0.29 s).
--
-- Column order is deliberate. A (action_type, timestamp, ...) variant was
-- measured too: it made the repeated-commands pass windowed, but because it
-- is covering, the planner (no sqlite_stat1) preferred it for the stale-read
-- EXISTS probes over the 4-column seek on
-- idx_actions_session_target_action_ts, turning each probe into a scan of
-- every older read and the pass into minutes. With target second, every
-- probe that names a target seeks it.
--
-- `target` makes the index large (316 MB on the reference node, about
-- 1 % of the file) because run_command targets are long; that is the
-- measured price of turning the Overview's slowest panel from minutes into
-- about a second. idx_actions_type stays: it is the narrow index for
-- whole-history counts by type.
CREATE INDEX IF NOT EXISTS idx_actions_type_target_cover
    ON actions(action_type, target, session_id, project_id, timestamp, success);

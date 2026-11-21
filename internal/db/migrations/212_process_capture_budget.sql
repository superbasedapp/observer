-- 212_process_capture_budget.sql - the process capture budget's node-local
-- tables (docs/plans/process-capture-budget-plan-2026-11-04.md §9.2,
-- docs/process-observability.md §11 "Capture budget").
--
-- process_rollups holds the runs the decision table (internal/proccapture)
-- did not keep as their own process_runs row: folded console hosts, runs past
-- an exemplar budget, a service's subtree past its exemplar cap, and (with
-- session_id NULL) the machine-level rollup the unattributed policy writes.
-- One row per (session, bucket, group kind, parent, service root, executable,
-- argv template); an upsert ADDS to the counters, so counts stay exact.
--
-- process_capture_stats is one row per session ('' for the machine) of the
-- capture counters. The count invariant (plan §5): kept + folded + rolled_up +
-- service_kept + service_rolled_up + dropped == observed.
--
-- process_runs gains capture_class (exemplar / service_root / service; NULL
-- for rows written before the budget), service_root_key and fold_count (how
-- many folded runs this row absorbed).
--
-- All three are NODE-LOCAL: the two new tables join the privacy sentinel in
-- tests/invariant/privacy_test.go like process_runs. internal/store/
-- processrollups.go is the one writer of the two new tables;
-- internal/store/processobs.go stays the one writer of process_runs.
--
-- No foreign keys: rollups and stats are pruned by time with the rest of the
-- process capture ([observer.process].retention_days), and a session delete
-- must not scan them (internal/db/fkindex_test.go).

CREATE TABLE IF NOT EXISTS process_rollups (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id            TEXT,
    bucket_start          TEXT NOT NULL,
    group_kind            TEXT NOT NULL,
    parent_process_key    TEXT NOT NULL DEFAULT '',
    action_id             INTEGER,
    service_root_key      TEXT NOT NULL DEFAULT '',
    exe_basename          TEXT NOT NULL DEFAULT '',
    argv_template_hash    TEXT NOT NULL DEFAULT '',
    example_argv_preview  TEXT,
    example_process_key   TEXT,
    count                 INTEGER NOT NULL DEFAULT 0,
    failed_count          INTEGER NOT NULL DEFAULT 0,
    duration_sum_ms       INTEGER NOT NULL DEFAULT 0,
    duration_max_ms       INTEGER NOT NULL DEFAULT 0,
    cpu_sum_ms            INTEGER NOT NULL DEFAULT 0,
    peak_rss_bytes        INTEGER NOT NULL DEFAULT 0,
    first_seen            TEXT,
    last_seen             TEXT
);

-- The group key. SQLite treats NULLs as distinct in a UNIQUE index, so the
-- machine rollup (session_id NULL) is merged by the writer's NULL-safe
-- UPDATE-then-INSERT rather than by ON CONFLICT; the index still guards every
-- session's groups.
CREATE UNIQUE INDEX IF NOT EXISTS idx_process_rollups_group
    ON process_rollups(session_id, bucket_start, group_kind, parent_process_key,
                       service_root_key, exe_basename, argv_template_hash);

-- Summary reads: one session's rollups by count, and the retention sweep by
-- bucket.
CREATE INDEX IF NOT EXISTS idx_process_rollups_session_count
    ON process_rollups(session_id, count);
CREATE INDEX IF NOT EXISTS idx_process_rollups_bucket
    ON process_rollups(bucket_start);

CREATE TABLE IF NOT EXISTS process_capture_stats (
    session_id         TEXT PRIMARY KEY,
    observed           INTEGER NOT NULL DEFAULT 0,
    kept               INTEGER NOT NULL DEFAULT 0,
    folded             INTEGER NOT NULL DEFAULT 0,
    rolled_up          INTEGER NOT NULL DEFAULT 0,
    service_kept       INTEGER NOT NULL DEFAULT 0,
    service_rolled_up  INTEGER NOT NULL DEFAULT 0,
    dropped            INTEGER NOT NULL DEFAULT 0,
    budget_hits        INTEGER NOT NULL DEFAULT 0,
    updated_at         TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_process_capture_stats_updated
    ON process_capture_stats(updated_at);

ALTER TABLE process_runs ADD COLUMN capture_class    TEXT;
ALTER TABLE process_runs ADD COLUMN service_root_key TEXT;
ALTER TABLE process_runs ADD COLUMN fold_count       INTEGER NOT NULL DEFAULT 0;

-- The unattributed policy's batch scan (session_id IS NULL, oldest first)
-- rides the existing (session_id, started_at) index.

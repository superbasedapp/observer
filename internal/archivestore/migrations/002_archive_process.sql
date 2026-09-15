-- 002_archive_process.sql — cold storage for Bucket B of the corpus archival
-- arc (docs/plans/observer-corpus-archival-lazyload-design-2026-08-26.md §2.2,
-- §3.1, §9 task P3.1). These tables live in ~/.observer/archive.db.
--
-- BUCKET B IS THE ONLY-COPY BUCKET. Bucket A (codeintel, migration 001) is
-- regenerable: a defect there costs a re-index. These rows are live eBPF/ETW/
-- poll capture of processes that have since exited — there is no artifact on
-- disk to re-derive them from, so once they move here, THIS IS THE DATA. Every
-- decision below follows from that.
--
-- 1. COLUMN SHAPES MIRROR THE HOT TABLES EXACTLY, with no transform (§3.1) and
--    one added column (archived_at). The mover copies BY COLUMN NAME using the
--    column list the driver reports for the hot table, so a column present hot
--    and missing here fails LOUDLY at copy time — before any delete — instead
--    of being silently dropped. Keep this file in lockstep with agent
--    migrations 044 (process_runs 50 cols, process_events 15 cols), 045
--    (+6 process_runs metric cols) and 067 (process_network_bodies).
--
-- 2. NO FOREIGN KEYS. Same reasoning as migration 001: every write and delete
--    here is already scoped by day or by the parent's id set in one statement,
--    the cascade buys nothing, and hot-side cascade behaviour is exactly what
--    made the equivalent codeintel delete pathological. Referential integrity
--    comes from the mover copying a whole window atomically.
--
-- 3. process_key IS NOT UNIQUE HERE, unlike the hot table. Idempotency of a
--    re-copy after a crash rides on the PRESERVED id (INSERT OR REPLACE keyed
--    on the primary key). A UNIQUE(process_key) would instead make a re-copy
--    fail — or, worse, silently replace a different row — the moment a run was
--    ever re-keyed. An index gives the lookup speed without the failure mode.
--
-- 4. ROW IDS ARE PRESERVED. process_events.process_run_id references
--    process_runs.id and process_network_bodies.process_event_id references
--    process_events.id; a renumbered copy would rehydrate into a trail whose
--    every body is attached to the wrong request.
--
-- NODE-LOCAL, and pinned as such: the archive_process_* names are in
-- tests/invariant/privacy_test.go's forbidden-name sentinel, and orgpush.go
-- cannot reach a second database handle by construction.

CREATE TABLE IF NOT EXISTS archive_process_runs (
    id                       INTEGER PRIMARY KEY,   -- preserved hot process_runs.id
    process_key              TEXT NOT NULL,
    boot_id                  TEXT,
    pid                      INTEGER NOT NULL,
    ppid                     INTEGER,
    start_time_ticks         INTEGER,
    parent_process_key       TEXT,
    session_id               TEXT,
    project_id               INTEGER,
    tool                     TEXT,
    action_id                INTEGER,
    turn_index               INTEGER,
    attribution_source       TEXT,
    attribution_confidence   TEXT,
    exe_path                 TEXT,
    exe_basename             TEXT,
    exe_device               TEXT,
    exe_inode                TEXT,
    exe_hash                 TEXT,
    cwd                      TEXT,
    argv_preview             TEXT,
    argv_hash                TEXT,
    argv_argc                INTEGER,
    uid                      INTEGER,
    gid                      INTEGER,
    euid                     INTEGER,
    egid                     INTEGER,
    username                 TEXT,
    cgroup_hash              TEXT,
    container_id             TEXT,
    pid_namespace            TEXT,
    mount_namespace          TEXT,
    net_namespace            TEXT,
    seccomp_mode             TEXT,
    apparmor_label           TEXT,
    selinux_label            TEXT,
    capabilities_eff         TEXT,
    env_posture_json         TEXT,
    started_at               TEXT,
    last_seen_at             TEXT,
    exited_at                TEXT,
    exit_code                INTEGER,
    exit_signal              INTEGER,
    duration_ms              INTEGER,
    cpu_user_ms              INTEGER,
    cpu_system_ms            INTEGER,
    max_rss_bytes            INTEGER,
    read_bytes               INTEGER,
    write_bytes              INTEGER,
    metadata_json            TEXT,
    working_set_bytes        INTEGER,
    thread_count             INTEGER,
    handle_count             INTEGER,
    read_ops                 INTEGER,
    write_ops                INTEGER,
    metric_samples_json      TEXT,
    archived_at              INTEGER NOT NULL DEFAULT 0
);
-- started_at leads the day-window sweep (archive + cold expiry); session_id
-- leads the direct-read path a dashboard uses on a hot miss (§4.3).
CREATE INDEX IF NOT EXISTS idx_archive_process_runs_started
    ON archive_process_runs(started_at);
CREATE INDEX IF NOT EXISTS idx_archive_process_runs_session
    ON archive_process_runs(session_id, started_at);
CREATE INDEX IF NOT EXISTS idx_archive_process_runs_key
    ON archive_process_runs(process_key);

CREATE TABLE IF NOT EXISTS archive_process_events (
    id                       INTEGER PRIMARY KEY,   -- preserved hot process_events.id
    process_run_id           INTEGER,
    process_key              TEXT,
    timestamp                TEXT,
    event_type               TEXT,
    session_id               TEXT,
    project_id               INTEGER,
    tool                     TEXT,
    action_id                INTEGER,
    turn_index               INTEGER,
    target_kind              TEXT,
    target                   TEXT,
    target_hash              TEXT,
    severity                 TEXT,
    finding_rule_id          TEXT,
    details_json             TEXT,
    archived_at              INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_archive_process_events_ts
    ON archive_process_events(timestamp);
-- (event_type, session_id, timestamp) mirrors the hot read predicate the
-- direct-read fallback reuses verbatim: network events for one session.
CREATE INDEX IF NOT EXISTS idx_archive_process_events_type_session
    ON archive_process_events(event_type, session_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_archive_process_events_run
    ON archive_process_events(process_run_id);

CREATE TABLE IF NOT EXISTS archive_process_network_bodies (
    id                       INTEGER PRIMARY KEY,   -- preserved hot id
    process_event_id         INTEGER NOT NULL,
    capture_source           TEXT,
    api_turn_id              INTEGER,
    request_id               TEXT,
    method                   TEXT,
    url                      TEXT,
    host                     TEXT,
    status_code              INTEGER,
    duration_ms              INTEGER,
    request_headers_json     TEXT,
    response_headers_json    TEXT,
    request_body             TEXT,
    request_body_sha256      TEXT,
    request_body_bytes       INTEGER,
    request_body_truncated   INTEGER,
    response_body            TEXT,
    response_body_sha256     TEXT,
    response_body_bytes      INTEGER,
    response_body_truncated  INTEGER,
    response_content_type    TEXT,
    body_unavailable_reason  TEXT,
    created_at               TEXT,
    archived_at              INTEGER NOT NULL DEFAULT 0
);
-- NOT unique, unlike the hot index: uniqueness there is a live-capture
-- invariant, and enforcing it on the cold side would turn a re-copy after a
-- crash from an idempotent upsert into a hard failure.
CREATE INDEX IF NOT EXISTS idx_archive_process_network_bodies_event
    ON archive_process_network_bodies(process_event_id);

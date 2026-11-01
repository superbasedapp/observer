-- 198_hook_activity.sql - hook liveness: which hooks actually fired
-- (surface-gap review 2026-10-25, findings OBS-7 and CC-2, Wave 5 item 1;
-- docs/audits/surface-settings-precedence-gap-review-2026-10-25.md section
-- 3.6).
--
-- Before this table nothing recorded a SUCCESSFUL hook invocation:
-- guard_events holds rule hits and gate-hook failures only, and capture
-- integrity is artifact-only (checksums, drift, trust). A captured session
-- whose hooks never fired (a host that never runs hooks, a project
-- disableAllHooks, a --no-hooks flag, a missing shell) was invisible.
--
-- One row per (tool, event, session_id): how many invocations the daemon
-- drained and when the first and last one ran. event is the registry
-- binding's native event when the invocation resolved to one, else the argv
-- spelling as invoked. session_id = '' is the EXPLICIT unattributed bucket:
-- invocations whose payload carried no session id (or a receiver that does
-- not report one). It can never prove per-session liveness, and
-- internal/hookliveness never treats it as if it did.
--
-- env_classes is a JSON object of route-relevant environment variable NAMES
-- the hook process saw, each mapped to a coarse class (internal/hookliveness
-- EnvProbes: "set", "loopback", "provider_direct", "other_host", "invalid",
-- or a 16-hex path hash for a config-dir variable). Never a value.
--
-- Write path: the hook process never opens SQLite (internal/hookspool/doc.go
-- says why). Each invocation appends one DB-free activity record to the hook
-- spool; the daemon's single drainer (cmd/observer/hook_lifecycle_wire.go)
-- calls the ONE writer, store.UpsertHookActivity
-- (internal/store/hookactivity.go).
--
-- NODE-LOCAL: never selected by internal/store/orgpush.go; pinned in
-- tests/invariant/privacy_test.go (forbiddenCacheTables). Per-session org
-- reach is decision D14 and needs its own wire row. NO server pair.

CREATE TABLE IF NOT EXISTS hook_activity (
    tool        TEXT    NOT NULL,
    event       TEXT    NOT NULL,
    session_id  TEXT    NOT NULL DEFAULT '',
    count       INTEGER NOT NULL DEFAULT 0,
    first_at    TEXT    NOT NULL,
    last_at     TEXT    NOT NULL,
    env_classes TEXT    NOT NULL DEFAULT '',
    PRIMARY KEY (tool, event, session_id)
);

CREATE INDEX IF NOT EXISTS idx_hook_activity_session ON hook_activity(session_id);
CREATE INDEX IF NOT EXISTS idx_hook_activity_last_at ON hook_activity(last_at);

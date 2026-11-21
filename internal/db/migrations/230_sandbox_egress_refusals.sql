-- 230_sandbox_egress_refusals.sql - the sandbox egress refusal audit
-- (OpenShell build plan 05 section 3.1, the frozen N1 contract; agent
-- migration block 230 to 239 reserved by plan 05 section 4).
--
-- One row per refused egress attempt of a sandboxed run, at most one per
-- (run, host) per wall-clock minute: the gateway in the run's host helper
-- refuses a request, the helper hands the refusal to the daemon over the
-- capture relay link (a helper never opens the database), and the daemon
-- writes it through the ONE store seam internal/store/sandboxegress.go.
--
--   run_id        the stored terminal run (terminal_run.run_id) the relay
--                 run belongs to, or the relay run id when the run has no
--                 stored row; from the relay channel, never from the box
--   project_root  the run record's project attribution (host side)
--   backend       the run's isolation stack (terminal_run.stack) when known
--   tier          the run's egress tier (terminal_run.egress_tier)
--   host, port    the refused target as the box named it
--   rule          internal/sandboxnet.RefusalRule, a closed vocabulary
--   rule_key      the config or pin key that decided
--   minute_bucket Unix minutes of refused_at; the unique key on
--                 (run_id, host, minute_bucket) is the flood bound's last
--                 line (INSERT OR IGNORE)
--   refused_at    fixed-width RFC 3339 UTC
--
-- Retention: rows older than store.SandboxEgressRefusalRetention (30 days)
-- are pruned by the daemon's refusal receiver.
--
-- NODE-LOCAL: never selected by internal/store/orgpush.go (decision D6,
-- refusal events stay on the node in v1); pinned in
-- tests/invariant/privacy_test.go (forbiddenCacheTables). NO server pair.

CREATE TABLE IF NOT EXISTS sandbox_egress_refusals (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id        TEXT    NOT NULL,
    project_root  TEXT    NOT NULL DEFAULT '',
    backend       TEXT    NOT NULL DEFAULT '',
    tier          TEXT    NOT NULL DEFAULT '',
    host          TEXT    NOT NULL,
    port          INTEGER NOT NULL DEFAULT 0,
    rule          TEXT    NOT NULL,
    rule_key      TEXT    NOT NULL DEFAULT '',
    minute_bucket INTEGER NOT NULL,
    refused_at    TEXT    NOT NULL,
    UNIQUE (run_id, host, minute_bucket)
);

CREATE INDEX IF NOT EXISTS idx_sandbox_egress_refusals_run ON sandbox_egress_refusals(run_id, refused_at);
CREATE INDEX IF NOT EXISTS idx_sandbox_egress_refusals_project ON sandbox_egress_refusals(project_root, refused_at);
CREATE INDEX IF NOT EXISTS idx_sandbox_egress_refusals_at ON sandbox_egress_refusals(refused_at);

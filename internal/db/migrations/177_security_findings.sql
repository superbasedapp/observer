-- 177_security_findings.sql - the security pillar's findings store, the
-- four tables the module root (component `security`) owns (security pillar
-- plan docs/plans/security-pillar-plan-2026-10-19.md section 4.6, Phase A).
-- NODE-LOCAL: all four are in the privacy sentinel's forbidden-table list,
-- so internal/store/orgpush.go can never select them by name; org rows are
-- composed later through the SecurityOrgProviders function seam (Phase E).
-- NO server pair. One writer: internal/store/secfindings.go.
--
-- There is one embedded migration lineage, so these tables exist (empty) in
-- every build, including one compiled with sbo_omit_security (section 4.3).
--
-- Never content: paths, line numbers, redacted capped evidence and hashes,
-- never file contents or a secret value (CLAUDE.md "Don't store file
-- contents").

-- One row per open-or-closed finding, unique per project on its
-- location-free lifecycle key (section 4.5.1).
CREATE TABLE IF NOT EXISTS sec_findings (
    id                     TEXT    PRIMARY KEY,
    project_root_hash      TEXT    NOT NULL,
    local_key              TEXT    NOT NULL,
    org_key                TEXT    NOT NULL DEFAULT '',
    rel_path               TEXT    NOT NULL DEFAULT '',
    start_line             INTEGER NOT NULL DEFAULT 0,
    end_line               INTEGER NOT NULL DEFAULT 0,
    path_aliases_json      TEXT    NOT NULL DEFAULT '',
    rule_id                TEXT    NOT NULL,
    rule_version           TEXT    NOT NULL DEFAULT '',
    rule_pack              TEXT    NOT NULL DEFAULT '',
    rule_pack_version      TEXT    NOT NULL DEFAULT '',
    driver                 TEXT    NOT NULL DEFAULT '',
    driver_version         TEXT    NOT NULL DEFAULT '',
    engine_digest          TEXT    NOT NULL DEFAULT '',
    database_epoch         TEXT    NOT NULL DEFAULT '',
    category               TEXT    NOT NULL,
    severity               TEXT    NOT NULL,
    confidence             TEXT    NOT NULL,
    refs_json              TEXT    NOT NULL DEFAULT '',
    scope                  TEXT    NOT NULL DEFAULT '',
    project_identity_hash  TEXT    NOT NULL DEFAULT '',
    org_project_id         TEXT    NOT NULL DEFAULT '',
    evidence_redacted      TEXT    NOT NULL DEFAULT '',
    evidence_hash          TEXT    NOT NULL DEFAULT '',
    message                TEXT    NOT NULL DEFAULT '',
    fix_hint               TEXT    NOT NULL DEFAULT '',
    baseline               TEXT    NOT NULL DEFAULT 'unknown',
    baseline_ref_json      TEXT    NOT NULL DEFAULT '',
    attribution            TEXT    NOT NULL DEFAULT 'unknown',
    attribution_method     TEXT    NOT NULL DEFAULT '',
    attribution_confidence TEXT    NOT NULL DEFAULT '',
    -- Nullable: a session purge drops the lineage link (null_link).
    session_id             TEXT             DEFAULT '',
    action_id              TEXT    NOT NULL DEFAULT '',
    prompt_action_id       TEXT    NOT NULL DEFAULT '',
    tool                   TEXT    NOT NULL DEFAULT '',
    tool_version           TEXT    NOT NULL DEFAULT '',
    model                  TEXT    NOT NULL DEFAULT '',
    surface                TEXT    NOT NULL DEFAULT '',
    taint_at_write         INTEGER NOT NULL DEFAULT 0,
    taint_origin_class     TEXT    NOT NULL DEFAULT '',
    commit_sha             TEXT    NOT NULL DEFAULT '',
    patch_fp               TEXT    NOT NULL DEFAULT '',
    landed                 INTEGER NOT NULL DEFAULT 0,
    status                 TEXT    NOT NULL DEFAULT 'open',
    first_seen             TEXT    NOT NULL,
    last_seen              TEXT    NOT NULL,
    closed_at              TEXT    NOT NULL DEFAULT '',
    fix_json               TEXT    NOT NULL DEFAULT '',
    exception_id           TEXT    NOT NULL DEFAULT '',
    verdict_ids_json       TEXT    NOT NULL DEFAULT '',
    UNIQUE (project_root_hash, local_key)
);
CREATE INDEX IF NOT EXISTS idx_sec_findings_project_status ON sec_findings (project_root_hash, status);
CREATE INDEX IF NOT EXISTS idx_sec_findings_closed ON sec_findings (status, closed_at);

-- Append-only lifecycle: seen, closed, reopened, suppressed, exception
-- expired, verdict referenced, baseline set, baseline reset.
CREATE TABLE IF NOT EXISTS sec_finding_events (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id        TEXT    NOT NULL DEFAULT '',
    project_root_hash TEXT    NOT NULL,
    kind              TEXT    NOT NULL CHECK (kind IN ('seen', 'closed', 'reopened', 'suppressed',
                                                       'exception_expired', 'verdict_referenced',
                                                       'baseline_set', 'baseline_reset')),
    detail            TEXT    NOT NULL DEFAULT '',
    at                TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sec_finding_events_finding ON sec_finding_events (finding_id, id);

-- One row per driver run: driver, scope, target, coverage, engine
-- identity, duration, outcome.
CREATE TABLE IF NOT EXISTS sec_scan_runs (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    project_root_hash TEXT    NOT NULL,
    driver            TEXT    NOT NULL,
    scope             TEXT    NOT NULL,
    target_json       TEXT    NOT NULL DEFAULT '',
    coverage_json     TEXT    NOT NULL DEFAULT '',
    engine_json       TEXT    NOT NULL DEFAULT '',
    outcome           TEXT    NOT NULL CHECK (outcome IN ('clean', 'findings', 'unknown', 'not_scanned', 'failed')),
    findings          INTEGER NOT NULL DEFAULT 0,
    started_at        TEXT    NOT NULL,
    duration_ms       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_sec_scan_runs_project ON sec_scan_runs (project_root_hash, started_at);

-- The baselines (section 4.5.2): an approved commit or a signed CI result,
-- who approved it, when, and the versions in force. Newest row per project
-- wins; a reset is a row too, never an update.
CREATE TABLE IF NOT EXISTS sec_baselines (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    project_root_hash TEXT    NOT NULL,
    kind              TEXT    NOT NULL CHECK (kind IN ('commit', 'ci_result', 'reset')),
    ref               TEXT    NOT NULL DEFAULT '',
    approver          TEXT    NOT NULL DEFAULT '',
    pack_version      TEXT    NOT NULL DEFAULT '',
    policy_version    TEXT    NOT NULL DEFAULT '',
    created_at        TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sec_baselines_project ON sec_baselines (project_root_hash, id);

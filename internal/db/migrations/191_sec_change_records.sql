-- 191_sec_change_records.sql - the signed AI change record per commit
-- (security pillar plan sections 5.9 and 7.10, ruling Q8; component
-- security.provenance; lane sec-f2a).
--
-- sec_change_records: one row per (project, commit, signing key), the
-- DSSE envelope as signed (canonical JSON) plus the summary columns the
-- org wire row (orgcontract.AIChangeRecordRow) is read from. The envelope
-- holds path hashes and counts only, never prompt text; paths_json is the
-- commit's changed paths, read only under raw content.
--
-- sec_change_keys: the node's signing keys (public half and key id only;
-- the private key lives in the OS keychain through internal/keystore, or
-- its 0600 file fallback reported as file_key). A rotated key is retired,
-- never deleted, so its records stay verifiable.
--
-- sec_change_consent: the per-repository consent a person gave for the
-- repository writers (git notes, the commit trailer). Revoking clears the
-- flags and keeps the row's history in revoked_at.
--
-- NODE-LOCAL: all three stay in the privacy sentinel's forbidden-table
-- list; the change record rows reach the org only through the
-- SecurityOrgProviders function seam. NO server pair (the server's table
-- is server 249 / pg 0116, lane sec-e2). One writer:
-- internal/store/secchange.go.

CREATE TABLE IF NOT EXISTS sec_change_records (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id         INTEGER NOT NULL DEFAULT 0,
    project_root_hash  TEXT    NOT NULL,
    commit_sha         TEXT    NOT NULL,
    tree_sha           TEXT    NOT NULL,
    patch_fp           TEXT    NOT NULL DEFAULT '',
    key_id             TEXT    NOT NULL,
    attestation_level  TEXT    NOT NULL,
    key_storage        TEXT    NOT NULL,
    record_digest      TEXT    NOT NULL,
    envelope           TEXT    NOT NULL,
    files              INTEGER NOT NULL DEFAULT 0,
    ai_lines           INTEGER NOT NULL DEFAULT 0,
    human_lines        INTEGER NOT NULL DEFAULT 0,
    unknown_lines      INTEGER NOT NULL DEFAULT 0,
    human_capture      TEXT    NOT NULL DEFAULT 'none',
    sessions_json      TEXT    NOT NULL DEFAULT '[]',
    models_json        TEXT    NOT NULL DEFAULT '[]',
    tools_json         TEXT    NOT NULL DEFAULT '[]',
    scanners_json      TEXT    NOT NULL DEFAULT '[]',
    packs_json         TEXT    NOT NULL DEFAULT '[]',
    exceptions_json    TEXT    NOT NULL DEFAULT '[]',
    paths_json         TEXT    NOT NULL DEFAULT '[]',
    findings_open      INTEGER NOT NULL DEFAULT 0,
    findings_blocking  INTEGER NOT NULL DEFAULT 0,
    evidence_digest    TEXT    NOT NULL DEFAULT '',
    committed_at       TEXT    NOT NULL,
    recorded_at        TEXT    NOT NULL,
    note_written_at    TEXT    NOT NULL DEFAULT '',
    UNIQUE (project_root_hash, commit_sha, key_id)
);

CREATE INDEX IF NOT EXISTS idx_sec_change_records_recorded ON sec_change_records (recorded_at);
CREATE INDEX IF NOT EXISTS idx_sec_change_records_commit ON sec_change_records (commit_sha);
CREATE INDEX IF NOT EXISTS idx_sec_change_records_patch ON sec_change_records (patch_fp) WHERE patch_fp != '';

CREATE TABLE IF NOT EXISTS sec_change_keys (
    key_id      TEXT    PRIMARY KEY,
    public_key  TEXT    NOT NULL,
    storage     TEXT    NOT NULL,
    attestation TEXT    NOT NULL,
    enrolment   TEXT    NOT NULL DEFAULT '',
    created_at  TEXT    NOT NULL,
    retired_at  TEXT    NOT NULL DEFAULT '',
    retire_reason TEXT  NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS sec_change_consent (
    project_root_hash TEXT    PRIMARY KEY,
    root_path         TEXT    NOT NULL,
    notes             INTEGER NOT NULL DEFAULT 0,
    trailer           INTEGER NOT NULL DEFAULT 0,
    surface           TEXT    NOT NULL DEFAULT '',
    given_at          TEXT    NOT NULL DEFAULT '',
    revoked_at        TEXT    NOT NULL DEFAULT ''
);

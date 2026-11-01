-- 178_sec_config_baseline.sql - the repository trust accept flow and the
-- config baseline of the security pillar (security pillar plan sections 4.6
-- and 5.1; component security.trust). NODE-LOCAL, privacy sentinel, owner
-- internal/store/sectrust.go.
--
-- One row per judged item of one project: a command the repository makes an
-- agent run (a project hook, an MCP stdio server, a plugin, a folder-open
-- task and their siblings), named by its content digest. A row with
-- accepted_at set is the developer's accept of that EXACT digest: the
-- repository trust check then reports it as flagged instead of untrusted.
-- Any change to the command makes a new digest, so an accept never carries
-- over to changed content (MCPoison). Observer never marks anything trusted
-- inside the vendor's tool (plan principle PR13); this table is Observer's
-- own record.
--
-- project_root_hash is the sha256 of the canonical repository root (the
-- same spelling the guard posture uses); rel_path is slash-separated and
-- relative to that root. No file content is stored: only the path, the key
-- inside the file, the reason code and the digest.
CREATE TABLE IF NOT EXISTS sec_config_baseline (
    project_root_hash TEXT    NOT NULL,
    content_hash      TEXT    NOT NULL,
    scope             TEXT    NOT NULL DEFAULT 'project_shared',
    path_class        TEXT    NOT NULL DEFAULT '',
    rel_path          TEXT    NOT NULL DEFAULT '',
    item_key          TEXT    NOT NULL DEFAULT '',
    reason_code       TEXT    NOT NULL DEFAULT '',
    first_seen_at     TEXT    NOT NULL,
    last_seen_at      TEXT    NOT NULL,
    accepted_by       TEXT    NOT NULL DEFAULT '',
    accepted_at       TEXT    NOT NULL DEFAULT '',
    PRIMARY KEY (project_root_hash, content_hash)
);

CREATE INDEX IF NOT EXISTS idx_sec_config_baseline_accepted
    ON sec_config_baseline(project_root_hash, accepted_at);

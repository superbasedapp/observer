-- 180_sec_config_files.sql - the config baseline snapshot of the security
-- pillar (security pillar plan section 5.1 item 1; component
-- security.trust). NODE-LOCAL, privacy sentinel, owner
-- internal/store/sectrust.go.
--
-- One row per agent config file the repository trust check read in one
-- project: its path from the repository root, the path-table class it was
-- read as, and the SHA-256 and size of its bytes. The daemon's baseline
-- loop compares each new snapshot with the stored one and raises an
-- agent_config finding per added, changed or removed file. No file content
-- is stored.
CREATE TABLE IF NOT EXISTS sec_config_files (
    project_root_hash TEXT    NOT NULL,
    rel_path          TEXT    NOT NULL,
    path_class        TEXT    NOT NULL DEFAULT '',
    content_sha256    TEXT    NOT NULL,
    size_bytes        INTEGER NOT NULL DEFAULT 0,
    seen_at           TEXT    NOT NULL,
    PRIMARY KEY (project_root_hash, rel_path)
);

-- 182_sec_pkg_cache.sql - the install gate's online-answer cache (security
-- pillar plan section 8.3 "Cache"; component security.deps, Phase D1).
-- NODE-LOCAL, privacy sentinel, owner internal/store/secpkgcache.go.
--
-- One row per public package (ecosystem, normalized name, pinned version
-- or ''): what the online check last said about it. Only public-routable
-- names ever reach this table (a private name is never looked up), and a
-- failed lookup is never cached. answer_json is the secfeed.OnlineAnswer
-- (status, first publish time, advisory ids); expires_at follows the cache
-- rules (24 h positive, 6 h with advisories, 1 h not found). A row past its
-- expiry is kept as the last-known-good copy until a refresh replaces it or
-- the retention pass removes it; it is never served as a fresh answer.
CREATE TABLE IF NOT EXISTS sec_pkg_cache (
    ecosystem   TEXT NOT NULL,
    name        TEXT NOT NULL,
    version     TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL,
    answer_json TEXT NOT NULL,
    fetched_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    PRIMARY KEY (ecosystem, name, version)
);

CREATE INDEX IF NOT EXISTS idx_sec_pkg_cache_expires ON sec_pkg_cache(expires_at);

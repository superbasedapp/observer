-- 168_provider_links.sql - code-host connections (commit-pr-merge-tracking
-- plan 6.1, 7.3 and 12.3, D-689: GitHub, opt-in, off by default).
--
-- Written ONLY by internal/store/delivery.go. NODE-LOCAL (privacy sentinel).
--
-- THE SECRET IS NEVER HERE. A token lives in the OS keychain (service
-- "sbo-delivery-v1", internal/keystore); key_name is only the NAME of that
-- keychain entry. auth_mode 'gh_cli' borrows the user's gh login and stores
-- nothing at all. One connection per (provider, host).

CREATE TABLE IF NOT EXISTS provider_links (
    id                    INTEGER PRIMARY KEY,
    provider              TEXT NOT NULL,
    host                  TEXT NOT NULL,
    auth_mode             TEXT NOT NULL,
    key_name              TEXT NOT NULL DEFAULT '',
    account_login         TEXT NOT NULL DEFAULT '',
    scopes_seen           TEXT NOT NULL DEFAULT '',
    status                TEXT NOT NULL DEFAULT 'never_checked',
    last_ok_at            TEXT NOT NULL DEFAULT '',
    last_error_kind       TEXT NOT NULL DEFAULT '',
    last_error            TEXT NOT NULL DEFAULT '',
    next_run_at           TEXT NOT NULL DEFAULT '',
    consecutive_failures  INTEGER NOT NULL DEFAULT 0,
    created_at            TEXT NOT NULL,
    UNIQUE (provider, host)
);

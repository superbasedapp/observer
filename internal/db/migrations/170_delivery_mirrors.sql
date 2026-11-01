-- 170_delivery_mirrors.sql - Observer-owned bare blobless mirrors of a
-- remote (commit-pr-merge-tracking plan 12.2, D-689: no active change to the
-- user's repository).
--
-- Written ONLY by internal/store/delivery.go. NODE-LOCAL (privacy sentinel).
-- A mirror lives at ~/.observer/delivery/mirrors/<url_hash>.git, is cloned
-- and refreshed only inside that directory (internal/deliverynet), and is
-- never made an alternate of the user's repository or the other way round.
-- url never carries userinfo. size_bytes counts toward
-- [delivery].mirror_cap_mb.
--
--   status  ok | cloning | failed | over_cap | never

CREATE TABLE IF NOT EXISTS delivery_mirrors (
    id               INTEGER PRIMARY KEY,
    url_hash         TEXT NOT NULL UNIQUE,
    url              TEXT NOT NULL,
    path             TEXT NOT NULL,
    default_branch   TEXT NOT NULL DEFAULT '',
    tip_sha          TEXT NOT NULL DEFAULT '',
    size_bytes       INTEGER NOT NULL DEFAULT 0,
    status           TEXT NOT NULL DEFAULT 'never',
    last_error       TEXT NOT NULL DEFAULT '',
    last_refresh_at  TEXT NOT NULL DEFAULT '',
    last_check_at    TEXT NOT NULL DEFAULT '',
    created_at       TEXT NOT NULL
);

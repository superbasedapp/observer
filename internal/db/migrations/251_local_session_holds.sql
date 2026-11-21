-- 251: local_session_holds - sessions this node's own retention must keep
-- (managed-SaaS plan 07 row M8.8, `observer sessions hold <id>`; plan 06
-- 5.7 "Saved sessions": "a hold that outlives retention").
--
-- One row per held session. While a row exists, node retention
-- (internal/retention) never removes that session: the aged-actions pass
-- (and the excerpts, failure context and link columns that go with an
-- action), the orphaned-session sweep, the size-cap shed, the tool account
-- observation ageing and the compaction-event sweep all skip it.
--
--   session_id - sessions.id of the held session
--   held_at    - RFC3339 time the hold was placed
--   note       - free text the developer gave ('' when none)
--
-- This is the NODE's hold. The org's holds (legal and saved, org
-- PostgreSQL 0230 session_holds, plan 07 M7a.4) are separate and set on the
-- org; nothing here reaches the org. A hold names a session id only, with
-- no foreign key, so a hold placed before a session's rows land (or after
-- a component purge removed them) stays harmless.
--
-- NODE-LOCAL. One owner: internal/store/sessionholds.go, the only writer;
-- internal/retention reads it by name inside its delete predicates. Never
-- on the org push wire (the privacy sentinel's forbidden set,
-- tests/invariant/privacy_test.go); no server pair.
CREATE TABLE IF NOT EXISTS local_session_holds (
    session_id TEXT PRIMARY KEY NOT NULL CHECK (session_id <> ''),
    held_at    TEXT NOT NULL,
    note       TEXT NOT NULL DEFAULT ''
);

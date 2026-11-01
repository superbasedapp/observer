-- 173_org_message_rail.sql - the node half of admin and developer messaging
-- (docs/plans/admin-developer-messaging-plan-2026-10-15.md sections 6.2 and
-- 17.6, T-854). Migrations 173 to 176 add four NODE-LOCAL tables with no
-- server pair; each is pinned by the privacy sentinel in
-- tests/invariant/privacy_test.go and owned by internal/store/orgmessages.go.
--
-- org_message_rail: the single-row state of the signed per-caller pull
-- (GET /api/agent/messages?after=<cursor>). cursor is the highest server
-- message id this node has stored; version is the org's message version on
-- the last VERIFIED page (a lower one from the same key is a replay and is
-- refused); etag is the validator of the last final page, echoed in
-- If-None-Match; key_fingerprint is the org signing key that verified it.
-- policy_json is the developer-facing policy the last verified page carried
-- (whether "Ask my admin" is offered, which topics). fetch_state is the
-- closed outcome of the last attempt (ok, not_supported, auth_failed,
-- channel_off, unreachable, unverified); last_ok_at is the last verified
-- contact, which the Messages page shows as "last contact" while offline.
CREATE TABLE IF NOT EXISTS org_message_rail (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    org_id          TEXT    NOT NULL DEFAULT '',
    subject         TEXT    NOT NULL DEFAULT '',
    cursor          INTEGER NOT NULL DEFAULT 0,
    version         INTEGER NOT NULL DEFAULT 0,
    etag            TEXT    NOT NULL DEFAULT '',
    key_fingerprint TEXT    NOT NULL DEFAULT '',
    policy_json     TEXT    NOT NULL DEFAULT '',
    fetch_state     TEXT    NOT NULL DEFAULT '',
    last_error      TEXT    NOT NULL DEFAULT '',
    last_attempt_at TEXT    NOT NULL DEFAULT '',
    last_ok_at      TEXT    NOT NULL DEFAULT ''
);

-- 174_org_message_threads_local.sql - the thread headers this node has
-- received over the signed message pull (T-854; see 173 for the family).
-- NODE-LOCAL, privacy sentinel, owner internal/store/orgmessages.go.
--
-- One row per thread the pull touched, replaced by the newest verified
-- header. closed_seen_at is the LOCAL time this node first saw the thread
-- closed: the local retention cap counts from it, so a node that was
-- offline when the admin closed the thread still keeps it for the full
-- window.
CREATE TABLE IF NOT EXISTS org_message_threads_local (
    thread_id      TEXT PRIMARY KEY,
    subject        TEXT NOT NULL DEFAULT '',
    kind           TEXT NOT NULL DEFAULT 'note',
    topic          TEXT NOT NULL DEFAULT '',
    started_by     TEXT NOT NULL DEFAULT '',
    status         TEXT NOT NULL DEFAULT 'open',
    updated_at     TEXT NOT NULL DEFAULT '',
    received_at    TEXT NOT NULL DEFAULT '',
    closed_seen_at TEXT NOT NULL DEFAULT ''
);

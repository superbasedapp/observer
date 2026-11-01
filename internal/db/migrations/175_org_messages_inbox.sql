-- 175_org_messages_inbox.sql - verified messages for this developer (T-854;
-- see 173 for the family). NODE-LOCAL, privacy sentinel, owner
-- internal/store/orgmessages.go.
--
-- message_id is the server's org-wide message id (also the pull cursor), so
-- a page re-delivered after a lost response inserts nothing twice. Both
-- authors land here: admin messages, and the developer's own replies (the
-- pull returns them too, so a reply sent from another machine shows).
-- read_at / acked_at are the developer's own marks and the source of truth
-- for the bell, the VS Code badge and the status line. The receipt that
-- tells the org travels through org_message_outbox, never from this table.
CREATE TABLE IF NOT EXISTS org_messages_inbox (
    message_id       INTEGER PRIMARY KEY,
    thread_id        TEXT    NOT NULL,
    author_kind      TEXT    NOT NULL,
    author_name      TEXT    NOT NULL DEFAULT '',
    body             TEXT    NOT NULL DEFAULT '',
    require_ack      INTEGER NOT NULL DEFAULT 0,
    created_at       TEXT    NOT NULL DEFAULT '',
    client_msg_id    TEXT    NOT NULL DEFAULT '',
    attachments_json TEXT    NOT NULL DEFAULT '',
    received_at      TEXT    NOT NULL DEFAULT '',
    read_at          TEXT    NOT NULL DEFAULT '',
    acked_at         TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_org_messages_inbox_thread
    ON org_messages_inbox (thread_id, message_id);

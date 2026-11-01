-- 176_org_message_outbox.sql - what this node owes the org (T-854; see 173
-- for the family). NODE-LOCAL, privacy sentinel, owner
-- internal/store/orgmessages.go.
--
-- Two kinds of row, one queue:
--   post    a reply (thread_id set) or a developer-started thread
--           (new_subject / new_topic set), sent to POST /api/agent/messages;
--   receipt a read or acknowledged mark for one admin message, sent to
--           POST /api/agent/messages/receipts.
-- client_msg_id is minted on the node (a UUID for a post, a deterministic
-- "receipt:<message id>:<state>" for a receipt) and makes every retry
-- idempotent: the server answers a repeated post with the original ids.
--
-- state is queued (waiting, retried every cycle), sent (the org accepted
-- it; a post row stays until the pull brings the stored message back, then
-- goes) or failed (the org refused it on its merits; kept with last_error
-- and last_error_code until the developer retries or discards it).
CREATE TABLE IF NOT EXISTS org_message_outbox (
    client_msg_id      TEXT    PRIMARY KEY,
    org_id             TEXT    NOT NULL,
    kind               TEXT    NOT NULL CHECK (kind IN ('post', 'receipt')),
    thread_id          TEXT    NOT NULL DEFAULT '',
    new_subject        TEXT    NOT NULL DEFAULT '',
    new_topic          TEXT    NOT NULL DEFAULT '',
    body               TEXT    NOT NULL DEFAULT '',
    attachments_json   TEXT    NOT NULL DEFAULT '',
    receipt_message_id INTEGER NOT NULL DEFAULT 0,
    receipt_state      TEXT    NOT NULL DEFAULT '',
    receipt_at         TEXT    NOT NULL DEFAULT '',
    created_at         TEXT    NOT NULL,
    state              TEXT    NOT NULL DEFAULT 'queued' CHECK (state IN ('queued', 'sent', 'failed')),
    attempts           INTEGER NOT NULL DEFAULT 0,
    last_error         TEXT    NOT NULL DEFAULT '',
    last_error_code    TEXT    NOT NULL DEFAULT '',
    last_attempt_at    TEXT    NOT NULL DEFAULT '',
    sent_at            TEXT    NOT NULL DEFAULT '',
    result_message_id  INTEGER NOT NULL DEFAULT 0,
    result_thread_id   TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_org_message_outbox_state
    ON org_message_outbox (state, created_at);

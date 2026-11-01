-- 189_sec_finding_feedback_sent.sql - the feedback_sent finding event
-- (security pillar plan sections 5.11 (c) and 6.2 step 2; lane sec-h;
-- renumbered from 185 at merge).
-- When the agent's post-tool hook carries a feedback line about a finding
-- (component security.feedback), the daemon records one feedback_sent
-- event for it, so each finding reaches the agent once. SQLite cannot
-- widen a CHECK in place, so the append-only events table is rebuilt with
-- the one new kind; every existing row is copied as it was. The detail of
-- a feedback_sent row is the session id the line was sent to (an opaque
-- vendor id, never content).
--
-- NODE-LOCAL: sec_finding_events stays in the privacy sentinel's
-- forbidden-table list. NO server pair. One writer:
-- internal/store/secfindings.go.

CREATE TABLE sec_finding_events_new (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id        TEXT    NOT NULL DEFAULT '',
    project_root_hash TEXT    NOT NULL,
    kind              TEXT    NOT NULL CHECK (kind IN ('seen', 'closed', 'reopened', 'suppressed',
                                                       'exception_expired', 'verdict_referenced',
                                                       'baseline_set', 'baseline_reset',
                                                       'feedback_sent')),
    detail            TEXT    NOT NULL DEFAULT '',
    at                TEXT    NOT NULL
);

INSERT INTO sec_finding_events_new (id, finding_id, project_root_hash, kind, detail, at)
    SELECT id, finding_id, project_root_hash, kind, detail, at FROM sec_finding_events;

DROP TABLE sec_finding_events;

ALTER TABLE sec_finding_events_new RENAME TO sec_finding_events;

CREATE INDEX IF NOT EXISTS idx_sec_finding_events_finding ON sec_finding_events (finding_id, id);
CREATE INDEX IF NOT EXISTS idx_sec_finding_events_feedback ON sec_finding_events (kind, finding_id) WHERE kind = 'feedback_sent';

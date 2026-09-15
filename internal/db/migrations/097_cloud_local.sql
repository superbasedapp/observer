-- 097: Node-local cloud-intelligence persistence (CI-P2 Lane D — cloud-
-- intelligence Azure Foundry plan of record,
-- docs/plans/cloud-intelligence-azure-foundry-plan-of-record-2026-08-30.md
-- §6 "CI-P2" node-migrations bullet + §6 "CI-P1" bullet "Consent/rebuild
-- coherence"; §7 invariants 1-2).
--
-- These five tables are the node's OWN record of what the Signed-in Free
-- cloud spine did on this machine: the consent receipts a developer confirmed,
-- the random local<->cloud pseudonym maps, the send outbox (a rebuild-at-send
-- state machine — NO envelope bodies live here), and the validated enrichment
-- results pulled back plus the user's edits over them.
--
-- NODE-LOCAL, and STRENGTHENED-privacy-sentinel enforced. None of these five
-- tables may ever enter the org-push wire: their names are in the generalized
-- forbidden-table denylist walked by tests/invariant/privacy_test.go
-- (TestSelectUnpushedSinceExcludesCacheTables scans orgpush.go for the names,
-- and a seeded-value wire test proves distinctive sentinels stuffed into every
-- text column never appear in a real SelectUnpushedSince serialization under
-- any share posture — metadata-only, full_content, admin_managed). The single
-- org-push SQL seam (internal/store/orgpush.go::SelectUnpushedSince) enumerates
-- its columns/tables explicitly and never names these — the personal cloud
-- plane and the org plane are separate destinations by construction.
--
-- Content posture: rows are content-free EXCEPT cloud_results.result_json (and
-- cloud_result_overrides.user_value). The enrichment result IS the product —
-- an allowed, validated session_enrichment payload — and it stays node-local
-- like everything else here; it is never a wire surface. No raw evidence /
-- envelope bytes are stored anywhere: the outbox rebuilds the envelope at send
-- from the live session (consent/rebuild coherence), so a stale local copy can
-- never be uploaded without re-passing the two-digest check.
--
-- Times are stored as RFC3339(Nano) TEXT (internal/store/cloudlocal.go's
-- cloudFormatTime/cloudParseTime), consistent with the other node-local
-- control-plane tables (org_enrolment_grant). No down-migration is provided;
-- the tables are additive and a pre-097 binary simply never reads them.

-- cloud_consent_receipts: one row per receipt the developer confirmed. Binds
-- the upload digest of the literal preview they saw (amendment §4.2 receipt-
-- binding fields) so a later rebuild-and-compare can detect any drift.
CREATE TABLE cloud_consent_receipts (
    id                       TEXT PRIMARY KEY,
    account_pseudonym        TEXT NOT NULL,
    device_label_ref         TEXT NOT NULL DEFAULT '',
    purpose                  TEXT NOT NULL,
    field_classes_json       TEXT NOT NULL DEFAULT '[]',
    envelope_schema_version  TEXT NOT NULL,
    scrubber_version         TEXT NOT NULL,
    endpoint                 TEXT NOT NULL DEFAULT '',
    retention_policy_version TEXT NOT NULL DEFAULT '',
    upload_digest            TEXT NOT NULL,
    created_at               TEXT NOT NULL,
    invalidated_at           TEXT
);

-- cloud_session_map / cloud_project_map: local id <-> RANDOM cloud pseudonym.
-- The pseudonym is generated at map time from crypto/rand and is NEVER derived
-- from the local id (no hash, no encoding of the local value), so the mapping
-- discloses nothing about the local identifier even if a pseudonym leaks.
CREATE TABLE cloud_session_map (
    local_session_id TEXT PRIMARY KEY,
    cloud_pseudonym  TEXT NOT NULL UNIQUE,
    created_at       TEXT NOT NULL
);

CREATE TABLE cloud_project_map (
    local_project_id TEXT PRIMARY KEY,
    cloud_pseudonym  TEXT NOT NULL UNIQUE,
    created_at       TEXT NOT NULL
);

-- cloud_outbox: the send state machine. Holds session ref + feature set +
-- the two confirmed digests + the bound receipt + retry state ONLY — never an
-- envelope body. last_error is a content-free error CLASS string, never body
-- text. state is one of pending|reconfirmation_required|sending|sent|
-- failed_retryable|failed_terminal|cancelled (internal/store/cloudlocal.go
-- owns the transition table).
CREATE TABLE cloud_outbox (
    id                      TEXT PRIMARY KEY,
    session_id              TEXT NOT NULL,
    feature_set_json        TEXT NOT NULL DEFAULT '[]',
    evidence_content_digest TEXT NOT NULL,
    upload_digest           TEXT NOT NULL,
    receipt_id              TEXT NOT NULL,
    state                   TEXT NOT NULL,
    retry_count             INTEGER NOT NULL DEFAULT 0,
    last_error              TEXT NOT NULL DEFAULT '',
    created_at              TEXT NOT NULL,
    updated_at              TEXT NOT NULL
);
CREATE INDEX idx_cloud_outbox_state ON cloud_outbox(state);
CREATE INDEX idx_cloud_outbox_receipt ON cloud_outbox(receipt_id);
CREATE INDEX idx_cloud_outbox_session ON cloud_outbox(session_id);

-- cloud_results: the validated enrichment results pulled back, versioned per
-- session. superseded_by chains an older result to the row that replaced it
-- (a regeneration); the newest row has superseded_by NULL. Provenance is
-- carried as columns (model_route / prompt_hash / tokens / cost_usd).
CREATE TABLE cloud_results (
    id             TEXT PRIMARY KEY,
    session_id     TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    result_json    TEXT NOT NULL,
    model_route    TEXT NOT NULL DEFAULT '',
    prompt_hash    TEXT NOT NULL DEFAULT '',
    tokens         INTEGER NOT NULL DEFAULT 0,
    cost_usd       REAL NOT NULL DEFAULT 0,
    received_at    TEXT NOT NULL,
    superseded_by  TEXT
);
CREATE INDEX idx_cloud_results_session ON cloud_results(session_id);

-- cloud_result_overrides: the user's edits over a result field. User edit
-- always wins on read, and a regenerated result never clobbers an override —
-- reads aggregate the latest override per field across ALL of a session's
-- results, so an override bound to a superseded result still applies to its
-- replacement.
CREATE TABLE cloud_result_overrides (
    result_id  TEXT NOT NULL,
    field      TEXT NOT NULL,
    user_value TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (result_id, field)
);

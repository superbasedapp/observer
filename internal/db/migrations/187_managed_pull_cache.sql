-- 187_managed_pull_cache.sql - the node's persisted copy of each module
-- managed pull's last VERIFIED signed document (roadmap F0-7, lane SHR-KIT;
-- design docs/plans/spikes/JSP-1-governance-and-wire-2026-10.md). One row per
-- rail (orgcontract.ManagedPullRails: "security", "sandbox"), so a restart
-- does not drop a managed node to local values until its next poll.
--
-- NODE-LOCAL: in the privacy sentinel's forbidden-table list, so
-- internal/store/orgpush.go can never select it by name. NO server pair (the
-- org server's issuance table is its own, server migration 244 / pg 0111).
-- One writer: internal/store/managedpull.go. Only a verified 200 writes a
-- row; only a SIGNED empty body at a newer version clears it, and a clear
-- leaves a tombstone (doc_json '') that keeps the version as the
-- anti-rollback floor; every other answer leaves it alone.
--
-- doc_json is the whole signed document (re-verified against the pinned org
-- key on every load); org_key and generation bind it to the enrolment that
-- accepted it, so a row from a replaced enrolment reads as absent.

CREATE TABLE IF NOT EXISTS managed_pull_cache (
    rail               TEXT    NOT NULL PRIMARY KEY,
    org_key            TEXT    NOT NULL,
    generation         INTEGER NOT NULL,
    version            INTEGER NOT NULL,
    expires_at         INTEGER NOT NULL,
    body_hash          TEXT    NOT NULL,
    doc_json           TEXT    NOT NULL,
    signer_fingerprint TEXT    NOT NULL,
    fetched_at         TEXT    NOT NULL
);

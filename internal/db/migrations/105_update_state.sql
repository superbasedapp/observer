-- 105_update_state.sql — the node's own update state and its audit ledger
-- (docs/plans/enterprise-update-management-plan-2026-09-07.md §3.4, wave W3).
--
-- TWO TABLES, both NODE-LOCAL and both in the privacy sentinel's
-- forbidden-name set (tests/invariant/privacy_test.go): neither name may ever
-- appear inside internal/store/orgpush.go. What DOES reach an org server is a
-- strict, enum-only SUBSET — orgcontract.UpdatePostureRow — composed by
-- internal/store/updateposture.go and reached from the push seam by a FUNCTION
-- CALL, exactly the arrangement routingsummary.go / locsummary.go use for
-- router_decisions / file_changes. That is not a stylistic preference: the
-- ledger below stores LOCAL PATHS (a staged binary, a rollback binary, a DB
-- snapshot) and a free-text detail line, and both are precisely the classes of
-- value ruling R10 keeps off the wire.
--
-- WHY A SINGLE-ROW TABLE. update_state is the node's ONE current update
-- posture; there is no history dimension to it and two rows would be two
-- answers to "what is this node doing". CHECK(id = 1) states that in the
-- schema rather than in a comment, the same shape other singleton state uses.
-- The row is created here so every reader can SELECT without a NULL-vs-missing
-- branch, and so the very first write is an UPDATE (one writer, one seam:
-- internal/store/update.go).
--
-- previous_schema_version IS LOAD-BEARING AND EASY TO MISS. Migrations run
-- automatically INSIDE db.Open (internal/db/db.go:498, high-water mark in
-- schema_meta at :576). By the time any update-aware code on the NEW binary
-- could look, the pre-apply number is already overwritten. So the OLD binary
-- records it here, with the existing db.Version accessor, BEFORE the swap
-- (§3.7 step 5). Without it a rollback across a migration cannot tell whether
-- restoring an older binary is safe, and forward-only migrations make "older
-- binary against a newer schema" a corruption risk, not an inconvenience.
--
-- previous_db_backup_path names the VACUUM INTO snapshot taken in the same
-- step when the target's migration set is ahead. A rollback after a schema
-- advance restores binary AND snapshot; the rows ingested between the snapshot
-- and the restore are DISCARDED, which ruling R15 states plainly rather than
-- leaving an operator to discover it. update_events records the snapshot's
-- timestamp so `observer update history` can name the exact window.
--
-- NO PAIRED SERVER MIGRATION. The org side of this feature is server migration
-- 127 (org_update_manifests / org_update_artifacts / org_update_rollouts /
-- org_node_versions), which landed in W2 and shares no column with these two
-- tables. The wire between them is UpdatePostureRow, and it carries none of
-- the path columns below.

CREATE TABLE IF NOT EXISTS update_state (
    -- id is pinned to 1: this is the node's single current posture.
    id                      INTEGER PRIMARY KEY CHECK (id = 1),
    -- channel is the channel this node is assigned to ("" = whatever the org
    -- assigns; a local [update].channel overrides).
    channel                 TEXT    NOT NULL DEFAULT '',
    -- last_manifest_version is the highest manifest_version accepted on
    -- channel. Verify rule 6 (replay refusal) is the only reader.
    last_manifest_version   INTEGER NOT NULL DEFAULT 0,
    -- last_manifest_json is the accepted manifest's canonical bytes, kept so a
    -- restarted daemon can resume an apply without a fetch. NODE-LOCAL: it is
    -- the org's own signed document coming back, never node data going out.
    last_manifest_json      TEXT    NOT NULL DEFAULT '',
    last_manifest_seen_at   TEXT    NOT NULL DEFAULT '',
    -- target_version is the version this node is trying to reach.
    target_version          TEXT    NOT NULL DEFAULT '',
    -- state / reason / error_class are update.State / update.Reason /
    -- update.ErrorClass — closed vocabularies, never messages.
    state                   TEXT    NOT NULL DEFAULT 'idle',
    reason                  TEXT    NOT NULL DEFAULT '',
    error_class             TEXT    NOT NULL DEFAULT '',
    -- The rollback triple. previous_binary_path and previous_db_backup_path
    -- are LOCAL PATHS and are why this table name is in the sentinel set.
    previous_binary_path    TEXT    NOT NULL DEFAULT '',
    previous_version        TEXT    NOT NULL DEFAULT '',
    previous_schema_version INTEGER NOT NULL DEFAULT 0,
    previous_db_backup_path TEXT    NOT NULL DEFAULT '',
    -- applying_started_at is set before the swap and cleared on settle; a
    -- non-empty value on boot means "no parent is watching" (a host reboot or
    -- a kill after the old parent exited), which the boot-time detector reads.
    applying_started_at     TEXT    NOT NULL DEFAULT '',
    applied_at              TEXT    NOT NULL DEFAULT '',
    updated_at              TEXT    NOT NULL DEFAULT ''
);

-- The singleton row. Created here so every reader is unconditional.
INSERT OR IGNORE INTO update_state (id) VALUES (1);

CREATE TABLE IF NOT EXISTS update_events (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    at               TEXT    NOT NULL,
    from_version     TEXT    NOT NULL DEFAULT '',
    to_version       TEXT    NOT NULL DEFAULT '',
    manifest_version INTEGER NOT NULL DEFAULT 0,
    state            TEXT    NOT NULL,
    error_class      TEXT    NOT NULL DEFAULT '',
    -- detail is the human-readable reason, and it MAY contain a local path
    -- (which snapshot was restored, which directory was not writable). It is
    -- what makes `observer update history` usable and it is exactly why this
    -- table NEVER leaves the node.
    detail           TEXT    NOT NULL DEFAULT '',
    duration_ms      INTEGER NOT NULL DEFAULT 0
);

-- History is read newest-first and never joined; one index is the whole story.
CREATE INDEX IF NOT EXISTS idx_update_events_at ON update_events(at DESC, id DESC);

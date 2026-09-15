-- 098: Structural-insights rail — node-local persistence (W2 node half,
-- docs/plans/cloud-intelligence-divergence-remediation-plan-2026-09-01.md
-- rev 4.1 §2 R1 "standing-grant consent protocol" + §3 W2 "Node half" /
-- "Revision model").
--
-- Additive on top of 097's node-local cloud tables. Three changes:
--
--   1. cloud_outbox grows a `kind` discriminator and a `payload_bytes` blob.
--   2. cloud_consent_receipts grows the R1 STANDING-GRANT binding set.
--   3. a new cloud_structural_windows table owns window identity + revision
--      allocation + send bookkeeping.
--
-- NODE-LOCAL, and STRENGTHENED-privacy-sentinel enforced, exactly like 097:
-- cloud_structural_windows joins the forbidden-table denylist walked by
-- tests/invariant/privacy_test.go (the AST scan of orgpush.go plus the
-- seeded-sentinel wire test under metadata-only / full_content /
-- admin_managed). There is no org share key and no paired orgserver migration:
-- the personal cloud plane is a separate destination from the org push wire by
-- construction.
--
-- Times are RFC3339(Nano) TEXT via internal/store/cloudlocal.go's
-- cloudFormatTime/cloudParseTime, consistent with 097. No down-migration; a
-- pre-098 binary simply never reads the new columns/table.

-- ---------------------------------------------------------------------------
-- 1. cloud_outbox: kind + payload_bytes
-- ---------------------------------------------------------------------------
--
-- `kind` discriminates the two payload shapes the outbox now carries:
--
--   'session_evidence'    — the 097 shape. NO body is stored; the envelope is
--                           REBUILT at send from the live session and
--                           re-checked against the confirmed digests
--                           (consent/rebuild coherence).
--   'structural_insights' — the W2 shape. The exact canonical snapshot bytes
--                           ARE stored, in payload_bytes, and resent verbatim.
--
-- The DEFAULT is 'session_evidence' so every pre-098 row keeps its meaning
-- without a backfill.
--
-- NAMED EXCEPTION to the "the outbox stores no content" rule (plan rev 4,
-- re-review residual #2). That rule guards session CONTENT — excerpts, paths,
-- command strings, anything derived from what the developer was working on. A
-- structural snapshot contains none of those: it is bounded deterministic
-- aggregates over a time window (counts, token/cost sums, categorical mixes
-- keyed by tool identifier and coarse model family, two closed-vocabulary
-- coverage bands), and the contract TYPE
-- (internal/cloudcontract.StructuralSnapshot) has no field in which a path or
-- an excerpt could be expressed. Storing the bytes is what makes a retry
-- immune to late, backfilled, or pruned source rows: a resend replays the
-- EXACT bytes the digest was taken over, and never re-aggregates.
--
-- The exception is ENFORCED, not merely documented: the two triggers below
-- reject payload_bytes on any kind other than 'structural_insights', at the
-- storage layer, for every writer including raw SQL. The Go seam
-- (internal/store/structuralinsights.go) checks the same rule before the write
-- so the failure is a typed error rather than a constraint surprise, and
-- tests/invariant/privacy_test.go pins the trigger by attempting the forbidden
-- write directly.
ALTER TABLE cloud_outbox ADD COLUMN kind TEXT NOT NULL DEFAULT 'session_evidence';
ALTER TABLE cloud_outbox ADD COLUMN payload_bytes BLOB;

CREATE INDEX idx_cloud_outbox_kind ON cloud_outbox(kind, state);

CREATE TRIGGER cloud_outbox_payload_kind_guard_insert
BEFORE INSERT ON cloud_outbox
FOR EACH ROW WHEN NEW.payload_bytes IS NOT NULL AND NEW.kind <> 'structural_insights'
BEGIN
    SELECT RAISE(ABORT, 'cloud_outbox: payload_bytes is permitted only on kind=structural_insights');
END;

CREATE TRIGGER cloud_outbox_payload_kind_guard_update
BEFORE UPDATE ON cloud_outbox
FOR EACH ROW WHEN NEW.payload_bytes IS NOT NULL AND NEW.kind <> 'structural_insights'
BEGIN
    SELECT RAISE(ABORT, 'cloud_outbox: payload_bytes is permitted only on kind=structural_insights');
END;

-- ---------------------------------------------------------------------------
-- 2. cloud_consent_receipts: the R1 standing-grant binding set
-- ---------------------------------------------------------------------------
--
-- R1 (RULED APPROVED, operator 2026-09-01) adds a second grant mode. The
-- binding list below is NORMATIVE — a standing receipt binds {purpose,
-- grant_mode, schema version + data-dictionary digest, field classes,
-- retention policy version, declared timezone, source-window rule, endpoint,
-- expiry/review date, consent generation}. purpose, field_classes_json,
-- envelope_schema_version, retention_policy_version and endpoint already exist
-- on the 097 table; these six columns complete the set.
--
--   grant_mode             'per_upload' (the 097 semantics — the receipt binds
--                          ONE exact upload) or 'standing' (the receipt
--                          authorizes a SCHEMA; each upload still gets its own
--                          digest, its own local audit row, and a pre-send
--                          revocation check). DEFAULT 'per_upload' so every
--                          pre-098 receipt keeps exactly its old meaning.
--   data_dictionary_digest the digest over the published data dictionary the
--                          standing grant authorizes.
--   declared_timezone      the IANA zone the account declared; it decides what
--                          a "day" period means, so it is part of what the
--                          developer agreed to, not an implementation detail.
--   source_window_rule     the versioned rule identifier for how activity maps
--                          to a window.
--   review_at              the expiry / review date (NULL = none set).
--   consent_generation     bumped whenever the grant is re-confirmed under
--                          changed terms. A queued snapshot records the
--                          generation it was built under; a mismatch at send
--                          time means the terms moved and the item requires
--                          reconfirmation instead of being silently sent.
--
-- REUSE NOTE on upload_digest (deliberate, documented in the Go type too):
-- for a 'per_upload' receipt, upload_digest is what it always was — the digest
-- of the ONE literal preview the developer confirmed. For a 'standing'
-- receipt there is no single upload to bind, so upload_digest instead holds the
-- DATA-DICTIONARY digest: the schema-level thing the standing grant actually
-- authorizes. Each individual upload's own digest lives on its cloud_outbox
-- row, not here. data_dictionary_digest carries the same value explicitly, so
-- a reader never has to infer the meaning of upload_digest from grant_mode;
-- the reuse exists so the NOT NULL column stays meaningful under both modes
-- rather than being stuffed with a placeholder.
ALTER TABLE cloud_consent_receipts ADD COLUMN grant_mode TEXT NOT NULL DEFAULT 'per_upload';
ALTER TABLE cloud_consent_receipts ADD COLUMN data_dictionary_digest TEXT NOT NULL DEFAULT '';
ALTER TABLE cloud_consent_receipts ADD COLUMN declared_timezone TEXT NOT NULL DEFAULT '';
ALTER TABLE cloud_consent_receipts ADD COLUMN source_window_rule TEXT NOT NULL DEFAULT '';
ALTER TABLE cloud_consent_receipts ADD COLUMN review_at TEXT;
ALTER TABLE cloud_consent_receipts ADD COLUMN consent_generation INTEGER NOT NULL DEFAULT 0;

-- ---------------------------------------------------------------------------
-- 3. cloud_structural_windows: window identity + revision allocation
-- ---------------------------------------------------------------------------
--
-- One row per snapshot taken of a window. Device identity is IMPLICIT: this is
-- a single-node database, so the plan's UNIQUE(device, period,
-- period_rule_version, schema_version, revision) reduces to the four non-device
-- columns here. The server-side table carries the device column, derived from
-- the authenticated PoP principal rather than from anything the node declares.
--
-- The UNIQUE constraint is what actually allocates revisions: a snapshot is
-- taken inside ONE immediate transaction that reads the window's current max
-- revision and inserts max+1, so two concurrent snapshot builds of the same
-- window serialize behind SQLite's write lock and receive distinct revisions.
-- The constraint is the backstop that turns any future racy path into a loud
-- failure rather than a silent overwrite.
--
-- Re-snapshotting an already-captured window (late or backfilled data)
-- allocates revision N+1 explicitly — including while revision N is still
-- pending-unsent; both then drain in revision order. A window is NEVER
-- overwritten and a revision is NEVER reused.
--
-- CONTENT-FREE: period is a calendar day, digest is a hash, outbox_id is a
-- random local id. Nothing here is derived from what the developer was
-- working on.
CREATE TABLE cloud_structural_windows (
    period              TEXT    NOT NULL,
    period_rule_version INTEGER NOT NULL,
    schema_version      TEXT    NOT NULL,
    revision            INTEGER NOT NULL,
    outbox_id           TEXT    NOT NULL,
    digest              TEXT    NOT NULL,
    created_at          TEXT    NOT NULL,
    UNIQUE(period, period_rule_version, schema_version, revision)
);
CREATE INDEX idx_cloud_structural_windows_outbox ON cloud_structural_windows(outbox_id);

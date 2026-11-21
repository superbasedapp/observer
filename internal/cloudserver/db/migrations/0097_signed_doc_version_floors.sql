-- 0097_signed_doc_version_floors.sql - the document signer's version floor
-- in the database (managed-SaaS plan 07 wave 16 lane control-plane; lead
-- decision W16-D6; docs/security.md CPSIGN-6;
-- docs/saas-platform-control-plane-runbook.md section 7, step 3).
--
-- step: expand
--
-- WHY. The document signer keeps its own durable record of the last version
-- it signed per (kind, scope) (versions.json, outside the database restore
-- domain on purpose). When the database is restored to a point BEFORE that
-- record, the worker asks the signer for versions it already signed; the
-- signer refuses them and that stream stalls. The operator verb
-- `observer-cloud signer document raise-floor --record <the exported
-- versions.json>` closes the gap: per (kind, scope) of the record it appends
-- one row here with the record's version when the database holds nothing at
-- or above it. The worker then asks for max(latest stored version, floor) + 1,
-- and the store refuses to store a version at or below the floor. The verb
-- never touches versions.json: it raises the database, never the record.
--
-- APPEND-ONLY, AND ITS OWN AUDIT. Each row names the operator who ran the
-- verb and the sha256 of the record file it read. A floor never lowers: the
-- store appends a row only above the stream's current floor and stored
-- maximum, under the stream's document lock (store.documentLockKey, the lock
-- every document write of that stream takes). No role holds UPDATE or
-- DELETE.
--
-- CLASS S (no row-level security), like the two document tables (0055):
--
--   sbci_app     SELECT + INSERT: the operator verb (the admin DSN), and the
--                dev/test single-role fallback; InsertEntitlementDocument
--                reads the floor too.
--   sbci_worker  SELECT: the entitlements issuer reads the floor before it
--                asks the signer for a version, and the store's insert
--                re-checks it.
--
-- sbci_api, sbci_aggregator and sbci_staff get nothing: no customer-session
-- or staff handler reads a floor.
--
-- scope is an org id for an entitlements stream and the fixed scope
-- 'platform' for the one availability stream (platformcontract
-- ValidateDocumentScope; the Go side checks it before any SQL). There is no
-- foreign key to orgs: after a restore to a point before an org existed, the
-- record still names the org, and its floor is harmless.

SET LOCAL lock_timeout = '5s';

CREATE TABLE signed_doc_version_floors (
    seq           bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kind          text        NOT NULL CHECK (kind IN ('entitlements', 'availability')),
    scope         text        NOT NULL CHECK (char_length(scope) BETWEEN 1 AND 128 AND scope !~ '\s'),
    floor_version bigint      NOT NULL CHECK (floor_version > 0),
    -- sha256 of the record file the verb read (lowercase hex).
    record_sha256 text        NOT NULL CHECK (record_sha256 ~ '^[0-9a-f]{64}$'),
    -- Who ran the verb (its --operator flag).
    operator      text        NOT NULL CHECK (operator ~ '^[A-Za-z0-9._@-]{1,64}$'),
    at            timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT signed_doc_version_floors_availability_scope
        CHECK (kind <> 'availability' OR scope = 'platform')
);

CREATE INDEX signed_doc_version_floors_stream ON signed_doc_version_floors (kind, scope, floor_version DESC);

COMMENT ON TABLE signed_doc_version_floors IS
    'W16-D6: operator-raised version floors per signed-document stream after a database restore behind the signer record; append-only (class S).';

GRANT SELECT, INSERT ON signed_doc_version_floors TO sbci_app;
GRANT SELECT ON signed_doc_version_floors TO sbci_worker;

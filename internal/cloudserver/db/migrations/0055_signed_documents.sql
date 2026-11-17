-- 0055_signed_documents.sql - the control plane's signed-document tables
-- (managed-SaaS plan 07 M6.3; design
-- docs/plans/managed-saas/m6.0-control-plane-design-2026-11-13.md 3.3, 4.5;
-- plan 06 5.8.4 and 18.3.5).
--
-- step: expand
--
-- One step of the M6.3 block (0055-0057 in docs/migration-numbering.md): this
-- step creates the two document tables and grants nothing; 0056 grants;
-- 0057 is reserved. Both tables are class S (design 3.2): no row-level
-- security, reachable only through explicit grants.
--
-- TABLES
--
--   org_entitlement_docs  every signed entitlements document
--                         (sbo-entitlements-v1) issued for an org, one row
--                         per (org, version). The version is monotonic per
--                         org: the primary key refuses a repeat and the store
--                         seam (store.InsertEntitlementDocument) refuses a
--                         version not above the org's highest, under a
--                         per-org transaction lock. The document signer
--                         applies the same rule with its own durable record,
--                         so a lost database row cannot make it re-sign an old
--                         version, and a lost signer record cannot get an old
--                         version stored.
--   availability_docs     every signed availability envelope
--                         (sbo-availability-v1), one platform-wide row per
--                         version, monotonic the same way.
--
-- Rows are append-only (no UPDATE or DELETE grant anywhere): delivery state
-- lives in org_outbox, one owner per fact, so the design's pushed_version
-- column is not created here. The design's availability_inputs table (what
-- staff edit) is created with its only writer, the M6.8 staff routes.
--
-- body and signature are the exact bytes signed and the Ed25519 signature
-- over platformcontract.DocumentSigningMessage; key_id is
-- platformcontract.DocumentKeyID of the signing key (43 base64url
-- characters). issued_by is 'system' or 'staff:<staff id>'.

SET LOCAL lock_timeout = '5s';

-- ---------------------------------------------------------------------------
-- org_entitlement_docs (class S, append-only)
-- ---------------------------------------------------------------------------
CREATE TABLE org_entitlement_docs (
    org_id     uuid        NOT NULL REFERENCES orgs (org_id),
    version    bigint      NOT NULL CHECK (version > 0),
    body       bytea       NOT NULL CHECK (octet_length(body) BETWEEN 1 AND 131072),
    signature  bytea       NOT NULL CHECK (octet_length(signature) = 64),
    key_id     text        NOT NULL CHECK (key_id ~ '^[A-Za-z0-9_-]{43}$'),
    issued_at  timestamptz NOT NULL,
    issued_by  text        NOT NULL CHECK (issued_by = 'system' OR issued_by ~ '^staff:[A-Za-z0-9_-]{1,64}$'),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, version)
);

-- ---------------------------------------------------------------------------
-- availability_docs (class S, append-only)
-- ---------------------------------------------------------------------------
CREATE TABLE availability_docs (
    version    bigint      NOT NULL PRIMARY KEY CHECK (version > 0),
    body       bytea       NOT NULL CHECK (octet_length(body) BETWEEN 1 AND 131072),
    signature  bytea       NOT NULL CHECK (octet_length(signature) = 64),
    key_id     text        NOT NULL CHECK (key_id ~ '^[A-Za-z0-9_-]{43}$'),
    issued_at  timestamptz NOT NULL,
    issued_by  text        NOT NULL CHECK (issued_by = 'system' OR issued_by ~ '^staff:[A-Za-z0-9_-]{1,64}$'),
    created_at timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE org_entitlement_docs IS 'M6.3: signed sbo-entitlements-v1 documents per org, monotonic version (class S, append-only).';
COMMENT ON TABLE availability_docs IS 'M6.3: signed sbo-availability-v1 platform envelopes, monotonic version (class S, append-only).';

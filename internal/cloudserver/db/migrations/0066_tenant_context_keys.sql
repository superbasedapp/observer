-- 0066_tenant_context_keys.sql - the key table of the MAC'd tenant context
-- (managed-SaaS plan 07 M3b.2 and M6.1b; internal/tenantctx).
--
-- step: expand
--
-- 0067 makes sbci_current_account() verify a MAC'd token instead of reading
-- a bare account id from the sbci.account_id setting. The MAC is an
-- HMAC-SHA256 under a key the cloud service loads (SBCI_TENANT_CONTEXT_KEY
-- or its _FILE form) and installs here through sbci_tenant_context_install
-- (0067). The key is never generated in SQL.
--
-- One row per installed key. The table stores the key's two HMAC pads
-- (RFC 2104: the zero-padded key XOR 0x36 and XOR 0x5c), not the key, so the
-- check needs only core sha256() and no extension:
--
--   key_id     16 lower-case hex digits: the first 8 bytes of
--              sha256('sbo-tenant-context-key-id-v1' || newline || key),
--              tenantctx.KeyID. The same key always names the same row, so
--              an install is idempotent.
--   inner_key  the 64-byte inner pad
--   outer_key  the 64-byte outer pad
--   created_at when the key was installed
--   not_after  when the key stops verifying; NULL while it is current. A
--              rotation caps every other key at now() plus an overlap of at
--              most 24 hours.
--
-- Access: no application role (sbci_app, sbci_api, sbci_worker,
-- sbci_aggregator) holds any privilege on it. sbci_defs, which owns the
-- SECURITY DEFINER sbci_current_account() from 0067, may read it. The
-- migrating login owns it and is the only role that may install a key. The
-- table holds no account data (the deletion matrix classes it excluded).

SET LOCAL lock_timeout = '5s';

CREATE TABLE sbci_tenant_context_keys (
    key_id     text        PRIMARY KEY CHECK (key_id ~ '^[0-9a-f]{16}$'),
    inner_key  bytea       NOT NULL CHECK (length(inner_key) = 64),
    outer_key  bytea       NOT NULL CHECK (length(outer_key) = 64),
    created_at timestamptz NOT NULL DEFAULT now(),
    not_after  timestamptz
);

GRANT SELECT ON sbci_tenant_context_keys TO sbci_defs;

-- 0131_portal_passkeys.sql - the portal's passkey second factor (managed-SaaS
-- plan 07 tracker row "C2 portal WebAuthn second factor"; lead decision L-92:
-- C2 before GA; wave 17 lane portal-guardrails; docs/security.md PLATRAIL-3).
--
-- step: expand
--
-- New tables and nullable / constant-default columns only; row-level
-- security for the three tables is 0132, a step of its own (migcheck).
--
-- portal_passkeys: an account's WebAuthn credentials, verified by the staff
-- console's passkey code (staffauth.Verifier, L-92). Public halves only; a
-- revoked passkey keeps its row (revoked_at), so a re-registration of the
-- same credential id is refused.
--
-- portal_passkey_ceremonies: one WebAuthn challenge, bound to the account AND
-- the browser session that asked, single use, at most ten minutes. Only the
-- hash of the ceremony token is stored.
--
-- portal_recovery_codes: the hashes of an account's one-time recovery codes
-- (portalmfa.HashRecoveryCode); the codes are shown once and never stored.
-- A new batch deletes the old one.
--
-- browser_sessions gains how THIS session completed its second factor:
-- second_factor_at, second_factor_method ('passkey' | 'recovery_code') and
-- second_factor_amr (the RFC 8176 values the platform OIDC issuer signs;
-- empty for a recovery code). NULL on every existing session.
--
-- orgs gains require_second_factor: an org owner or admin may require every
-- member to sign in with a passkey; the platform OIDC issuer enforces it at
-- the tenant sign-in. Default false (no existing org changes). sbci_api may
-- update it under the existing orgs_admin_update policy (0048).
--
-- Deletion: the three account-keyed tables are purged at account deletion
-- (store/deletion.go) and cascade with the tombstone at the 24-month sweep.

SET LOCAL lock_timeout = '5s';

CREATE TABLE portal_passkeys (
    credential_id   bytea       NOT NULL PRIMARY KEY CHECK (octet_length(credential_id) BETWEEN 1 AND 1023),
    account_id      uuid        NOT NULL REFERENCES accounts (account_id) ON DELETE CASCADE,
    public_key      bytea       NOT NULL CHECK (octet_length(public_key) BETWEEN 1 AND 2048),
    sign_count      bigint      NOT NULL DEFAULT 0 CHECK (sign_count BETWEEN 0 AND 4294967295),
    aaguid          bytea       CHECK (aaguid IS NULL OR octet_length(aaguid) = 16),
    transports      text[]      NOT NULL DEFAULT '{}' CHECK (cardinality(transports) <= 8),
    backup_eligible boolean     NOT NULL DEFAULT false,
    label           text        NOT NULL DEFAULT '' CHECK (char_length(label) <= 60),
    created_at      timestamptz NOT NULL DEFAULT now(),
    last_used_at    timestamptz,
    revoked_at      timestamptz
);

CREATE INDEX portal_passkeys_account ON portal_passkeys (account_id) WHERE revoked_at IS NULL;

COMMENT ON TABLE portal_passkeys IS
    'C2: an account''s portal passkeys (public halves); the portal second factor and the platform rail''s amr (class S).';

CREATE TABLE portal_passkey_ceremonies (
    ceremony_hash text        NOT NULL PRIMARY KEY CHECK (ceremony_hash ~ '^[0-9a-f]{64}$'),
    account_id    uuid        NOT NULL REFERENCES accounts (account_id) ON DELETE CASCADE,
    session_id    uuid        NOT NULL,
    kind          text        NOT NULL CHECK (kind IN ('register', 'assert')),
    challenge     bytea       NOT NULL CHECK (octet_length(challenge) = 32),
    label         text        NOT NULL DEFAULT '' CHECK (char_length(label) <= 60),
    created_at    timestamptz NOT NULL,
    expires_at    timestamptz NOT NULL,
    consumed_at   timestamptz,
    CONSTRAINT portal_passkey_ceremonies_short_lived CHECK (expires_at > created_at AND expires_at <= created_at + interval '10 minutes')
);

CREATE INDEX portal_passkey_ceremonies_expiry ON portal_passkey_ceremonies (account_id, expires_at);

COMMENT ON TABLE portal_passkey_ceremonies IS
    'C2: single-use portal WebAuthn challenges bound to account and browser session (class S).';

CREATE TABLE portal_recovery_codes (
    code_hash  text        NOT NULL PRIMARY KEY CHECK (code_hash ~ '^[0-9a-f]{64}$'),
    account_id uuid        NOT NULL REFERENCES accounts (account_id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    used_at    timestamptz
);

CREATE INDEX portal_recovery_codes_account ON portal_recovery_codes (account_id);

COMMENT ON TABLE portal_recovery_codes IS
    'C2: hashes of an account''s one-time portal recovery codes (class S).';

ALTER TABLE browser_sessions ADD COLUMN second_factor_at timestamptz;
ALTER TABLE browser_sessions ADD COLUMN second_factor_method text;
-- NOT VALID: every existing row is NULL (the column is new), and the check
-- holds for every row written from here on.
ALTER TABLE browser_sessions ADD CONSTRAINT browser_sessions_second_factor_method
    CHECK (second_factor_method IS NULL OR second_factor_method IN ('passkey', 'recovery_code')) NOT VALID;
ALTER TABLE browser_sessions ADD COLUMN second_factor_amr text[];

ALTER TABLE orgs ADD COLUMN require_second_factor boolean NOT NULL DEFAULT false;

GRANT SELECT, INSERT, UPDATE, DELETE ON portal_passkeys, portal_passkey_ceremonies, portal_recovery_codes TO sbci_api, sbci_app;
GRANT UPDATE (require_second_factor) ON orgs TO sbci_api;

-- 0009_portal_auth_transactions.sql — the portal WorkOS sign-in leg (W1 of the
-- cloud-intelligence divergence remediation plan, §3 W1).
--
-- Two tables, deliberately in DIFFERENT tenancy classes (0002's split):
--
--   auth_transactions — a SYSTEM table (no RLS), the exact class
--   exchange_nonces is in. The row is minted PRE-AUTH at
--   GET /portal/auth/workos/start: at that moment there is no account and no
--   tenant context, so an RLS-scoped table could not be written at all. It is
--   keyed by a high-entropy secret's hash (state_hash), single-use, and
--   globally expiring. Per the rev-4 F6 classification these rows are NOT
--   account-linked: they expire on expires_at, are excluded from account
--   export, and are not part of the account-deletion matrix — the same basis
--   as exchange_nonces. (The step_up flavour DOES carry an account_id/
--   session_id binding so the callback can prove the re-authenticated identity
--   is the signed-in one; that binding is a short-lived check, not an account
--   data record, and the row still expires globally.)
--
--   step_up_authorizations — a TENANT table (RLS ENABLE + FORCE + the same
--   sbci_current_account() policy 0004 installs on every account-owned table).
--   These rows ARE account-scoped and purge with the account.
--
-- Both tables are single-use by conditional UPDATE ... RETURNING (the
-- exchange_nonces precedent), never by a read-then-write.

-- ---------------------------------------------------------------------------
-- auth_transactions (SYSTEM)
-- ---------------------------------------------------------------------------
CREATE TABLE auth_transactions (
    txn_id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- hex sha256 of the raw transaction secret. The raw value is carried BOTH
    -- as the OAuth `state` parameter and in a separate SameSite=Lax
    -- transaction cookie; the callback requires the two to match before it
    -- consumes this row, so neither a forged state nor a stolen cookie alone
    -- completes a sign-in.
    state_hash        text NOT NULL UNIQUE,
    -- The PKCE code verifier, encrypted at rest with the store's Encryptor
    -- seam (the same AES-256-GCM path evidence blobs use). It is a bearer
    -- secret for the duration of the flow, so it never lands in the clear.
    pkce_verifier_enc bytea NOT NULL,
    nonce_hash        text NOT NULL,
    -- The EXACT redirect_uri sent to WorkOS. Re-checked at callback so a
    -- transaction minted for one origin cannot complete against another.
    redirect_uri      text NOT NULL,
    purpose           text NOT NULL CHECK (purpose IN ('login', 'step_up')),
    action            text CHECK (action IN ('deletion', 'export', 'security')),
    -- return_to is the same-origin PATH the callback redirects the browser to
    -- on success. It is validated as a path (leading '/', never '//', no
    -- scheme/host/backslash) at mint time AND again at redirect time.
    return_to         text,
    -- session_id/account_id are set ONLY for a step_up transaction: they bind
    -- the re-authentication to the browser session that started it.
    session_id        uuid,
    account_id        uuid REFERENCES accounts(account_id),
    created_at        timestamptz NOT NULL DEFAULT now(),
    expires_at        timestamptz NOT NULL,
    consumed_at       timestamptz,
    -- Structural guarantee of the sentence above: a login transaction carries
    -- no account binding and no action; a step_up transaction carries all
    -- three. A mis-shaped row is impossible, not merely unwritten.
    CONSTRAINT auth_transactions_purpose_shape CHECK (
        (purpose = 'login'
            AND action IS NULL AND session_id IS NULL AND account_id IS NULL)
     OR (purpose = 'step_up'
            AND action IS NOT NULL AND session_id IS NOT NULL AND account_id IS NOT NULL)
    )
);

-- The opportunistic sweep (mirroring the pop_replay expiry index, FC3) deletes
-- purely by expires_at.
CREATE INDEX auth_transactions_expiry ON auth_transactions (expires_at);

-- ---------------------------------------------------------------------------
-- step_up_authorizations (TENANT: RLS + FORCE + policy, mirroring 0004)
-- ---------------------------------------------------------------------------
CREATE TABLE step_up_authorizations (
    authz_id    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id  uuid NOT NULL REFERENCES accounts(account_id),
    -- The browser session that re-authenticated. A step-up minted for one
    -- session can never authorize a mutation issued from another.
    session_id  uuid NOT NULL,
    action      text NOT NULL CHECK (action IN ('deletion', 'export', 'security')),
    -- auth_time is when the identity provider actually re-authenticated the
    -- user (the callback instant), not when the row happened to be written.
    auth_time   timestamptz NOT NULL,
    expires_at  timestamptz NOT NULL,
    consumed_at timestamptz,
    -- 0002's composite-uniqueness convention, so a child row could carry a
    -- composite FK that cannot cross accounts.
    UNIQUE (account_id, authz_id)
);

CREATE INDEX step_up_authorizations_lookup
    ON step_up_authorizations (account_id, session_id, action, expires_at);

ALTER TABLE step_up_authorizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE step_up_authorizations FORCE ROW LEVEL SECURITY;
CREATE POLICY step_up_authorizations_tenant ON step_up_authorizations
    USING (account_id = sbci_current_account())
    WITH CHECK (account_id = sbci_current_account());

-- ---------------------------------------------------------------------------
-- Grants to sbci_app (RLS still constrains every step_up_authorizations row).
-- ---------------------------------------------------------------------------
GRANT SELECT, INSERT, UPDATE, DELETE ON auth_transactions TO sbci_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON step_up_authorizations TO sbci_app;

-- 0150_connect_requests.sql - Getting started v2, the connect flow
-- (docs/plans/onboarding-v2-connect-flow.md; docs/security.md CONNECT-1).
--
-- step: expand
--
-- Three new tables, created in one transaction.
--
-- connect_requests - a SYSTEM table (no RLS), the class exchange_nonces and
-- auth_transactions are in: a request is created PRE-AUTH by
-- POST /v1/connect/requests, when there is no account and no tenant context.
-- It gains an account only when a signed-in browser approves or declines it.
-- 'expired' is never stored: a pending row past expires_at reads as expired.
-- The shape CHECK makes a mis-shaped row impossible, not merely unwritten.
-- Only the masked network prefix of the requester is stored, never the full
-- address. Rows are swept 24 hours after they end (30 days for an approved
-- row, which the account home lists) and purged on account deletion.
--
-- connect_poll_replay - the single-use proof-of-possession jti of each poll
-- (the request has no account, so the account-scoped pop_replay cannot hold
-- it). Cascades with its request.
--
-- connect_consents - a TENANT table (RLS ENABLE + FORCE + the
-- sbci_current_account() policy): the consent receipt of one Connect, bound to
-- the disclosure version and the SHA-256 of the text the server served.
-- Append-only (SELECT and INSERT only). Retained on account deletion like the
-- other consent records; dropped with the account row by the tombstone sweep.

SET LOCAL lock_timeout = '5s';

CREATE TABLE connect_requests (
    request_id        uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Set while pending; cleared when the request is approved or declined so
    -- a code never resolves twice.
    user_code         text        UNIQUE CHECK (user_code ~ '^[BCDFGHJKLMNPQRSTVWXZ]{4}-[0-9]{4}$'),
    device_public_key bytea       NOT NULL CHECK (octet_length(device_public_key) = 32),
    device_thumbprint text        NOT NULL CHECK (char_length(device_thumbprint) BETWEEN 1 AND 64),
    machine_name      text        NOT NULL CHECK (char_length(machine_name) BETWEEN 1 AND 64),
    os                text        NOT NULL CHECK (os ~ '^[a-z0-9_]{1,16}$'),
    arch              text        NOT NULL CHECK (arch ~ '^[a-z0-9_]{1,16}$'),
    observer_version  text        NOT NULL CHECK (observer_version ~ '^[0-9A-Za-z.+_-]{1,32}$'),
    target_hint       text        NOT NULL DEFAULT '' CHECK (char_length(target_hint) <= 40),
    origin_network    text        NOT NULL DEFAULT '' CHECK (char_length(origin_network) <= 64),
    status            text        NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'declined')),
    created_at        timestamptz NOT NULL,
    expires_at        timestamptz NOT NULL,
    resolved_at       timestamptz,
    account_id        uuid        REFERENCES accounts (account_id) ON DELETE CASCADE,
    approver_session  uuid,
    target_org_id     uuid,
    target_slug       text        CHECK (target_slug IS NULL OR char_length(target_slug) BETWEEN 1 AND 63),
    target_kind       text        CHECK (target_kind IS NULL OR target_kind IN ('personal', 'team')),
    target_name       text        CHECK (target_name IS NULL OR char_length(target_name) BETWEEN 1 AND 200),
    share_level       text        CHECK (share_level IS NULL OR share_level IN ('summary', 'full')),
    consent_id        uuid,
    deliveries        integer     NOT NULL DEFAULT 0 CHECK (deliveries BETWEEN 0 AND 3),
    delivered_token   uuid,
    CONSTRAINT connect_requests_lifetime CHECK (
        expires_at > created_at AND expires_at <= created_at + interval '1 hour'
    ),
    CONSTRAINT connect_requests_target_whole CHECK (
        (target_org_id IS NULL AND target_slug IS NULL AND target_kind IS NULL
            AND target_name IS NULL AND share_level IS NULL AND consent_id IS NULL)
     OR (target_org_id IS NOT NULL AND target_slug IS NOT NULL AND target_kind IS NOT NULL
            AND target_name IS NOT NULL AND share_level IS NOT NULL AND consent_id IS NOT NULL)
    ),
    CONSTRAINT connect_requests_shape CHECK (
        (status = 'pending'
            AND user_code IS NOT NULL AND account_id IS NULL AND resolved_at IS NULL
            AND approver_session IS NULL AND target_org_id IS NULL
            AND deliveries = 0 AND delivered_token IS NULL)
     OR (status = 'approved'
            AND user_code IS NULL AND account_id IS NOT NULL AND resolved_at IS NOT NULL
            AND approver_session IS NOT NULL)
     OR (status = 'declined'
            AND user_code IS NULL AND account_id IS NOT NULL AND resolved_at IS NOT NULL
            AND target_org_id IS NULL AND deliveries = 0 AND delivered_token IS NULL)
    )
);

COMMENT ON TABLE connect_requests IS
    'Getting started v2: one machine asking to be signed in and connected (system table; CONNECT-1).';

-- The sweep deletes by expiry and resolution time; the account home reads
-- an account's recent approvals.
CREATE INDEX connect_requests_expiry ON connect_requests (expires_at);
CREATE INDEX connect_requests_account ON connect_requests (account_id, resolved_at DESC)
    WHERE account_id IS NOT NULL;

CREATE TABLE connect_poll_replay (
    request_id uuid        NOT NULL REFERENCES connect_requests (request_id) ON DELETE CASCADE,
    jti        text        NOT NULL CHECK (char_length(jti) BETWEEN 16 AND 64),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (request_id, jti)
);

COMMENT ON TABLE connect_poll_replay IS
    'Single-use proof jti of each connect poll (system table; CONNECT-1).';

CREATE TABLE connect_consents (
    consent_id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id         uuid        NOT NULL REFERENCES accounts (account_id) ON DELETE CASCADE,
    -- Opaque: the request row is swept long before the receipt ends.
    request_id         uuid        NOT NULL UNIQUE,
    org_id             uuid        NOT NULL,
    share_level        text        NOT NULL CHECK (share_level IN ('summary', 'full')),
    disclosure_version text        NOT NULL CHECK (char_length(disclosure_version) BETWEEN 1 AND 64),
    disclosure_sha256  text        NOT NULL CHECK (disclosure_sha256 ~ '^[0-9a-f]{64}$'),
    created_at         timestamptz NOT NULL
);

COMMENT ON TABLE connect_consents IS
    'Consent receipt of one Connect: dashboard, share level and the exact disclosure shown (tenant table; CONNECT-1).';

ALTER TABLE connect_consents ENABLE ROW LEVEL SECURITY;
ALTER TABLE connect_consents FORCE ROW LEVEL SECURITY;
CREATE POLICY connect_consents_tenant ON connect_consents
    USING (account_id = sbci_current_account())
    WITH CHECK (account_id = sbci_current_account());

GRANT SELECT, INSERT, UPDATE, DELETE ON connect_requests, connect_poll_replay TO sbci_api, sbci_app;
GRANT SELECT, INSERT ON connect_consents TO sbci_api, sbci_app;

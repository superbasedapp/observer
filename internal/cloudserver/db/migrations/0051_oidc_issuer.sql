-- 0051_oidc_issuer.sql - the control plane's OIDC issuer tables (managed-SaaS
-- plan 07 M6.2; design
-- docs/plans/managed-saas/m6.0-control-plane-design-2026-11-13.md 3.3, 4.4;
-- lead decision L-9 Q5).
--
-- step: expand
--
-- One step of four (0051-0054, the M6.2 block in docs/migration-numbering.md).
-- This step creates the four issuer tables and grants nothing: their grants
-- arrive in 0052, the audit-mirror outbox in 0053 and the org_sub_seen
-- trigger in 0054. All four are class S (design 3.2): no row-level security,
-- reachable only through explicit grants, never by a customer-facing policy.
--
-- TABLES
--
--   oidc_clients       one PUBLIC client per org: client_id "org:<org_id>",
--                      exactly one exact redirect URI
--                      (https://<slug>.<tenant domain>/auth/oidc/callback),
--                      PKCE S256, no secret (design A7). The audience of the
--                      id_token is the client id itself (OIDC Core 2: aud
--                      MUST contain the client_id, and the tenant rail checks
--                      exactly that), so there is no separate aud column; the
--                      design note's "aud = the tenant host" would fail the
--                      tenant's own check.
--   oidc_codes         authorization codes, by the hex SHA-256 of the code
--                      (the raw code is never stored). 60-second life, single
--                      use through one conditional UPDATE ... RETURNING (the
--                      exchange_nonces precedent), so authorize and token may
--                      run on different replicas. nonce is stored as given:
--                      the id_token must echo it, so a hash (the design's
--                      nonce_hash) cannot work, and it is not a secret (it
--                      rides the authorize URL). No address is stored: the
--                      token step re-reads it from the display profile.
--   oidc_signing_keys  the PUBLIC halves of the signers' RSA keys, one kid
--                      per VM. staged (reported, not published) -> active
--                      (published; signs from not_before) -> retiring
--                      (published, signs nothing) -> retired (gone).
--   oidc_issued        every id_token issued, by jti, recorded BEFORE the
--                      token is returned. The jti primary key is the replay
--                      guard. Append-only (no UPDATE grant anywhere): the
--                      mirror's delivery state lives in oidc_audit_mirror
--                      (0053), so the design's mirrored_at column is not
--                      created (one owner per fact).
--
-- ACCOUNT REFERENCES. account_id columns are opaque ids with no foreign key,
-- as in 0047/0049: the 24-month retention sweep DELETEs account tombstones and
-- a foreign key from an audit row would block it. org_id references orgs.

SET LOCAL lock_timeout = '5s';

-- ---------------------------------------------------------------------------
-- oidc_clients (class S)
-- ---------------------------------------------------------------------------
CREATE TABLE oidc_clients (
    client_id     text        NOT NULL PRIMARY KEY,
    org_id        uuid        NOT NULL UNIQUE REFERENCES orgs (org_id),
    -- Exactly one https URI ending in the tenant rail's callback path.
    redirect_uris text[]      NOT NULL
        CHECK (cardinality(redirect_uris) = 1
               AND redirect_uris[1] ~ '^https://[a-z0-9-]+(\.[a-z0-9-]+)+/auth/oidc/callback$'),
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    disabled_at   timestamptz,
    CONSTRAINT oidc_clients_id_is_org CHECK (client_id = 'org:' || org_id::text)
);

-- ---------------------------------------------------------------------------
-- oidc_codes (class S)
-- ---------------------------------------------------------------------------
CREATE TABLE oidc_codes (
    code_hash      text        NOT NULL PRIMARY KEY CHECK (code_hash ~ '^[0-9a-f]{64}$'),
    client_id      text        NOT NULL REFERENCES oidc_clients (client_id),
    org_id         uuid        NOT NULL REFERENCES orgs (org_id),
    account_id     uuid        NOT NULL,
    sub            text        NOT NULL CHECK (sub <> '' AND char_length(sub) <= 255),
    nonce          text        NOT NULL CHECK (nonce <> '' AND char_length(nonce) <= 512),
    -- An S256 challenge: 43 base64url characters.
    code_challenge text        NOT NULL CHECK (code_challenge ~ '^[A-Za-z0-9_-]{43}$'),
    redirect_uri   text        NOT NULL,
    amr            text[]      NOT NULL DEFAULT '{}',
    created_at     timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL,
    consumed_at    timestamptz,
    CONSTRAINT oidc_codes_short_lived CHECK (expires_at > created_at AND expires_at <= created_at + interval '5 minutes')
);

-- The sweep of spent and expired codes.
CREATE INDEX oidc_codes_expires ON oidc_codes (expires_at);

-- ---------------------------------------------------------------------------
-- oidc_signing_keys (class S)
-- ---------------------------------------------------------------------------
CREATE TABLE oidc_signing_keys (
    -- The RFC 7638 thumbprint of the public key (base64url SHA-256).
    kid        text        NOT NULL PRIMARY KEY CHECK (kid ~ '^[A-Za-z0-9_-]{43}$'),
    alg        text        NOT NULL DEFAULT 'RS256' CHECK (alg = 'RS256'),
    public_jwk jsonb       NOT NULL CHECK (public_jwk->>'kty' = 'RSA' AND public_jwk->>'kid' = kid),
    -- The app VM whose signer holds the private half.
    vm_id      text        NOT NULL CHECK (vm_id <> '' AND char_length(vm_id) <= 100),
    status     text        NOT NULL DEFAULT 'staged'
        CHECK (status IN ('staged', 'active', 'retiring', 'retired')),
    -- When an active key may first sign (the JWKS lists it from promotion);
    -- required once a key leaves staged.
    not_before timestamptz,
    -- When the key stops being published and stops signing; NULL open.
    not_after  timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT oidc_signing_keys_promoted_has_not_before CHECK (status = 'staged' OR not_before IS NOT NULL),
    CONSTRAINT oidc_signing_keys_window CHECK (not_after IS NULL OR not_before IS NULL OR not_after > not_before)
);

-- ---------------------------------------------------------------------------
-- oidc_issued (class S, append-only)
-- ---------------------------------------------------------------------------
CREATE TABLE oidc_issued (
    jti        text        NOT NULL PRIMARY KEY CHECK (jti ~ '^[A-Za-z0-9_.~-]{16,128}$'),
    org_id     uuid        NOT NULL REFERENCES orgs (org_id),
    account_id uuid        NOT NULL,
    sub        text        NOT NULL CHECK (sub <> '' AND char_length(sub) <= 255),
    client_id  text        NOT NULL,
    kid        text        NOT NULL,
    iat        timestamptz NOT NULL,
    exp        timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT oidc_issued_lifetime CHECK (exp > iat AND exp <= iat + interval '5 minutes')
);

-- Account deletion (M6.9) and the audit trail look sign-ins up by account.
CREATE INDEX oidc_issued_account ON oidc_issued (account_id);
CREATE INDEX oidc_issued_org_iat ON oidc_issued (org_id, iat);

COMMENT ON TABLE oidc_clients IS 'M6.2 OIDC issuer: one public client per org (class S), client_id org:<org_id>, one exact redirect URI.';
COMMENT ON TABLE oidc_codes IS 'M6.2 OIDC issuer: single-use 60-second authorization codes by hash (class S).';
COMMENT ON TABLE oidc_signing_keys IS 'M6.2 OIDC issuer: public halves of the per-VM signer keys (class S); staged, active, retiring, retired.';
COMMENT ON TABLE oidc_issued IS 'M6.2 OIDC issuer: every id_token issued, by jti, recorded before it is returned (class S, append-only).';

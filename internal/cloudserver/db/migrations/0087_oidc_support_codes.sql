-- 0087_oidc_support_codes.sql - the platform OIDC issuer's support path
-- (managed-SaaS plan 07 M7a.2; plan 06 5.8.7; design
-- docs/plans/managed-saas/m6.0-control-plane-design-2026-11-13.md 4.9 "The
-- support claim"; lane lane-w11-support-oplog).
--
-- step: expand
--
-- A SuperBased staff member signs in to a tenant org as support through the
-- staff process (its own host and login, sbci_staff): the staff console's
-- authorize route checks the staff session (a recent passkey assertion) and
-- writes a SUPPORT code; the serve process's token endpoint redeems it and
-- signs an id_token carrying support: true and sub staff:<staff_id>. The
-- tenant then admits a support session only while one of its own grants
-- names that staff identity (the control plane never sees the grant).
--
-- Two class S tables (no RLS: the grants ARE the access control), kept apart
-- from oidc_codes / oidc_issued, which key every row to a customer account:
--
--   oidc_support_codes   single-use 60-second codes for a staff identity,
--                        by hash. Written ONLY by sbci_staff (the staff
--                        process); consumed by sbci_api (the token
--                        endpoint), which may mark consumed_at and sweep.
--                        auth_time is the staff session's WebAuthn assertion
--                        time, always known.
--   oidc_support_issued  every support id_token, by jti, recorded before the
--                        token is returned (audit before act). Append-only
--                        (INSERT only for sbci_api). No audit-mirror row:
--                        oidc_audit_mirror keys to oidc_issued, and the
--                        tenant writes its own support audit rows.
--
-- sbci_staff also gains SELECT on oidc_clients: authorize validates the
-- client and its exact redirect URI before writing a code, as the member
-- path does. It reads nothing else of the issuer.

SET LOCAL lock_timeout = '5s';

CREATE TABLE oidc_support_codes (
    code_hash      text        NOT NULL PRIMARY KEY CHECK (code_hash ~ '^[0-9a-f]{64}$'),
    client_id      text        NOT NULL REFERENCES oidc_clients (client_id),
    org_id         uuid        NOT NULL REFERENCES orgs (org_id),
    staff_id       uuid        NOT NULL REFERENCES staff_users (staff_id),
    nonce          text        NOT NULL CHECK (nonce <> '' AND char_length(nonce) <= 512),
    code_challenge text        NOT NULL CHECK (code_challenge ~ '^[A-Za-z0-9_-]{43}$'),
    redirect_uri   text        NOT NULL,
    auth_time      timestamptz NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL,
    consumed_at    timestamptz,
    CONSTRAINT oidc_support_codes_short_lived CHECK (expires_at > created_at AND expires_at <= created_at + interval '5 minutes')
);

CREATE INDEX oidc_support_codes_expires ON oidc_support_codes (expires_at);

CREATE TABLE oidc_support_issued (
    jti        text        NOT NULL PRIMARY KEY CHECK (jti ~ '^[A-Za-z0-9_.~-]{16,128}$'),
    org_id     uuid        NOT NULL REFERENCES orgs (org_id),
    staff_id   uuid        NOT NULL REFERENCES staff_users (staff_id),
    client_id  text        NOT NULL,
    kid        text        NOT NULL,
    iat        timestamptz NOT NULL,
    exp        timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT oidc_support_issued_lifetime CHECK (exp > iat AND exp <= iat + interval '5 minutes')
);

CREATE INDEX oidc_support_issued_org_iat ON oidc_support_issued (org_id, iat);
CREATE INDEX oidc_support_issued_staff ON oidc_support_issued (staff_id);

GRANT SELECT                         ON oidc_clients        TO sbci_staff;
GRANT INSERT                         ON oidc_support_codes  TO sbci_staff;

GRANT SELECT, DELETE                 ON oidc_support_codes  TO sbci_api;
GRANT UPDATE (consumed_at)           ON oidc_support_codes  TO sbci_api;
GRANT INSERT                         ON oidc_support_issued TO sbci_api;

GRANT SELECT, INSERT, UPDATE, DELETE ON oidc_support_codes  TO sbci_app;
GRANT SELECT, INSERT                 ON oidc_support_issued TO sbci_app;

COMMENT ON TABLE oidc_support_codes IS 'M7a.2 OIDC issuer support path: single-use 60-second support codes for a staff identity, written by sbci_staff, redeemed by sbci_api (class S).';
COMMENT ON TABLE oidc_support_issued IS 'M7a.2 OIDC issuer support path: every support id_token issued, by jti, recorded before it is returned (class S, append-only).';

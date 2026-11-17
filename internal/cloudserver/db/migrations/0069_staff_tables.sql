-- 0069_staff_tables.sql - the staff console's tables and their grants
-- (managed-SaaS plan 07 M6.8; design
-- docs/plans/managed-saas/m6.0-control-plane-design-2026-11-13.md 3.5, 4.5,
-- 4.9; plan 06 5.4 and 18.3.5).
--
-- step: expand
--
-- Seven tables, all reachable only by the roles granted below; 0070 adds
-- row-level security bound to those same roles (a stray grant to any other
-- role still reads nothing). None carries account data: a staff member is an
-- operator of the platform, not a customer account, and NO staff row holds an
-- email address or keys anything on one. A staff member is keyed by
-- staff_id and authenticated by a WebAuthn credential id.
--
-- TABLES
--
--   staff_users                 one row per staff member: an operator-chosen
--                               display name and a console role
--                               (support < ops < admin). Never deleted:
--                               disabled instead, so the action log keeps
--                               its subject.
--   staff_webauthn_credentials  the PUBLIC half of each staff passkey (the
--                               credential public key as the verifier
--                               returns it), its signature counter and
--                               revocation.
--   staff_enrolments            one-time enrolment codes, by the hex SHA-256
--                               of the code (the raw code is printed once by
--                               `observer-cloud staff enrol` and never
--                               stored). Single use: used_at is set in the
--                               same transaction that stores the credential.
--                               At most an hour of life (default 30 minutes).
--   staff_ceremonies            the server half of each WebAuthn ceremony
--                               (register or assert): the challenge, bound
--                               to a short-lived ceremony cookie by the hash
--                               of its value. Single use, at most 10 minutes.
--   staff_sessions              staff browser sessions, by the hash of the
--                               __Host-sbci-staff cookie. Minted ONLY by a
--                               verified WebAuthn assertion; webauthn_at is
--                               that assertion's time, which a mutation
--                               requires to be fresh. At most 12 hours.
--   staff_actions               the append-only staff action log: every
--                               enrolment, registration, sign-in, sign-out
--                               and staff mutation, with a reason. INSERT
--                               and SELECT only, for every role.
--   availability_inputs         the staff-authored inputs the availability
--                               envelope (sbo-availability-v1, M6.3) is
--                               composed from, one row per (section, key).
--                               Written only through the staff routes, each
--                               write logged in staff_actions in the same
--                               transaction; the worker reads them.
--
-- GRANTS. sbci_staff holds exactly what the staff routes and the operator
-- command use; UPDATE is column-level where a row has only a few mutable
-- columns. sbci_worker reads availability_inputs. sbci_api, sbci_app and
-- sbci_aggregator hold NOTHING on any table here.

SET LOCAL lock_timeout = '5s';

-- ---------------------------------------------------------------------------
-- staff_users
-- ---------------------------------------------------------------------------
CREATE TABLE staff_users (
    staff_id     uuid        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    display_name text        NOT NULL CHECK (char_length(btrim(display_name)) BETWEEN 1 AND 100),
    staff_role   text        NOT NULL CHECK (staff_role IN ('support', 'ops', 'admin')),
    status       text        NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at   timestamptz NOT NULL DEFAULT now(),
    disabled_at  timestamptz,
    CONSTRAINT staff_users_disabled_at CHECK ((status = 'disabled') = (disabled_at IS NOT NULL))
);

-- ---------------------------------------------------------------------------
-- staff_webauthn_credentials
-- ---------------------------------------------------------------------------
CREATE TABLE staff_webauthn_credentials (
    credential_id bytea       NOT NULL PRIMARY KEY CHECK (octet_length(credential_id) BETWEEN 1 AND 1023),
    staff_id      uuid        NOT NULL REFERENCES staff_users (staff_id),
    public_key    bytea       NOT NULL CHECK (octet_length(public_key) BETWEEN 1 AND 2048),
    sign_count    bigint      NOT NULL DEFAULT 0 CHECK (sign_count BETWEEN 0 AND 4294967295),
    aaguid        bytea       CHECK (aaguid IS NULL OR octet_length(aaguid) = 16),
    transports    text[]      NOT NULL DEFAULT '{}',
    label         text        NOT NULL DEFAULT '' CHECK (char_length(label) <= 100),
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_used_at  timestamptz,
    revoked_at    timestamptz
);

CREATE INDEX staff_webauthn_credentials_staff ON staff_webauthn_credentials (staff_id);

-- ---------------------------------------------------------------------------
-- staff_enrolments
-- ---------------------------------------------------------------------------
CREATE TABLE staff_enrolments (
    code_hash  text        NOT NULL PRIMARY KEY CHECK (code_hash ~ '^[0-9a-f]{64}$'),
    staff_id   uuid        NOT NULL REFERENCES staff_users (staff_id),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at    timestamptz,
    CONSTRAINT staff_enrolments_short_lived CHECK (expires_at > created_at AND expires_at <= created_at + interval '1 hour')
);

CREATE INDEX staff_enrolments_staff ON staff_enrolments (staff_id);

-- ---------------------------------------------------------------------------
-- staff_ceremonies
-- ---------------------------------------------------------------------------
CREATE TABLE staff_ceremonies (
    ceremony_hash  text        NOT NULL PRIMARY KEY CHECK (ceremony_hash ~ '^[0-9a-f]{64}$'),
    kind           text        NOT NULL CHECK (kind IN ('register', 'assert')),
    challenge      bytea       NOT NULL CHECK (octet_length(challenge) = 32),
    -- A registration ceremony belongs to one staff member and one enrolment
    -- code; an assertion ceremony to neither (the credential names the staff
    -- member at finish).
    staff_id       uuid        REFERENCES staff_users (staff_id),
    enrolment_hash text        REFERENCES staff_enrolments (code_hash),
    created_at     timestamptz NOT NULL,
    expires_at     timestamptz NOT NULL,
    consumed_at    timestamptz,
    CONSTRAINT staff_ceremonies_short_lived CHECK (expires_at > created_at AND expires_at <= created_at + interval '10 minutes'),
    CONSTRAINT staff_ceremonies_kind_shape CHECK (
        (kind = 'register' AND staff_id IS NOT NULL AND enrolment_hash IS NOT NULL)
        OR (kind = 'assert' AND staff_id IS NULL AND enrolment_hash IS NULL))
);

CREATE INDEX staff_ceremonies_expires ON staff_ceremonies (expires_at);

-- ---------------------------------------------------------------------------
-- staff_sessions
-- ---------------------------------------------------------------------------
CREATE TABLE staff_sessions (
    session_hash    text        NOT NULL PRIMARY KEY CHECK (session_hash ~ '^[0-9a-f]{64}$'),
    staff_id        uuid        NOT NULL REFERENCES staff_users (staff_id),
    credential_id   bytea       NOT NULL REFERENCES staff_webauthn_credentials (credential_id),
    csrf_hash       text        NOT NULL CHECK (csrf_hash ~ '^[0-9a-f]{64}$'),
    webauthn_at     timestamptz NOT NULL,
    created_at      timestamptz NOT NULL,
    last_seen_at    timestamptz NOT NULL,
    idle_expires_at timestamptz NOT NULL,
    expires_at      timestamptz NOT NULL,
    revoked_at      timestamptz,
    CONSTRAINT staff_sessions_lifetime CHECK (expires_at > created_at AND expires_at <= created_at + interval '12 hours'),
    CONSTRAINT staff_sessions_idle_within CHECK (idle_expires_at <= expires_at)
);

CREATE INDEX staff_sessions_staff ON staff_sessions (staff_id);

-- ---------------------------------------------------------------------------
-- staff_actions (append-only)
-- ---------------------------------------------------------------------------
CREATE TABLE staff_actions (
    action_id        uuid        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    at               timestamptz NOT NULL,
    -- 'operator' for the CLI; 'staff:<staff_id>' for a signed-in staff member.
    actor            text        NOT NULL CHECK (actor = 'operator' OR actor ~ '^staff:[0-9a-f-]{36}$'),
    verb             text        NOT NULL CHECK (verb ~ '^[a-z][a-z_.]{1,63}$'),
    subject_staff_id uuid        REFERENCES staff_users (staff_id),
    -- An opaque org id with no foreign key: an org's deletion (M6.9) must not
    -- be blocked by, or erase, the log of what staff did to it.
    org_id           uuid,
    target           text        CHECK (target IS NULL OR char_length(target) BETWEEN 1 AND 300),
    detail           jsonb       CHECK (detail IS NULL OR octet_length(detail::text) <= 16384),
    reason           text        NOT NULL CHECK (char_length(btrim(reason)) BETWEEN 1 AND 1000),
    result           text        NOT NULL CHECK (result IN ('ok', 'refused'))
);

CREATE INDEX staff_actions_at ON staff_actions (at);

-- ---------------------------------------------------------------------------
-- availability_inputs
-- ---------------------------------------------------------------------------
CREATE TABLE availability_inputs (
    section    text        NOT NULL CHECK (section IN ('components', 'org_controls', 'release_flags')),
    key        text        NOT NULL CHECK (key ~ '^[A-Za-z0-9._:-]{1,128}$'),
    value      jsonb       NOT NULL CHECK (jsonb_typeof(value) = 'object' AND octet_length(value::text) <= 8192),
    reason     text        NOT NULL CHECK (char_length(btrim(reason)) BETWEEN 1 AND 1000),
    author     text        NOT NULL CHECK (author ~ '^staff:[0-9a-f-]{36}$'),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (section, key)
);

-- ---------------------------------------------------------------------------
-- Grants
-- ---------------------------------------------------------------------------
GRANT SELECT, INSERT ON staff_users TO sbci_staff;

GRANT SELECT, INSERT ON staff_webauthn_credentials TO sbci_staff;
GRANT UPDATE (sign_count, last_used_at, revoked_at) ON staff_webauthn_credentials TO sbci_staff;

GRANT SELECT, INSERT ON staff_enrolments TO sbci_staff;
GRANT UPDATE (used_at) ON staff_enrolments TO sbci_staff;

GRANT SELECT, INSERT, DELETE ON staff_ceremonies TO sbci_staff;
GRANT UPDATE (consumed_at) ON staff_ceremonies TO sbci_staff;

GRANT SELECT, INSERT ON staff_sessions TO sbci_staff;
GRANT UPDATE (last_seen_at, idle_expires_at, revoked_at) ON staff_sessions TO sbci_staff;

GRANT SELECT, INSERT ON staff_actions TO sbci_staff;

GRANT SELECT, INSERT, UPDATE, DELETE ON availability_inputs TO sbci_staff;
GRANT SELECT ON availability_inputs TO sbci_worker;

COMMENT ON TABLE staff_users IS 'M6.8 staff console: staff members by staff_id (no email), role support|ops|admin; never deleted.';
COMMENT ON TABLE staff_webauthn_credentials IS 'M6.8 staff console: public halves of staff passkeys, sign counter, revocation.';
COMMENT ON TABLE staff_enrolments IS 'M6.8 staff console: single-use operator-minted enrolment codes by hash.';
COMMENT ON TABLE staff_ceremonies IS 'M6.8 staff console: single-use WebAuthn challenges bound to a ceremony cookie hash.';
COMMENT ON TABLE staff_sessions IS 'M6.8 staff console: staff sessions by cookie hash, minted only by a WebAuthn assertion.';
COMMENT ON TABLE staff_actions IS 'M6.8 staff console: append-only log of staff and operator actions with reasons.';
COMMENT ON TABLE availability_inputs IS 'M6.8 staff console: staff-authored availability envelope inputs (M6.3 composes from them).';

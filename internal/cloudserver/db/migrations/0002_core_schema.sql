-- 0002_core_schema.sql — every table for the CI-P3 hosted service foundation.
--
-- Two tenancy classes:
--
--   SYSTEM tables (no RLS): accounts, exchange_nonces, route_registry,
--   kill_switches, free_tier_budget, security_audit_events. These are
--   global/pre-tenant control-plane state, keyed by a primary key or a
--   high-entropy secret, never listed per-tenant through an API. sbci_app
--   accesses them directly (RLS would create a bootstrap chicken-and-egg).
--
--   TENANT tables (RLS ENABLE + FORCE, account_id NOT NULL, composite
--   (account_id, id) uniqueness so children can carry composite FKs): every
--   account-owned resource. RLS + grants are applied in 0004_rls_grants.sql.
--
-- gen_random_uuid() is core in PostgreSQL 13+ (no extension needed).

-- ---------------------------------------------------------------------------
-- SYSTEM tables
-- ---------------------------------------------------------------------------

CREATE TABLE accounts (
    account_id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    status             text NOT NULL DEFAULT 'active'
                           CHECK (status IN ('active', 'suspended', 'closed', 'deleted')),
    -- consent_generation is the monotonic per-account generation (Sol SC4):
    -- every consent grant/revoke/preview-confirmation bumps it; a job records
    -- the generation at admission and the execution lease revalidates it.
    consent_generation bigint NOT NULL DEFAULT 0,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now()
);

-- exchange_nonces are minted anonymously at GET /v1/auth/nonce (pre-auth) and
-- consumed once at POST /v1/auth/exchange. Stored hashed; single-use via a
-- conditional UPDATE ... RETURNING; expiry bounds the window.
CREATE TABLE exchange_nonces (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    nonce_hash  text NOT NULL UNIQUE,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    consumed_at timestamptz
);

-- route_registry is the placeholder server-side route table (plan §6 CI-P3):
-- the server resolves route_version + prompt_version once, folding them into
-- the canonical job key. CI-P4 grows it (dialect verification record, price
-- snapshot, per-route kill switch/generation).
CREATE TABLE route_registry (
    route_id       text PRIMARY KEY,
    feature        text NOT NULL,
    deployment     text NOT NULL,
    dialect        text NOT NULL DEFAULT 'chat_completions'
                       CHECK (dialect IN ('chat_completions', 'responses_store_false')),
    route_version  bigint NOT NULL DEFAULT 1,
    prompt_version bigint NOT NULL DEFAULT 1,
    price_version  text NOT NULL DEFAULT 'unset',
    active         boolean NOT NULL DEFAULT true,
    created_at     timestamptz NOT NULL DEFAULT now()
);

-- kill_switches are global (scope='global', key='all') or per-route
-- (scope='route', key=route_id). generation is monotonic so a flip is
-- observable to a running lease.
CREATE TABLE kill_switches (
    scope      text NOT NULL CHECK (scope IN ('global', 'route')),
    key        text NOT NULL,
    active     boolean NOT NULL DEFAULT false,
    generation bigint NOT NULL DEFAULT 0,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (scope, key)
);

-- free_tier_budget is the single global spend ceiling for the whole Signed-in
-- Free tier — a singleton row locked FOR UPDATE inside the reservation
-- transaction (Sol SD6). Global by nature, so it is a system table.
CREATE TABLE free_tier_budget (
    id         int PRIMARY KEY CHECK (id = 1),
    cap        bigint NOT NULL,
    used       bigint NOT NULL DEFAULT 0,
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- security_audit_events records content-free security facts. account_id is
-- nullable (a failed exchange has no account yet); it is never surfaced through
-- a tenant API this arc, so it is a system table.
CREATE TABLE security_audit_events (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id uuid REFERENCES accounts(account_id),
    event_type text NOT NULL,
    detail     jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- TENANT tables (account-owned) — RLS + grants applied in 0004
-- ---------------------------------------------------------------------------

CREATE TABLE identity_links (
    id         uuid NOT NULL DEFAULT gen_random_uuid(),
    account_id uuid NOT NULL REFERENCES accounts(account_id),
    provider   text NOT NULL,
    subject    text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (id),
    UNIQUE (account_id, id),
    UNIQUE (provider, subject)
);

CREATE TABLE device_registrations (
    id         uuid NOT NULL DEFAULT gen_random_uuid(),
    account_id uuid NOT NULL REFERENCES accounts(account_id),
    public_key bytea NOT NULL,
    thumbprint text NOT NULL,
    label      text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    PRIMARY KEY (id),
    UNIQUE (account_id, id),
    UNIQUE (account_id, thumbprint)
);

CREATE TABLE api_tokens (
    id         uuid NOT NULL DEFAULT gen_random_uuid(),
    account_id uuid NOT NULL REFERENCES accounts(account_id),
    device_id  uuid NOT NULL,
    token_hash text NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    PRIMARY KEY (id),
    UNIQUE (account_id, id),
    FOREIGN KEY (account_id, device_id) REFERENCES device_registrations(account_id, id)
);

CREATE TABLE browser_sessions (
    id           uuid NOT NULL DEFAULT gen_random_uuid(),
    account_id   uuid NOT NULL REFERENCES accounts(account_id),
    session_hash text NOT NULL UNIQUE,
    csrf_hash    text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    revoked_at   timestamptz,
    PRIMARY KEY (id),
    UNIQUE (account_id, id)
);

CREATE TABLE consent_receipts (
    id                      uuid NOT NULL DEFAULT gen_random_uuid(),
    account_id              uuid NOT NULL REFERENCES accounts(account_id),
    device_id               uuid,
    purposes                text[] NOT NULL,
    field_classes           text[] NOT NULL,
    evidence_schema         text NOT NULL,
    scrubber_version        text NOT NULL,
    retention_policy        text NOT NULL DEFAULT 'temp_1h',
    endpoint                text NOT NULL DEFAULT '',
    subprocessors           text[] NOT NULL DEFAULT '{}',
    upload_digest           text NOT NULL,
    evidence_content_digest text,
    generation              bigint NOT NULL,
    created_at              timestamptz NOT NULL DEFAULT now(),
    expires_at              timestamptz,
    PRIMARY KEY (id),
    UNIQUE (account_id, id)
);

CREATE TABLE consent_events (
    id         uuid NOT NULL DEFAULT gen_random_uuid(),
    account_id uuid NOT NULL REFERENCES accounts(account_id),
    receipt_id uuid,
    event_type text NOT NULL
                   CHECK (event_type IN ('grant', 'revoke', 'update', 'preview_confirmation')),
    purposes   text[] NOT NULL DEFAULT '{}',
    generation bigint NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (id),
    UNIQUE (account_id, id),
    FOREIGN KEY (account_id, receipt_id) REFERENCES consent_receipts(account_id, id)
);

CREATE TABLE entitlements (
    account_id      uuid NOT NULL REFERENCES accounts(account_id),
    feature         text NOT NULL,
    source          text NOT NULL DEFAULT 'beta_manual',
    daily_cap       int NOT NULL,
    monthly_cap     int NOT NULL,
    concurrency_cap int NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, feature)
);

-- usage_cycles holds one lockable counter row per (account, feature,
-- cycle_kind, window_key). daily/monthly are monotonic-within-window;
-- concurrency (window_key='live') goes up on reserve and down on
-- settle/release. The row is SELECT ... FOR UPDATE'd so racing devices
-- serialize on it and cannot exceed a cap.
CREATE TABLE usage_cycles (
    account_id uuid NOT NULL REFERENCES accounts(account_id),
    feature    text NOT NULL,
    cycle_kind text NOT NULL CHECK (cycle_kind IN ('daily', 'monthly', 'concurrency')),
    window_key text NOT NULL,
    cap        int NOT NULL,
    used       int NOT NULL DEFAULT 0,
    source     text NOT NULL DEFAULT 'beta_manual',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, feature, cycle_kind, window_key),
    CHECK (used >= 0)
);

CREATE TABLE usage_reservations (
    id            uuid NOT NULL DEFAULT gen_random_uuid(),
    account_id    uuid NOT NULL REFERENCES accounts(account_id),
    feature       text NOT NULL,
    job_id        uuid,
    state         text NOT NULL DEFAULT 'reserved'
                      CHECK (state IN ('reserved', 'settled', 'released', 'expired')),
    user_units    int NOT NULL DEFAULT 1,
    daily_window  text NOT NULL,
    monthly_window text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (id),
    UNIQUE (account_id, id)
);

CREATE TABLE cloud_projects (
    id              uuid NOT NULL DEFAULT gen_random_uuid(),
    account_id      uuid NOT NULL REFERENCES accounts(account_id),
    cloud_project_id text NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (id),
    UNIQUE (account_id, id),
    UNIQUE (account_id, cloud_project_id)
);

CREATE TABLE cloud_sessions (
    id              uuid NOT NULL DEFAULT gen_random_uuid(),
    account_id      uuid NOT NULL REFERENCES accounts(account_id),
    project_pk      uuid NOT NULL,
    cloud_session_id text NOT NULL,
    tool            text NOT NULL DEFAULT '',
    model_family    text NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (id),
    UNIQUE (account_id, id),
    UNIQUE (account_id, cloud_session_id),
    FOREIGN KEY (account_id, project_pk) REFERENCES cloud_projects(account_id, id)
);

-- evidence_objects: expires_at is IMMUTABLE (plan §2.8) — set to
-- created_at + 1h at creation and never extended, enforced by the BEFORE
-- UPDATE trigger below. deletion is early (deleted_at set) at the earlier of
-- terminal job state or expiry.
CREATE TABLE evidence_objects (
    id                      uuid NOT NULL DEFAULT gen_random_uuid(),
    account_id              uuid NOT NULL REFERENCES accounts(account_id),
    session_pk              uuid,
    blob_ref                text NOT NULL,
    upload_digest           text NOT NULL,
    evidence_content_digest text NOT NULL,
    size_bytes              bigint NOT NULL DEFAULT 0,
    created_at              timestamptz NOT NULL DEFAULT now(),
    expires_at              timestamptz NOT NULL,
    deleted_at              timestamptz,
    PRIMARY KEY (id),
    UNIQUE (account_id, id),
    FOREIGN KEY (account_id, session_pk) REFERENCES cloud_sessions(account_id, id)
);

CREATE OR REPLACE FUNCTION sbci_evidence_immutable_ttl()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
        RAISE EXCEPTION 'evidence_objects.expires_at is immutable (plan §2.8): % -> %',
            OLD.expires_at, NEW.expires_at;
    END IF;
    IF NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'evidence_objects.created_at is immutable';
    END IF;
    RETURN NEW;
END$$;

CREATE TRIGGER sbci_evidence_immutable_ttl
    BEFORE UPDATE ON evidence_objects
    FOR EACH ROW EXECUTE FUNCTION sbci_evidence_immutable_ttl();

CREATE TABLE analysis_jobs (
    id                    uuid NOT NULL DEFAULT gen_random_uuid(),
    account_id            uuid NOT NULL REFERENCES accounts(account_id),
    session_pk            uuid,
    evidence_pk           uuid NOT NULL,
    feature               text NOT NULL,
    route_id              text NOT NULL,
    route_version         bigint NOT NULL,
    prompt_version        bigint NOT NULL,
    canonical_job_key     text NOT NULL,
    client_idempotency_key text,
    consent_generation    bigint NOT NULL,
    consent_receipt_id    uuid,
    upload_digest         text NOT NULL,
    state                 text NOT NULL DEFAULT 'queued'
                              CHECK (state IN ('queued', 'leased', 'running',
                                               'succeeded', 'failed', 'parked', 'canceled')),
    terminal_reason       text,
    reservation_id        uuid,
    lease_worker          text,
    lease_acquired_at     timestamptz,
    lease_expires_at      timestamptz,
    available_at          timestamptz NOT NULL DEFAULT now(),
    attempts              int NOT NULL DEFAULT 0,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (id),
    UNIQUE (account_id, id),
    UNIQUE (account_id, canonical_job_key),
    FOREIGN KEY (account_id, evidence_pk) REFERENCES evidence_objects(account_id, id),
    FOREIGN KEY (account_id, reservation_id) REFERENCES usage_reservations(account_id, id),
    FOREIGN KEY (account_id, consent_receipt_id) REFERENCES consent_receipts(account_id, id)
);

CREATE INDEX analysis_jobs_lease_scan ON analysis_jobs (state, available_at)
    WHERE state IN ('queued', 'leased', 'running');

CREATE TABLE analysis_results (
    id             uuid NOT NULL DEFAULT gen_random_uuid(),
    account_id     uuid NOT NULL REFERENCES accounts(account_id),
    job_id         uuid NOT NULL,
    seq            bigint GENERATED BY DEFAULT AS IDENTITY,
    result         jsonb NOT NULL,
    schema_version text NOT NULL,
    ai_source      boolean NOT NULL DEFAULT true,
    created_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (id),
    UNIQUE (account_id, id),
    UNIQUE (seq),
    FOREIGN KEY (account_id, job_id) REFERENCES analysis_jobs(account_id, id)
);

CREATE INDEX analysis_results_cursor ON analysis_results (account_id, seq);

-- analysis_usage_ledger is append-only: 0004 grants sbci_app only SELECT +
-- INSERT (no UPDATE/DELETE).
CREATE TABLE analysis_usage_ledger (
    id            uuid NOT NULL DEFAULT gen_random_uuid(),
    account_id    uuid NOT NULL REFERENCES accounts(account_id),
    job_id        uuid,
    event         text NOT NULL,
    user_units    int NOT NULL DEFAULT 0,
    internal_units int NOT NULL DEFAULT 0,
    route_version bigint,
    price_version text,
    tokens_in     bigint,
    tokens_out    bigint,
    attempts      int,
    detail        jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (id),
    UNIQUE (account_id, id)
);

CREATE TABLE deletion_requests (
    id           uuid NOT NULL DEFAULT gen_random_uuid(),
    account_id   uuid NOT NULL REFERENCES accounts(account_id),
    scope        text NOT NULL DEFAULT 'account',
    state        text NOT NULL DEFAULT 'received'
                     CHECK (state IN ('received', 'processing', 'done', 'failed')),
    requested_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    detail       jsonb NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (id),
    UNIQUE (account_id, id)
);

-- pop_replay is the DPoP-style jti replay cache (Sol SC2), account-scoped so it
-- lives under RLS and is written inside the tenant transaction the middleware
-- opens after resolving the account from the token. TTL-pruned by a sweep.
CREATE TABLE pop_replay (
    account_id uuid NOT NULL REFERENCES accounts(account_id),
    jti        text NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, jti)
);

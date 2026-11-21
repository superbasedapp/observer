-- 0049_org_outbox_and_deletion_requests.sql - the org deletion work queue,
-- the host-API outbox base, and the grants on the membership-class tables
-- (managed-SaaS M6.1a; design
-- docs/plans/managed-saas/m6.0-control-plane-design-2026-11-13.md 3.4, 4.1).
--
-- step: expand
--
-- TABLES (both class S: no RLS, explicit grants only)
--
--   org_deletion_requests  the org deletion work queue (design 3.4). One open
--                          request per org. M6.9 adds org_deletion_steps and
--                          the behaviour; the restore-surviving record is the
--                          deletionjournal package (extended by M6.9, not
--                          here). Only sbci_app is granted until M6.9.
--   org_outbox             one row per host-API intent (design 4.1). The
--                          provisioning transaction inserts the create_tenant
--                          row so org, owner, slug and intent commit together.
--                          M6.4 owns sending, retries and reconciliation and
--                          adds the worker's grants. Payloads carry no secrets.
--                          verb is the closed vocabulary of the mutating
--                          host-API verbs (store.KnownOrgOutboxVerbs; a store
--                          test inserts each one).
--
-- GRANTS ON orgs AND org_members. They land here, one step after 0048 gave
-- the two tables their policies, so no role could reach them without
-- row-level security. sbci_api (the serve process: console, provisioning)
-- reads both, inserts both, writes memberships under the policy, and may
-- UPDATE only orgs.display_name and orgs.updated_at: status, lifecycle_gen,
-- host_id, tenancy and the rail flag belong to the host-API client and the
-- operator, and a slug change (M6.5) must also write org_slugs, so it widens
-- this grant in its own step. sbci_app (operator paths, the dev/test
-- single-role fallback) holds the same at table level. sbci_worker and
-- sbci_aggregator hold nothing on the registry; M6.4 adds the worker's
-- access with its reconciler.

SET LOCAL lock_timeout = '5s';

-- ---------------------------------------------------------------------------
-- org_deletion_requests (class S)
-- ---------------------------------------------------------------------------
CREATE TABLE org_deletion_requests (
    request_id     uuid        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id         uuid        NOT NULL REFERENCES orgs (org_id),
    -- The account that asked; opaque, no foreign key (an audit fact that must
    -- not block the account retention sweep).
    requested_by   uuid        NOT NULL,
    state          text        NOT NULL DEFAULT 'accepted'
        CHECK (state IN ('accepted', 'deactivating_members', 'notifying_idp_admins',
                         'deleting_workos', 'tenant_purge', 'done', 'blocked')),
    blocked_reason text,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    done_at        timestamptz,
    CONSTRAINT org_deletion_requests_blocked_has_reason CHECK (state <> 'blocked' OR blocked_reason IS NOT NULL),
    CONSTRAINT org_deletion_requests_done_has_time CHECK ((state = 'done') = (done_at IS NOT NULL))
);

-- One open request per org.
CREATE UNIQUE INDEX org_deletion_requests_one_open ON org_deletion_requests (org_id) WHERE state <> 'done';

-- ---------------------------------------------------------------------------
-- org_outbox (class S)
-- ---------------------------------------------------------------------------
CREATE TABLE org_outbox (
    outbox_id        uuid        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id           uuid        NOT NULL REFERENCES orgs (org_id),
    verb             text        NOT NULL
        CHECK (verb IN ('create_tenant', 'set_state', 'set_entitlements', 'members_deactivate', 'evict')),
    -- create_tenant's key is the org id (design 4.1); M6.4 and M6.9 name the
    -- rest (e.g. deact:<org>:<sub>).
    idempotency_key  text        NOT NULL UNIQUE CHECK (idempotency_key <> ''),
    payload          jsonb       NOT NULL DEFAULT '{}'::jsonb,
    lifecycle_gen    bigint      NOT NULL DEFAULT 0 CHECK (lifecycle_gen >= 0),
    state            text        NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'sent', 'acked', 'failed')),
    attempts         int         NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at  timestamptz NOT NULL DEFAULT now(),
    last_error_class text,
    created_at       timestamptz NOT NULL DEFAULT now(),
    done_at          timestamptz
);

-- The sender's queue scan (M6.4: FOR UPDATE SKIP LOCKED over due rows).
CREATE INDEX org_outbox_due ON org_outbox (next_attempt_at) WHERE state IN ('pending', 'sent');
CREATE INDEX org_outbox_org ON org_outbox (org_id);

-- ---------------------------------------------------------------------------
-- Grants.
-- ---------------------------------------------------------------------------

-- Membership-class tables (policies from 0048).
GRANT SELECT, INSERT                 ON orgs        TO sbci_api;
GRANT UPDATE (display_name, updated_at) ON orgs     TO sbci_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON org_members TO sbci_api;
GRANT SELECT, INSERT, UPDATE         ON orgs        TO sbci_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON org_members TO sbci_app;

-- S tables created here. sbci_api inserts the provisioning intent only (no
-- SELECT: it never reads the queue).
GRANT INSERT                 ON org_outbox            TO sbci_api;
GRANT SELECT, INSERT, UPDATE ON org_outbox            TO sbci_app;
GRANT SELECT, INSERT, UPDATE ON org_deletion_requests TO sbci_app;

COMMENT ON TABLE org_deletion_requests IS 'M6.1a org deletion work queue (class S); M6.9 adds the steps and behaviour.';
COMMENT ON TABLE org_outbox IS 'M6.1a host-API intent outbox (class S); M6.4 sends it.';

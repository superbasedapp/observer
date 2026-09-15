-- 0012_entitlement_plans.sql — versioned entitlement plans, non-overlapping
-- per-account plan assignment, and per-plan budget pools (W4 of the
-- cloud-intelligence divergence remediation plan, §3 W4; operator ruling R4).
--
-- R4 (ruled 2026-09-01): Plus caps are 500/month, 25/day, concurrency 4, drawn
-- from Plus's OWN budget pool and NEVER the free pool; an upgrade takes effect
-- mid-cycle, a downgrade at cycle end; the label is the honest
-- "Plus beta entitlement simulation" — this is entitlement plumbing only, with
-- no payment rail (Paddle is work-stream W9).
--
-- Tenancy classification (0002's split):
--
--   plans         — SYSTEM (no RLS). A global, immutable, VERSIONED catalogue:
--                   a plan row is never UPDATEd, a change is a new version
--                   (enforced two ways below — sbci_app holds SELECT only, and
--                   a BEFORE UPDATE trigger refuses the write even for the
--                   table owner). Not account data: excluded from account
--                   export and from the deletion matrix.
--   budget_pools  — SYSTEM (no RLS). The evolution of free_tier_budget from a
--                   single global singleton into one keyed spend ceiling per
--                   plan pool, so a Plus reservation can never consume the
--                   free tier's ceiling. Not account data.
--   account_plans — TENANT (RLS ENABLE + FORCE + the sbci_current_account()
--                   policy every 0002 tenant table carries). These rows ARE
--                   account-scoped entitlement records and purge WITH the
--                   account, exactly like entitlements/usage_cycles. The FK
--                   keeps 0002's default NO ACTION rather than 0011's cascade:
--                   0011 cascades only rows it classified as NOT account data,
--                   and how account data is removed stays the deletion
--                   pipeline's explicit decision.
--
-- The two LIVE conflicts this migration closes (plan review finding 12):
--
--   1. usage_cycles.cap was a SNAPSHOT taken when the window's counter row was
--      first created, and the reservation path took min(snapshot, entitlement)
--      — so a mid-cycle upgrade could never raise headroom within the running
--      window. The cap is now re-resolved from the account's live plan at
--      reservation time and the snapshot column is refreshed to match (the
--      counter itself keeps counting; only the ceiling moves).
--   2. Every reservation drew from ONE global free_tier_budget row. It now
--      draws from the pool named by the account's resolved plan, and the pool
--      drawn from is recorded on the reservation so a later refund returns the
--      unit to the same pool even if the account's plan changed meanwhile.

-- ---------------------------------------------------------------------------
-- plans (SYSTEM, immutable, versioned)
-- ---------------------------------------------------------------------------
CREATE TABLE plans (
    plan_id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Stable plan identity. (name, version) is the addressable key; plan_id is
    -- the FK target so an assignment pins ONE immutable definition.
    name            text NOT NULL,
    version         int  NOT NULL CHECK (version >= 1),
    -- Operator/user-facing copy. R4 fixes the Plus label to
    -- "Plus beta entitlement simulation" — it is surfaced verbatim by
    -- /v1/usage so nobody can mistake the beta grant for a purchased plan.
    label           text NOT NULL,
    daily_cap       int  NOT NULL CHECK (daily_cap >= 0),
    monthly_cap     int  NOT NULL CHECK (monthly_cap >= 0),
    concurrency_cap int  NOT NULL CHECK (concurrency_cap >= 0),
    -- budget_pools.pool this plan's reservations draw from. Not a foreign key
    -- on purpose: a plan version is immutable, and a pool row is operational
    -- state (its cap/used move); binding them with an FK would let pool
    -- maintenance fail against the immutable catalogue. The store fails closed
    -- when a named pool is missing.
    budget_pool     text NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (name, version)
);

-- Immutability, defense in depth. sbci_app is granted SELECT only (below), so
-- the application cannot rewrite a plan; this trigger additionally refuses an
-- UPDATE from the table owner, mirroring 0002's sbci_evidence_immutable_ttl
-- precedent. DELETE is deliberately NOT guarded: retiring an unreferenced
-- version stays an operator action.
CREATE OR REPLACE FUNCTION sbci_plans_immutable()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'plans rows are immutable (W4/R4): publish a new (name, version) instead of updating %/% ',
        OLD.name, OLD.version;
END$$;

CREATE TRIGGER sbci_plans_immutable
    BEFORE UPDATE ON plans
    FOR EACH ROW EXECUTE FUNCTION sbci_plans_immutable();

-- ---------------------------------------------------------------------------
-- budget_pools (SYSTEM) — free_tier_budget, keyed by pool
-- ---------------------------------------------------------------------------
CREATE TABLE budget_pools (
    pool       text PRIMARY KEY,
    cap        bigint NOT NULL,
    used       bigint NOT NULL DEFAULT 0,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (used >= 0)
);

-- Move the existing global free-tier ceiling to the 'free' pool, balance and
-- all: the free tier's semantics are preserved exactly, it just stopped being
-- the only pool.
INSERT INTO budget_pools (pool, cap, used)
SELECT 'free', cap, used FROM free_tier_budget WHERE id = 1
ON CONFLICT (pool) DO NOTHING;

-- Fallback for the (unexpected) case where the 0004 singleton was removed.
INSERT INTO budget_pools (pool, cap, used) VALUES ('free', 100000000, 0)
    ON CONFLICT (pool) DO NOTHING;

-- Plus's OWN pool (R4: never the free pool). Staging-generous like the free
-- seed; the operator narrows it in production. Enforcement is real from the
-- first reservation — the value is not the point in the beta phase.
INSERT INTO budget_pools (pool, cap, used) VALUES ('plus_beta', 100000000, 0)
    ON CONFLICT (pool) DO NOTHING;

DROP TABLE free_tier_budget;

-- ---------------------------------------------------------------------------
-- Seed plans (immutable v1 definitions)
-- ---------------------------------------------------------------------------
INSERT INTO plans (name, version, label, daily_cap, monthly_cap, concurrency_cap, budget_pool) VALUES
    ('free',      1, 'Signed-in Free',                     5, 100, 2, 'free'),
    ('plus_beta', 1, 'Plus beta entitlement simulation',   25, 500, 4, 'plus_beta')
ON CONFLICT (name, version) DO NOTHING;

-- ---------------------------------------------------------------------------
-- account_plans (TENANT)
-- ---------------------------------------------------------------------------
CREATE TABLE account_plans (
    id              uuid NOT NULL DEFAULT gen_random_uuid(),
    account_id      uuid NOT NULL REFERENCES accounts(account_id),
    plan_id         uuid NOT NULL REFERENCES plans(plan_id),
    effective_from  timestamptz NOT NULL,
    -- NULL = open-ended (the current assignment). A deferred downgrade closes
    -- the running row by setting this to the next cycle boundary and inserting
    -- the new open row starting there.
    effective_until timestamptz,
    source          text NOT NULL DEFAULT 'beta_manual',
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (id),
    UNIQUE (account_id, id),
    CHECK (effective_until IS NULL OR effective_until > effective_from)
);

-- At most ONE open assignment per account. This is the database-level guard
-- against overlapping assignments; the store's AssignPlan additionally closes
-- the running row in the same transaction, so the index catches a second
-- writer, not the normal path.
CREATE UNIQUE INDEX account_plans_one_open ON account_plans (account_id)
    WHERE effective_until IS NULL;

CREATE INDEX account_plans_effective ON account_plans (account_id, effective_from DESC);

ALTER TABLE account_plans ENABLE ROW LEVEL SECURITY;
ALTER TABLE account_plans FORCE ROW LEVEL SECURITY;
CREATE POLICY account_plans_tenant ON account_plans
    USING (account_id = sbci_current_account())
    WITH CHECK (account_id = sbci_current_account());

-- ---------------------------------------------------------------------------
-- entitlements becomes an explicit per-account OVERRIDE layer over the plan
-- ---------------------------------------------------------------------------
--
-- The plan is now the authority for "how much"; the entitlements row keeps its
-- other job — "is this feature enabled for this account" (its absence is still
-- ErrNoEntitlement) — and gains an explicit flag for the operator-grant escape
-- hatch. There is exactly ONE composition point for the two
-- (store.resolveAllowanceTx), so this is a layered default + override, not two
-- competing authorities.
--
-- DEFAULT true so a row an operator INSERTs by hand means what it says (these
-- caps, for this account). Every row that exists TODAY is an untouched
-- account-creation seed carrying the free defaults, on a service that has not
-- launched — so they are flipped to plan-managed, which is what makes an
-- upgrade actually raise headroom with NO backfill of account_plans.
ALTER TABLE entitlements ADD COLUMN overrides_plan boolean NOT NULL DEFAULT true;
UPDATE entitlements SET overrides_plan = false;

-- ---------------------------------------------------------------------------
-- usage_reservations records the pool it drew from
-- ---------------------------------------------------------------------------
--
-- A refund must return the unit to the pool the reservation actually consumed,
-- even if the account's plan changed between reserve and release. Existing rows
-- predate pools and drew from the old global (now 'free') budget, so the
-- default backfills them correctly.
ALTER TABLE usage_reservations ADD COLUMN budget_pool text NOT NULL DEFAULT 'free';

-- ---------------------------------------------------------------------------
-- Grants
-- ---------------------------------------------------------------------------
-- plans: SELECT only — the application resolves plans, it never authors them.
GRANT SELECT ON plans TO sbci_app;
-- budget_pools: SELECT + UPDATE — pool rows are seeded by migration, so no
-- INSERT (the app cannot invent a pool) and no DELETE.
GRANT SELECT, UPDATE ON budget_pools TO sbci_app;
-- account_plans: full DML (RLS still constrains each row).
GRANT SELECT, INSERT, UPDATE, DELETE ON account_plans TO sbci_app;

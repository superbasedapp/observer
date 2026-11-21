-- 0095_org_plan_grants.sql - an operator-only plan grant for ONE org
-- (managed-SaaS plan 07 wave 15 lane console-fixes; lead decision W15-D13;
-- docs/security.md PORTALORG-11).
--
-- step: contract
--
-- Contract label: the REVOKE of PUBLIC's default EXECUTE on the new definer
-- (migcheck's revoke rule, the 0082 / 0091 / 0093 pattern). The table and the
-- function are new in this step; the label is the rule's, not a real
-- contraction.
--
-- WHY. A team org runs on its launch plan for 14 days after its tenant is
-- created and then falls to its floor (every cap zero) unless it has a live
-- Paddle subscription (entitlementwork.SubscriptionPlans). Production has no
-- live Paddle yet (L-114), and the account grant (observer-cloud grant-plan,
-- account_plans) does not reach an org's document. An internal org must stay
-- on its plan, so the operator grants a catalog plan to one org: the per-org
-- counterpart of grant-plan, CLI only (observer-cloud grant-plan org), never
-- an HTTP route. The plan source reads it after a live subscription and
-- before the launch window (plans.go planRules).
--
-- APPEND-ONLY, AND ITS OWN AUDIT. A grant and a revoke are each a new row
-- with the actor and a required reason; the newest row of an org decides
-- (a 'grant' row in force until its effective_until, or a 'revoke' row: no
-- grant). No role holds UPDATE or DELETE, so the history cannot be rewritten
-- by the application roles. org_id has a foreign key with no cascade: orgs
-- rows are never deleted (a purged org keeps its row), so the history keeps
-- its org.
--
-- READS. Class S (no row-level security), like the rest of the org
-- registry's system tables: the worker (sbci_worker) reads it directly for
-- the plan source, the operator role (sbci_app) reads and appends. The
-- console (sbci_api) holds no grant; it reads one org's newest row through
-- sbci_portal_org_plan_grant(org), a SECURITY DEFINER owned by sbci_defs
-- that answers only a caller who is an org owner or admin or the org's
-- billing owner (the same rule as sbci_portal_org_subscription, 0091), so
-- the console's plan view agrees with the issued document. One org id in, at
-- most one row out; no actor, no reason.

SET LOCAL lock_timeout = '5s';

CREATE TABLE org_plan_grants (
    seq             bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    org_id          uuid        NOT NULL REFERENCES orgs (org_id),
    action          text        NOT NULL CHECK (action IN ('grant', 'revoke')),
    -- A catalog plan (internal/entitlements); the CLI checks it is a plan of
    -- the org's kind before it writes.
    plan_name       text        CHECK (plan_name IS NULL OR plan_name ~ '^[a-z][a-z0-9_]{0,63}$'),
    plan_version    integer     CHECK (plan_version IS NULL OR plan_version >= 1),
    -- NULL: the grant has no end (it stays until revoked).
    effective_until timestamptz,
    actor           text        NOT NULL CHECK (actor = 'operator'),
    reason          text        NOT NULL CHECK (char_length(btrim(reason)) BETWEEN 1 AND 1000),
    at              timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT org_plan_grants_shape CHECK (
        (action = 'grant'  AND plan_name IS NOT NULL AND plan_version IS NOT NULL)
     OR (action = 'revoke' AND plan_name IS NULL AND plan_version IS NULL AND effective_until IS NULL))
);

CREATE INDEX org_plan_grants_org ON org_plan_grants (org_id, seq DESC);

COMMENT ON TABLE org_plan_grants IS
    'W15-D13: operator plan grants per org; append-only, newest row wins; read by the entitlements plan source before the launch window (class S).';

GRANT SELECT ON org_plan_grants TO sbci_worker;
GRANT SELECT, INSERT ON org_plan_grants TO sbci_app;
GRANT SELECT (org_id, seq, action, plan_name, plan_version, effective_until) ON org_plan_grants TO sbci_defs;

CREATE FUNCTION sbci_portal_org_plan_grant(p_org uuid)
RETURNS TABLE (
    action          text,
    plan_name       text,
    plan_version    int,
    effective_until timestamptz
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT g.action, g.plan_name, g.plan_version, g.effective_until
      FROM public.org_plan_grants g
     WHERE g.org_id = p_org
       AND (public.sbci_is_org_member(p_org, 'admin')
            OR EXISTS (SELECT 1
                         FROM public.org_members m
                        WHERE m.org_id = p_org
                          AND m.account_id = public.sbci_current_account()
                          AND m.is_billing_owner))
     ORDER BY g.seq DESC
     LIMIT 1
$$;

ALTER FUNCTION sbci_portal_org_plan_grant(uuid) OWNER TO sbci_defs;
REVOKE ALL ON FUNCTION sbci_portal_org_plan_grant(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_portal_org_plan_grant(uuid) TO sbci_api, sbci_app;

-- 0155_personal_org_owner_subscription.sql - the worker reads the account
-- subscription of a personal org's owner (operator ruling L-167, 2026-11-24:
-- Personal Pro is what the Plus subscription buys; SDK onboarding lane).
--
-- step: contract
--
-- Contract only because migcheck treats every REVOKE as one (rule
-- "revoke"), as for 0140, 0151 and 0152: the step creates one new function
-- and revokes PUBLIC on it, so nothing the running release uses changes.
--
-- Why. The live Paddle Personal Pro price maps to the account plan
-- plus_beta, so a Plus purchase writes an account-scoped paddle_subscriptions
-- row (org_id NULL) and the account's personal org stayed on its floor until
-- `observer-cloud migrate-personal` re-keyed the row onto the org. The
-- entitlement worker (entitlementwork.SubscriptionPlans, rule
-- account_subscription) now issues the personal org the personal plan the
-- catalog pairs with the owner's live account plan (entitlements
-- PairedPersonalPlan: plus_beta -> personal_pro), so a Plus purchase lands on
-- the org at once, before and after E3, with no write to the row.
--
-- The worker reads paddle_subscriptions only through definers (it holds no
-- table grant; sbci_org_subscription_v2 is the org-scoped one, 0098). This
-- one answers the owner's account-scoped row of a PERSONAL org only: the org
-- must be kind 'personal', the row's account must be the org's creator, and
-- the row must not be bound to any org (a row re-keyed onto the org is
-- sbci_org_subscription_v2's). Same order and columns as 0098's function.
-- Hardened as 0152 requires: every relation public.*, search_path ending in
-- pg_temp. Owner sbci_defs, PUBLIC revoked, EXECUTE to the worker and to
-- sbci_app (the shared operator role, as 0098's); the front door reads its
-- caller's own row through RLS (store.AccountSubscription) and gets nothing.

SET LOCAL lock_timeout = '5s';

CREATE FUNCTION sbci_personal_org_owner_subscription(p_org uuid)
RETURNS TABLE (
    paddle_subscription_id text,
    plan_name              text,
    plan_version           int,
    status                 text,
    current_period_end     timestamptz,
    canceled_at            timestamptz,
    trial_ends_at          timestamptz,
    past_due_since         timestamptz
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
    SELECT ps.paddle_subscription_id, ps.plan_name, ps.plan_version, ps.status,
           ps.current_period_end, ps.canceled_at, ps.trial_ends_at, ps.past_due_since
      FROM public.orgs o
      JOIN public.paddle_subscriptions ps ON ps.account_id = o.created_by
     WHERE o.org_id = p_org
       AND o.kind = 'personal'
       AND ps.org_id IS NULL
     ORDER BY (ps.status IN ('active', 'trialing', 'past_due', 'paused')) DESC, ps.updated_at DESC
     LIMIT 1
$$;

ALTER FUNCTION sbci_personal_org_owner_subscription(uuid) OWNER TO sbci_defs;
REVOKE ALL ON FUNCTION sbci_personal_org_owner_subscription(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_personal_org_owner_subscription(uuid) TO sbci_worker, sbci_app;

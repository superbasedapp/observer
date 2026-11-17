-- 0091_portal_org_reads.sql - the narrow reads the webcloud console and the
-- entitlements worker need about ONE org (managed-SaaS plan 07 M6.5; lead
-- decision W14-D3, wave 14 lane front-door; docs/security.md PORTALORG-2,
-- PORTALORG-5 and PORTALORG-6).
--
-- step: contract
--
-- Contract label: the REVOKE of PUBLIC's default EXECUTE (migcheck's revoke
-- rule, the 0082 / 0088 / 0093 pattern). Every function is new in this step,
-- so no running release can hold or lose the privilege; the label is the
-- rule's, not a real contraction.
--
-- WHY. The console's roles hold less than these reads need, by design:
-- sbci_api has only INSERT on org_slugs and org_outbox (0048, 0049), no grant
-- on org_usage_days (0085), and paddle_subscriptions is account-scoped under
-- RLS (0024), so an org admin cannot see the row another member paid with.
-- The worker (sbci_worker) has no grant on paddle_subscriptions at all.
-- Rather than widen any table grant, each read is a SECURITY DEFINER function
-- owned by sbci_defs (BYPASSRLS) that answers for ONE org (or one slug) and
-- checks the caller first:
--
--   sbci_org_slug_available(slug)        boolean, for a signed-in caller only
--     (NULL without an account context): is the slug free as an org's current
--     slug AND as any org_slugs row (an expired rename alias still holds the
--     primary key, so the provisioning insert would refuse it; the answer
--     matches what ProvisionOrg will do). It names no org.
--   sbci_portal_org_create_status(org)   the newest create_tenant outbox row
--     of an org the CALLER is a member of: state, attempts, last error class
--     (e.g. refused:capacity_waitlist), next attempt, created and done times.
--     No payload, no key, no host id.
--   sbci_portal_org_subscription(org)    the org's most relevant subscription
--     (live first, then the latest), for a caller who is an org admin or
--     owner, or the org's billing owner.
--   sbci_portal_org_seats(org)           the latest usage day's seat count and
--     member count of an org the caller is a member of. The member ids stay in
--     the table.
--   sbci_org_subscription(org)           the worker's read (W14-D3, the
--     entitlements PlanSource): plan, status and dates of the org's most
--     relevant subscription. No customer id and no management link. Not a
--     listing: one org id in, at most one row out.
--
-- Executable: the three portal reads and the slug check by sbci_api and
-- sbci_app; the worker read by sbci_worker and sbci_app. PUBLIC is revoked in
-- this step (the 0082 rule, pinned by TestDefinerFunctionExecuteGrants).
-- sbci_defs already reads orgs, org_members and org_slugs (0048) and
-- paddle_subscriptions (0030); it gains SELECT on the org_outbox and
-- org_usage_days columns the bodies read.

SET LOCAL lock_timeout = '5s';

GRANT SELECT (org_id, verb, state, attempts, next_attempt_at, last_error_class, created_at, done_at, seq)
    ON org_outbox TO sbci_defs;
GRANT SELECT (org_id, day, seat_member_ids, members) ON org_usage_days TO sbci_defs;

-- ---------------------------------------------------------------------------
-- sbci_org_slug_available
-- ---------------------------------------------------------------------------
CREATE FUNCTION sbci_org_slug_available(p_slug text)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT CASE
        WHEN public.sbci_current_account() IS NULL THEN NULL
        ELSE NOT EXISTS (SELECT 1 FROM public.orgs o WHERE lower(o.slug) = lower(p_slug))
         AND NOT EXISTS (SELECT 1 FROM public.org_slugs s WHERE s.slug = lower(p_slug))
    END
$$;

ALTER FUNCTION sbci_org_slug_available(text) OWNER TO sbci_defs;
REVOKE ALL ON FUNCTION sbci_org_slug_available(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_org_slug_available(text) TO sbci_api, sbci_app;

-- ---------------------------------------------------------------------------
-- sbci_portal_org_create_status
-- ---------------------------------------------------------------------------
CREATE FUNCTION sbci_portal_org_create_status(p_org uuid)
RETURNS TABLE (
    state            text,
    attempts         int,
    last_error_class text,
    next_attempt_at  timestamptz,
    created_at       timestamptz,
    done_at          timestamptz
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT o.state, o.attempts, o.last_error_class, o.next_attempt_at, o.created_at, o.done_at
      FROM public.org_outbox o
     WHERE o.org_id = p_org
       AND o.verb = 'create_tenant'
       AND public.sbci_is_org_member(p_org, 'member')
     ORDER BY o.created_at DESC, o.seq DESC NULLS LAST
     LIMIT 1
$$;

ALTER FUNCTION sbci_portal_org_create_status(uuid) OWNER TO sbci_defs;
REVOKE ALL ON FUNCTION sbci_portal_org_create_status(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_portal_org_create_status(uuid) TO sbci_api, sbci_app;

-- ---------------------------------------------------------------------------
-- sbci_portal_org_subscription
-- ---------------------------------------------------------------------------
CREATE FUNCTION sbci_portal_org_subscription(p_org uuid)
RETURNS TABLE (
    paddle_subscription_id text,
    paddle_customer_id     text,
    plan_name              text,
    plan_version           int,
    status                 text,
    current_period_end     timestamptz,
    canceled_at            timestamptz,
    trial_ends_at          timestamptz,
    management_update_url  text,
    management_cancel_url  text
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT ps.paddle_subscription_id, ps.paddle_customer_id, ps.plan_name, ps.plan_version,
           ps.status, ps.current_period_end, ps.canceled_at, ps.trial_ends_at,
           ps.management_update_url, ps.management_cancel_url
      FROM public.paddle_subscriptions ps
     WHERE ps.org_id = p_org
       AND (public.sbci_is_org_member(p_org, 'admin')
            OR EXISTS (SELECT 1
                         FROM public.org_members m
                        WHERE m.org_id = p_org
                          AND m.account_id = public.sbci_current_account()
                          AND m.is_billing_owner))
     ORDER BY (ps.status IN ('active', 'trialing', 'past_due', 'paused')) DESC, ps.updated_at DESC
     LIMIT 1
$$;

ALTER FUNCTION sbci_portal_org_subscription(uuid) OWNER TO sbci_defs;
REVOKE ALL ON FUNCTION sbci_portal_org_subscription(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_portal_org_subscription(uuid) TO sbci_api, sbci_app;

-- ---------------------------------------------------------------------------
-- sbci_portal_org_seats
-- ---------------------------------------------------------------------------
CREATE FUNCTION sbci_portal_org_seats(p_org uuid)
RETURNS TABLE (
    day     date,
    seats   int,
    members bigint
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT u.day, cardinality(u.seat_member_ids), u.members
      FROM public.org_usage_days u
     WHERE u.org_id = p_org
       AND public.sbci_is_org_member(p_org, 'member')
     ORDER BY u.day DESC
     LIMIT 1
$$;

ALTER FUNCTION sbci_portal_org_seats(uuid) OWNER TO sbci_defs;
REVOKE ALL ON FUNCTION sbci_portal_org_seats(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_portal_org_seats(uuid) TO sbci_api, sbci_app;

-- ---------------------------------------------------------------------------
-- sbci_org_subscription (the worker's read)
-- ---------------------------------------------------------------------------
CREATE FUNCTION sbci_org_subscription(p_org uuid)
RETURNS TABLE (
    paddle_subscription_id text,
    plan_name              text,
    plan_version           int,
    status                 text,
    current_period_end     timestamptz,
    canceled_at            timestamptz,
    trial_ends_at          timestamptz
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT ps.paddle_subscription_id, ps.plan_name, ps.plan_version, ps.status,
           ps.current_period_end, ps.canceled_at, ps.trial_ends_at
      FROM public.paddle_subscriptions ps
     WHERE ps.org_id = p_org
     ORDER BY (ps.status IN ('active', 'trialing', 'past_due', 'paused')) DESC, ps.updated_at DESC
     LIMIT 1
$$;

ALTER FUNCTION sbci_org_subscription(uuid) OWNER TO sbci_defs;
REVOKE ALL ON FUNCTION sbci_org_subscription(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_org_subscription(uuid) TO sbci_worker, sbci_app;

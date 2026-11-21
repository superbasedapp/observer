-- 0098_paddle_past_due_since.sql - when a subscription entered past_due, so
-- the dunning window can end (managed-SaaS plan 07 wave 16 lane
-- control-plane; lead decision W16-D5; operator ruling L-124: a 14-day
-- past_due window; C2.tenant-cloud-4).
--
-- step: contract
--
-- Contract label: the REVOKE of PUBLIC's default EXECUTE on the new
-- functions (migcheck's revoke rule, the 0082 / 0091 / 0095 pattern). Every
-- function is new in this step and nothing the running release uses is
-- changed or removed; the label is the rule's, not a real contraction.
--
-- WHY. Until now a past_due org subscription counted as live for as long as
-- Paddle kept it past_due (entitlementwork liveSubscriptionStatuses). W16-D5:
-- it counts as live for SBCI_PADDLE_PAST_DUE_GRACE_DAYS (default 14) days
-- from when it ENTERED past_due, then the plan source treats it as not live
-- and the org falls to its operator grant, its launch window or its floor
-- (planRules order). Nothing is deleted.
--
-- ONE WRITER. past_due_since is set by the BEFORE INSERT OR UPDATE trigger
-- below and by nothing else: the Paddle webhook (store paddle*.go, the one
-- writer of subscription state, W14-D3) moves status, and the trigger records
-- the moment it moved into past_due (the event's last_event_at, the Paddle
-- occurrence time the F3 ordering guard keeps; now() if the row has none).
-- It keeps the first instant while the row stays past_due, so a repeated
-- past_due event does not restart the window, and clears it on any other
-- status, so a recovered-then-lapsed subscription starts a new window. A
-- direct write of the column is overwritten on insert and on entry; on a row
-- that stays past_due an existing value is kept, which is how 0099 backfills
-- the rows already past_due when this step runs (their value is NULL).
--
-- READS. The worker and the console read subscriptions through the 0091
-- definers, which cannot gain a column in place (a changed RETURNS TABLE is
-- a DROP and CREATE the running release would notice). So this step adds
-- _v2 twins with the same row choice, the same access rule and grants, plus
-- past_due_since; the store switches to them; the 0091 functions stay for
-- the release still running and a later step may drop them.

SET LOCAL lock_timeout = '5s';

ALTER TABLE paddle_subscriptions ADD COLUMN past_due_since timestamptz;

COMMENT ON COLUMN paddle_subscriptions.past_due_since IS
    'W16-D5: when the subscription entered past_due (set only by the sbci_paddle_past_due_since trigger); NULL in any other status.';

-- ---------------------------------------------------------------------------
-- the trigger (invoker rights: it reads nothing, it only sets NEW)
-- ---------------------------------------------------------------------------
CREATE FUNCTION sbci_paddle_past_due_since()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NEW.status = 'past_due' THEN
        IF TG_OP = 'UPDATE' AND OLD.status = 'past_due' THEN
            NEW.past_due_since := COALESCE(OLD.past_due_since, NEW.past_due_since, NEW.last_event_at, now());
        ELSE
            NEW.past_due_since := COALESCE(NEW.last_event_at, now());
        END IF;
    ELSE
        NEW.past_due_since := NULL;
    END IF;
    RETURN NEW;
END
$$;

REVOKE ALL ON FUNCTION sbci_paddle_past_due_since() FROM PUBLIC;

CREATE TRIGGER paddle_subscriptions_past_due_since
    BEFORE INSERT OR UPDATE ON paddle_subscriptions
    FOR EACH ROW EXECUTE FUNCTION sbci_paddle_past_due_since();

COMMENT ON FUNCTION sbci_paddle_past_due_since() IS
    'W16-D5: records when a paddle_subscriptions row entered past_due; the only writer of past_due_since.';

-- ---------------------------------------------------------------------------
-- sbci_portal_org_subscription_v2 (0091's sbci_portal_org_subscription plus
-- past_due_since)
-- ---------------------------------------------------------------------------
CREATE FUNCTION sbci_portal_org_subscription_v2(p_org uuid)
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
    management_cancel_url  text,
    past_due_since         timestamptz
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT ps.paddle_subscription_id, ps.paddle_customer_id, ps.plan_name, ps.plan_version,
           ps.status, ps.current_period_end, ps.canceled_at, ps.trial_ends_at,
           ps.management_update_url, ps.management_cancel_url, ps.past_due_since
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

ALTER FUNCTION sbci_portal_org_subscription_v2(uuid) OWNER TO sbci_defs;
REVOKE ALL ON FUNCTION sbci_portal_org_subscription_v2(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_portal_org_subscription_v2(uuid) TO sbci_api, sbci_app;

-- ---------------------------------------------------------------------------
-- sbci_org_subscription_v2 (0091's sbci_org_subscription plus
-- past_due_since)
-- ---------------------------------------------------------------------------
CREATE FUNCTION sbci_org_subscription_v2(p_org uuid)
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
SET search_path = pg_catalog, public
AS $$
    SELECT ps.paddle_subscription_id, ps.plan_name, ps.plan_version, ps.status,
           ps.current_period_end, ps.canceled_at, ps.trial_ends_at, ps.past_due_since
      FROM public.paddle_subscriptions ps
     WHERE ps.org_id = p_org
     ORDER BY (ps.status IN ('active', 'trialing', 'past_due', 'paused')) DESC, ps.updated_at DESC
     LIMIT 1
$$;

ALTER FUNCTION sbci_org_subscription_v2(uuid) OWNER TO sbci_defs;
REVOKE ALL ON FUNCTION sbci_org_subscription_v2(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_org_subscription_v2(uuid) TO sbci_worker, sbci_app;

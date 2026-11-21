-- 0090_paddle_org_scope.sql - one live subscription per ORG beside one per
-- account (managed-SaaS plan 07 M6.5; lead decision W14-D3, wave 14 lane
-- front-door; docs/security.md PORTALORG-4).
--
-- step: contract
--
-- Contract label: the DROP INDEX below (migcheck's drop-index rule; the cloud
-- runner has no non-transactional class, so DROP INDEX CONCURRENTLY cannot
-- land here) and the REVOKE of PUBLIC's default EXECUTE on the new trigger
-- function (the 0082 rule). The running release never names the index: its
-- webhook path pre-checks a second live subscription itself (P2-3,
-- store.applyPaddleActivate) and only relies on the index as a backstop. The
-- trigger created in the same transaction takes over that backstop, so no
-- moment exists with neither.
--
-- WHY. W14-D3 keeps ONE subscription store: an org's paid plan is a
-- paddle_subscriptions row with org_id set (0050 added the column), written by
-- the existing webhook handler's org branch. The row's account_id stays the
-- account that paid (the RLS key of 0024, unchanged), so the old partial
-- unique index, one live row per account_id, would refuse an account that
-- holds a personal subscription AND pays for a team org, or pays for two team
-- orgs. The rule becomes:
--
--   an account row (org_id IS NULL)   at most one live per account_id  (as before)
--   an org row     (org_id NOT NULL)  at most one live per org_id      (new)
--
-- The replacement cannot be two partial unique indexes: a CREATE INDEX on an
-- existing table needs CONCURRENTLY and the non-transactional class, which
-- the cloud runner refuses (docs/migration-numbering.md "Step labels"). It is
-- a BEFORE INSERT OR UPDATE trigger instead:
--
--   * a non-live status (canceled, refunded, charged_back: the index's own
--     predicate) passes;
--   * otherwise it takes a transaction advisory lock on the row's SCOPE
--     ('sbci_paddle_live:org:<org>' or 'sbci_paddle_live:account:<account>')
--     and then looks for another live row of the same scope with a different
--     subscription id. The lock serializes two writers of one scope; the look
--     runs after it, in a fresh statement snapshot (plpgsql, READ COMMITTED),
--     so it sees the other writer's committed row. Found: it raises
--     unique_violation naming constraint paddle_subscriptions_one_live, the
--     same SQLSTATE and name the index raised.
--   * SECURITY DEFINER, owner sbci_defs (BYPASSRLS, already holding SELECT on
--     paddle_subscriptions since 0030): an org's rows may belong to several
--     paying accounts, and the caller's account-scoped RLS would hide the
--     others.
--
-- The store's org branch takes the SAME advisory key before its own
-- pre-check, so the trigger's lock is a re-entry there, never a new wait.
-- Lock order: the webhook takes its per-account lock first and the scope lock
-- second, never the other way, so no cycle is possible.

SET LOCAL lock_timeout = '5s';

DROP INDEX paddle_subscriptions_one_live;

CREATE FUNCTION sbci_paddle_one_live_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_scope text;
    v_other text;
BEGIN
    IF NEW.status IN ('canceled', 'refunded', 'charged_back') THEN
        RETURN NEW;
    END IF;
    IF NEW.org_id IS NOT NULL THEN
        v_scope := 'org:' || NEW.org_id::text;
    ELSE
        v_scope := 'account:' || NEW.account_id::text;
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('sbci_paddle_live:' || v_scope, 0));
    SELECT ps.paddle_subscription_id INTO v_other
      FROM public.paddle_subscriptions ps
     WHERE ps.paddle_subscription_id <> NEW.paddle_subscription_id
       AND ps.status NOT IN ('canceled', 'refunded', 'charged_back')
       AND ((NEW.org_id IS NOT NULL AND ps.org_id = NEW.org_id)
         OR (NEW.org_id IS NULL AND ps.org_id IS NULL AND ps.account_id = NEW.account_id))
     LIMIT 1;
    IF v_other IS NOT NULL THEN
        RAISE EXCEPTION 'paddle_subscriptions: a live subscription already exists for this %',
                split_part(v_scope, ':', 1)
            USING ERRCODE = 'unique_violation', CONSTRAINT = 'paddle_subscriptions_one_live';
    END IF;
    RETURN NEW;
END
$$;

ALTER FUNCTION sbci_paddle_one_live_guard() OWNER TO sbci_defs;

CREATE TRIGGER paddle_subscriptions_one_live
    BEFORE INSERT OR UPDATE ON paddle_subscriptions
    FOR EACH ROW EXECUTE FUNCTION sbci_paddle_one_live_guard();

REVOKE ALL ON FUNCTION sbci_paddle_one_live_guard() FROM PUBLIC;

COMMENT ON FUNCTION sbci_paddle_one_live_guard() IS
    'W14-D3: one live paddle_subscriptions row per account (org_id NULL) and per org (org_id set); replaces the paddle_subscriptions_one_live index.';

-- 0027_sweep_retention_hardening.sql — Sol adversarial review of the W5
-- contribution-upload wave (commit 62e3897b6), server-half findings F1, F5(b),
-- F10. Bundles three fixes into the SECURITY DEFINER retention/trigger surface
-- because all three touch the same two functions and a single migration keeps
-- the before/after diff legible.
--
-- F1 (BLOCKER, live-confirmed) — sbci_sweep_retention is SECURITY DEFINER,
-- executable by sbci_api/sbci_app, but used UNQUALIFIED relation names under
-- `SET search_path = public` (0021/0026). sbci_api holds default TEMP
-- privilege (has_database_privilege(...,'TEMP') = true) and pg_temp is
-- implicitly searched BEFORE public, so `CREATE TEMP TABLE accounts (...)`
-- inside the caller's own session shadows the real table for the entire
-- function body — a caller-controlled `due` CTE could drive cross-tenant
-- deletion. 0017/0023/0025 already pin `search_path = pg_catalog, public`
-- for this exact reason; 0021/0026 missed it. Fix: schema-qualify every
-- relation referenced in the function body as `public.*` (belt) AND pin
-- `search_path = pg_catalog, public, pg_temp` (suspenders — pg_temp stays
-- last so legitimate ON COMMIT DROP scratch use elsewhere is unaffected, but
-- every name this function itself writes is fully qualified so it can never
-- resolve to a caller's shadow regardless of search_path).
--
-- F5(b) (BLOCKER, live-confirmed) — a `leaderboard_contributions` row can
-- exist for a deleted account (store/community.go's write-time guard closes
-- the hole that let one land there in the first place, fixed alongside this
-- migration) but ANY stray row — from before this fix shipped, or from a
-- direct-SQL path — carries a NO-ACTION FK to accounts. The 24-month sweep
-- did not purge this table, so a stray row makes `DELETE FROM accounts` throw
-- `leaderboard_contributions_account_id_fkey` (23503) and roll back the WHOLE
-- sweep, silently blocking every other due account too. Fix: add
-- `leaderboard_contributions` to the 24-month CTE, following the
-- `community_grants` precedent 0026 already added for the same FK class.
--
-- F10 (MAJOR) — both the store-side guard and this trigger reject only
-- ELAPSED windows, so an authenticated device can upload an arbitrary value
-- into a FUTURE window (e.g. next month, or 9999-12) before being revoked;
-- that value later becomes eligible for materialization once its window
-- naturally arrives. Fix: require window_id == the server's current UTC-month
-- window, not merely "not yet elapsed" — tightened here AND in
-- store/community.go's IsCurrentWindow (Go-side companion, same change).

-- ===========================================================================
-- F1 + F5(b) — schema-qualified, pg_temp-hardened sweep with the
-- leaderboard_contributions purge folded into the 24-month CTE.
-- ===========================================================================
CREATE OR REPLACE FUNCTION sbci_sweep_retention(p_now timestamptz)
RETURNS TABLE (consent_purged int, audit_purged int, accounts_purged int)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    v_consent  int := 0;
    v_audit    int := 0;
    v_accounts int := 0;
    v_n        int;
BEGIN
    -- 12-month clock: consent-proof + billing rows of tombstoned accounts.
    WITH due AS (
        SELECT account_id FROM public.accounts
         WHERE status = 'deleted' AND deleted_at IS NOT NULL
           AND deleted_at <= p_now - interval '12 months'
    ), d1 AS (DELETE FROM public.consent_receipts      WHERE account_id IN (SELECT account_id FROM due) RETURNING 1),
       d2 AS (DELETE FROM public.consent_events        WHERE account_id IN (SELECT account_id FROM due) RETURNING 1),
       d3 AS (DELETE FROM public.portal_consent_events WHERE account_id IN (SELECT account_id FROM due) RETURNING 1),
       d4 AS (DELETE FROM public.analysis_usage_ledger WHERE account_id IN (SELECT account_id FROM due) RETURNING 1)
    SELECT (SELECT count(*) FROM d1) + (SELECT count(*) FROM d2)
         + (SELECT count(*) FROM d3) + (SELECT count(*) FROM d4)
      INTO v_consent;

    -- 24-month clock: audit + lifecycle rows, then the account row itself. The
    -- retained standing-grant registrations (structural + community) and any
    -- stray leaderboard_contributions row age out here so their NO-ACTION FKs
    -- cannot block the account DELETE (leaderboard_contributions added by
    -- this migration — Sol F5(b); it should normally already be gone via
    -- deletion.go's own-tx purge, this is the backstop for a stray row).
    WITH due AS (
        SELECT account_id FROM public.accounts
         WHERE status = 'deleted' AND purge_after IS NOT NULL
           AND purge_after <= p_now
    ), d1 AS (DELETE FROM public.security_audit_events      WHERE account_id IN (SELECT account_id FROM due) RETURNING 1),
       d2 AS (DELETE FROM public.deletion_requests          WHERE account_id IN (SELECT account_id FROM due) RETURNING 1),
       d3 AS (DELETE FROM public.structural_grants          WHERE account_id IN (SELECT account_id FROM due) RETURNING 1),
       d4 AS (DELETE FROM public.community_grants           WHERE account_id IN (SELECT account_id FROM due) RETURNING 1),
       d5 AS (DELETE FROM public.leaderboard_contributions   WHERE account_id IN (SELECT account_id FROM due) RETURNING 1)
    SELECT (SELECT count(*) FROM d1) + (SELECT count(*) FROM d2)
         + (SELECT count(*) FROM d3) + (SELECT count(*) FROM d4)
         + (SELECT count(*) FROM d5)
      INTO v_audit;

    -- Account rows last (cascades any residual auth_transactions).
    DELETE FROM public.accounts
     WHERE status = 'deleted' AND purge_after IS NOT NULL AND purge_after <= p_now;
    GET DIAGNOSTICS v_n = ROW_COUNT;
    v_accounts := v_n;

    RETURN QUERY SELECT v_consent, v_audit, v_accounts;
END$$;

ALTER FUNCTION sbci_sweep_retention(timestamptz) OWNER TO sbci_defs;
REVOKE ALL ON FUNCTION sbci_sweep_retention(timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_sweep_retention(timestamptz) TO sbci_api, sbci_app;

-- sbci_defs already holds SELECT+DELETE on leaderboard_contributions from
-- 0022 (the table's own migration); re-asserted here defensively since this
-- migration is the first to have the DEFINER function actually touch it.
GRANT SELECT, DELETE ON leaderboard_contributions TO sbci_defs;

-- ===========================================================================
-- F10 — freeze trigger tightened from "not yet elapsed" to "is the current
-- window", matching store/community.go's IsCurrentWindow. CREATE OR REPLACE
-- keeps the existing leaderboard_contributions_freeze trigger bound (a
-- function body replacement does not require re-creating dependent triggers).
-- ===========================================================================
CREATE OR REPLACE FUNCTION sbci_reject_finalized_contribution()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_window_start  date;
    v_current_start date;
BEGIN
    -- The first day of the window's month vs. the first day of the server's
    -- current UTC-month, both as absolute UTC dates. Only exact equality is
    -- writable: a window whose month has already ended is rejected (as
    -- before), and — new in this migration — a window whose month has not
    -- yet STARTED is rejected too, closing the pre-seed-a-future-window hole
    -- (Sol F10). AT TIME ZONE 'UTC' keeps the same F6 session-timezone
    -- independence the prior version had.
    v_window_start  := to_date(NEW.window_id || '-01', 'YYYY-MM-DD');
    v_current_start := date_trunc('month', clock_timestamp() AT TIME ZONE 'UTC')::date;
    IF v_window_start <> v_current_start THEN
        RAISE EXCEPTION 'contribution window % is not the current, in-progress window (%); only the in-progress window accepts writes', NEW.window_id, to_char(v_current_start, 'YYYY-MM')
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END$$;

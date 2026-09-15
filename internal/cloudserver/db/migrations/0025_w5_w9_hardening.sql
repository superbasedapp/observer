-- 0025_w5_w9_hardening.sql — fixes the Sol adversarial-review findings against
-- the W5 (community percentile) + W9 (Paddle billing) commits (2026-09-02).
-- Every change below closes a defect confirmed by CALLING the DB, not just read.
--
--   F1 (BLOCKER) — the production front-door role sbci_api holds SELECT (0015) +
--     DELETE (0019) on account_plans but NOT INSERT/UPDATE, so a real Paddle
--     webhook (which runs as sbci_api and assigns a plan via account_plans) 500s
--     and only partially commits. Grant the missing INSERT/UPDATE.
--
--   F9 (BLOCKER) — billing_events carries account_id with a NO ACTION FK, so the
--     24-month retention sweep's `DELETE FROM accounts` fails on any billed
--     account. billing_events is a SYSTEM audit log (deletion matrix: excluded),
--     so the correct behavior is to KEEP the content-free event row but drop the
--     account linkage on deletion: change the FK to ON DELETE SET NULL. This is
--     FK-safe for BOTH the immediate pseudonymize path and the retention purge.
--
--   F5 (BLOCKER) — finalized (fully-elapsed) contribution windows were not
--     frozen: a value UPDATE (or a fresh INSERT) into a past window still
--     succeeded, letting its published aggregate move — a repeated-window
--     differencing signal. Add a BEFORE INSERT/UPDATE trigger that REJECTS any
--     write whose window month has already elapsed (UTC). DELETE is untouched, so
--     opt-out/account-deletion still removes contributions. This is the DB
--     backstop for the same rule the store's UpsertContribution now enforces.
--
--   F6 (MAJOR) — the finalization gate in sbci_community_bands /
--     sbci_community_cohort_size compared `to_date(...)+interval` (a timestamp
--     WITHOUT time zone) against clock_timestamp() (timestamptz). Postgres
--     coerces the former using the SESSION TimeZone, which WithAggregator does
--     not pin, so a positive-offset session could unlock a UTC month early.
--     Re-create both functions with the boundary computed AT TIME ZONE 'UTC', so
--     the comparison is an absolute instant independent of session TimeZone. The
--     trigger uses the same AT TIME ZONE 'UTC' form.

-- ===========================================================================
-- F1 — sbci_api can assign plans (INSERT/UPDATE account_plans).
-- ===========================================================================
GRANT INSERT, UPDATE ON account_plans TO sbci_api;

-- ===========================================================================
-- F9 — billing_events.account_id FK becomes ON DELETE SET NULL.
-- ===========================================================================
ALTER TABLE billing_events DROP CONSTRAINT billing_events_account_id_fkey;
ALTER TABLE billing_events
    ADD CONSTRAINT billing_events_account_id_fkey
    FOREIGN KEY (account_id) REFERENCES accounts(account_id) ON DELETE SET NULL;

-- ===========================================================================
-- F3 — per-subscription event ordering. paddle_subscriptions gains last_event_at
-- (the provider `occurred_at` of the most-recently-APPLIED event) so a stale
-- delivery arriving out of order can be ignored rather than restoring an old
-- state (e.g. a late activation after a cancellation reviving paid access).
-- ===========================================================================
ALTER TABLE paddle_subscriptions ADD COLUMN last_event_at timestamptz;

-- ===========================================================================
-- F5 — freeze finalized contribution windows (DB backstop for the store rule).
-- ===========================================================================
CREATE OR REPLACE FUNCTION sbci_reject_finalized_contribution()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    -- The instant the window month ENDS, as an absolute UTC instant (AT TIME ZONE
    -- 'UTC' fixes the F6 session-timezone dependency here too). A write is allowed
    -- ONLY while that instant is still in the future (the window is in progress).
    IF (to_date(NEW.window_id || '-01', 'YYYY-MM-DD') + interval '1 month')
           AT TIME ZONE 'UTC' <= clock_timestamp() THEN
        RAISE EXCEPTION 'contribution window % is finalized (frozen); only the in-progress window accepts writes', NEW.window_id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END$$;

CREATE TRIGGER leaderboard_contributions_freeze
    BEFORE INSERT OR UPDATE ON leaderboard_contributions
    FOR EACH ROW EXECUTE FUNCTION sbci_reject_finalized_contribution();

-- ===========================================================================
-- F6 — UTC-correct finalization in both aggregation functions.
-- ===========================================================================
CREATE OR REPLACE FUNCTION sbci_community_bands(
    p_cohort_key     text,
    p_metric_id      text,
    p_metric_version int,
    p_window_id      text)
RETURNS TABLE (
    cohort_key     text,
    metric_id      text,
    metric_version int,
    window_id      text,
    band           int,
    band_count     bigint)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_edges numeric[];
    v_floor int;
    v_k     int;
    v_total bigint;
BEGIN
    SELECT cm.band_edges, GREATEST(cm.min_cohort, 30), GREATEST(cm.k_min, 5)
      INTO v_edges, v_floor, v_k
      FROM public.community_metrics cm
     WHERE cm.metric_id = p_metric_id
       AND cm.metric_version = p_metric_version;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    IF p_window_id !~ '^[0-9]{4}-(0[1-9]|1[0-2])$' THEN
        RETURN;
    END IF;
    -- Absolute UTC month-end instant (F6): independent of session TimeZone.
    IF (to_date(p_window_id || '-01', 'YYYY-MM-DD') + interval '1 month')
           AT TIME ZONE 'UTC' > clock_timestamp() THEN
        RETURN;
    END IF;

    SELECT count(*)
      INTO v_total
      FROM public.leaderboard_contributions lc
     WHERE lc.cohort_key = p_cohort_key
       AND lc.metric_id = p_metric_id
       AND lc.metric_version = p_metric_version
       AND lc.window_id = p_window_id;
    IF v_total < v_floor THEN
        RETURN;
    END IF;

    RETURN QUERY
    WITH cells AS (
        SELECT width_bucket(lc.value, v_edges) AS b, count(*)::bigint AS c
          FROM public.leaderboard_contributions lc
         WHERE lc.cohort_key = p_cohort_key
           AND lc.metric_id = p_metric_id
           AND lc.metric_version = p_metric_version
           AND lc.window_id = p_window_id
         GROUP BY width_bucket(lc.value, v_edges)
    ),
    survivors AS (
        SELECT cells.b, cells.c FROM cells WHERE cells.c >= v_k
    ),
    nsupp AS (
        SELECT (SELECT count(*) FROM cells) - (SELECT count(*) FROM survivors) AS n
    ),
    smallest AS (
        SELECT s.b FROM survivors s ORDER BY s.c ASC, s.b ASC LIMIT 1
    )
    SELECT p_cohort_key, p_metric_id, p_metric_version, p_window_id, s.b, s.c
      FROM survivors s
     WHERE NOT (
               (SELECT n FROM nsupp) = 1
               AND s.b = (SELECT smallest.b FROM smallest)
           )
     ORDER BY s.b;
END$$;

ALTER FUNCTION sbci_community_bands(text, text, int, text) OWNER TO sbci_defs;
REVOKE ALL ON FUNCTION sbci_community_bands(text, text, int, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_community_bands(text, text, int, text) TO sbci_aggregator;

CREATE OR REPLACE FUNCTION sbci_community_cohort_size(
    p_cohort_key     text,
    p_metric_id      text,
    p_metric_version int,
    p_window_id      text)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_floor int;
    v_total bigint;
BEGIN
    SELECT GREATEST(cm.min_cohort, 30) INTO v_floor
      FROM public.community_metrics cm
     WHERE cm.metric_id = p_metric_id AND cm.metric_version = p_metric_version;
    IF NOT FOUND THEN
        RETURN 0;
    END IF;
    IF p_window_id !~ '^[0-9]{4}-(0[1-9]|1[0-2])$' THEN
        RETURN 0;
    END IF;
    IF (to_date(p_window_id || '-01', 'YYYY-MM-DD') + interval '1 month')
           AT TIME ZONE 'UTC' > clock_timestamp() THEN
        RETURN 0;
    END IF;
    SELECT count(*) INTO v_total
      FROM public.leaderboard_contributions lc
     WHERE lc.cohort_key = p_cohort_key
       AND lc.metric_id = p_metric_id
       AND lc.metric_version = p_metric_version
       AND lc.window_id = p_window_id;
    IF v_total < v_floor THEN
        RETURN 0;
    END IF;
    RETURN v_total;
END$$;

ALTER FUNCTION sbci_community_cohort_size(text, text, int, text) OWNER TO sbci_defs;
REVOKE ALL ON FUNCTION sbci_community_cohort_size(text, text, int, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_community_cohort_size(text, text, int, text) TO sbci_aggregator;

-- ===========================================================================
-- F7 — deletion must propagate to OLD published snapshots within 24h (R3). The
-- materialization previously recomputed only the last 3 finalized windows, so an
-- opt-out/deletion of an older contribution left its stale band published
-- indefinitely. sbci_community_windows() enumerates every FINALIZED
-- (cohort, metric, version, window) that still HAS a contribution, so the worker
-- can recompute all of them (and prune snapshots for windows that no longer
-- appear — a fully-emptied cohort). Aggregator-only, same hardening as the rest.
-- Returns only aggregate identifiers (no account, no value).
-- ===========================================================================
CREATE OR REPLACE FUNCTION sbci_community_windows()
RETURNS TABLE (cohort_key text, metric_id text, metric_version int, window_id text)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT DISTINCT lc.cohort_key, lc.metric_id, lc.metric_version, lc.window_id
      FROM public.leaderboard_contributions lc
     WHERE (to_date(lc.window_id || '-01', 'YYYY-MM-DD') + interval '1 month')
               AT TIME ZONE 'UTC' <= clock_timestamp();
$$;

ALTER FUNCTION sbci_community_windows() OWNER TO sbci_defs;
REVOKE ALL ON FUNCTION sbci_community_windows() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_community_windows() TO sbci_aggregator;

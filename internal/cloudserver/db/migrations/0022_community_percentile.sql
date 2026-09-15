-- 0022_community_percentile.sql — W5 community phase 1: PRIVATE cohort
-- percentile (cloud-intelligence divergence remediation plan rev 4.2, §3 "W5";
-- operator ruling R3; closes D5 phase 1). This is the single most
-- security-critical migration in the arc: it introduces the ONLY cross-tenant
-- read in the whole hosted service besides the auth-bootstrap lookups, and it
-- must never let one account's contribution be isolated, differenced out, or
-- read by the front-door role.
--
-- Shape (plan §3 W5 / F4, and the session-6 parking design):
--
--   community_metrics        — SYSTEM/config registry (NOT tenant data): the
--                              fixed, versioned metric definitions. A metric's
--                              row carries the band edges (width_bucket
--                              thresholds), the displayed-cohort floor, and the
--                              cell-suppression threshold k. A metric_id/version
--                              with NO row is unregistered ⇒ un-contributable
--                              (the contributions FK below) AND unreadable (the
--                              aggregation function returns nothing). This is the
--                              SQL half of the "forbidden metrics enforced
--                              table-driven" rule; the compiled-in Go registry
--                              (upload-path follow-on) must match this seed.
--
--   leaderboard_contributions — TENANT (RLS ENABLE + FORCE + the
--                              sbci_current_account() policy every tenant table
--                              carries). It DOES carry account_id — that is the
--                              deletion/opt-out linkage (plan §3 W5: "revocation
--                              and account deletion are ordinary tenant-scoped
--                              deletes that reliably locate every contribution").
--                              De-identification happens at the READ boundary,
--                              not in the row. The account reads its OWN value
--                              via RLS to place its own percentile; the ONLY
--                              cross-tenant reader is the DEFINER function below.
--
--   sbci_community_bands(cohort_key, metric_id, metric_version, window_id)
--                              — SECURITY DEFINER, owner sbci_defs (BYPASSRLS),
--                              search_path pinned to `pg_catalog, public` with
--                              every referenced object schema-qualified (hardened
--                              past 0003's bare `SET search_path = public`).
--                              EXECUTE granted ONLY to sbci_aggregator — never
--                              sbci_api, never sbci_app, never sbci_worker (F4).
--                              Its arguments are FIXED registry identifiers only:
--                              no account-selective argument, no free predicate,
--                              no caller-supplied "now" (finalization is judged
--                              against the server clock so a window can never be
--                              unlocked early). It returns ONLY finalized,
--                              floored, k-suppressed band cells
--                              {cohort_key, metric_id, metric_version, window_id,
--                              band, band_count} — never a raw value, never a
--                              per-contribution row, never a cohort total, never
--                              an account id. It therefore cannot return, filter
--                              by, or join out an account.
--
-- Differencing resistance (the two attacks the plan names):
--   * cohort-minus-one — STRUCTURALLY impossible: the signature has no
--     account-selective argument and no free predicate, so "this cohort minus
--     account X" is inexpressible.
--   * repeated-window — a window is readable ONLY once fully elapsed
--     (finalized); the upload path refuses contributions to an elapsed window
--     (follow-on), so a finalized window's contribution set is FROZEN and
--     repeated calls return byte-identical results — no signal accrues over
--     time. In-progress/future windows return nothing at all.
--   * small-cell inference — a cell with count < k is dropped; if that leaves
--     exactly ONE dropped cell (whose size would be inferable from the cohort
--     total), the smallest surviving cell is dropped too, so at least two cells
--     are always missing (complementary suppression).
--
-- The ≥30 displayed-cohort floor and cell-level k-suppression are enforced
-- INSIDE the function and HARD-floored (GREATEST(min_cohort,30) /
-- GREATEST(k_min,5)) so a bad seed can never weaken them.

-- ===========================================================================
-- community_metrics — the fixed, versioned metric registry (SYSTEM data).
-- ===========================================================================
CREATE TABLE community_metrics (
    metric_id      text NOT NULL CHECK (metric_id <> ''),
    metric_version int  NOT NULL CHECK (metric_version > 0),
    -- Ascending width_bucket thresholds. width_bucket(value, band_edges) yields
    -- bucket 0 (value below the first edge) .. N (value at/above the last edge),
    -- so N+1 fixed, data-INDEPENDENT bands. Data-independent edges are what makes
    -- the histogram differencing-resistant (a quantile/NTILE edge shifts when one
    -- contributor is added or removed — a cohort-minus-one signal — so it is
    -- deliberately NOT used).
    band_edges     numeric[] NOT NULL CHECK (array_length(band_edges, 1) >= 1),
    -- Displayed-cohort floor: below this many contributions in a (cohort, metric,
    -- window) the function returns nothing. Hard-floored at 30 by the function.
    min_cohort     int  NOT NULL DEFAULT 30 CHECK (min_cohort >= 30),
    -- Cell-suppression threshold: a band with fewer than this many contributions
    -- is suppressed. Hard-floored at 5 by the function.
    k_min          int  NOT NULL DEFAULT 5 CHECK (k_min >= 5),
    created_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (metric_id, metric_version)
);

COMMENT ON TABLE community_metrics IS
    'W5 fixed versioned metric registry (band edges + floor + k). SYSTEM data, not account data (deletion matrix: excluded). The compiled-in Go registry must match this seed.';

-- Seed the phase-1 metrics. Edges are fixed, published, versioned constants; a
-- change to a metric ships as a NEW metric_version (never an in-place edit), so
-- historical windows keep the bands they were computed under. Keep in lockstep
-- with the compiled-in Go registry (internal/cloudserver/community) landed with
-- the upload path.
INSERT INTO community_metrics (metric_id, metric_version, band_edges, min_cohort, k_min) VALUES
    -- Sessions per active day (rounded to 1 decimal upstream): bands
    -- <1, 1-2, 2-3, 3-5, 5-8, 8-13, >=13.
    ('sessions_per_active_day', 1, ARRAY[1, 2, 3, 5, 8, 13]::numeric[], 30, 5),
    -- Verification coverage percent (0-100): bands <10, 10-25, 25-50, 50-75,
    -- 75-90, >=90.
    ('verification_coverage_pct', 1, ARRAY[10, 25, 50, 75, 90]::numeric[], 30, 5);

-- ===========================================================================
-- leaderboard_contributions — the per-account contribution (TENANT).
-- ===========================================================================
CREATE TABLE leaderboard_contributions (
    id             uuid NOT NULL DEFAULT gen_random_uuid(),
    account_id     uuid NOT NULL REFERENCES accounts(account_id),
    -- Fixed versioned cohort identifier (e.g. 'global', 'lang:go'). No arbitrary
    -- slicing: the upload path only ever writes known cohort keys, and an unknown
    -- key simply has no/too-few contributions ⇒ the function returns nothing.
    cohort_key     text NOT NULL CHECK (cohort_key <> ''),
    metric_id      text NOT NULL,
    metric_version int  NOT NULL CHECK (metric_version > 0),
    -- The UTC-month window this value belongs to, 'YYYY-MM'. The function only
    -- reads FINALIZED (fully-elapsed) windows; the upload path refuses writes to
    -- an already-finalized window (follow-on), freezing its contribution set.
    window_id      text NOT NULL CHECK (window_id ~ '^[0-9]{4}-(0[1-9]|1[0-2])$'),
    -- The account's own metric value for this window. Read cross-tenant ONLY
    -- through the banding function (never projected raw); read directly ONLY by
    -- the owning account via RLS (its own-percentile surface).
    value          numeric NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (id),
    UNIQUE (account_id, id),
    -- One contribution per account per (cohort, metric, version, window): a
    -- re-contribution updates the value in place (upload path), it never stacks.
    UNIQUE (account_id, cohort_key, metric_id, metric_version, window_id),
    -- Only a REGISTERED metric can be contributed — the SQL half of forbidden-
    -- metric enforcement. Deleting a metric definition is blocked while
    -- contributions reference it (NO ACTION), which is intended.
    FOREIGN KEY (metric_id, metric_version)
        REFERENCES community_metrics (metric_id, metric_version)
);

-- The aggregation scan groups by (cohort, metric, version, window).
CREATE INDEX leaderboard_contributions_cohort
    ON leaderboard_contributions (cohort_key, metric_id, metric_version, window_id);

ALTER TABLE leaderboard_contributions ENABLE ROW LEVEL SECURITY;
ALTER TABLE leaderboard_contributions FORCE ROW LEVEL SECURITY;
CREATE POLICY leaderboard_contributions_tenant ON leaderboard_contributions
    USING (account_id = sbci_current_account())
    WITH CHECK (account_id = sbci_current_account());

-- ===========================================================================
-- sbci_community_bands — the hardened cross-tenant aggregation (F4).
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
    v_wstart date;
    v_total bigint;
BEGIN
    -- 1. Registered metric only. An unknown/forbidden (metric_id, version) has no
    --    row ⇒ no output. Hard-floor the cohort floor at 30 and k at 5 so a bad
    --    seed can never weaken the privacy guarantees.
    SELECT cm.band_edges, GREATEST(cm.min_cohort, 30), GREATEST(cm.k_min, 5)
      INTO v_edges, v_floor, v_k
      FROM public.community_metrics cm
     WHERE cm.metric_id = p_metric_id
       AND cm.metric_version = p_metric_version;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    -- 2. The window must be a well-formed UTC month AND fully elapsed (finalized).
    --    There is deliberately no caller-supplied "now": finalization is judged
    --    against the server clock only, so an in-progress window can never be
    --    unlocked early and a finalized window is frozen (repeated-window
    --    differencing defense). A malformed window_id yields nothing (never an
    --    error).
    IF p_window_id !~ '^[0-9]{4}-(0[1-9]|1[0-2])$' THEN
        RETURN;
    END IF;
    v_wstart := to_date(p_window_id || '-01', 'YYYY-MM-DD');
    IF (v_wstart + interval '1 month') > clock_timestamp() THEN
        RETURN;
    END IF;

    -- 3. ≥floor displayed-cohort floor over the frozen contribution set. Below it
    --    the whole cohort is unreadable.
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

    -- 4. Band into data-independent buckets, k-suppress small cells, and apply
    --    complementary suppression when exactly one cell was dropped. Returns
    --    only surviving {band, count} cells — never a raw value, cohort total, or
    --    account id.
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

-- ===========================================================================
-- Grants.
-- ===========================================================================
--
-- Base-table privileges the DEFINER body needs past BYPASSRLS. Both are PURE
-- READS inside the function, so SELECT alone suffices (contrast the retention
-- sweep, whose DELETE's WHERE also needs SELECT).
GRANT SELECT ON community_metrics           TO sbci_defs;
GRANT SELECT ON leaderboard_contributions   TO sbci_defs;

-- community_metrics is a read-only registry for the application roles (the
-- upload path validates a contribution's metric against it; the account's own
-- percentile surface reads the edges). No application role writes it — seeds
-- ship by migration.
GRANT SELECT ON community_metrics TO sbci_api, sbci_app, sbci_worker;

-- leaderboard_contributions: the front-door role owns the tenant lifecycle
-- (contribute on the upload path, read the account's own value, delete on
-- revocation/account-deletion). sbci_app mirrors it for the dev/admin +
-- deletion-runs-as-app test fallback. The worker never touches contributions.
GRANT SELECT, INSERT, UPDATE, DELETE ON leaderboard_contributions TO sbci_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON leaderboard_contributions TO sbci_app;

-- The aggregator's WithAggregator tx clears tenant context and asserts
-- sbci_current_account() IS NULL as a fail-closed guard (WithSystem parity), so
-- the role needs EXECUTE on that RLS helper even though it holds no RLS'd table
-- grant to use it against. Harmless: with no table grants the value is inert.
GRANT EXECUTE ON FUNCTION sbci_current_account() TO sbci_aggregator;

-- The aggregation function is the aggregator role's ALONE (F4). Revoke the
-- implicit PUBLIC EXECUTE and grant it to exactly one role — never the
-- front-door api, never the shared app role, never the worker.
REVOKE ALL ON FUNCTION sbci_community_bands(text, text, int, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_community_bands(text, text, int, text) TO sbci_aggregator;

-- ===========================================================================
-- Staging-window guard (mirrors 0015). The aggregation runs as sbci_aggregator,
-- assumed via `SET LOCAL ROLE sbci_aggregator`, which requires the login
-- principal to be a MEMBER of the role. The deploy script grants membership to
-- the dedicated login roles (sbci_svc / sbci_worker_svc); grant here too so the
-- new image works the instant it deploys, before the script runs. Guarded so a
-- cluster without those login roles (tests, a fresh prod) is a clean no-op.
-- ===========================================================================
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sbci_svc') THEN
        GRANT sbci_aggregator TO sbci_svc;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sbci_worker_svc') THEN
        GRANT sbci_aggregator TO sbci_worker_svc;
    END IF;
END$$;

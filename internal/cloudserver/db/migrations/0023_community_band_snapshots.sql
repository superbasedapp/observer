-- 0023_community_band_snapshots.sql — W5 follow-on: the delayed-band
-- materialization the own-percentile READ surface reads (cloud-intelligence
-- divergence remediation plan §3 "W5"; operator ruling R3 "delayed snapshot
-- bands"). This is the read-side companion to 0022's cross-tenant aggregation.
--
-- Why a materialized table rather than a live read. 0022 grants EXECUTE on the
-- cross-tenant SECURITY DEFINER aggregation (sbci_community_bands) ONLY to
-- sbci_aggregator — never sbci_api. The front-door serve process (sbci_api) must
-- therefore NEVER compute bands live: it would be the wrong attack surface for a
-- cross-tenant read. Instead the WORKER (which assumes the aggregator role for
-- the read) periodically materializes each finalized window's floored/
-- k-suppressed cells into this table, and the api/portal read THIS — an
-- aggregate-only table with NO account_id and no raw values. This is also
-- exactly what "delayed bands" means: the distribution a developer sees is a
-- finalized, delayed snapshot, not a live count.
--
-- Privacy shape. Every row is a {cohort, metric, version, window, band, count}
-- cell that already passed the ≥30 floor + k-suppression + complementary
-- suppression INSIDE sbci_community_bands. cohort_size is the total contribution
-- count for the window (≥30 by construction — a window below the floor
-- materializes NO rows at all, so its very presence already implies ≥30). There
-- is no account linkage of any kind, so this table is NOT tenant data:
-- the W6d deletion matrix classifies it `excluded` (nothing to purge per
-- account; a deleted account's contribution is removed from
-- leaderboard_contributions and the next materialization recomputes the bands
-- without it — the R3 24h removal).

CREATE TABLE community_band_snapshots (
    cohort_key     text NOT NULL CHECK (cohort_key <> ''),
    metric_id      text NOT NULL,
    metric_version int  NOT NULL CHECK (metric_version > 0),
    window_id      text NOT NULL CHECK (window_id ~ '^[0-9]{4}-(0[1-9]|1[0-2])$'),
    band           int  NOT NULL CHECK (band >= 0),
    band_count     bigint NOT NULL CHECK (band_count > 0),
    -- The cohort's total contribution count for this window (≥ the floor, since a
    -- sub-floor window produces no rows). Shown on the portal Community page as
    -- "cohort size" (R3).
    cohort_size    bigint NOT NULL CHECK (cohort_size >= 30),
    -- When this snapshot cell was materialized (delayed-band recompute stamp).
    computed_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (cohort_key, metric_id, metric_version, window_id, band),
    -- A registered metric only — the SQL-side forbidden-metric guard, matching
    -- leaderboard_contributions' FK.
    FOREIGN KEY (metric_id, metric_version)
        REFERENCES community_metrics (metric_id, metric_version)
);

-- The read path fetches a whole window's cells at once.
CREATE INDEX community_band_snapshots_window
    ON community_band_snapshots (cohort_key, metric_id, metric_version, window_id);

COMMENT ON TABLE community_band_snapshots IS
    'W5 delayed-band materialization: aggregate-only {cohort,metric,version,window,band,count} cells written by the worker (via sbci_community_bands under the aggregator role) and read by api/portal. No account linkage; deletion matrix = excluded.';

-- ===========================================================================
-- sbci_community_cohort_size — the finalized cohort total (aggregator-only).
-- ===========================================================================
-- The materializer stamps the cohort_size onto each snapshot cell. The size
-- comes from a companion SECURITY DEFINER function that applies the SAME
-- finalization + ≥30 floor gates as sbci_community_bands, so it can NEVER reveal
-- a sub-floor or unfinalized cohort's size (returns 0 there). Revealing an
-- exact size ≥ 30 is intended (the portal shows "cohort size", R3); it carries
-- no per-account information. Same hardening as 0022: owner sbci_defs,
-- search_path pinned qualified, EXECUTE to sbci_aggregator ONLY.
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
    v_wstart date;
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
    v_wstart := to_date(p_window_id || '-01', 'YYYY-MM-DD');
    IF (v_wstart + interval '1 month') > clock_timestamp() THEN
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
GRANT SELECT ON community_metrics         TO sbci_defs; -- (already granted in 0022; idempotent belt-and-braces)
GRANT SELECT ON leaderboard_contributions TO sbci_defs;
REVOKE ALL ON FUNCTION sbci_community_cohort_size(text, text, int, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_community_cohort_size(text, text, int, text) TO sbci_aggregator;

-- ===========================================================================
-- Grants. The WORKER materializes (SELECT to diff/replace, INSERT/DELETE to
-- rewrite a window's cells); the api/serve process READS to serve the portal
-- Community page + the own-percentile surface. sbci_app mirrors the worker set
-- for the dev/single-process + test fallback.
-- ===========================================================================
GRANT SELECT, INSERT, DELETE ON community_band_snapshots TO sbci_worker;
GRANT SELECT, INSERT, DELETE ON community_band_snapshots TO sbci_app;
GRANT SELECT                 ON community_band_snapshots TO sbci_api;

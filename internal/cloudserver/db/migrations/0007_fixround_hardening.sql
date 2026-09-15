-- 0007_fixround_hardening.sql — the end-of-arc fix-round hardening (Sol
-- adversarial review 2026-08-31, docs/audits/cloud-intelligence-shipped-code-
-- sol-review-2026-08-31.md). It carries the DDL for three findings:
--
--   * FA8 — a UNIQUE(account_id, job_id) backstop on analysis_results so a
--     lease-expiry/re-lease race can never leave two attributable results for
--     one job. The primary guard is the CAS in CompleteJobWithResult (only the
--     current lease owner, on a still-running unexpired job, may complete); this
--     constraint is the final wall.
--   * FA5 — bind a responses_store_false verification record to the ROUTE
--     GENERATION it was taken against. SetRouteBinding bumps the route
--     generation on any endpoint/api-version/deployment/audience change, so a
--     generation-bound record is invalidated the moment the route it verified
--     is mutated. (api_version + deployment are also matched against the
--     resolved route snapshot in the query, as defence in depth.)
--   * FC3 — an expiry index + a cross-tenant SECURITY DEFINER sweep so the
--     pop_replay jti cache cannot grow without bound. pop_replay is RLS
--     tenant-scoped, so the sweep is owned by the BYPASSRLS sbci_defs role and
--     deletes purely by expires_at, mirroring sbci_sweep_expired_evidence.

-- ---------------------------------------------------------------------------
-- FA8: at most one result per job.
-- ---------------------------------------------------------------------------
ALTER TABLE analysis_results
    ADD CONSTRAINT analysis_results_unique_job UNIQUE (account_id, job_id);

-- ---------------------------------------------------------------------------
-- FA5: generation-bound dialect verification records.
-- ---------------------------------------------------------------------------
ALTER TABLE dialect_verification_records
    ADD COLUMN route_generation bigint NOT NULL DEFAULT 0;

DROP INDEX IF EXISTS dialect_verification_lookup;
CREATE INDEX dialect_verification_lookup
    ON dialect_verification_records (route_id, dialect, route_generation, active, expires_at);

-- ---------------------------------------------------------------------------
-- FC3: pop_replay expiry index + cross-tenant sweep.
-- ---------------------------------------------------------------------------
CREATE INDEX pop_replay_expiry ON pop_replay (expires_at);

CREATE OR REPLACE FUNCTION sbci_sweep_expired_pop_replay(p_now timestamptz)
RETURNS int
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_deleted int;
BEGIN
    DELETE FROM pop_replay WHERE expires_at < p_now;
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    RETURN v_deleted;
END$$;

ALTER FUNCTION sbci_sweep_expired_pop_replay(timestamptz) OWNER TO sbci_defs;

-- Base-table privilege the DEFINER function needs (BYPASSRLS removes the row
-- filter, not the table grant).
GRANT SELECT, DELETE ON pop_replay TO sbci_defs;

REVOKE ALL ON FUNCTION sbci_sweep_expired_pop_replay(timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_sweep_expired_pop_replay(timestamptz) TO sbci_app;

-- 0037_project_digest.sql — the project-digest job kind + per-plan results
-- retention (cloud-intelligence value-upgrade plan, 2026-09-15, W5).
--
-- Three independent additions:
--
--   1. cloud_sessions.metrics — a content-free structural snapshot captured at
--      every job submit (api/jobs.go handleSubmitJob), mirroring the envelope's
--      MetricsBlock/Outcomes/ActivityMix field names verbatim. It carries no
--      excerpts, no paths, and no action targets — the SAME content-free bar
--      the envelope itself is held to (plan §2.8) — and is the substrate the
--      digest scheduler folds into project-digest evidence without asking the
--      node to upload anything new.
--
--   2. analysis_results gains a KIND discriminator (default
--      'session_enrichment', so every pre-existing row classifies itself
--      unchanged) plus the digest's own linkage (project_pk, period_start,
--      period_end) — nullable, populated only on a 'project_digest' row.
--
--   3. plans gains two DEFINITION columns: digest_weekly (which plans include
--      the weekly project digest) and results_retention_days (how long a
--      plan's results stay in hosted history). `plans` rows are otherwise
--      IMMUTABLE (migration 0012's sbci_plans_immutable trigger refuses any
--      UPDATE, even from the table owner) — a migration is deliberately the
--      ONE place a plan's definition may still move, because it runs with
--      superuser/owner privilege outside the trigger's application-facing
--      guarantee. The trigger is disabled for the duration of the two seed
--      UPDATEs below and re-enabled immediately after, so the immutability
--      contract holds for every ordinary write once this migration commits.
--      The CAPS (daily/monthly/concurrency_cap, budget_pool) are untouched —
--      this migration only ever writes digest_weekly, results_retention_days,
--      and (once) the plus_beta v1 label.
--
-- Plus a per-plan results-retention sweep function (sbci_sweep_results_retention,
-- mirroring 0021's sbci_sweep_retention): unlike 0021 (which ages out rows a
-- COMPLETED ACCOUNT DELETION retained), this ages out results of LIVE accounts
-- once they outlive their plan's results_retention_days. It deletes
-- result_revisions before analysis_results (FK-safe: 0018's
-- result_revisions -> analysis_results FK has no ON DELETE clause, so the
-- child must go first) — superseded and current rows alike, so a correction's
-- revision HISTORY is purged along with the result it corrected. That is a
-- deliberate consequence, documented here: retention aging removes the row and
-- everything appended to it, unlike account deletion's separate retain/purge
-- matrix.

-- ---------------------------------------------------------------------------
-- 1) cloud_sessions.metrics — content-free structural snapshot at submit time.
-- ---------------------------------------------------------------------------
ALTER TABLE cloud_sessions ADD COLUMN metrics jsonb;

-- ---------------------------------------------------------------------------
-- 2) analysis_results — the kind discriminator + digest linkage.
-- ---------------------------------------------------------------------------
ALTER TABLE analysis_results
    ADD COLUMN kind         text NOT NULL DEFAULT 'session_enrichment',
    ADD COLUMN project_pk   uuid,
    ADD COLUMN period_start date,
    ADD COLUMN period_end   date;

ALTER TABLE analysis_results
    ADD CONSTRAINT analysis_results_project_pk_fk
    FOREIGN KEY (account_id, project_pk)
    REFERENCES cloud_projects (account_id, id);

CREATE INDEX analysis_results_kind_created
    ON analysis_results (account_id, kind, created_at);

-- ---------------------------------------------------------------------------
-- 3) plans — digest entitlement + retention window (definition columns).
-- ---------------------------------------------------------------------------
ALTER TABLE plans
    ADD COLUMN digest_weekly          boolean NOT NULL DEFAULT false,
    ADD COLUMN results_retention_days int     NOT NULL DEFAULT 30;

-- The one place a plan definition may still change (see header comment): the
-- immutability trigger is application-facing, not migration-facing. Disable it
-- for exactly the two UPDATEs below, then restore it before this transaction
-- commits — every ordinary write after this migration is refused again.
ALTER TABLE plans DISABLE TRIGGER sbci_plans_immutable;

UPDATE plans SET digest_weekly = true, results_retention_days = 365
 WHERE name = 'plus_beta';

-- R4's original "Plus beta entitlement simulation" label predates a real
-- payment rail; Plus is now a purchasable plan (Paddle), so the label is
-- corrected to the honest, unqualified "Plus".
UPDATE plans SET label = 'Plus'
 WHERE name = 'plus_beta' AND version = 1;

ALTER TABLE plans ENABLE TRIGGER sbci_plans_immutable;

-- ---------------------------------------------------------------------------
-- Per-plan results-retention sweep (SECURITY DEFINER, owned by sbci_defs).
-- ---------------------------------------------------------------------------
-- Schema-qualified + pg_temp-hardened, mirroring 0027's Sol F1 fix for
-- sbci_sweep_retention: this SECURITY DEFINER function is EXECUTABLE by
-- sbci_worker/sbci_app, both of which hold default TEMP privilege, and
-- pg_temp is implicitly searched BEFORE public regardless of search_path — so
-- `CREATE TEMP TABLE accounts (...)` in the CALLER's own session would shadow
-- the real table for the whole function body if any reference here were left
-- unqualified. Every persistent relation is qualified `public.*` (belt) AND
-- search_path pins `pg_catalog, public, pg_temp` (suspenders, pg_temp last so
-- the function's OWN scratch temp table still resolves there). The scratch
-- table itself is explicitly `pg_temp.sbci_due_results` for the same reason —
-- an unqualified reference to it would be just as searchable-first as a real
-- table's shadow, so qualifying it removes any ambiguity rather than relying
-- on it being "obviously fine" because this function created it.
CREATE OR REPLACE FUNCTION sbci_sweep_results_retention(p_now timestamptz)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    v_count bigint := 0;
BEGIN
    CREATE TEMP TABLE IF NOT EXISTS sbci_due_results (id uuid) ON COMMIT DROP;
    TRUNCATE pg_temp.sbci_due_results;

    -- Resolve each LIVE (status='active') account's CURRENT plan's
    -- results_retention_days (30 when the account has no assignment at all —
    -- absence-means-free, mirroring resolvePlanTx) and select every result
    -- older than that window.
    INSERT INTO pg_temp.sbci_due_results (id)
    SELECT r.id
      FROM public.analysis_results r
      JOIN public.accounts a ON a.account_id = r.account_id
     WHERE a.status = 'active'
       AND r.created_at < p_now - (
           coalesce(
               (SELECT p.results_retention_days
                  FROM public.account_plans ap
                  JOIN public.plans p ON p.plan_id = ap.plan_id
                 WHERE ap.account_id = r.account_id
                   AND ap.effective_from <= p_now
                   AND (ap.effective_until IS NULL OR ap.effective_until > p_now)
                 ORDER BY ap.effective_from DESC
                 LIMIT 1),
               30
           ) || ' days'
       )::interval;

    -- Children before the parent (FK-safe): result_revisions has no ON DELETE
    -- clause on its analysis_results FK (migration 0018).
    DELETE FROM public.result_revisions WHERE result_id IN (SELECT id FROM pg_temp.sbci_due_results);
    DELETE FROM public.analysis_results WHERE id IN (SELECT id FROM pg_temp.sbci_due_results);
    GET DIAGNOSTICS v_count = ROW_COUNT;

    RETURN v_count;
END$$;

ALTER FUNCTION sbci_sweep_results_retention(timestamptz) OWNER TO sbci_defs;

-- Base-table privileges the DEFINER body needs past BYPASSRLS (mirrors 0021's
-- SELECT+DELETE precedent — a DELETE's WHERE/USING clause reads columns, so
-- SELECT is required alongside DELETE even though it never SELECTs a result
-- row's own columns directly here).
GRANT SELECT, DELETE ON analysis_results  TO sbci_defs;
GRANT SELECT, DELETE ON result_revisions  TO sbci_defs;
GRANT SELECT         ON accounts          TO sbci_defs;
GRANT SELECT         ON account_plans     TO sbci_defs;
GRANT SELECT         ON plans             TO sbci_defs;

REVOKE ALL ON FUNCTION sbci_sweep_results_retention(timestamptz) FROM PUBLIC;
-- The worker process runs this sweep (cmd/observer-cloud's daily retention
-- loop); sbci_app keeps EXECUTE for the operator/test single-role fallback.
GRANT EXECUTE ON FUNCTION sbci_sweep_results_retention(timestamptz) TO sbci_worker, sbci_app;

-- ---------------------------------------------------------------------------
-- Cross-tenant project-digest candidate scan (SECURITY DEFINER, mirrors the
-- sbci_lease_next_job precedent as the ONLY way to enumerate across accounts).
-- ---------------------------------------------------------------------------
--
-- Returns one row per (account, project) whose account's CURRENT plan carries
-- digest_weekly=true, which has at least p_min_sessions non-superseded
-- session_enrichment results in [p_range_start, p_range_end), and which has NO
-- project_digest result yet for the exact (p_period_start, p_period_end) pair
-- — so a re-run of the scheduler is naturally idempotent (nothing new is
-- returned once a digest has landed for that project/period).
-- Schema-qualified + pg_temp-hardened for the SAME reason as
-- sbci_sweep_results_retention above (Sol F1 precedent, migration 0027):
-- executable by sbci_worker/sbci_app, both with default TEMP privilege, so
-- every relation is qualified `public.*` and search_path pins
-- `pg_catalog, public, pg_temp`.
CREATE OR REPLACE FUNCTION sbci_project_digest_candidates(
    p_period_start date,
    p_period_end   date,
    p_range_start  timestamptz,
    p_range_end    timestamptz,
    p_min_sessions int,
    p_now          timestamptz,
    p_limit        int
)
RETURNS TABLE (account_id uuid, project_pk uuid, cloud_project_id text, session_count bigint)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
STABLE
AS $$
    SELECT r.account_id, cp.id AS project_pk, cp.cloud_project_id, count(*) AS session_count
      FROM public.analysis_results r
      JOIN public.analysis_jobs   j  ON j.account_id  = r.account_id AND j.id  = r.job_id
      JOIN public.cloud_sessions  cs ON cs.account_id = r.account_id AND cs.id = j.session_pk
      JOIN public.cloud_projects  cp ON cp.account_id = r.account_id AND cp.id = cs.project_pk
      JOIN public.account_plans   ap ON ap.account_id = r.account_id
                              AND ap.effective_from <= p_now
                              AND (ap.effective_until IS NULL OR ap.effective_until > p_now)
      JOIN public.plans p ON p.plan_id = ap.plan_id AND p.digest_weekly = true
     WHERE r.kind = 'session_enrichment'
       AND r.superseded = false
       AND r.created_at >= p_range_start
       AND r.created_at <  p_range_end
       AND NOT EXISTS (
               SELECT 1 FROM public.analysis_results d
                WHERE d.account_id    = r.account_id
                  AND d.kind          = 'project_digest'
                  AND d.project_pk    = cp.id
                  AND d.period_start  = p_period_start
                  AND d.period_end    = p_period_end
           )
     GROUP BY r.account_id, cp.id, cp.cloud_project_id
    HAVING count(*) >= p_min_sessions
     LIMIT p_limit;
$$;

ALTER FUNCTION sbci_project_digest_candidates(date, date, timestamptz, timestamptz, int, timestamptz, int) OWNER TO sbci_defs;

-- Base-table privileges the DEFINER body needs past BYPASSRLS. analysis_jobs
-- is already SELECT-granted to sbci_defs (0004), and analysis_results /
-- account_plans / plans are granted just above (shared with
-- sbci_sweep_results_retention) — only cloud_sessions and cloud_projects are
-- new reads this function introduces.
GRANT SELECT ON cloud_sessions TO sbci_defs;
GRANT SELECT ON cloud_projects TO sbci_defs;

REVOKE ALL ON FUNCTION sbci_project_digest_candidates(date, date, timestamptz, timestamptz, int, timestamptz, int) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_project_digest_candidates(date, date, timestamptz, timestamptz, int, timestamptz, int) TO sbci_worker, sbci_app;

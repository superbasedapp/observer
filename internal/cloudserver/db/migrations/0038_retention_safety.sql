-- 0038_retention_safety.sql — preserve per-account result cursors across
-- retention, including inserts from older workers during an image roll.
-- A separate counter avoids locking accounts after completion locks a job:
-- deletion fences accounts before purging jobs. Only this opaque watermark is
-- retained with the account tombstone; its FK cascades on final account purge.
CREATE TABLE account_result_cursors (
    account_id uuid PRIMARY KEY REFERENCES accounts(account_id) ON DELETE CASCADE,
    last_sequence bigint NOT NULL CHECK (last_sequence >= 0)
);
ALTER TABLE account_result_cursors ENABLE ROW LEVEL SECURITY;
ALTER TABLE account_result_cursors FORCE ROW LEVEL SECURITY;
CREATE POLICY account_result_cursors_tenant ON account_result_cursors
    USING (account_id = sbci_current_account())
    WITH CHECK (account_id = sbci_current_account());
GRANT SELECT ON account_result_cursors TO sbci_app, sbci_worker;
GRANT SELECT, INSERT, UPDATE ON account_result_cursors TO sbci_defs;
INSERT INTO account_result_cursors (account_id, last_sequence)
SELECT account_id, max(account_seq) FROM analysis_results GROUP BY account_id;

-- Every insert, including an old worker's MAX(account_seq)+1 proposal,
-- advances the durable watermark. The counter row serializes allocation and
-- rolls back with a refused insert. Existing RLS gates the result INSERT;
-- app roles cannot invoke the trigger directly or write the counter.
CREATE FUNCTION sbci_allocate_result_sequence() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
BEGIN
    INSERT INTO public.account_result_cursors (account_id, last_sequence)
    VALUES (NEW.account_id, greatest(1, coalesce(NEW.account_seq, 1)))
    ON CONFLICT (account_id) DO UPDATE
        SET last_sequence = greatest(account_result_cursors.last_sequence + 1, EXCLUDED.last_sequence)
    RETURNING last_sequence INTO NEW.account_seq;
    RETURN NEW;
END$$;
ALTER FUNCTION sbci_allocate_result_sequence() OWNER TO sbci_defs;
REVOKE ALL ON FUNCTION sbci_allocate_result_sequence() FROM PUBLIC;
CREATE TRIGGER sbci_results_allocate_sequence BEFORE INSERT ON analysis_results
FOR EACH ROW EXECUTE FUNCTION sbci_allocate_result_sequence();

-- A caller-owned pg_temp table may carry a SECURITY INVOKER trigger that
-- executes as sbci_defs. Use a private PL/pgSQL value, never IF NOT EXISTS
-- scratch relations, while retaining child-before-parent deletion semantics.
CREATE OR REPLACE FUNCTION sbci_sweep_results_retention(p_now timestamptz)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    v_count bigint := 0;
    v_due uuid[];
BEGIN

    -- Resolve each LIVE (status='active') account's CURRENT plan's
    -- results_retention_days (30 when the account has no assignment at all —
    -- absence-means-free, mirroring resolvePlanTx) and select every result
    -- older than that window.
    SELECT array_agg(r.id) INTO v_due
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
    DELETE FROM public.result_revisions WHERE result_id = ANY(v_due);
    DELETE FROM public.analysis_results WHERE id = ANY(v_due);
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


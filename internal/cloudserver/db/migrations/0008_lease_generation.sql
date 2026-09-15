-- 0008_lease_generation.sql — durable per-lease generation (Sol re-review
-- 2026-08-31, FA8 close). The FA8 completion CAS in CompleteJobWithResult
-- required (state='running', lease_worker, lease_expires_at > now, consent
-- generation, account active). Sol's residual: let a lease EXPIRE and re-lease
-- the SAME job to another process using the SAME default worker id
-- ("sbci-worker"); the stale first attempt's completion then matches state,
-- lease_worker, AND the fresh (re-lease) expiry, so its stale result wins and
-- the UNIQUE(account_id, job_id) backstop only stops the SECOND (legitimate)
-- write — the wrong result is already stored.
--
-- The fix is a durable, monotonically increasing lease_generation on the job:
-- every lease (fresh OR expiry-reclaim) increments it, sbci_lease_next_job
-- returns it, the worker carries it, and the completion CAS requires it to be
-- unchanged. A re-lease bumps the generation, so a stale attempt's completion
-- CAS affects zero rows regardless of worker id or refreshed expiry.

ALTER TABLE analysis_jobs
    ADD COLUMN IF NOT EXISTS lease_generation bigint NOT NULL DEFAULT 0;

-- The return type grows by one column, so CREATE OR REPLACE cannot be used
-- (Postgres refuses a return-type change) — DROP then CREATE, and re-apply the
-- owner + the 0004 grants (DROP removes them).
DROP FUNCTION IF EXISTS sbci_lease_next_job(text, timestamptz, text[], int);

CREATE FUNCTION sbci_lease_next_job(
    p_worker        text,
    p_now           timestamptz,
    p_classes       text[],
    p_lease_seconds int
)
RETURNS TABLE (
    job_id             uuid,
    account_id         uuid,
    evidence_pk        uuid,
    feature            text,
    route_id           text,
    route_version      bigint,
    prompt_version     bigint,
    consent_generation bigint,
    consent_receipt_id uuid,
    reservation_id     uuid,
    attempts           int,
    lease_generation   bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_id uuid;
BEGIN
    SELECT j.id INTO v_id
      FROM analysis_jobs j
     WHERE j.feature = ANY (p_classes)
       AND (
             (j.state = 'queued' AND j.available_at <= p_now)
             OR (j.state IN ('leased', 'running') AND j.lease_expires_at < p_now)
           )
     ORDER BY j.available_at, j.created_at
     FOR UPDATE SKIP LOCKED
     LIMIT 1;

    IF v_id IS NULL THEN
        RETURN;
    END IF;

    RETURN QUERY
    UPDATE analysis_jobs j
       SET state             = 'leased',
           lease_worker      = p_worker,
           lease_acquired_at = p_now,
           lease_expires_at  = p_now + make_interval(secs => p_lease_seconds),
           lease_generation  = j.lease_generation + 1,
           attempts          = j.attempts + 1,
           updated_at        = p_now
     WHERE j.id = v_id
    RETURNING j.id, j.account_id, j.evidence_pk, j.feature, j.route_id,
              j.route_version, j.prompt_version, j.consent_generation,
              j.consent_receipt_id, j.reservation_id, j.attempts, j.lease_generation;
END$$;

ALTER FUNCTION sbci_lease_next_job(text, timestamptz, text[], int) OWNER TO sbci_defs;
REVOKE ALL ON FUNCTION sbci_lease_next_job(text, timestamptz, text[], int) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_lease_next_job(text, timestamptz, text[], int) TO sbci_app;

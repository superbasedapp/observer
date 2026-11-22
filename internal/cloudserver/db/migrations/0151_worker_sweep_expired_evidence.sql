-- 0151_worker_sweep_expired_evidence.sql - harden the expired-evidence sweep,
-- then let the worker run it (findings 2026-11-22 CLOUD-01; docs/security.md
-- CLOUD-SWEEP-1).
--
-- step: contract
--
-- Contract because it replaces a function 0005 created and the running
-- release uses (same signature, same result, same grants plus one). The body
-- deletes exactly what 0005's did; only how it names its tables changes.
--
-- Why the worker needs it. The worker process (`observer-cloud worker`,
-- store.RoleWorker) now runs store.SweepExpiredEvidence on a ticker
-- (jobs.StartEvidenceSweeper), so an evidence object is deleted at its
-- immutable expires_at even when its job never reaches a terminal state: no
-- worker leasing, a revalidation error that keeps re-leasing the job, a
-- feature no worker leases, a backlog longer than the TTL. Until now nothing
-- called the sweep, and 0005 granted EXECUTE to sbci_app only, so the
-- worker's `SET LOCAL ROLE sbci_worker` met "permission denied for function"
-- (store.TestRoleSplitWorkerCanSweepExpiredEvidence).
--
-- Why the hardening comes first. 0005 wrote the body with unqualified
-- relation names under `SET search_path = public`, the shape 0027 fixed for
-- sbci_sweep_retention (Sol F1) and 0037/0038 avoided for the results sweep.
-- The application roles hold the default TEMP privilege, and pg_temp is
-- searched before public for relations unless the search_path names it, so a
-- caller's own `CREATE TEMP TABLE evidence_objects (...)` (granted to PUBLIC
-- by its owner) shadowed the real table for the whole SECURITY DEFINER body:
-- the caller chose which tenant's live evidence blobs the BYPASSRLS definer
-- deleted, and a trigger on the shadow would run as sbci_defs. sbci_app could
-- already do this; granting the unhardened function would have handed it to
-- the least-privilege worker too (db.TestSweepExpiredEvidenceIgnoresTempTableShadow
-- reproduced it as sbci_worker). Fix, as in 0027: schema-qualify both tables
-- as public.* and pin `search_path = pg_catalog, public, pg_temp`.
--
-- What the worker gains: EXECUTE on this one function. No table privilege
-- (it already held DELETE on evidence_blobs and UPDATE on evidence_objects for
-- its own lease path, 0015). sbci_defs already holds the table grants (0005).
-- PUBLIC stays revoked (0005, 0082), and sbci_api gets nothing: the sweep is
-- a worker-plane job, so the front door's rights do not widen.

SET LOCAL lock_timeout = '5s';

CREATE OR REPLACE FUNCTION sbci_sweep_expired_evidence(p_now timestamptz)
RETURNS int
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    v_deleted int;
BEGIN
    DELETE FROM public.evidence_blobs b
     USING public.evidence_objects o
     WHERE b.account_id = o.account_id
       AND b.blob_ref   = o.blob_ref
       AND o.expires_at <= p_now;
    GET DIAGNOSTICS v_deleted = ROW_COUNT;

    UPDATE public.evidence_objects
       SET deleted_at = p_now
     WHERE expires_at <= p_now
       AND deleted_at IS NULL;

    RETURN v_deleted;
END$$;

ALTER FUNCTION sbci_sweep_expired_evidence(timestamptz) OWNER TO sbci_defs;
REVOKE ALL ON FUNCTION sbci_sweep_expired_evidence(timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_sweep_expired_evidence(timestamptz) TO sbci_app, sbci_worker;

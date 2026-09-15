-- 0003_functions.sql — the SECURITY DEFINER cross-tenant primitives.
--
-- These are the ONLY code paths that read across account boundaries. Each is
-- owned by sbci_defs (BYPASSRLS, NOLOGIN), runs with SET search_path = public
-- (so a caller cannot hijack name resolution), is REVOKEd from PUBLIC, and is
-- granted EXECUTE only to sbci_app (0004). sbci_app is never a member of
-- sbci_defs, so these functions are its only window past RLS.
--
--   sbci_lease_next_job  — the plan §6 CI-P3 named data-plane dequeue: leases
--                          exactly one due job (or one whose lease has
--                          expired) and returns its account scope, after which
--                          the worker opens an ordinary tenant transaction.
--   sbci_introspect_token / sbci_find_identity_link — the two auth-bootstrap
--                          lookups that are inherently pre-tenant (a bearer
--                          secret or an external identity is presented before
--                          any account is known).

-- PostgreSQL 16 revoked the default CREATE privilege on schema public from
-- PUBLIC, and on a managed server (e.g. Azure Flexible Server, PG16) the
-- connecting admin is not the owner of the public schema. Without CREATE on
-- public, the `ALTER FUNCTION ... OWNER TO sbci_defs` transfers below fail with
-- "permission denied for schema public" (a new owner must be able to create in
-- the object's schema). Grant it here — idempotent, before the first ownership
-- transfer — so the lineage applies cleanly on PG16. (Surfaced by the first
-- real staging apply, 2026-08-31; on pre-16 servers this grant is a harmless
-- no-op.)
GRANT CREATE ON SCHEMA public TO sbci_defs;

-- Lease one due job. FOR UPDATE SKIP LOCKED makes a two-worker race resolve to
-- exactly one winner; an expired lease (lease_expires_at < now) is reclaimable
-- so a crashed worker's job requeues. attempts increments per lease.
CREATE OR REPLACE FUNCTION sbci_lease_next_job(
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
    attempts           int
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
           attempts          = j.attempts + 1,
           updated_at        = p_now
     WHERE j.id = v_id
    RETURNING j.id, j.account_id, j.evidence_pk, j.feature, j.route_id,
              j.route_version, j.prompt_version, j.consent_generation,
              j.consent_receipt_id, j.reservation_id, j.attempts;
END$$;

ALTER FUNCTION sbci_lease_next_job(text, timestamptz, text[], int) OWNER TO sbci_defs;

-- Resolve a bearer token hash to its principal. Returns at most one row.
CREATE OR REPLACE FUNCTION sbci_introspect_token(p_token_hash text)
RETURNS TABLE (
    account_id        uuid,
    token_id          uuid,
    device_id         uuid,
    public_key        bytea,
    thumbprint        text,
    token_expires_at  timestamptz,
    token_revoked_at  timestamptz,
    device_revoked_at timestamptz,
    account_status    text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    RETURN QUERY
    SELECT t.account_id, t.id, t.device_id, d.public_key, d.thumbprint,
           t.expires_at, t.revoked_at, d.revoked_at, a.status
      FROM api_tokens t
      JOIN device_registrations d
        ON d.account_id = t.account_id AND d.id = t.device_id
      JOIN accounts a
        ON a.account_id = t.account_id
     WHERE t.token_hash = p_token_hash;
END$$;

ALTER FUNCTION sbci_introspect_token(text) OWNER TO sbci_defs;

-- Resolve an external (provider, subject) identity to an existing account.
CREATE OR REPLACE FUNCTION sbci_find_identity_link(p_provider text, p_subject text)
RETURNS TABLE (account_id uuid, link_id uuid)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    RETURN QUERY
    SELECT l.account_id, l.id
      FROM identity_links l
     WHERE l.provider = p_provider AND l.subject = p_subject;
END$$;

ALTER FUNCTION sbci_find_identity_link(text, text) OWNER TO sbci_defs;

-- 0152_definer_search_path_pg_temp.sql - no SECURITY DEFINER function may
-- resolve a name to the caller's temporary schema (docs/security.md
-- CLOUD-DEFINER-TEMP-2; lane cloud-sweeper NEW-CS-01; review FR-SEC-5(b)).
--
-- step: contract
--
-- Contract because it replaces seven functions earlier steps created and
-- changes the configuration of thirty-nine more, all of which the running
-- release calls. Every body behaves exactly as before; only how names in it
-- resolve changes. No owner, grant or signature changes: CREATE OR REPLACE
-- keeps each function's OID, owner, ACL and comment, and the owner, REVOKE and
-- GRANT lines below restate today's catalog (db.TestDefinerFunctionExecuteGrants
-- pins every definer's owner and grantees).
--
-- The class. PostgreSQL searches the session's pg_temp schema FIRST for
-- relation and type names whenever a search_path does not list pg_temp
-- explicitly, and the temporary schema belongs to the session, not to the
-- role, so it stays in effect inside a SECURITY DEFINER body. Every
-- application role holds the default TEMP privilege. A caller could therefore
-- create a temp table named like a table (or a type) a definer uses and grant
-- it to PUBLIC: the BYPASSRLS owner sbci_defs then read and wrote the caller's
-- table, and a trigger on it (or a cast to its row type) ran the caller's own
-- code as sbci_defs. 0027 and 0151 fixed two sweeps; their headers took
-- `pg_catalog, public` to be safe, but without pg_temp last it is not.
--
-- Part 1: seven definers that named their tables unqualified. Each is
-- re-created with every relation written public.* and
-- `SET search_path = pg_catalog, public, pg_temp`, the 0027/0151 shape:
--   sbci_lease_next_job             0008  analysis_jobs              worker, app
--   sbci_sweep_expired_exports      0020  export_artifacts           api, app
--   sbci_sweep_expired_pop_replay   0007  pop_replay                 api, app
--   sbci_introspect_token           0003  api_tokens, device_registrations, accounts   api, app
--   sbci_find_identity_link         0003  identity_links             api, app
--   sbci_introspect_browser_session 0035  browser_sessions, accounts api, app
--   sbci_rate_limit_at              0017  sbci_rate_limit_counters   none; reached through
--                                                                    sbci_rate_limit (api, app, staff)
-- Live-verified before this step: a sbci_worker session's BEFORE UPDATE
-- trigger on a temp analysis_jobs ran as sbci_defs and read every tenant's
-- evidence_blobs; the two sweeps and the rate limiter fired the same trigger
-- as sbci_defs; the three lookups answered a caller-chosen token, identity or
-- browser-session hash with another tenant's account; a caller's empty temp
-- counters table admitted a key whose real window was exhausted
-- (db.TestDefinersIgnoreCallerTempTableShadows).
--
-- Part 2: thirty-nine definers that already wrote every relation public.*
-- but kept `search_path = pg_catalog, public`. Their type names were still
-- shadowable: a caller's temp table named `date` became the `date` type inside
-- sbci_expire_org_usage_days, and a cast the caller defined to that row type
-- ran as sbci_defs (db.TestDefinerTypeNamesIgnoreCallerTempShadows). Their
-- bodies are left as they are; ALTER FUNCTION ... SET puts pg_temp last, so
-- pg_catalog and public win for relations and types, and pg_temp is never
-- searched for functions or operators at all.
--
-- Six definers already end in pg_temp and are not touched:
-- sbci_current_account (pg_catalog, pg_temp; 0067), sbci_sweep_retention
-- (0027), sbci_project_digest_candidates (0037), sbci_sweep_results_retention
-- and sbci_allocate_result_sequence (0038), sbci_sweep_expired_evidence (0151).
-- The catalog ratchet db.TestEveryDefinerSearchPathEndsInPgTemp now holds for
-- all 52 definers (7 + 39 + 6), with an empty allow-list.

SET LOCAL lock_timeout = '5s';

-- ===========================================================================
-- Part 1: re-created with public.* names.
-- ===========================================================================

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
    attempts           int,
    lease_generation   bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    v_id uuid;
BEGIN
    SELECT j.id INTO v_id
      FROM public.analysis_jobs j
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
    UPDATE public.analysis_jobs j
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
GRANT EXECUTE ON FUNCTION sbci_lease_next_job(text, timestamptz, text[], int) TO sbci_app, sbci_worker;

CREATE OR REPLACE FUNCTION sbci_sweep_expired_exports(p_now timestamptz)
RETURNS int
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    v_deleted int;
BEGIN
    DELETE FROM public.export_artifacts WHERE expires_at <= p_now;
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    RETURN v_deleted;
END$$;

ALTER FUNCTION sbci_sweep_expired_exports(timestamptz) OWNER TO sbci_defs;
REVOKE ALL ON FUNCTION sbci_sweep_expired_exports(timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_sweep_expired_exports(timestamptz) TO sbci_api, sbci_app;

CREATE OR REPLACE FUNCTION sbci_sweep_expired_pop_replay(p_now timestamptz)
RETURNS int
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    v_deleted int;
BEGIN
    DELETE FROM public.pop_replay WHERE expires_at < p_now;
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    RETURN v_deleted;
END$$;

ALTER FUNCTION sbci_sweep_expired_pop_replay(timestamptz) OWNER TO sbci_defs;
REVOKE ALL ON FUNCTION sbci_sweep_expired_pop_replay(timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_sweep_expired_pop_replay(timestamptz) TO sbci_api, sbci_app;

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
SET search_path = pg_catalog, public, pg_temp
AS $$
BEGIN
    RETURN QUERY
    SELECT t.account_id, t.id, t.device_id, d.public_key, d.thumbprint,
           t.expires_at, t.revoked_at, d.revoked_at, a.status
      FROM public.api_tokens t
      JOIN public.device_registrations d
        ON d.account_id = t.account_id AND d.id = t.device_id
      JOIN public.accounts a
        ON a.account_id = t.account_id
     WHERE t.token_hash = p_token_hash;
END$$;

ALTER FUNCTION sbci_introspect_token(text) OWNER TO sbci_defs;
REVOKE ALL ON FUNCTION sbci_introspect_token(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_introspect_token(text) TO sbci_api, sbci_app;

-- Resolve an external (provider, subject) identity to an existing account.
CREATE OR REPLACE FUNCTION sbci_find_identity_link(p_provider text, p_subject text)
RETURNS TABLE (account_id uuid, link_id uuid)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
BEGIN
    RETURN QUERY
    SELECT l.account_id, l.id
      FROM public.identity_links l
     WHERE l.provider = p_provider AND l.subject = p_subject;
END$$;

ALTER FUNCTION sbci_find_identity_link(text, text) OWNER TO sbci_defs;
REVOKE ALL ON FUNCTION sbci_find_identity_link(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_find_identity_link(text, text) TO sbci_api, sbci_app;

CREATE OR REPLACE FUNCTION sbci_introspect_browser_session(p_session_hash text)
RETURNS TABLE (
    account_id      uuid,
    session_id      uuid,
    csrf_hash       text,
    expires_at      timestamptz,
    revoked_at      timestamptz,
    account_status  text,
    idle_expires_at timestamptz,
    last_seen_at    timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
BEGIN
    RETURN QUERY
    SELECT b.account_id, b.id, b.csrf_hash, b.expires_at, b.revoked_at, a.status,
           b.idle_expires_at, b.last_seen_at
      FROM public.browser_sessions b
      JOIN public.accounts a ON a.account_id = b.account_id
     WHERE b.session_hash = p_session_hash;
END$$;

ALTER FUNCTION sbci_introspect_browser_session(text) OWNER TO sbci_defs;
REVOKE ALL ON FUNCTION sbci_introspect_browser_session(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_introspect_browser_session(text) TO sbci_api, sbci_app;

-- The W6e counter (0017), body unchanged but for public.sbci_rate_limit_counters.
-- See 0017 for the INVARIANT this body keeps: a "limit N" window admits
-- EXACTLY N requests.
CREATE OR REPLACE FUNCTION sbci_rate_limit_at(
    p_bucket          text,
    p_counter_key_hash text,
    p_limit           integer,
    p_window_ms       bigint,
    p_now             timestamptz
)
RETURNS TABLE (
    allowed        boolean,
    retry_after_ms bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    v_now          timestamptz;
    v_window       interval;
    v_window_start timestamptz;
    v_count        bigint;
    v_over_cap     boolean;
    v_retry_ms     bigint;
BEGIN
    -- A disabled dimension must be a no-op.  Do this before validating the
    -- key/window so Store.AllowRateLimit can disable a dimension without a
    -- database round trip at all.
    IF p_limit <= 0 THEN
        allowed := true;
        retry_after_ms := 0;
        RETURN NEXT;
        RETURN;
    END IF;

    IF p_bucket IS NULL OR btrim(p_bucket) = ''
       OR octet_length(p_bucket) > 64 THEN
        RAISE EXCEPTION 'rate-limit bucket must be 1..64 bytes'
            USING ERRCODE = '22023';
    END IF;
    IF p_counter_key_hash IS NULL
       OR p_counter_key_hash !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'rate-limit key hash must be 64 lowercase hexadecimal bytes'
            USING ERRCODE = '22023';
    END IF;
    IF p_window_ms IS NULL OR p_window_ms <= 0 THEN
        RAISE EXCEPTION 'rate-limit window must be positive milliseconds'
            USING ERRCODE = '22023';
    END IF;

    v_now := coalesce(p_now, clock_timestamp());
    -- Millisecond precision is the wire contract.  floor() is intentional:
    -- at exactly a window boundary the request is in the following window.
    v_window_start := to_timestamp((
        floor(extract(epoch FROM v_now) * 1000.0 / p_window_ms)
        * p_window_ms / 1000.0
    )::double precision);
    v_window := make_interval(secs => p_window_ms::double precision / 1000.0);

    -- Keep one current row per key in normal monotonic operation.  The
    -- retention predicate is scoped to this key so concurrent requests for
    -- unrelated keys never contend on old rows.
    DELETE FROM public.sbci_rate_limit_counters
     WHERE bucket = p_bucket
       AND counter_key_hash = p_counter_key_hash
       AND window_start < v_window_start;

    -- An abandoned key must not remain forever merely because it never gets
    -- another request.  A bounded SKIP LOCKED batch keeps this maintenance
    -- cheap on the hot path while ensuring active traffic eventually cleans
    -- old rows for every key.  Retention is at least one whole window, so an
    -- active counter cannot be removed before its window closes.
    WITH expired AS (
        SELECT ctid
          FROM public.sbci_rate_limit_counters
         WHERE expires_at <= v_now
         ORDER BY expires_at
         LIMIT 100
         FOR UPDATE SKIP LOCKED
    )
    DELETE FROM public.sbci_rate_limit_counters c
     USING expired
     WHERE c.ctid = expired.ctid;

    -- Seed the row, then lock it explicitly.  INSERT ... ON CONFLICT DO
    -- NOTHING handles the first concurrent writer; the SELECT FOR UPDATE is
    -- the single serialized admission point for both existing and newly
    -- inserted rows.
    -- Seed a fresh row at hit_count=0.  The admission branch below then applies
    -- ONE uniform increment (0->1 for this fresh row, n->n+1 for an existing
    -- one), so a "limit N" window admits exactly N requests.  Seeding at 1 would
    -- double-count the first request (it would also be incremented), making the
    -- window one request too strict.
    INSERT INTO public.sbci_rate_limit_counters
        (bucket, counter_key_hash, window_start, hit_count, over_cap,
         expires_at, updated_at)
    VALUES (p_bucket, p_counter_key_hash, v_window_start, 0, false,
            v_window_start + v_window + interval '1 hour', v_now)
    ON CONFLICT (bucket, counter_key_hash, window_start) DO NOTHING;

    SELECT c.hit_count, c.over_cap
      INTO v_count, v_over_cap
      FROM public.sbci_rate_limit_counters AS c
     WHERE c.bucket = p_bucket
       AND c.counter_key_hash = p_counter_key_hash
       AND c.window_start = v_window_start
     FOR UPDATE;

    -- The marker stores one count above the policy that produced the first
    -- denial and sets over_cap=true.  If the operator raises the limit to at
    -- least that marker, first restore the admitted-hit count (marker - 1),
    -- then process this request normally.  This means a raise from L to M
    -- admits exactly M-L new requests, including the request that first
    -- observes the raised policy.  Without the separate boolean, the marker
    -- would be indistinguishable from an ordinary admitted hit at the new
    -- limit and would consume one slot after every policy raise.
    IF v_over_cap THEN
        IF p_limit < v_count THEN
            allowed := false;
        ELSE
            v_count := v_count - 1;
            v_over_cap := false;
        END IF;
    END IF;

    IF v_over_cap THEN
        -- The current policy is still at or below the retained marker.
        NULL;
    ELSIF v_count < p_limit THEN
        v_count := v_count + 1;
        allowed := true;
    ELSIF v_count = p_limit THEN
        -- Retain exactly one marker for the first denied request.  Subsequent
        -- denials leave it unchanged, so a hostile burst cannot grow rows.
        v_count := v_count + 1;
        v_over_cap := true;
        allowed := false;
    ELSE
        -- A policy decrease can leave an ordinary admitted count above the new
        -- cap.  Collapse it to the new cap's marker and deny this request.
        v_count := p_limit + 1;
        v_over_cap := true;
        allowed := false;
    END IF;

    UPDATE public.sbci_rate_limit_counters
       SET hit_count = v_count,
           over_cap = v_over_cap,
           expires_at = v_window_start + v_window + interval '1 hour',
           updated_at = v_now
     WHERE bucket = p_bucket
       AND counter_key_hash = p_counter_key_hash
       AND window_start = v_window_start;

    IF allowed THEN
        retry_after_ms := 0;
    ELSE
        v_retry_ms := ceil(extract(epoch FROM
            (v_window_start + v_window - v_now)) * 1000.0)::bigint;
        IF v_retry_ms < 1 THEN
            v_retry_ms := 1;
        END IF;
        retry_after_ms := v_retry_ms;
    END IF;
    RETURN NEXT;
END$$;

ALTER FUNCTION sbci_rate_limit_at(text, text, integer, bigint, timestamptz)
    OWNER TO sbci_defs;
REVOKE ALL ON FUNCTION sbci_rate_limit_at(text, text, integer, bigint, timestamptz)
    FROM PUBLIC, sbci_app, sbci_api, sbci_worker, sbci_aggregator;

-- ===========================================================================
-- Part 2: relations already public.*; pg_temp moves last. Bodies unchanged.
-- ===========================================================================

ALTER FUNCTION sbci_community_bands(text, text, integer, text)                SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION sbci_community_cohort_size(text, text, integer, text)          SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION sbci_community_windows()                                       SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION sbci_deletion_followup_check(uuid)                             SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION sbci_expire_org_usage_days(date)                               SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION sbci_is_org_member(uuid, text)                                 SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION sbci_oidc_note_sub_seen()                                      SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION sbci_org_create_owner_email_hint(uuid)                         SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION sbci_org_create_owner_email_verified(uuid)                     SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION sbci_org_create_owner_sub(uuid)                                SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION sbci_org_live_member_counts(uuid)                              SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION sbci_org_member_write_ok(uuid, uuid, text, boolean)            SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION sbci_org_slug_available(text)                                  SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION sbci_org_subscription(uuid)                                    SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION sbci_org_subscription_v2(uuid)                                 SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION sbci_paddle_account_for_subscription(text)                     SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION sbci_paddle_one_live_guard()                                   SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION sbci_portal_org_create_status(uuid)                            SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION sbci_portal_org_deletion_cancel(uuid)                          SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION sbci_portal_org_deletion_open(uuid, timestamptz)               SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION sbci_portal_org_deletion_status(uuid)                          SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION sbci_portal_org_departure_notices(uuid)                        SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION sbci_portal_org_last_seat_day(uuid)                            SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION sbci_portal_org_plan_grant(uuid)                               SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION sbci_portal_org_seats(uuid)                                    SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION sbci_portal_org_subscription(uuid)                             SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION sbci_portal_org_subscription_v2(uuid)                          SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION sbci_rate_limit(text, text, integer, bigint)                   SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION sbci_slug_org(text)                                            SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION sbci_staff_availability_doc()                                  SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION sbci_staff_org_deletion(uuid)                                  SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION sbci_staff_org_entitlements(uuid)                              SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION sbci_staff_org_intents(uuid)                                   SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION sbci_staff_org_plan_grants(uuid)                               SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION sbci_staff_org_usage(uuid, integer)                            SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION sbci_staff_orgs(uuid)                                          SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION sbci_support_target(uuid, uuid)                                SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION sbci_team_create_allowed()                                     SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION sbci_team_org_limit()                                          SET search_path = pg_catalog, public, pg_temp;

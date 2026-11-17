-- 0140_org_deletion_fixes.sql - the org deletion fixes of the 2026-11-17
-- review (docs/audits/fable-review-2026-11-17.md FR-11, FR-12, FR-23; lane
-- fix/fr-deletion).
--
-- step: contract
--
-- Contract label: the 0082 rule only (the three new definer functions REVOKE
-- PUBLIC's default EXECUTE). Every other statement adds: a column with a
-- STABLE default, a CREATE OR REPLACE of 0120's open function with its
-- signature, result and grants unchanged, and two grants.
--
-- WHAT.
--
--   org_deletion_requests.step_entered_at (FR-23). When the request reached
--     its current step; the driver sets it on every move and the operator's
--     resume restarts it. await_host's bounded wait (HostPurgeGrace) is
--     measured from it, so a host that never acks purged blocks the request
--     as host_purge_overdue instead of leaving it polling for ever. Existing
--     rows take the time of this step.
--
--   sbci_portal_org_deletion_open (0120, replaced; FR-11). Also refuses an org
--     of kind personal ('personal_org'): a personal org is deleted with its
--     account, never from the console (its purged tombstone would hold the
--     one-personal-org index for the account for ever). Everything else is
--     0120's body.
--
--   sbci_portal_org_last_seat_day(org) (new; FR-23). The newest usage day of
--     the org that reported a seat in use, for any member (NULL: none). The
--     cooling-off window read sbci_portal_org_seats, which answers the newest
--     day only, and filtered seats > 0 after it, so a zero-seat newest day
--     made an active free team look never used (14 days instead of 30).
--
--   sbci_org_live_member_counts(org) (new; FR-23). The org's owners and
--     members whose account is not closed or deleted, for any member (zeros
--     for anyone else). The account deletion precheck counted every
--     org_members row, including those of an account already deleted whose
--     membership the worker had not yet removed, so two owners deleting
--     their accounts one after the other could leave a team with no owner.
--     The precheck also takes a per-org transaction lock (store), so two at
--     once serialise.
--
--   sbci_deletion_followup_check(request) (new; FR-12). The worker's check of
--     an account follow-up row before it acts on it: the row's
--     (request_id, account_id) must be a finished account deletion in
--     deletion_requests, and its personal_org_id (when set) an org of kind
--     personal created by that account. It answers 'ok' or an enum word
--     (no_followup, no_account_deletion, personal_org_mismatch). EXECUTE
--     sbci_worker and sbci_app.
--
--   sbci_worker gains DELETE on org_sub_seen (FR-23): a purged org's (org,
--     subject) rows go with it at finalize, and a finished account
--     follow-up forgets its subjects' rows.

SET LOCAL lock_timeout = '5s';

-- ---------------------------------------------------------------------------
-- org_deletion_requests.step_entered_at
-- ---------------------------------------------------------------------------
ALTER TABLE org_deletion_requests ADD COLUMN step_entered_at timestamptz NOT NULL DEFAULT now();

-- ---------------------------------------------------------------------------
-- sbci_portal_org_deletion_open (0120), refusing a personal org
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION sbci_portal_org_deletion_open(p_org uuid, p_purge_after timestamptz)
RETURNS TABLE (outcome text, request_id uuid)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_me     uuid := public.sbci_current_account();
    v_status text;
    v_kind   text;
    v_id     uuid;
BEGIN
    IF v_me IS NULL OR NOT public.sbci_is_org_member(p_org, 'owner') THEN
        RETURN QUERY SELECT 'not_owner'::text, NULL::uuid;
        RETURN;
    END IF;
    SELECT o.status, o.kind INTO v_status, v_kind FROM public.orgs o WHERE o.org_id = p_org;
    -- FR-11: a personal org is deleted with its account, never from here.
    IF v_kind = 'personal' THEN
        RETURN QUERY SELECT 'personal_org'::text, NULL::uuid;
        RETURN;
    END IF;
    IF v_status IS NULL OR v_status NOT IN ('active', 'suspended') THEN
        RETURN QUERY SELECT 'org_not_deletable'::text, NULL::uuid;
        RETURN;
    END IF;
    -- The floor allows an hour of clock difference between the console's
    -- host and the database (the console computes exactly 14 days).
    IF p_purge_after IS NULL OR p_purge_after < now() + interval '14 days' - interval '1 hour' THEN
        RAISE EXCEPTION 'sbci_portal_org_deletion_open: the cooling-off window ends before the 14-day floor'
            USING ERRCODE = '22023';
    END IF;
    -- The one-open index decides a race between two opens: the loser
    -- inserts nothing and answers deletion_open.
    INSERT INTO public.org_deletion_requests (org_id, requested_by, state, origin, step, purge_after)
    VALUES (p_org, v_me, 'cooling_off', 'owner', 'announce', p_purge_after)
    ON CONFLICT (org_id) WHERE step <> 'done' DO NOTHING
    RETURNING org_deletion_requests.request_id INTO v_id;
    IF v_id IS NULL THEN
        RETURN QUERY SELECT 'deletion_open'::text, NULL::uuid;
        RETURN;
    END IF;
    RETURN QUERY SELECT 'created'::text, v_id;
END
$$;

-- ---------------------------------------------------------------------------
-- sbci_portal_org_last_seat_day
-- ---------------------------------------------------------------------------
CREATE FUNCTION sbci_portal_org_last_seat_day(p_org uuid)
RETURNS date
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT max(u.day)
      FROM public.org_usage_days u
     WHERE u.org_id = p_org
       AND coalesce(u.seat_count, cardinality(u.seat_member_ids)) > 0
       AND public.sbci_is_org_member(p_org, 'member')
$$;

ALTER FUNCTION sbci_portal_org_last_seat_day(uuid) OWNER TO sbci_defs;
REVOKE ALL ON FUNCTION sbci_portal_org_last_seat_day(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_portal_org_last_seat_day(uuid) TO sbci_api, sbci_app;

-- ---------------------------------------------------------------------------
-- sbci_org_live_member_counts
-- ---------------------------------------------------------------------------
CREATE FUNCTION sbci_org_live_member_counts(p_org uuid)
RETURNS TABLE (owners bigint, members bigint)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT count(*) FILTER (WHERE m.console_role = 'owner'), count(*)
      FROM public.org_members m
      JOIN public.accounts a ON a.account_id = m.account_id
     WHERE m.org_id = p_org
       AND a.status NOT IN ('closed', 'deleted')
       AND public.sbci_is_org_member(p_org, 'member')
$$;

ALTER FUNCTION sbci_org_live_member_counts(uuid) OWNER TO sbci_defs;
REVOKE ALL ON FUNCTION sbci_org_live_member_counts(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_org_live_member_counts(uuid) TO sbci_api, sbci_app;

-- ---------------------------------------------------------------------------
-- sbci_deletion_followup_check
-- ---------------------------------------------------------------------------
GRANT SELECT (request_id, account_id, personal_org_id) ON account_deletion_followups TO sbci_defs;

CREATE FUNCTION sbci_deletion_followup_check(p_request uuid)
RETURNS text
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_account  uuid;
    v_personal uuid;
BEGIN
    SELECT f.account_id, f.personal_org_id INTO v_account, v_personal
      FROM public.account_deletion_followups f
     WHERE f.request_id = p_request;
    IF v_account IS NULL THEN
        RETURN 'no_followup';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.deletion_requests d
         WHERE d.id = p_request AND d.account_id = v_account
           AND d.scope = 'account' AND d.state = 'done'
    ) THEN
        RETURN 'no_account_deletion';
    END IF;
    IF v_personal IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM public.orgs o
         WHERE o.org_id = v_personal AND o.kind = 'personal' AND o.created_by = v_account
    ) THEN
        RETURN 'personal_org_mismatch';
    END IF;
    RETURN 'ok';
END
$$;

ALTER FUNCTION sbci_deletion_followup_check(uuid) OWNER TO sbci_defs;
REVOKE ALL ON FUNCTION sbci_deletion_followup_check(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_deletion_followup_check(uuid) TO sbci_worker, sbci_app;

-- ---------------------------------------------------------------------------
-- org_sub_seen: the worker forgets a purged org's and a deleted account's rows
-- ---------------------------------------------------------------------------
GRANT DELETE ON org_sub_seen TO sbci_worker;

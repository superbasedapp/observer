-- 0120_org_account_deletion.sql - org deletion and account deletion with
-- orgs (managed-SaaS plan 07 M6.9 and M7a.1; plan 06 5.3.10 and 5.4; design
-- docs/plans/managed-saas/m6.0-control-plane-design-2026-11-13.md 3.4 and
-- 4.10; lane w17/deletion-purge).
--
-- step: contract
--
-- Contract label: org_deletion_requests is dropped and created again in its
-- working shape (migcheck's drop-table rule), and the new definer functions
-- REVOKE PUBLIC's default EXECUTE (the 0082 / 0091 rule). No released code
-- writes or reads org_deletion_requests (M6.1a created it for this work
-- package; it holds no row on any deployment), so the running release loses
-- nothing.
--
-- WHAT.
--
--   org_deletion_requests (replaced, class S). One row per org deletion. The
--     state is the user-facing word (cooling_off, canceled, purging, done,
--     blocked); step is the control-plane driver's position in the step table
--     (internal/cloudserver/orgdeletion, Go owns the vocabulary). A request
--     is OPEN while step <> 'done' (a canceled request stays open until the
--     driver restored the org), and an org has at most one open request.
--     origin says who asked: the owner from the console, an account deletion
--     (the account's personal org) or staff. purge_after is the end of the
--     cooling-off window (plan 06 5.3.10: 30 days, 14 for an inactive free
--     org, none for a personal org deleted with its account); purge_gen is the
--     lifecycle generation of the transition to purging. attempts,
--     next_attempt_at and last_error_class are the driver's retry state,
--     enum-like words only.
--
--   account_deletion_followups (new, class S). The org-side half of an
--     account deletion (design 4.10 steps 2-5) that cannot run in the
--     account deletion's own transaction: delete the personal org, remove the
--     account's team memberships, deactivate its WorkOS subject in every org
--     the issuer saw it sign in to (host-API members_deactivate, durably
--     retried by the outbox), leave a notice for the admins of those orgs, and
--     delete the WorkOS user. Written by the account deletion transaction
--     (store.deletionCompleteTx, so a journal replay after a restore writes it
--     again), driven by the worker. subs is emptied when the row is done
--     (data minimisation: the subject is needed only to finish).
--
--   org_member_departure_notices (new, class S). One row per (account
--     deletion, team org the subject was seen in): the console shows the
--     org's admins that a member deleted their SuperBased account and that
--     their own identity provider may still list them (design 4.10 step 4).
--     No name, email or subject: the admins already hold the person in their
--     IdP; the notice carries the org and the time only.
--
-- GRANTS (no role gains anything beyond what its path needs).
--
--   sbci_worker (the deletion driver, store.WithSystem): reads and drives
--     both work tables, writes the notices, reads org_sub_seen, removes
--     memberships (org_members DELETE, reached through 0121's worker policies),
--     disables an org's OIDC client and deletes its unused codes.
--   sbci_api (the console): INSERT only on account_deletion_followups (the
--     account deletion transaction writes it; it never reads the queue). It
--     reaches org_deletion_requests and the notices only through the definer
--     functions below.
--   sbci_staff (the staff console): SELECT on the two work tables, every
--     column but the subjects, for the staff status route.
--   sbci_app (operator paths, the dev/test single role): full access.
--
-- DEFINER FUNCTIONS (owner sbci_defs, search_path pinned, PUBLIC revoked;
-- each answers for ONE org and checks the caller first, the 0091 pattern):
--
--   sbci_portal_org_deletion_open(org, purge_after)    an OWNER opens a
--     cooling-off request; the outcome is a word (created, not_owner,
--     deletion_open, org_not_deletable). The window may not end sooner than
--     14 days from now (less an hour of clock skew): the console computes the
--     window (30 or 14 days), and this floor keeps a console defect from
--     shortening it.
--   sbci_portal_org_deletion_cancel(org)               an OWNER cancels while
--     cooling off (canceled, not_owner, not_cancellable, none).
--   sbci_portal_org_deletion_status(org)               any MEMBER reads the
--     org's newest request.
--   sbci_portal_org_departure_notices(org)             an ADMIN reads the
--     org's notices of the last 90 days.

SET LOCAL lock_timeout = '5s';

-- ---------------------------------------------------------------------------
-- org_deletion_requests (replaced)
-- ---------------------------------------------------------------------------
-- M6.1a's provisional shape is dropped and the table created again in the
-- shape the behaviour needs: nothing ever wrote a row (see the header), and a
-- fresh table takes its constraints and indexes at once where an ALTER of the
-- existing one would need NOT VALID constraints and concurrent index builds
-- across several steps for an empty table.
DROP TABLE org_deletion_requests;

CREATE TABLE org_deletion_requests (
    request_id         uuid        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id             uuid        NOT NULL REFERENCES orgs (org_id),
    -- The account that asked; opaque, no foreign key (an audit fact that must
    -- not block the account retention sweep).
    requested_by       uuid        NOT NULL,
    state              text        NOT NULL DEFAULT 'cooling_off'
        CHECK (state IN ('cooling_off', 'canceled', 'purging', 'done', 'blocked')),
    blocked_reason     text        CHECK (blocked_reason IS NULL OR blocked_reason ~ '^[a-z0-9_:.-]{1,80}$'),
    origin             text        NOT NULL DEFAULT 'owner'
        CHECK (origin IN ('owner', 'account_deletion', 'staff')),
    step               text        NOT NULL DEFAULT 'announce' CHECK (step ~ '^[a-z_]{1,40}$'),
    purge_after        timestamptz NOT NULL DEFAULT now(),
    announced_at       timestamptz,
    canceled_at        timestamptz,
    -- The account that canceled; opaque, no foreign key (requested_by's rule).
    canceled_by        uuid,
    purge_gen          bigint      CHECK (purge_gen IS NULL OR purge_gen > 0),
    attempts           integer     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at    timestamptz NOT NULL DEFAULT now(),
    last_error_class   text        CHECK (last_error_class IS NULL OR last_error_class ~ '^[a-z0-9_:.-]{1,80}$'),
    -- The account deletion that asked (deletion_requests.id); opaque.
    account_request_id uuid,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    done_at            timestamptz,
    CONSTRAINT org_deletion_requests_blocked_has_reason CHECK (state <> 'blocked' OR blocked_reason IS NOT NULL),
    CONSTRAINT org_deletion_requests_done_has_time CHECK ((state = 'done') = (done_at IS NOT NULL)),
    -- A finished request is done or canceled; a canceled one finishes once
    -- the driver restored the org (step restore, then done).
    CONSTRAINT org_deletion_requests_finished CHECK (step <> 'done' OR state IN ('done', 'canceled'))
);

-- One open request per org: open until the driver's step is done.
CREATE UNIQUE INDEX org_deletion_requests_one_open ON org_deletion_requests (org_id) WHERE step <> 'done';
-- The driver's queue scan.
CREATE INDEX org_deletion_requests_due ON org_deletion_requests (next_attempt_at) WHERE step <> 'done';

COMMENT ON TABLE org_deletion_requests IS
    'M6.9/M7a.1 org deletion work queue (class S): state is the user word, step the driver position; open while step <> done.';

-- ---------------------------------------------------------------------------
-- account_deletion_followups (class S)
-- ---------------------------------------------------------------------------
CREATE TABLE account_deletion_followups (
    -- deletion_requests.id of the account deletion; opaque, no foreign key.
    request_id       uuid        NOT NULL PRIMARY KEY,
    -- Opaque, no foreign key: the account row is a tombstone swept at 24
    -- months, and this audit fact must not block that sweep.
    account_id       uuid        NOT NULL,
    -- The account's WorkOS subjects (identity_links), captured before the
    -- account deletion purged them; emptied when the row is done.
    subs             text[]      NOT NULL DEFAULT '{}',
    -- The account's personal org, when it had one (captured in the same
    -- transaction; the worker cannot read orgs.created_by).
    personal_org_id  uuid,
    step             text        NOT NULL DEFAULT 'personal_org' CHECK (step ~ '^[a-z_]{1,40}$'),
    state            text        NOT NULL DEFAULT 'running' CHECK (state IN ('running', 'blocked', 'done')),
    blocked_reason   text        CHECK (blocked_reason IS NULL OR blocked_reason ~ '^[a-z0-9_:.-]{1,80}$'),
    attempts         integer     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at  timestamptz NOT NULL DEFAULT now(),
    last_error_class text        CHECK (last_error_class IS NULL OR last_error_class ~ '^[a-z0-9_:.-]{1,80}$'),
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    done_at          timestamptz,
    CONSTRAINT account_deletion_followups_blocked_has_reason CHECK (state <> 'blocked' OR blocked_reason IS NOT NULL),
    CONSTRAINT account_deletion_followups_done_has_time CHECK ((state = 'done') = (done_at IS NOT NULL)),
    CONSTRAINT account_deletion_followups_done_forgets_subs CHECK (state <> 'done' OR cardinality(subs) = 0)
);

CREATE INDEX account_deletion_followups_due ON account_deletion_followups (next_attempt_at) WHERE state <> 'done';

COMMENT ON TABLE account_deletion_followups IS
    'M6.9 the org-side steps of an account deletion (class S): personal org, memberships, sub deactivation, notices, WorkOS user.';

-- ---------------------------------------------------------------------------
-- org_member_departure_notices (class S)
-- ---------------------------------------------------------------------------
CREATE TABLE org_member_departure_notices (
    request_id uuid        NOT NULL,
    org_id     uuid        NOT NULL REFERENCES orgs (org_id),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (request_id, org_id)
);

CREATE INDEX org_member_departure_notices_org ON org_member_departure_notices (org_id, created_at DESC);

COMMENT ON TABLE org_member_departure_notices IS
    'M6.9 a member of the org deleted their account; the admins'' IdP may still list them (class S, no personal data).';

-- ---------------------------------------------------------------------------
-- Grants.
-- ---------------------------------------------------------------------------
GRANT SELECT, INSERT, UPDATE ON org_deletion_requests        TO sbci_worker;
GRANT SELECT, UPDATE         ON account_deletion_followups   TO sbci_worker;
GRANT INSERT                 ON org_member_departure_notices TO sbci_worker;
GRANT SELECT                 ON org_sub_seen                 TO sbci_worker;
GRANT SELECT (org_id, account_id, console_role, is_billing_owner) ON org_members TO sbci_worker;
GRANT DELETE                 ON org_members                  TO sbci_worker;
GRANT SELECT (client_id, org_id, disabled_at) ON oidc_clients TO sbci_worker;
GRANT UPDATE (disabled_at, updated_at)        ON oidc_clients TO sbci_worker;
GRANT SELECT (client_id), DELETE              ON oidc_codes   TO sbci_worker;

GRANT INSERT ON account_deletion_followups TO sbci_api;

GRANT SELECT (request_id, org_id, state, step, origin, blocked_reason, created_at, updated_at, done_at,
              purge_after, announced_at, canceled_at, purge_gen, attempts, next_attempt_at, last_error_class)
    ON org_deletion_requests TO sbci_staff;
GRANT SELECT (request_id, personal_org_id, step, state, blocked_reason, attempts, next_attempt_at,
              last_error_class, created_at, updated_at, done_at)
    ON account_deletion_followups TO sbci_staff;

GRANT SELECT, INSERT, UPDATE         ON org_deletion_requests        TO sbci_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON account_deletion_followups   TO sbci_app;
GRANT SELECT, INSERT, DELETE         ON org_member_departure_notices TO sbci_app;

GRANT SELECT, INSERT, UPDATE ON org_deletion_requests        TO sbci_defs;
GRANT SELECT                 ON org_member_departure_notices TO sbci_defs;

-- ---------------------------------------------------------------------------
-- sbci_portal_org_deletion_open
-- ---------------------------------------------------------------------------
CREATE FUNCTION sbci_portal_org_deletion_open(p_org uuid, p_purge_after timestamptz)
RETURNS TABLE (outcome text, request_id uuid)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_me     uuid := public.sbci_current_account();
    v_status text;
    v_id     uuid;
BEGIN
    IF v_me IS NULL OR NOT public.sbci_is_org_member(p_org, 'owner') THEN
        RETURN QUERY SELECT 'not_owner'::text, NULL::uuid;
        RETURN;
    END IF;
    SELECT o.status INTO v_status FROM public.orgs o WHERE o.org_id = p_org;
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

ALTER FUNCTION sbci_portal_org_deletion_open(uuid, timestamptz) OWNER TO sbci_defs;
REVOKE ALL ON FUNCTION sbci_portal_org_deletion_open(uuid, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_portal_org_deletion_open(uuid, timestamptz) TO sbci_api, sbci_app;

-- ---------------------------------------------------------------------------
-- sbci_portal_org_deletion_cancel
-- ---------------------------------------------------------------------------
CREATE FUNCTION sbci_portal_org_deletion_cancel(p_org uuid)
RETURNS text
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_me    uuid := public.sbci_current_account();
    v_id    uuid;
    v_state text;
BEGIN
    IF v_me IS NULL OR NOT public.sbci_is_org_member(p_org, 'owner') THEN
        RETURN 'not_owner';
    END IF;
    SELECT r.request_id, r.state INTO v_id, v_state
      FROM public.org_deletion_requests r
     WHERE r.org_id = p_org AND r.step <> 'done'
     FOR UPDATE;
    IF v_id IS NULL THEN
        RETURN 'none';
    END IF;
    IF v_state = 'canceled' THEN
        RETURN 'canceled';
    END IF;
    IF v_state <> 'cooling_off' THEN
        RETURN 'not_cancellable';
    END IF;
    UPDATE public.org_deletion_requests
       SET state = 'canceled', step = 'restore', canceled_at = now(), canceled_by = v_me,
           next_attempt_at = now(), attempts = 0, last_error_class = NULL, updated_at = now()
     WHERE request_id = v_id;
    RETURN 'canceled';
END
$$;

ALTER FUNCTION sbci_portal_org_deletion_cancel(uuid) OWNER TO sbci_defs;
REVOKE ALL ON FUNCTION sbci_portal_org_deletion_cancel(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_portal_org_deletion_cancel(uuid) TO sbci_api, sbci_app;

-- ---------------------------------------------------------------------------
-- sbci_portal_org_deletion_status
-- ---------------------------------------------------------------------------
CREATE FUNCTION sbci_portal_org_deletion_status(p_org uuid)
RETURNS TABLE (
    request_id     uuid,
    state          text,
    step           text,
    origin         text,
    created_at     timestamptz,
    purge_after    timestamptz,
    canceled_at    timestamptz,
    done_at        timestamptz,
    blocked_reason text
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT r.request_id, r.state, r.step, r.origin, r.created_at, r.purge_after,
           r.canceled_at, r.done_at, r.blocked_reason
      FROM public.org_deletion_requests r
     WHERE r.org_id = p_org
       AND public.sbci_is_org_member(p_org, 'member')
     ORDER BY (r.step <> 'done') DESC, r.created_at DESC
     LIMIT 1
$$;

ALTER FUNCTION sbci_portal_org_deletion_status(uuid) OWNER TO sbci_defs;
REVOKE ALL ON FUNCTION sbci_portal_org_deletion_status(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_portal_org_deletion_status(uuid) TO sbci_api, sbci_app;

-- ---------------------------------------------------------------------------
-- sbci_portal_org_departure_notices
-- ---------------------------------------------------------------------------
CREATE FUNCTION sbci_portal_org_departure_notices(p_org uuid)
RETURNS TABLE (created_at timestamptz)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT n.created_at
      FROM public.org_member_departure_notices n
     WHERE n.org_id = p_org
       AND n.created_at > now() - interval '90 days'
       AND public.sbci_is_org_member(p_org, 'admin')
     ORDER BY n.created_at DESC
     LIMIT 50
$$;

ALTER FUNCTION sbci_portal_org_departure_notices(uuid) OWNER TO sbci_defs;
REVOKE ALL ON FUNCTION sbci_portal_org_departure_notices(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_portal_org_departure_notices(uuid) TO sbci_api, sbci_app;

-- 0133_staff_console_reads.sql - the staff console's reads of the org
-- registry (managed-SaaS plan 07 M6.8, the staff UI window; design
-- docs/plans/managed-saas/m6.0-control-plane-design-2026-11-13.md 4.9,
-- "GET /staff/api/orgs, GET /staff/api/orgs/{id}"; lane w17/staff-console).
--
-- step: contract
--
-- Contract label: the REVOKE of PUBLIC's default EXECUTE on the new definers
-- (migcheck's revoke rule, the 0082 / 0091 / 0095 pattern). Every function is
-- new in this step and the column grants only add, so no running release can
-- hold or lose a privilege; the label is the rule's, not a real contraction.
--
-- NUMBER. Written as 0110 on the lane; renumbered 0133 at the merge onto
-- saas/wave3 (2026-11-16) so it sits above every cloud step merged with it
-- (0097-0101, 0120-0121, 0130-0132): the cloud runner applies only steps
-- above the database's max(version).
--
-- WHY. The staff process connects as sbci_staff_svc and acts as sbci_staff,
-- which holds grants on the staff tables only (0068-0070, 0087): it cannot
-- read orgs, org_members or any billing or usage table, and must not be given
-- them. The design's org reads are therefore SECURITY DEFINER functions owned
-- by sbci_defs and executable by sbci_staff ALONE, each returning registry
-- and control-plane facts only:
--
--   sbci_staff_orgs(org)             registry fields of one org (or every org
--     when org is NULL, newest first, at most 2000): kind, slug, name,
--     status, tenancy, host id, lifecycle generation, the member COUNT (no
--     member id, account or email), the newest plan grant row, the most
--     relevant subscription's plan and status (no customer id, no
--     management link), the latest usage day's seat and member counts, and
--     the newest entitlements document's version and issue time.
--   sbci_staff_org_plan_grants(org)  the org's whole org_plan_grants history
--     with its actor and reason (the operator's `grant-plan org show`).
--   sbci_staff_org_usage(org, days)  the last `days` usage days (1..400):
--     seat count, members, sessions, machine identities. The member ids stay
--     in the table.
--   sbci_staff_org_entitlements(org) the newest signed entitlements document:
--     version, key id, issue time, issuer and the signed body bytes (the
--     document every host already holds; no secret).
--   sbci_staff_org_intents(org)      the org's newest 50 org_outbox intents:
--     verb, state, attempts, last error class and times. No payload and no
--     idempotency key.
--   sbci_staff_org_deletion(org)     the org's newest org_deletion_requests
--     row: state, blocked reason and times. No requesting account.
--   sbci_staff_availability_doc()    the newest signed availability envelope
--     (version, key id, issue time, issuer, body), so the console can show
--     what was issued next to the staff inputs it was composed from.
--
-- Every function is STABLE, sets its search_path, is owned by sbci_defs and is
-- executable by sbci_staff only (db_definer_grants_test.go pins it). None of
-- them writes: the staff console's writes stay the staff-table writes of 0069
-- (availability inputs and the action log). The columns sbci_defs did not yet
-- hold are granted below, column by column.

SET LOCAL lock_timeout = '5s';

GRANT SELECT (actor, reason, at) ON org_plan_grants TO sbci_defs;
GRANT SELECT (sessions, machine_identities) ON org_usage_days TO sbci_defs;
GRANT SELECT (org_id, version, key_id, issued_at, issued_by, body) ON org_entitlement_docs TO sbci_defs;
GRANT SELECT (version, key_id, issued_at, issued_by, body) ON availability_docs TO sbci_defs;
GRANT SELECT (org_id, state, blocked_reason, created_at, updated_at, done_at) ON org_deletion_requests TO sbci_defs;

-- ---------------------------------------------------------------------------
-- sbci_staff_orgs
-- ---------------------------------------------------------------------------
CREATE FUNCTION sbci_staff_orgs(p_org uuid)
RETURNS TABLE (
    org_id                uuid,
    kind                  text,
    slug                  text,
    display_name          text,
    status                text,
    tenancy               text,
    host_id               text,
    platform_rail_enabled boolean,
    lifecycle_gen         bigint,
    created_at            timestamptz,
    updated_at            timestamptz,
    members               bigint,
    grant_action          text,
    grant_plan            text,
    grant_version         int,
    grant_until           timestamptz,
    sub_status            text,
    sub_plan              text,
    sub_version           int,
    sub_period_end        timestamptz,
    usage_day             date,
    usage_seats           int,
    usage_members         bigint,
    entitlements_version  bigint,
    entitlements_issued   timestamptz
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT o.org_id, o.kind, o.slug, o.display_name, o.status, o.tenancy, o.host_id,
           o.platform_rail_enabled, o.lifecycle_gen, o.created_at, o.updated_at,
           (SELECT count(*) FROM public.org_members m WHERE m.org_id = o.org_id),
           g.action, g.plan_name, g.plan_version, g.effective_until,
           ps.status, ps.plan_name, ps.plan_version, ps.current_period_end,
           u.day, cardinality(u.seat_member_ids), u.members,
           d.version, d.issued_at
      FROM public.orgs o
      LEFT JOIN LATERAL (
            SELECT g.action, g.plan_name, g.plan_version, g.effective_until
              FROM public.org_plan_grants g
             WHERE g.org_id = o.org_id
             ORDER BY g.seq DESC
             LIMIT 1) g ON true
      LEFT JOIN LATERAL (
            SELECT ps.status, ps.plan_name, ps.plan_version, ps.current_period_end
              FROM public.paddle_subscriptions ps
             WHERE ps.org_id = o.org_id
             ORDER BY (ps.status IN ('active', 'trialing', 'past_due', 'paused')) DESC, ps.updated_at DESC
             LIMIT 1) ps ON true
      LEFT JOIN LATERAL (
            SELECT u.day, u.seat_member_ids, u.members
              FROM public.org_usage_days u
             WHERE u.org_id = o.org_id
             ORDER BY u.day DESC
             LIMIT 1) u ON true
      LEFT JOIN LATERAL (
            SELECT d.version, d.issued_at
              FROM public.org_entitlement_docs d
             WHERE d.org_id = o.org_id
             ORDER BY d.version DESC
             LIMIT 1) d ON true
     WHERE p_org IS NULL OR o.org_id = p_org
     ORDER BY o.created_at DESC, o.org_id
     LIMIT 2000
$$;

ALTER FUNCTION sbci_staff_orgs(uuid) OWNER TO sbci_defs;
REVOKE ALL ON FUNCTION sbci_staff_orgs(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_staff_orgs(uuid) TO sbci_staff;

-- ---------------------------------------------------------------------------
-- sbci_staff_org_plan_grants
-- ---------------------------------------------------------------------------
CREATE FUNCTION sbci_staff_org_plan_grants(p_org uuid)
RETURNS TABLE (
    seq             bigint,
    action          text,
    plan_name       text,
    plan_version    int,
    effective_until timestamptz,
    actor           text,
    reason          text,
    at              timestamptz
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT g.seq, g.action, g.plan_name, g.plan_version, g.effective_until, g.actor, g.reason, g.at
      FROM public.org_plan_grants g
     WHERE g.org_id = p_org
     ORDER BY g.seq DESC
     LIMIT 500
$$;

ALTER FUNCTION sbci_staff_org_plan_grants(uuid) OWNER TO sbci_defs;
REVOKE ALL ON FUNCTION sbci_staff_org_plan_grants(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_staff_org_plan_grants(uuid) TO sbci_staff;

-- ---------------------------------------------------------------------------
-- sbci_staff_org_usage
-- ---------------------------------------------------------------------------
CREATE FUNCTION sbci_staff_org_usage(p_org uuid, p_days int)
RETURNS TABLE (
    day                date,
    seats              int,
    members            bigint,
    sessions           bigint,
    machine_identities bigint
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT u.day, cardinality(u.seat_member_ids), u.members, u.sessions, u.machine_identities
      FROM public.org_usage_days u
     WHERE u.org_id = p_org
     ORDER BY u.day DESC
     LIMIT greatest(1, least(coalesce(p_days, 30), 400))
$$;

ALTER FUNCTION sbci_staff_org_usage(uuid, int) OWNER TO sbci_defs;
REVOKE ALL ON FUNCTION sbci_staff_org_usage(uuid, int) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_staff_org_usage(uuid, int) TO sbci_staff;

-- ---------------------------------------------------------------------------
-- sbci_staff_org_entitlements
-- ---------------------------------------------------------------------------
CREATE FUNCTION sbci_staff_org_entitlements(p_org uuid)
RETURNS TABLE (
    version   bigint,
    key_id    text,
    issued_at timestamptz,
    issued_by text,
    body      bytea
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT d.version, d.key_id, d.issued_at, d.issued_by, d.body
      FROM public.org_entitlement_docs d
     WHERE d.org_id = p_org
     ORDER BY d.version DESC
     LIMIT 1
$$;

ALTER FUNCTION sbci_staff_org_entitlements(uuid) OWNER TO sbci_defs;
REVOKE ALL ON FUNCTION sbci_staff_org_entitlements(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_staff_org_entitlements(uuid) TO sbci_staff;

-- ---------------------------------------------------------------------------
-- sbci_staff_org_intents
-- ---------------------------------------------------------------------------
CREATE FUNCTION sbci_staff_org_intents(p_org uuid)
RETURNS TABLE (
    verb             text,
    state            text,
    attempts         int,
    last_error_class text,
    next_attempt_at  timestamptz,
    created_at       timestamptz,
    done_at          timestamptz
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT o.verb, o.state, o.attempts, o.last_error_class, o.next_attempt_at, o.created_at, o.done_at
      FROM public.org_outbox o
     WHERE o.org_id = p_org
     ORDER BY o.created_at DESC, o.seq DESC NULLS LAST
     LIMIT 50
$$;

ALTER FUNCTION sbci_staff_org_intents(uuid) OWNER TO sbci_defs;
REVOKE ALL ON FUNCTION sbci_staff_org_intents(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_staff_org_intents(uuid) TO sbci_staff;

-- ---------------------------------------------------------------------------
-- sbci_staff_org_deletion
-- ---------------------------------------------------------------------------
CREATE FUNCTION sbci_staff_org_deletion(p_org uuid)
RETURNS TABLE (
    state          text,
    blocked_reason text,
    created_at     timestamptz,
    updated_at     timestamptz,
    done_at        timestamptz
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT r.state, r.blocked_reason, r.created_at, r.updated_at, r.done_at
      FROM public.org_deletion_requests r
     WHERE r.org_id = p_org
     ORDER BY r.created_at DESC
     LIMIT 1
$$;

ALTER FUNCTION sbci_staff_org_deletion(uuid) OWNER TO sbci_defs;
REVOKE ALL ON FUNCTION sbci_staff_org_deletion(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_staff_org_deletion(uuid) TO sbci_staff;

-- ---------------------------------------------------------------------------
-- sbci_staff_availability_doc
-- ---------------------------------------------------------------------------
CREATE FUNCTION sbci_staff_availability_doc()
RETURNS TABLE (
    version   bigint,
    key_id    text,
    issued_at timestamptz,
    issued_by text,
    body      bytea
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT d.version, d.key_id, d.issued_at, d.issued_by, d.body
      FROM public.availability_docs d
     ORDER BY d.version DESC
     LIMIT 1
$$;

ALTER FUNCTION sbci_staff_availability_doc() OWNER TO sbci_defs;
REVOKE ALL ON FUNCTION sbci_staff_availability_doc() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_staff_availability_doc() TO sbci_staff;

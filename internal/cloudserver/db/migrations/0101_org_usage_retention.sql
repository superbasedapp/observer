-- 0101_org_usage_retention.sql - the 10-year floor of org_usage_days and the
-- seat read over minimised days (managed-SaaS plan 07 wave 16 lane
-- plan-policy; lead decision W16-D9; L-124 C3.ENTL-usage-retention;
-- docs/security.md USAGE-1 to USAGE-3).
--
-- step: contract
--
-- Contract label: the REVOKE of PUBLIC's default EXECUTE on the new definer
-- function (migcheck's revoke rule, the 0082 / 0093 / 0096 pattern) and the
-- replacement of sbci_portal_org_seats (0091), which the running release
-- calls; its signature, result and grants are unchanged.
--
-- 1. VALIDATE the two checks 0100 added NOT VALID.
--
-- 2. sbci_portal_org_seats reads a minimised day's kept count:
--    coalesce(seat_count, cardinality(seat_member_ids)). A live day's
--    answer is what 0091 returned.
--
-- 3. sbci_expire_org_usage_days(before) deletes the days strictly before
--    `before` and returns how many. It is the ONLY delete path of the
--    table (no role holds DELETE on it), and it REFUSES a `before` later
--    than the day ten years before today: the 10-year retention L-124 set
--    is enforced here, in the database, whatever the worker's configuration
--    says (SBCI_USAGE_RETENTION_YEARS may only lengthen it). The org's
--    deletion never reaches these rows: the foreign key to orgs has no
--    cascade, so a delete of the org row is blocked while a day is kept.
--    Executable by sbci_worker (the retention pass) and sbci_app; PUBLIC
--    revoked (pinned by TestDefinerFunctionExecuteGrants).

SET LOCAL lock_timeout = '5s';

ALTER TABLE org_usage_days VALIDATE CONSTRAINT org_usage_days_seat_count_check;
ALTER TABLE org_usage_days VALIDATE CONSTRAINT org_usage_days_minimised_check;

-- ---------------------------------------------------------------------------
-- sbci_portal_org_seats (0091), reading a minimised day's count
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION sbci_portal_org_seats(p_org uuid)
RETURNS TABLE (
    day     date,
    seats   int,
    members bigint
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT u.day, coalesce(u.seat_count, cardinality(u.seat_member_ids)), u.members
      FROM public.org_usage_days u
     WHERE u.org_id = p_org
       AND public.sbci_is_org_member(p_org, 'member')
     ORDER BY u.day DESC
     LIMIT 1
$$;

ALTER FUNCTION sbci_portal_org_seats(uuid) OWNER TO sbci_defs;
REVOKE ALL ON FUNCTION sbci_portal_org_seats(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_portal_org_seats(uuid) TO sbci_api, sbci_app;

-- ---------------------------------------------------------------------------
-- sbci_expire_org_usage_days
-- ---------------------------------------------------------------------------
GRANT DELETE ON org_usage_days TO sbci_defs;

CREATE FUNCTION sbci_expire_org_usage_days(p_before date)
RETURNS bigint
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    floor_day date := (current_date - interval '10 years')::date;
    n bigint;
BEGIN
    IF p_before IS NULL OR p_before > floor_day THEN
        RAISE EXCEPTION 'org_usage_days are kept 10 years: % is after %', p_before, floor_day
            USING ERRCODE = 'check_violation';
    END IF;
    DELETE FROM public.org_usage_days WHERE day < p_before;
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n;
END
$$;

ALTER FUNCTION sbci_expire_org_usage_days(date) OWNER TO sbci_defs;
REVOKE ALL ON FUNCTION sbci_expire_org_usage_days(date) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_expire_org_usage_days(date) TO sbci_worker, sbci_app;

-- 0088_oidc_support_target.sql - the token endpoint's re-check of a support
-- code (managed-SaaS plan 07 M7a.2; lane lane-w11-support-oplog).
--
-- step: contract
--
-- Contract label: the REVOKE of PUBLIC's default EXECUTE (migcheck's revoke
-- rule). The function is new in this step, so no running release can hold or
-- lose the privilege; the label is the rule's, not a real contraction.
--
-- The member path re-reads the caller's membership and the org at token
-- time, so a change between authorize and token is taken (oidcissuer
-- "Ordering rules"). The support path does the same: the staff member must
-- still be active, the org active, and its platform rail enabled. The serve
-- login (sbci_api) holds no grant on staff_users, and sees orgs only through
-- a member's own context, so the facts come through one SECURITY DEFINER
-- function owned by sbci_defs that returns three booleans' worth and nothing
-- else: it names no staff member, lists nothing, and reads one staff row and
-- one org row by key.
--
-- Executable by sbci_api and sbci_app only; PUBLIC is revoked in this step
-- (the 0082 rule, pinned by TestDefinerFunctionExecuteGrants). sbci_defs
-- gains SELECT on the two staff_users columns the body reads (it already
-- reads orgs, 0047).

SET LOCAL lock_timeout = '5s';

GRANT SELECT (staff_id, status) ON staff_users TO sbci_defs;

CREATE FUNCTION sbci_support_target(p_staff uuid, p_org uuid)
RETURNS TABLE (staff_active boolean, org_status text, rail_enabled boolean)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT EXISTS (SELECT 1 FROM public.staff_users s WHERE s.staff_id = p_staff AND s.status = 'active'),
           coalesce((SELECT o.status FROM public.orgs o WHERE o.org_id = p_org), ''),
           coalesce((SELECT o.platform_rail_enabled FROM public.orgs o WHERE o.org_id = p_org), false)
$$;

ALTER FUNCTION sbci_support_target(uuid, uuid) OWNER TO sbci_defs;
REVOKE ALL ON FUNCTION sbci_support_target(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_support_target(uuid, uuid) TO sbci_api, sbci_app;

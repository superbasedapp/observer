-- 0096_worker_create_owner_verified.sql - whether WorkOS verified the
-- address of ONE org's owner, for the create_tenant request (managed-SaaS
-- plan 07 wave 15 lane console-fixes; L-113 C2.tenant-cloud-2; docs/security.md
-- ENTLWORK-8).
--
-- step: contract
--
-- Contract label: the REVOKE of PUBLIC's default EXECUTE (migcheck's revoke
-- rule, the 0082 / 0093 pattern). The function is new in this step; the
-- label is the rule's, not a real contraction.
--
-- WHY. 0093's sbci_org_create_owner_email_hint sends the owner's
-- provider-asserted address as a display hint the request marks UNVERIFIED.
-- The adopted recommendation (C2.tenant-cloud-2) sends it as verified when
-- WorkOS verified it: account_verified_emails.email_verified is WorkOS's own
-- flag from the same user object (0074), written only by the WorkOS sign-in
-- leg. The host still binds the owner BY SUBJECT (W14-D2,
-- sbci_org_create_owner_sub); the flag only says how far the address may be
-- trusted for display and invitation matching on the tenant.
--
-- sbci_org_create_owner_email_verified(org) returns true only when the
-- owner the 0093 functions pick (the creator while still an owner member,
-- else the oldest owner) has a row whose email_verified is true; false when
-- the row says not verified; NULL for an org not being created, an unknown
-- org, no owner, or no row. The store reads it in the SAME statement as the
-- hint, so both come from one snapshot. One org id in, one boolean out; no
-- address, no account id, no listing. The owner choice is the 0093 rule
-- copied verbatim (TestOrgCreateOwnerEmailVerified pins that the three agree).
--
-- Executable by sbci_worker and sbci_app only; PUBLIC revoked (pinned by
-- TestDefinerFunctionExecuteGrants). sbci_defs gains SELECT on the one
-- column the body reads beyond 0093's.

SET LOCAL lock_timeout = '5s';

GRANT SELECT (email_verified) ON account_verified_emails TO sbci_defs;

CREATE FUNCTION sbci_org_create_owner_email_verified(p_org uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT (SELECT v.email_verified
              FROM public.account_verified_emails v
             WHERE v.account_id = m.account_id)
      FROM public.orgs o
      JOIN public.org_members m ON m.org_id = o.org_id AND m.console_role = 'owner'
     WHERE o.org_id = p_org
       AND o.status = 'provisioning'
     ORDER BY (m.account_id = o.created_by) DESC, m.created_at, m.account_id
     LIMIT 1
$$;

ALTER FUNCTION sbci_org_create_owner_email_verified(uuid) OWNER TO sbci_defs;
REVOKE ALL ON FUNCTION sbci_org_create_owner_email_verified(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_org_create_owner_email_verified(uuid) TO sbci_worker, sbci_app;

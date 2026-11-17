-- 0093_worker_create_owner.sql - the owner of ONE org being created, for the
-- outbox worker's create_tenant request (managed-SaaS plan 07 M6.4; lead
-- decisions L-43 and W14-D2, wave 14 lane tenant-cloud; docs/security.md
-- ENTLWORK-8).
--
-- step: contract
--
-- Contract label: the REVOKE of PUBLIC's default EXECUTE (migcheck's revoke
-- rule, the 0082 / 0088 pattern). Both functions are new in this step, so no
-- running release can hold or lose the privilege; the label is the rule's,
-- not a real contraction.
--
-- WHY. A create_tenant request names the tenant's owner: the host binds the
-- owner member BY WORKOS SUBJECT (W14-D2) and keeps the address for display.
-- The worker builds the request but holds no grant on org_members,
-- identity_links or account_verified_emails, and the outbox payload carries
-- no personal data (0049). Two narrow SECURITY DEFINER functions owned by
-- sbci_defs answer for one org at a time:
--
--   sbci_org_create_owner_sub(org)          the owner's subject, chosen by the
--     SAME rule the platform OIDC issuer uses for the member's `sub` claim
--     (store/oidc.go Member: the workos link first, then the oldest), so the
--     subject the host binds is the subject every later platform sign-in
--     presents;
--   sbci_org_create_owner_email_hint(org)   the owner's provider-asserted
--     address (account_verified_emails), sent ONLY as a display hint that the
--     request marks unverified (L-31 is unruled; the contract's
--     owner_email_verified stays false). It is never a lookup key.
--
-- NO LISTING. Each takes one org id and returns one scalar (text, or NULL);
-- neither returns a set, an account id or any other column. Each answers only
-- for an org whose status is 'provisioning' (a create in flight; the only
-- time a create_tenant request is built, including a reconciler
-- correction), and NULL for an active, suspended, purged or unknown org, so
-- the worker cannot walk the registry to collect owners of tenants that
-- already exist. The owner is the org's creator while they are still an
-- owner member, else its oldest owner member (the provisioning transaction
-- makes the creator the one owner, so these agree at create time).
-- TestOrgCreateOwnerLookupDoesNotList pins the shape and the refusals.
--
-- Two functions, not one returning both: no statement here pairs
-- identity_links with an address (the store's no-merge tripwire,
-- TestStoreSQLNeverJoinsIdentityLinksByEmail, guards the same rule in Go).
--
-- Executable by sbci_worker and sbci_app (the test / operator role) only;
-- PUBLIC is revoked in this step (the 0082 rule, pinned by
-- TestDefinerFunctionExecuteGrants). sbci_defs already reads orgs and
-- org_members (0047) and identity_links (0004); it gains SELECT on the two
-- account_verified_emails columns the hint body reads.

SET LOCAL lock_timeout = '5s';

GRANT SELECT (account_id, email) ON account_verified_emails TO sbci_defs;

CREATE FUNCTION sbci_org_create_owner_sub(p_org uuid)
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT (SELECT l.subject
              FROM public.identity_links l
             WHERE l.account_id = m.account_id
             ORDER BY (l.provider = 'workos') DESC, l.created_at, l.id
             LIMIT 1)
      FROM public.orgs o
      JOIN public.org_members m ON m.org_id = o.org_id AND m.console_role = 'owner'
     WHERE o.org_id = p_org
       AND o.status = 'provisioning'
     ORDER BY (m.account_id = o.created_by) DESC, m.created_at, m.account_id
     LIMIT 1
$$;

ALTER FUNCTION sbci_org_create_owner_sub(uuid) OWNER TO sbci_defs;
REVOKE ALL ON FUNCTION sbci_org_create_owner_sub(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_org_create_owner_sub(uuid) TO sbci_worker, sbci_app;

CREATE FUNCTION sbci_org_create_owner_email_hint(p_org uuid)
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT (SELECT v.email
              FROM public.account_verified_emails v
             WHERE v.account_id = m.account_id)
      FROM public.orgs o
      JOIN public.org_members m ON m.org_id = o.org_id AND m.console_role = 'owner'
     WHERE o.org_id = p_org
       AND o.status = 'provisioning'
     ORDER BY (m.account_id = o.created_by) DESC, m.created_at, m.account_id
     LIMIT 1
$$;

ALTER FUNCTION sbci_org_create_owner_email_hint(uuid) OWNER TO sbci_defs;
REVOKE ALL ON FUNCTION sbci_org_create_owner_email_hint(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_org_create_owner_email_hint(uuid) TO sbci_worker, sbci_app;

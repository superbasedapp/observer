-- 0047_org_registry.sql - the control plane's org registry (managed-SaaS
-- plan 07 M6.1a; design docs/plans/managed-saas/m6.0-control-plane-design-2026-11-13.md
-- sections 3.2 and 4.1; lead decision L-9).
--
-- step: expand
--
-- One step of four (0047-0050, the M6.1a block recorded in
-- docs/migration-numbering.md). This step creates the registry tables, their
-- indexes and the three SECURITY DEFINER helpers the 0048 policies call. It
-- grants nothing on the two membership-class tables: their policies arrive
-- in 0048 and their grants in 0049, so no application role can ever read or
-- write orgs / org_members while they have no row-level security (a crash
-- between steps leaves them unreachable, not open).
--
-- TABLES AND THEIR RLS CLASS (design 3.2)
--
--   orgs          M  one row per org (personal or team). status is the
--                    platform tenant lifecycle vocabulary, copied once from
--                    internal/platformcontract KnownTenantStates; a store
--                    test compares the two.
--   org_members   M  (org, account) with the console role owner|admin|member
--                    and the is_billing_owner flag (one per org). Console
--                    roles govern control-plane acts only; tenant RBAC stays
--                    in the tenant (design A2).
--   org_slugs     S  the slug namespace: the current slug of every org and the
--                    aliases a rename keeps for 90 days. A new org can take
--                    neither. No RLS; sbci_api may only INSERT (provisioning).
--   org_sub_seen  S  (org, WorkOS sub) the issuer records when it mints a
--                    token (M6.2); the list M6.9 fans members/deactivate out
--                    to. Created here so the schema is whole; only sbci_app
--                    is granted until M6.2 adds the issuer's grant.
--
-- One owner per fact: the billing owner is org_members.is_billing_owner
-- only. The design's orgs.billing_owner_account_id column is deliberately not
-- created (it would be a second writer of the same fact). Staff tables are not
-- here; they move to M6.8 with the sbci_staff role (design A9, lead L-9 Q6).
--
-- ACCOUNT REFERENCES. orgs.created_by is an opaque account id with no foreign
-- key, like an audit column: account deletion pseudonymizes the account row
-- and the 24-month retention sweep later DELETEs it, which a plain foreign key
-- would block. org_members.account_id references accounts ON DELETE CASCADE
-- for the same reason (the membership dies with the tombstone). Account
-- deletion with orgs (succession, deactivation) is M6.9.
--
-- THE MEMBERSHIP FUNCTIONS (design 3.2, class M). The policies on orgs and
-- org_members must read org_members; a policy that queried the table it
-- protects would recurse. So they call SECURITY DEFINER functions owned by
-- sbci_defs (BYPASSRLS), which read the tables without policies applying:
--
--   sbci_is_org_member(org, min_role)   is the CALLER a member of org with at
--                                        least min_role? (owner > admin > member;
--                                        an unknown min_role is never met)
--   sbci_org_member_write_ok(org, account, role, billing)
--                                        may the CALLER write this membership
--                                        row? The rule table is in the function.
--   sbci_slug_org(slug)                 the org a current slug or a live alias
--                                        names, ONLY when the caller is a member
--                                        of it (the M6.6 CORS check's lookup);
--                                        NULL otherwise.
--
-- "The caller" is sbci_current_account() and nothing else: no function or
-- policy here reads the sbci.account_id GUC directly. M6.1b (tenantctx)
-- changes the body of sbci_current_account() alone and every policy follows.
-- With no tenant context each function answers false / NULL.
--
-- EXECUTE PRIVILEGE. These functions are left EXECUTE-to-PUBLIC, the posture
-- 0004 gives sbci_current_account() and for the same reason: each answers only
-- for the transaction's own account context, so calling it grants nothing that
-- context could not already see through RLS, and with no context it answers
-- nothing. None is a cross-tenant primitive (contrast sbci_lease_next_job and
-- the introspection lookups, which 0004/0015 REVOKE from PUBLIC). A REVOKE is
-- also not available in an expand step: internal/migcheck classifies every
-- REVOKE as contract, including one on a function the same step creates.
-- The explicit GRANTs below document which roles the policies need.
--
-- Hardening as 0022/0035: owner sbci_defs, search_path pinned to
-- pg_catalog, public, every relation schema-qualified.

SET LOCAL lock_timeout = '5s';

-- ---------------------------------------------------------------------------
-- orgs (class M)
-- ---------------------------------------------------------------------------
CREATE TABLE orgs (
    org_id                uuid        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    kind                  text        NOT NULL CHECK (kind IN ('personal', 'team')),
    -- Lowercase DNS-label characters; the reserved names and the hyphen rules
    -- are in Go (store.ValidateOrgSlug), not SQL (design 4.1).
    slug                  text        NOT NULL CHECK (slug ~ '^[a-z0-9-]{3,40}$'),
    display_name          text        NOT NULL CHECK (display_name <> '' AND char_length(display_name) <= 200),
    -- internal/platformcontract KnownTenantStates, in lifecycle order.
    status                text        NOT NULL DEFAULT 'provisioning'
        CHECK (status IN ('provisioning', 'active', 'suspended', 'pending_deletion', 'purging', 'purged')),
    lifecycle_gen         bigint      NOT NULL DEFAULT 0 CHECK (lifecycle_gen >= 0),
    -- Which tenant host serves the org; set by the host-API client (M6.4).
    host_id               text,
    tenancy               text        NOT NULL CHECK (tenancy IN ('individual', 'managed')),
    -- false = the org opted out of the platform sign-in rail (Business).
    platform_rail_enabled boolean     NOT NULL DEFAULT true,
    created_by            uuid        NOT NULL,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT orgs_personal_is_individual CHECK (kind <> 'personal' OR tenancy = 'individual')
);

-- The current slug is unique across orgs (the CHECK keeps it lowercase, so
-- lower() is belt and braces against a future relaxation).
CREATE UNIQUE INDEX orgs_slug_lower ON orgs (lower(slug));

-- At most one personal org per account: "Personal" is created lazily and
-- idempotently (design 4.7, POST /portal/api/orgs/personal).
CREATE UNIQUE INDEX orgs_one_personal_per_account ON orgs (created_by) WHERE kind = 'personal';

-- ---------------------------------------------------------------------------
-- org_members (class M)
-- ---------------------------------------------------------------------------
CREATE TABLE org_members (
    org_id           uuid        NOT NULL REFERENCES orgs (org_id),
    account_id       uuid        NOT NULL REFERENCES accounts (account_id) ON DELETE CASCADE,
    console_role     text        NOT NULL CHECK (console_role IN ('owner', 'admin', 'member')),
    is_billing_owner boolean     NOT NULL DEFAULT false,
    created_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, account_id)
);

-- One billing owner per org.
CREATE UNIQUE INDEX org_members_one_billing_owner ON org_members (org_id) WHERE is_billing_owner;

-- "List my orgs" walks memberships by account.
CREATE INDEX org_members_account ON org_members (account_id);

-- ---------------------------------------------------------------------------
-- org_slugs (class S)
-- ---------------------------------------------------------------------------
CREATE TABLE org_slugs (
    slug        text        NOT NULL PRIMARY KEY CHECK (slug ~ '^[a-z0-9-]{3,40}$'),
    org_id      uuid        NOT NULL REFERENCES orgs (org_id),
    is_alias    boolean     NOT NULL DEFAULT false,
    -- An alias resolves until this instant (90 days after the rename).
    alias_until timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT org_slugs_alias_has_expiry CHECK (is_alias = (alias_until IS NOT NULL))
);

-- Exactly one current (non-alias) slug per org.
CREATE UNIQUE INDEX org_slugs_one_current ON org_slugs (org_id) WHERE NOT is_alias;

-- ---------------------------------------------------------------------------
-- org_sub_seen (class S)
-- ---------------------------------------------------------------------------
CREATE TABLE org_sub_seen (
    org_id     uuid        NOT NULL REFERENCES orgs (org_id),
    sub        text        NOT NULL CHECK (sub <> ''),
    first_seen timestamptz NOT NULL DEFAULT now(),
    last_seen  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, sub)
);

-- M6.9 fans out by sub across every org.
CREATE INDEX org_sub_seen_sub ON org_sub_seen (sub);

-- ---------------------------------------------------------------------------
-- The membership functions (SECURITY DEFINER, owner sbci_defs).
-- ---------------------------------------------------------------------------

-- Is the caller a member of p_org with at least p_min_role? Ranks: owner 3,
-- admin 2, member 1. An unknown p_min_role ranks 99 and is never met (fail
-- closed); a NULL context matches no row.
CREATE FUNCTION sbci_is_org_member(p_org uuid, p_min_role text)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT EXISTS (
        SELECT 1
          FROM public.org_members m
         WHERE m.org_id = p_org
           AND m.account_id = public.sbci_current_account()
           AND (CASE m.console_role WHEN 'owner' THEN 3 WHEN 'admin' THEN 2 WHEN 'member' THEN 1 ELSE 0 END)
               >= (CASE p_min_role WHEN 'owner' THEN 3 WHEN 'admin' THEN 2 WHEN 'member' THEN 1 ELSE 99 END)
    )
$$;

ALTER FUNCTION sbci_is_org_member(uuid, text) OWNER TO sbci_defs;

-- May the caller write the membership row (p_org, p_account, p_role,
-- p_billing)? Used for INSERT and for both the old row (USING) and the new
-- row (WITH CHECK) of UPDATE and DELETE. The rules, top-down, first match
-- wins (internal/cloudserver/store TestOrgConsoleRoleMatrix and
-- TestOrgMembershipBootstrapRules cover every rule):
--
--   1  no tenant context                                  -> refuse
--   2  bootstrap: the caller created the org, the org has
--      no member yet, and the row makes the caller its
--      owner and billing owner                            -> allow
--   3  the org is personal (exactly the bootstrap row)    -> refuse
--   4  the caller is an owner                             -> allow
--   5  the caller is an admin and the row is neither an
--      owner nor the billing owner                        -> allow
--   6  anything else (members, non-members)               -> refuse
CREATE FUNCTION sbci_org_member_write_ok(p_org uuid, p_account uuid, p_role text, p_billing boolean)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    WITH ctx AS (
        SELECT public.sbci_current_account() AS me
    ), org AS (
        SELECT o.kind, o.created_by
          FROM public.orgs o
         WHERE o.org_id = p_org
    ), caller AS (
        SELECT m.console_role
          FROM public.org_members m, ctx
         WHERE m.org_id = p_org AND m.account_id = ctx.me
    )
    SELECT CASE
        WHEN (SELECT me FROM ctx) IS NULL THEN false
        WHEN EXISTS (SELECT 1 FROM org, ctx WHERE org.created_by = ctx.me)
         AND NOT EXISTS (SELECT 1 FROM public.org_members m WHERE m.org_id = p_org)
         AND p_account = (SELECT me FROM ctx)
         AND p_role = 'owner'
         AND p_billing IS TRUE
            THEN true
        WHEN EXISTS (SELECT 1 FROM org WHERE org.kind = 'personal') THEN false
        WHEN EXISTS (SELECT 1 FROM caller WHERE caller.console_role = 'owner') THEN true
        WHEN EXISTS (SELECT 1 FROM caller WHERE caller.console_role = 'admin')
         AND p_role IS DISTINCT FROM 'owner'
         AND p_billing IS NOT TRUE
            THEN true
        ELSE false
    END
$$;

ALTER FUNCTION sbci_org_member_write_ok(uuid, uuid, text, boolean) OWNER TO sbci_defs;

-- The org a slug names (its current slug, or an alias still inside its 90
-- days), returned only when the caller is a member of that org; NULL for an
-- unknown slug, an expired alias, a non-member or no context. org_slugs has
-- no SELECT grant for sbci_api, so this is the api's only way to read it.
CREATE FUNCTION sbci_slug_org(p_slug text)
RETURNS uuid
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT s.org_id
      FROM public.org_slugs s
      JOIN public.org_members m
        ON m.org_id = s.org_id
       AND m.account_id = public.sbci_current_account()
     WHERE s.slug = p_slug
       AND (NOT s.is_alias OR s.alias_until > now())
$$;

ALTER FUNCTION sbci_slug_org(text) OWNER TO sbci_defs;

-- ---------------------------------------------------------------------------
-- Grants.
-- ---------------------------------------------------------------------------

-- What the definer bodies read (BYPASSRLS removes the row filter, not the
-- base-table privilege), and the context helper they call.
GRANT SELECT ON orgs, org_members, org_slugs TO sbci_defs;
GRANT EXECUTE ON FUNCTION sbci_current_account() TO sbci_defs;

-- The roles whose statements evaluate the 0048 policies, or call the slug
-- lookup, need EXECUTE (PUBLIC already holds it; see the header).
GRANT EXECUTE ON FUNCTION sbci_is_org_member(uuid, text)                       TO sbci_app, sbci_api;
GRANT EXECUTE ON FUNCTION sbci_org_member_write_ok(uuid, uuid, text, boolean) TO sbci_app, sbci_api;
GRANT EXECUTE ON FUNCTION sbci_slug_org(text)                                 TO sbci_app, sbci_api;

-- S tables. sbci_api writes a slug only at provisioning (no SELECT: reads go
-- through sbci_slug_org); renames (M6.5) widen this in their own step.
GRANT INSERT                 ON org_slugs    TO sbci_api;
GRANT SELECT, INSERT, UPDATE ON org_slugs    TO sbci_app;
GRANT SELECT, INSERT, UPDATE ON org_sub_seen TO sbci_app;

COMMENT ON TABLE orgs IS 'M6.1a org registry (class M: RLS through sbci_is_org_member).';
COMMENT ON TABLE org_members IS 'M6.1a console membership (class M): owner|admin|member plus is_billing_owner.';
COMMENT ON TABLE org_slugs IS 'M6.1a slug namespace (class S): current slugs and 90-day rename aliases.';
COMMENT ON TABLE org_sub_seen IS 'M6.1a (org, WorkOS sub) seen by the issuer (class S); written from M6.2, read by M6.9.';

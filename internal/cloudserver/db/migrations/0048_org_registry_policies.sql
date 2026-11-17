-- 0048_org_registry_policies.sql - row-level security for the two
-- membership-class tables 0047 created (managed-SaaS M6.1a; design
-- docs/plans/managed-saas/m6.0-control-plane-design-2026-11-13.md 3.2).
--
-- step: expand
--
-- A step of its own: internal/migcheck requires policy and row-level-security
-- changes to stand alone. Nothing can reach orgs or org_members yet (0049
-- grants them), so enabling RLS here changes no running path.
--
-- Class M: every policy decides through sbci_is_org_member /
-- sbci_org_member_write_ok (SECURITY DEFINER, owner sbci_defs, 0047), which
-- read org_members without policies applying, so a policy never queries the
-- table it protects and cannot recurse. The one direct comparison is
-- orgs_create's created_by = sbci_current_account(). No policy reads the
-- sbci.account_id GUC itself (the M6.1b seam). FORCE, as on every tenant
-- table since 0004, so a non-superuser table owner is held too.
--
-- The policy matrix (console roles; tenant RBAC stays in the tenant):
--
--   orgs         SELECT  member, admin, owner of the org
--                INSERT  anyone, for an org whose created_by is themself
--                        (provisioning; the membership row follows in the
--                        same transaction through rule 2 of
--                        sbci_org_member_write_ok)
--                UPDATE  admin, owner (column grants in 0049 narrow what
--                        sbci_api may change)
--                DELETE  no policy: an org is never deleted by a session; it
--                        moves through the lifecycle (org_deletion_requests)
--   org_members  SELECT  member, admin, owner of the org (members list)
--                INSERT, UPDATE, DELETE  sbci_org_member_write_ok on the
--                        written row (and on the old row for UPDATE/DELETE)
--
-- A missing tenant context matches no row and passes no check.

SET LOCAL lock_timeout = '5s';

ALTER TABLE orgs ENABLE ROW LEVEL SECURITY;
ALTER TABLE orgs FORCE ROW LEVEL SECURITY;

CREATE POLICY orgs_member_select ON orgs
    FOR SELECT
    USING (sbci_is_org_member(org_id, 'member'));

CREATE POLICY orgs_create ON orgs
    FOR INSERT
    WITH CHECK (created_by = sbci_current_account());

CREATE POLICY orgs_admin_update ON orgs
    FOR UPDATE
    USING (sbci_is_org_member(org_id, 'admin'))
    WITH CHECK (sbci_is_org_member(org_id, 'admin'));

ALTER TABLE org_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE org_members FORCE ROW LEVEL SECURITY;

CREATE POLICY org_members_member_select ON org_members
    FOR SELECT
    USING (sbci_is_org_member(org_id, 'member'));

CREATE POLICY org_members_write_insert ON org_members
    FOR INSERT
    WITH CHECK (sbci_org_member_write_ok(org_id, account_id, console_role, is_billing_owner));

CREATE POLICY org_members_write_update ON org_members
    FOR UPDATE
    USING (sbci_org_member_write_ok(org_id, account_id, console_role, is_billing_owner))
    WITH CHECK (sbci_org_member_write_ok(org_id, account_id, console_role, is_billing_owner));

CREATE POLICY org_members_write_delete ON org_members
    FOR DELETE
    USING (sbci_org_member_write_ok(org_id, account_id, console_role, is_billing_owner));

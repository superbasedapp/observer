-- 0121_org_members_deletion_worker_policies.sql - the deletion driver's row
-- access to org_members (managed-SaaS plan 07 M6.9; lane w17/deletion-purge).
--
-- step: expand
--
-- org_members is class M (0048): FORCE ROW LEVEL SECURITY with membership
-- policies that answer for sbci_current_account(). The deletion driver runs
-- with no tenant context (store.WithSystem as sbci_worker), so those policies
-- give it no row. It needs two things, both bounded by 0120's grants (SELECT
-- on four columns, DELETE):
--
--   * removing a deleted account's team memberships and every membership of
--     a purged org (DELETE);
--   * reading those rows to name the WHERE (SELECT).
--
-- These policies apply to sbci_worker ONLY (TO sbci_worker); every other role
-- keeps exactly the 0048 policies. The worker cannot insert or update a
-- membership (no grant). A policy step of its own (internal/migcheck), after
-- the grants in 0120; a crash between the two steps leaves the worker with
-- grants that reach no row (fail closed).

SET LOCAL lock_timeout = '5s';

CREATE POLICY org_members_deletion_worker_select ON org_members
    FOR SELECT
    TO sbci_worker
    USING (true);

CREATE POLICY org_members_deletion_worker_delete ON org_members
    FOR DELETE
    TO sbci_worker
    USING (true);

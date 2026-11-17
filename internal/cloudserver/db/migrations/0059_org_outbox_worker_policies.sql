-- 0059_org_outbox_worker_policies.sql - the outbox worker's row access to
-- orgs (managed-SaaS plan 07 M6.4; design
-- docs/plans/managed-saas/m6.0-control-plane-design-2026-11-13.md 3.2, 4.6).
--
-- step: expand
--
-- orgs is class M (0048): FORCE ROW LEVEL SECURITY with membership policies
-- that answer for sbci_current_account(). The outbox worker runs with no
-- tenant context (store.WithSystem), so those policies give it no row. It
-- needs every org: to route an intent to the org's host, to record the host
-- it placed a new tenant on, to adopt the host's answer to create, and to
-- reconcile. These two policies apply to sbci_worker ONLY (TO sbci_worker);
-- every other role keeps exactly the 0048 policies. The worker's column
-- grants (0058) bound what it can read and write: it cannot see slug,
-- tenancy or created_by, cannot rename, and cannot insert or delete an org.
-- org_members is untouched: the worker holds no grant on it.
--
-- A policy step of its own (internal/migcheck), after the grants in 0058; a
-- crash between the two steps leaves the worker with grants that reach no
-- row (fail closed).

SET LOCAL lock_timeout = '5s';

CREATE POLICY orgs_outbox_worker_select ON orgs
    FOR SELECT
    TO sbci_worker
    USING (true);

CREATE POLICY orgs_outbox_worker_update ON orgs
    FOR UPDATE
    TO sbci_worker
    USING (true)
    WITH CHECK (true);

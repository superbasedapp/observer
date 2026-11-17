-- 0068_staff_role.sql - the staff console's database role (managed-SaaS plan
-- 07 M6.8; design docs/plans/managed-saas/m6.0-control-plane-design-2026-11-13.md
-- 3.5 and 4.9; lead decision L-9 Q6).
--
-- step: contract
--
-- One step of the M6.8 block (0068-0071 in docs/migration-numbering.md):
-- 0068 creates the role, 0069 the staff tables and their grants, 0070 their
-- row-level security. 0071 is reserved.
--
--   sbci_staff  NOLOGIN NOBYPASSRLS. The staff console's handlers run
--               `SET LOCAL ROLE sbci_staff` (store.WithStaff). It holds
--               grants on the staff tables only (0069) and nothing on any
--               customer table, so a staff handler cannot read customer
--               data and a customer handler (sbci_api) cannot read staff
--               data, whatever a handler does.
--
-- WHY CONTRACT. Roles are cluster-wide and two databases can migrate on one
-- cluster at once (the test templates do), so the creation is a DO block
-- that tolerates a concurrent creator, exactly as 0001 and 0015 do. A DO
-- block is opaque to migcheck, which classes it contract; creating a role
-- does not change anything the running release uses.
--
-- MEMBERSHIP (operator ruling A3, 2026-11-13). `SET ROLE sbci_staff` is
-- authorized against the LOGIN role's memberships, so the role's members
-- are the whole of the staff surface's database authority:
--   * exactly ONE login is granted it: the dedicated staff login
--     sbci_staff_svc, which only the separate staff process
--     (`observer-cloud staff serve`, SBCI_STAFF_PG_DSN) and the operator's
--     staff commands connect with. 0076 grants it when that login exists;
--     a deployment that creates the login later grants it in its bootstrap
--     (deploy/demo-box/cloud-bootstrap.sh);
--   * the customer serve login (sbci_api_svc, or the single staging login
--     sbci_svc) and the worker login are NEVER granted it: any code
--     execution in a customer route could otherwise `SET ROLE sbci_staff`.
--     The first version of this step granted it to sbci_api_svc and sbci_svc;
--     that grant is removed here (the step had not shipped) and revoked by
--     0076 on a database that applied the first version. serve refuses to
--     start when its own login holds the role (cmd/observer-cloud);
--   * the migrating login is not granted it either: the operator commands
--     use the staff login, and a superuser (the dev and test posture) needs
--     no grant.

SET LOCAL lock_timeout = '5s';

DO $$
BEGIN
    CREATE ROLE sbci_staff NOLOGIN NOBYPASSRLS;
EXCEPTION WHEN duplicate_object THEN
    NULL;
END$$;

-- Belt and braces: an older role of the same name must not keep LOGIN or
-- BYPASSRLS.
ALTER ROLE sbci_staff NOLOGIN NOBYPASSRLS;

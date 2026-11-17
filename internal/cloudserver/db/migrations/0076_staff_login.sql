-- 0076_staff_login.sql - the staff console's own database login (managed-SaaS
-- plan 07 M6.8; operator ruling A3 of 2026-11-13: "a separate staff process
-- with its own DB login, the only one granted sbci_staff").
--
-- step: contract
--
-- The staff lane's steps are 0076-0077 (lead decision L-72); 0077 is
-- unused.
--
--   * sbci_staff_svc, the staff process's login, is granted sbci_staff when
--     the login exists. Like the other service logins (0015), the login
--     itself is created by the deployment's bootstrap with its password,
--     never by a migration; a bootstrap that creates it after this step
--     grants the role itself (deploy/demo-box/cloud-bootstrap.sh).
--   * Every customer and worker login loses sbci_staff: sbci_api_svc and the
--     single staging login sbci_svc were granted it by the first version of
--     0068 (since edited, before it shipped), and a database that applied
--     that version keeps the grant until this step. sbci_worker_svc never
--     had it; it is listed so no later mistake survives either.
--   * sbci_staff may execute the shared rate-limit counter
--     (sbci_rate_limit, 0017), so the staff process's per-IP limit runs on
--     the same SECURITY DEFINER counter the serve process uses. The function
--     touches only its own counter table.
--
-- WHY CONTRACT. Role memberships are cluster-wide and the grants run in DO
-- blocks (the logins may not exist), which migcheck cannot see into. Taking
-- sbci_staff away from the serve login removes nothing the running release
-- uses: serve no longer mounts a staff route and refuses to start while its
-- login holds the role.

SET LOCAL lock_timeout = '5s';

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sbci_api_svc') THEN
        REVOKE sbci_staff FROM sbci_api_svc;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sbci_svc') THEN
        REVOKE sbci_staff FROM sbci_svc;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sbci_worker_svc') THEN
        REVOKE sbci_staff FROM sbci_worker_svc;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sbci_staff_svc') THEN
        GRANT sbci_staff TO sbci_staff_svc;
    END IF;
END$$;

GRANT EXECUTE ON FUNCTION sbci_rate_limit(text, text, integer, bigint) TO sbci_staff;

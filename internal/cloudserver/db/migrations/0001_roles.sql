-- 0001_roles.sql — the two non-login roles the tenancy design pivots on
-- (plan of record §6 CI-P3, substrate contract §2/§6.5).
--
--   sbci_app  — NOLOGIN, NO BYPASSRLS. The application (api + worker) runs
--               every statement with this role's privileges via `SET LOCAL
--               ROLE sbci_app`, so RLS applies to it and it cannot escape a
--               tenant. Tests SET ROLE into it to prove isolation.
--
--   sbci_defs — NOLOGIN, BYPASSRLS. Owns the SECURITY DEFINER primitives
--               (0003_functions.sql) that are the ONLY code allowed to cross
--               tenants: the job-lease dequeue and the two auth-bootstrap
--               lookups (token introspection, identity-link resolution). It is
--               unreachable except through EXECUTE on those functions —
--               sbci_app is never granted membership in it.
--
-- Role creation is idempotent AND race-safe: cluster roles are global, so two
-- test databases migrating in parallel can hit CREATE ROLE simultaneously; the
-- duplicate_object handler makes the loser a no-op rather than a failure.
-- Creating a BYPASSRLS role requires a superuser at migrate time (true in
-- tests and in the staging deploy's admin connection). See the report's
-- production note: an Azure Flexible Server admin that cannot grant BYPASSRLS
-- would fall back to an owner-bypass lease function.

DO $$
BEGIN
    CREATE ROLE sbci_app NOLOGIN;
EXCEPTION WHEN duplicate_object THEN
    NULL;
END$$;

DO $$
BEGIN
    CREATE ROLE sbci_defs NOLOGIN BYPASSRLS;
EXCEPTION WHEN duplicate_object THEN
    NULL;
END$$;

-- Belt-and-braces: ensure the attributes are what we expect even if a role of
-- the same name pre-existed from an older lineage. NOBYPASSRLS on sbci_app is
-- the load-bearing one — the whole tenancy model assumes it cannot bypass.
ALTER ROLE sbci_app NOLOGIN NOBYPASSRLS;
ALTER ROLE sbci_defs NOLOGIN BYPASSRLS;

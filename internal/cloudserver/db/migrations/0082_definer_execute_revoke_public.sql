-- 0082_definer_execute_revoke_public.sql - no SECURITY DEFINER function is
-- executable by PUBLIC (managed-SaaS plan 07, operator ruling A9 (a) of
-- 2026-11-13, lead log L-16: "a later contract step revokes PUBLIC and grants
-- named roles").
--
-- step: contract
--
-- Five definer functions owned by sbci_defs still carried PostgreSQL's
-- default EXECUTE-to-PUBLIC grant; every other definer revoked it in the step
-- that created it. This step revokes PUBLIC from those five. The roles that
-- call each one today already hold explicit grants (below), so EXECUTE stays
-- with exactly those roles. The owner (sbci_defs) keeps
-- EXECUTE as owner; the migrator and operator verbs connect as the superuser,
-- which no function grant restricts. The service logins (sbci_api_svc,
-- sbci_worker_svc, sbci_staff_svc) inherit through their NOLOGIN roles.
--
--   sbci_current_account()  the RLS context helper every "tenant" policy calls
--     (0003, body replaced by 0067). The roles whose statements evaluate those
--     policies, or call it directly, already hold explicit grants: sbci_app
--     (0004), sbci_api and sbci_worker (0015), sbci_aggregator (0022) and
--     sbci_defs (0047, called from the membership function bodies). sbci_staff
--     holds no grant on a table whose policy calls it and needs none.
--   sbci_is_org_member(uuid, text)  the orgs / org_members read and admin
--     policies (0048). sbci_app and sbci_api hold grants (0047). sbci_worker
--     also reads and updates orgs, but through its own outbox policies (0059),
--     whose USING and WITH CHECK are the constant true: PostgreSQL ORs the
--     permissive policies and folds "true OR sbci_is_org_member(...)" to true
--     at plan time, so the worker never executes the function and gets no
--     grant. TestDefinerFunctionExecuteGrants runs the worker's read and
--     update of a real orgs row to keep that true; a worker policy narrowed
--     below true later must grant the worker EXECUTE in the same step.
--   sbci_org_member_write_ok(uuid, uuid, text, boolean)  the org_members write
--     policies (0048). Only sbci_app and sbci_api hold a write grant on
--     org_members, and both already hold EXECUTE (0047).
--   sbci_slug_org(text)  the slug lookup (0047), called by sbci_app and
--     sbci_api, which already hold EXECUTE.
--   sbci_oidc_note_sub_seen()  the oidc_issued AFTER INSERT trigger function
--     (0054). PostgreSQL checks EXECUTE on a trigger function when the trigger
--     is created, never when it fires, and a function returning trigger
--     cannot be called directly, so it is granted to no role: the owner alone
--     keeps it.
--
-- TestDefinerFunctionExecuteGrants (internal/cloudserver/db) pins that PUBLIC
-- holds EXECUTE on no definer function in the schema and the exact grantee set
-- of each one.
--
-- WHY CONTRACT. migcheck classes REVOKE as contract. The running release
-- loses nothing it uses: every role that executes one of these functions
-- already holds an explicit grant, so the step grants nothing new.

SET LOCAL lock_timeout = '5s';

REVOKE EXECUTE ON FUNCTION sbci_current_account() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION sbci_is_org_member(uuid, text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION sbci_org_member_write_ok(uuid, uuid, text, boolean) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION sbci_slug_org(text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION sbci_oidc_note_sub_seen() FROM PUBLIC;

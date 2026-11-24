-- 0153_revoke_temp_from_public.sql - no application role may create a
-- temporary table in the cloud database (docs/security.md CLOUD-TEMP-1;
-- defence in depth for CLOUD-DEFINER-TEMP-2; operator ruling 2026-11-22).
--
-- step: contract
--
-- Contract because it narrows a privilege the running release's roles hold.
-- No runtime path uses it: no Go file under internal/cloudserver or
-- cmd/observer-cloud creates a temp table, no function body in the schema
-- builds or names one (0037's sbci_project_digest_candidates did; 0038
-- replaced it; db.TestNoFunctionBodyCreatesATempTable), and the schema has no
-- materialized view (REFRESH ... CONCURRENTLY builds a temp table as the
-- view's owner).
--
-- The class. Every SECURITY DEFINER shadow attack (CLOUD-DEFINER-TEMP-1,
-- CLOUD-DEFINER-TEMP-2) starts with the caller creating a temp table named
-- like a table or type the definer uses; the caller could, because a
-- database's default ACL grants TEMPORARY to PUBLIC. 0152 put pg_temp last
-- in every definer's search_path; this step takes the tool away, so a future
-- definer that slips the catalog ratchet is not exploitable through it.
--
-- What changes, on the database the step runs in (named by
-- current_database(), so the step is the same on every deployment):
--   * TEMPORARY is revoked from PUBLIC, and from the cloud's six group roles
--     (sbci_app, sbci_api, sbci_worker, sbci_staff, sbci_aggregator and the
--     definer owner sbci_defs) in case one holds an explicit grant. The
--     runtime logins (sbci_api_svc, sbci_worker_svc, sbci_staff_svc, or
--     OVH's OpenTofu logins) inherit from those roles and so lose it too.
--     CONNECT stays with PUBLIC.
--   * The migrating login (current_user) is granted TEMPORARY explicitly:
--     migrations 0039, 0041 and 0043 build temp tables, and a later step may.
--     It owns the database or is a superuser on every documented deployment,
--     so it kept TEMP anyway; the explicit grant also covers a migrator that
--     only inherits the owner's privileges.
-- Then the step checks the result and fails, rolling back, when any group
-- role still holds TEMP (a migrator that may not change the database's ACL
-- gets a WARNING, not an error, from REVOKE) or the migrator lost it.
--
-- Effect on running sessions: TEMP is checked on every CREATE TEMP TABLE, so
-- the revoke holds at once in sessions already open; nothing else they do
-- changes. Residuals: a login role given its own explicit TEMP grant by hand
-- keeps it (the step and its tests cover the group roles); the single-login
-- dev posture, where the app runs as the migrating login, keeps TEMP for the
-- app, and its definers rest on 0152 alone.

SET LOCAL lock_timeout = '5s';

DO $$
DECLARE
    db    text := current_database();
    roles text[] := ARRAY['sbci_aggregator', 'sbci_api', 'sbci_app', 'sbci_defs', 'sbci_staff', 'sbci_worker'];
    r     text;
BEGIN
    EXECUTE format('REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC', db);
    FOREACH r IN ARRAY roles LOOP
        EXECUTE format('REVOKE TEMPORARY ON DATABASE %I FROM %I', db, r);
    END LOOP;
    EXECUTE format('GRANT TEMPORARY ON DATABASE %I TO %I', db, current_user);

    FOREACH r IN ARRAY roles LOOP
        IF has_database_privilege(r, db, 'TEMP') THEN
            RAISE EXCEPTION '0153: role % still holds TEMP on database % after the revoke', r, db
                USING ERRCODE = '42501',
                      HINT = 'run the step as the database owner or a superuser';
        END IF;
    END LOOP;
    IF NOT has_database_privilege(current_user, db, 'TEMP') THEN
        RAISE EXCEPTION '0153: the migrating login % lost TEMP on database %', current_user, db
            USING ERRCODE = '42501';
    END IF;
END
$$;

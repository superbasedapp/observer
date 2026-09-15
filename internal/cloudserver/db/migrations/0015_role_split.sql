-- 0015_role_split.sql — split the shared application role sbci_app into two
-- least-privilege application roles (E2 / W6rs; divergence-remediation plan
-- rev 4.1 §3 "W6 → W6rs"). ADDITIVE and GUARDED: it creates new roles and
-- narrow grants, and NEVER drops sbci_app or removes any of its grants.
--
-- Why. Until now the api server (cmd/observer-cloud serve) and the inference
-- worker (cmd/observer-cloud worker) both ran every statement as ONE non-login
-- role, sbci_app, via a transaction-scoped `SET LOCAL ROLE sbci_app`. RLS still
-- isolates tenants, but api and worker share one privilege set. This migration
-- gives each process its own NOLOGIN NOBYPASSRLS role with the exact per-table /
-- per-function privileges its runtime paths need — so a defect (or an injected
-- statement) in the front-door api can never lease a job or write a model
-- result, and the worker can never mint a browser session or an auth
-- transaction. It is defense-in-depth AND a hard prerequisite of W5
-- (cross-tenant community aggregation) and of W3b's gate list.
--
-- Three roles are created:
--
--   sbci_api    — NOLOGIN NOBYPASSRLS. The api/serve process assumes it via
--                 `SET LOCAL ROLE sbci_api`. Grants cover the auth/exchange,
--                 portal, consent, structural, submit/admission, deletion, and
--                 read surfaces. It is DENIED the worker-only lease function and
--                 DENIED INSERT on analysis_results (it never writes results —
--                 it only reads them and, on account deletion, tombstones them).
--
--   sbci_worker — NOLOGIN NOBYPASSRLS. The worker process assumes it via
--                 `SET LOCAL ROLE sbci_worker`. Grants cover leasing, execution,
--                 result writes, evidence read/purge, attestation record, and
--                 the reservation-settle path. It is DENIED writes to the
--                 auth/portal/consent/structural surfaces.
--
--   sbci_aggregator — NOLOGIN NOBYPASSRLS. The FUTURE W5 cross-tenant read role.
--                 Created here so the role topology is in place, but with NO
--                 cross-tenant EXECUTE and no table grants: W5 will add the
--                 SECURITY DEFINER aggregation function and the EXECUTE grant on
--                 it. Until then this role can do nothing — which is exactly the
--                 W5-not-yet-wired state the tests pin.
--
-- sbci_app STAYS INTACT. The operator/admin paths (migrate, grant-plan, prove)
-- and the dev/test single-role fallback still run as sbci_app with its existing
-- grants, and the SECURITY DEFINER functions keep their sbci_app EXECUTE grants
-- so an admin connection can still call them.
--
-- Staging-window guard. The running staging deployment authenticates as ONE
-- login role, sbci_svc (a member of sbci_app; created by the db-bootstrap step
-- of scripts/cloudintel/cloudintel-azure.sh). The new image issues
-- `SET LOCAL ROLE sbci_api` / `sbci_worker`, which requires sbci_svc to be a
-- MEMBER of those roles. The guarded block at the end grants both new roles to
-- sbci_svc when it exists, so the new code keeps working the moment it deploys,
-- before the deploy script provisions the two dedicated login principals
-- (sbci_api_svc / sbci_worker_svc) that complete the separation.
--
-- Role creation is idempotent AND race-safe (cluster roles are global; two test
-- databases migrating in parallel can hit CREATE ROLE simultaneously), mirroring
-- 0001_roles.sql's duplicate_object handler + belt-and-braces ALTER.

DO $$
BEGIN
    CREATE ROLE sbci_api NOLOGIN NOBYPASSRLS;
EXCEPTION WHEN duplicate_object THEN
    NULL;
END$$;

DO $$
BEGIN
    CREATE ROLE sbci_worker NOLOGIN NOBYPASSRLS;
EXCEPTION WHEN duplicate_object THEN
    NULL;
END$$;

DO $$
BEGIN
    CREATE ROLE sbci_aggregator NOLOGIN NOBYPASSRLS;
EXCEPTION WHEN duplicate_object THEN
    NULL;
END$$;

-- Belt-and-braces: NOBYPASSRLS is load-bearing on all three — the whole tenancy
-- model assumes an application role cannot bypass RLS. Re-assert in case a role
-- of the same name pre-existed from an older lineage.
ALTER ROLE sbci_api        NOLOGIN NOBYPASSRLS;
ALTER ROLE sbci_worker     NOLOGIN NOBYPASSRLS;
ALTER ROLE sbci_aggregator NOLOGIN NOBYPASSRLS;

-- ===========================================================================
-- RLS-policy helper: every tenant-table query evaluates sbci_current_account()
-- inside its USING/WITH CHECK clause AS THE QUERYING ROLE, so BOTH application
-- roles need EXECUTE on it or every tenant read/write fails. (WithSystem also
-- calls it explicitly to prove the missing-context deny.)
-- ===========================================================================
GRANT EXECUTE ON FUNCTION sbci_current_account() TO sbci_api, sbci_worker;

-- ===========================================================================
-- sbci_api — the front-door (serve) privilege set.
-- ===========================================================================

-- Auth / exchange / device / token bootstrap (system tables).
GRANT SELECT, INSERT, UPDATE ON exchange_nonces          TO sbci_api;
GRANT SELECT, INSERT, UPDATE ON accounts                 TO sbci_api;
GRANT SELECT, INSERT         ON identity_links            TO sbci_api;
GRANT SELECT, INSERT, UPDATE ON device_registrations     TO sbci_api;
GRANT SELECT, INSERT, UPDATE ON api_tokens               TO sbci_api;
GRANT SELECT, INSERT         ON pop_replay               TO sbci_api;
GRANT SELECT, INSERT         ON security_audit_events    TO sbci_api;

-- Portal browser sign-in + step-up + WorkOS lifecycle.
GRANT SELECT, INSERT, UPDATE ON browser_sessions         TO sbci_api;
GRANT SELECT, INSERT, UPDATE ON auth_transactions        TO sbci_api;
GRANT SELECT, INSERT, UPDATE ON step_up_authorizations   TO sbci_api;
GRANT SELECT, INSERT, UPDATE ON workos_events            TO sbci_api;

-- Consent (device-plane receipts + portal-plane choices).
GRANT SELECT, INSERT, UPDATE, DELETE ON consent_receipts        TO sbci_api;
GRANT SELECT, INSERT                 ON consent_events           TO sbci_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON portal_consent_choices  TO sbci_api;
GRANT SELECT, INSERT                 ON portal_consent_events    TO sbci_api;

-- Entitlement resolution (SELECT the immutable plan catalog + the assignment
-- history; seed/override the account's own entitlement row).
GRANT SELECT                 ON plans                     TO sbci_api;
GRANT SELECT                 ON account_plans             TO sbci_api;
GRANT SELECT, INSERT, UPDATE ON entitlements              TO sbci_api;

-- Submit / admission: reserve allowance, take evidence custody, enqueue the job,
-- record the append-only usage ledger, and (deletion) cancel + tombstone.
GRANT SELECT, INSERT, UPDATE ON cloud_projects           TO sbci_api;
GRANT SELECT, INSERT, UPDATE ON cloud_sessions           TO sbci_api;
GRANT SELECT, INSERT, UPDATE ON analysis_jobs            TO sbci_api;
GRANT SELECT, UPDATE         ON usage_reservations       TO sbci_api;
GRANT SELECT, INSERT, UPDATE ON usage_cycles             TO sbci_api;
GRANT SELECT, UPDATE         ON budget_pools             TO sbci_api;
GRANT SELECT, INSERT         ON analysis_usage_ledger    TO sbci_api;
GRANT SELECT, INSERT, UPDATE ON evidence_objects         TO sbci_api;
GRANT SELECT, INSERT, DELETE ON evidence_blobs           TO sbci_api;

-- Results: the api READS results (GET /v1/results) and, on account deletion,
-- TOMBSTONES them (UPDATE) — but it NEVER writes a result (that is the worker's
-- job). No INSERT is granted, which the negative tests pin.
GRANT SELECT, UPDATE         ON analysis_results         TO sbci_api;

-- Deletion request record.
GRANT SELECT, INSERT, UPDATE ON deletion_requests        TO sbci_api;

-- Structural-insights rail (register / list / snapshot / rollups + deletion).
GRANT SELECT, INSERT, UPDATE, DELETE ON structural_grants        TO sbci_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON structural_snapshots     TO sbci_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON structural_account_days  TO sbci_api;

-- Control-plane READS only: the api resolves a route + reads the global kill
-- switch at admission (ResolveRoute / GlobalKillSwitchActive) but NEVER mutates
-- either — every route/kill-switch writer (SetRouteBinding/Dialect/Active/
-- Environment, SetKillSwitch) is an operator/prove path that runs as sbci_app,
-- not a serve handler. So the front-door role gets SELECT only; a compromised
-- api cannot flip a route binding or a kill switch (pinned by the negative
-- test). PLUS the admission-time attestation cache (read AND record — the
-- enqueue admission gate persists a fresh attestation like the worker does).
GRANT SELECT                 ON route_registry           TO sbci_api;
GRANT SELECT                 ON kill_switches            TO sbci_api;
GRANT SELECT, INSERT         ON provider_attestations    TO sbci_api;

-- Sequences (identity columns on analysis_results, structural_*, etc.).
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO sbci_api;

-- Auth-bootstrap SECURITY DEFINER lookups + the serve-side pop_replay sweep.
-- (The definer functions run as their owner sbci_defs; the api needs only
-- EXECUTE.) The lease function is deliberately NOT granted here.
GRANT EXECUTE ON FUNCTION sbci_introspect_token(text)                    TO sbci_api;
GRANT EXECUTE ON FUNCTION sbci_introspect_browser_session(text)          TO sbci_api;
GRANT EXECUTE ON FUNCTION sbci_find_identity_link(text, text)            TO sbci_api;
GRANT EXECUTE ON FUNCTION sbci_sweep_expired_pop_replay(timestamptz)     TO sbci_api;

-- ===========================================================================
-- sbci_worker — the inference-worker privilege set.
-- ===========================================================================

-- Read the account's status/consent generation for lease revalidation + the
-- completion CAS subselects.
GRANT SELECT                 ON accounts                 TO sbci_worker;

-- Job lifecycle the worker drives: mark running, park/fail (terminate), and the
-- completion CAS — all UPDATE; it reads job columns in WHERE clauses. It never
-- INSERTs a job (that is submit) — no INSERT is granted, so an errant worker
-- cannot enqueue.
GRANT SELECT, UPDATE         ON analysis_jobs            TO sbci_worker;

-- Results: the worker WRITES the enrichment result (INSERT ... RETURNING id,
-- which needs SELECT on the returned column too). It never UPDATEs a result —
-- the deletion tombstone is an api/deletion-plane action — so no UPDATE is
-- granted, which the negative tests pin.
GRANT SELECT, INSERT         ON analysis_results         TO sbci_worker;

-- Reservation settle/release on completion or terminal transition: lock + flip
-- the reservation, decrement the usage cycles, refund the budget pool.
GRANT SELECT, UPDATE         ON usage_reservations       TO sbci_worker;
GRANT SELECT, UPDATE         ON usage_cycles             TO sbci_worker;
GRANT SELECT, UPDATE         ON budget_pools             TO sbci_worker;

-- Append-only internal-cost ledger (per-attempt + settle rows).
GRANT SELECT, INSERT         ON analysis_usage_ledger    TO sbci_worker;

-- Evidence: read the object + open the blob under the execution lease, then mark
-- the object deleted + purge the blob on completion/terminal. It never CREATES
-- evidence (that is submit) — no INSERT is granted.
GRANT SELECT, UPDATE         ON evidence_objects         TO sbci_worker;
GRANT SELECT, DELETE         ON evidence_blobs           TO sbci_worker;

-- Control-plane reads for revalidation: the route snapshot, the kill switches,
-- and the dialect-verification records; plus the attestation cache (read AND
-- record).
GRANT SELECT                 ON route_registry               TO sbci_worker;
GRANT SELECT                 ON kill_switches                TO sbci_worker;
GRANT SELECT                 ON dialect_verification_records TO sbci_worker;
GRANT SELECT, INSERT         ON provider_attestations        TO sbci_worker;

-- Sequences (analysis_results identity column on the worker's result INSERT).
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO sbci_worker;

-- The atomic dequeue primitive is the WORKER's alone (SECURITY DEFINER, runs as
-- sbci_defs). The api is deliberately never granted EXECUTE on it.
GRANT EXECUTE ON FUNCTION sbci_lease_next_job(text, timestamptz, text[], int) TO sbci_worker;

-- ===========================================================================
-- sbci_aggregator — intentionally EMPTY (W5 wires it later).
-- No table grants and NO EXECUTE on any sbci_* function: the cross-tenant
-- percentile aggregation function and its EXECUTE grant land in the W5 migration.
-- ===========================================================================
COMMENT ON ROLE sbci_aggregator IS
    'W5 cross-tenant read role: created in 0015 with no privileges; the W5 migration adds the SECURITY DEFINER aggregation function and grants EXECUTE on it.';

-- ===========================================================================
-- Staging-window guard: keep the single login principal (sbci_svc) working the
-- instant the new image deploys, before the deploy script provisions the two
-- dedicated login roles. Guarded so a cluster without sbci_svc (tests, a fresh
-- prod) is a clean no-op.
-- ===========================================================================
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sbci_svc') THEN
        GRANT sbci_api    TO sbci_svc;
        GRANT sbci_worker TO sbci_svc;
    END IF;
END$$;

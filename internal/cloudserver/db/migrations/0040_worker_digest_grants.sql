-- 0040_worker_digest_grants.sql — close the production project-digest
-- permission gap found 2026-09-17: the worker process (`SET LOCAL ROLE
-- sbci_worker`, see internal/cloudserver/store/store.go's setLocalRoleSQL)
-- runs the weekly project-digest scheduler
-- (internal/cloudserver/jobs/digest_scheduler.go ->
-- store.ListProjectDigestCandidates -> store.LoadProjectDigestEvidence ->
-- store.ResolveRouteForFeature -> store.SubmitDigestJob) and then executes the
-- leased job (internal/cloudserver/jobs/digest.go ->
-- store.CompleteDigestJobWithResult). Live log:
--
--   load digest evidence failed err="cloudserver/store.LoadProjectDigestEvidence:
--   ERROR: permission denied for table cloud_sessions (SQLSTATE 42501)"
--
-- Root cause. 0015_role_split.sql (line 127, the sbci_api grant block) gave
-- cloud_sessions to sbci_api ONLY. The digest read path added later by
-- 0037_project_digest.sql — LoadProjectDigestEvidence, store/digest.go line
-- 108 — joins cloud_sessions directly under whatever role the CALLER runs
-- as; it is NOT reached through the SECURITY DEFINER
-- sbci_project_digest_candidates function (which already carries its own
-- sbci_defs-owned SELECT grants on cloud_sessions/cloud_projects, granted by
-- 0037 alongside that function). So sbci_worker hit 42501 the first time a
-- plus_beta account produced a real digest candidate — nothing before that
-- had ever exercised this exact query under the worker role.
--
-- Reading every statement on the LoadProjectDigestEvidence ->
-- ResolveRouteForFeature -> SubmitDigestJob -> LeaseNextJob ->
-- CompleteDigestJobWithResult call path (the exact chain the production log
-- shows, and the chain internal/cloudserver/db's
-- TestWorkerDigestGrantsFixTheProductionDefect drives end to end under
-- store.RoleWorker) turned up eight further gaps on the SAME path, all
-- unnoticed for the same reason — no plus_beta account had produced a real
-- digest candidate before now:
--
--   * account_plans / plans — store/plans.go's resolvePlanTx (line 171,
--     reached from reserveDigestAllowanceTx, store/reserve.go line 122) runs
--     `SELECT ... FROM account_plans ap JOIN plans p ...` directly (not
--     through any SECURITY DEFINER function); sbci_worker held no grant on
--     either table. The same function's free-plan fallback (loadPlanTx,
--     store/plans.go line 143) also reads `plans` directly.
--   * analysis_jobs — store/jobs.go's SubmitDigestJob (line 553) does
--     `INSERT INTO analysis_jobs ...`; 0015 gave sbci_worker only SELECT,
--     UPDATE (the lease/run/complete path) — job submission was always the
--     API's job before W5 added this server-internal submitter.
--   * usage_reservations — store/reserve.go's reserveForAllowanceTx (line
--     170) does `INSERT INTO usage_reservations ...`; 0015 gave sbci_worker
--     only SELECT, UPDATE (the settle/release path).
--   * usage_cycles — store/reserve.go's reserveCycle (line 197) does
--     `INSERT INTO usage_cycles ... ON CONFLICT DO NOTHING`; 0015 gave
--     sbci_worker only SELECT, UPDATE (the settle/release path).
--   * evidence_objects — store/evidence.go's createEvidenceTx (line 66) does
--     `INSERT INTO evidence_objects ... RETURNING id`; 0015 gave sbci_worker
--     only SELECT, UPDATE (the lease-time TTL check + the
--     completion/purge mark-deleted path).
--   * evidence_blobs — store/blob.go's putEvidenceBlobTx (line 98) does
--     `INSERT INTO evidence_blobs ...`; 0015 gave sbci_worker only SELECT,
--     DELETE (the open-under-lease + purge-on-completion path).
--   * cloud_projects — found by the 2026-09-17 adversarial review of this
--     migration's FIRST cut, which stopped at SubmitDigestJob and missed the
--     COMPLETION half of the same worker lease. store/results.go's
--     completeJobWithResultTx (line 138) calls ensureProjectTx
--     (store/evidence.go line 17: `INSERT INTO cloud_projects ...
--     ON CONFLICT ... DO UPDATE ... RETURNING id`) whenever the result kind
--     carries a CloudProjectID — and CompleteDigestJobWithResult
--     (store/results.go line 79) ALWAYS sets it. 0015 gave cloud_projects to
--     sbci_api only (line 126); 0019 added api/app DELETE; 0037 added an
--     sbci_defs SELECT. sbci_worker held nothing. Left unfixed, the worker
--     would resolve evidence, pay for Luna inference, and only then abort at
--     commit — twice per lease, since the job is retried.
--   * accounts — store/jobs.go's SubmitDigestJob (line 514) does
--     `SELECT status FROM accounts WHERE account_id = $1::uuid FOR UPDATE`
--     (the FE4 deletion-fence lock, identical to SubmitJob's). Acquiring a
--     row lock via FOR UPDATE needs the UPDATE privilege on the table beyond
--     plain SELECT (verified empirically against this exact query: a
--     REFERENCES-only grant — sometimes cited as sufficient for FOR-UPDATE
--     locking — still 42501'd here). 0015 gave sbci_worker only SELECT on
--     accounts, so the row lock itself was denied with 42501 (a caller never
--     even reaches the RLS-scoped status check).
--
-- accounts is NOT RLS-protected — state this plainly, because this
-- migration's first cut claimed the opposite. `accounts` is listed under
-- "System (non-RLS) control-plane tables" in 0004_rls_grants.sql line 55 and
-- no migration since has run ENABLE ROW LEVEL SECURITY on it (pinned by
-- store/rolesplit_test.go's relrowsecurity assertion, CLOUD-RBAC-1). So a
-- table-level `GRANT UPDATE ON accounts` would have been an unrestricted,
-- all-column, ALL-ROWS write grant for the worker plane — the widest thing in
-- this migration by a wide margin, and the only grant here not confined by a
-- tenant policy. PostgreSQL requires UPDATE on at least ONE column to take a
-- FOR UPDATE row lock, so the narrowest shape that still lets the FE4 fence
-- lock the row is a COLUMN-level grant, and that is what ships:
-- `GRANT UPDATE (updated_at) ON accounts` (accounts.updated_at,
-- 0002_core_schema.sql line 30). Proven sufficient on a live PostgreSQL 16
-- rig by internal/cloudserver/db's TestWorkerDigestGrantsAccountsColumnGrant,
-- which revokes exactly this grant, observes the 42501, re-applies this file
-- and watches SubmitDigestJob succeed. The worker still writes no accounts
-- column on this path or any other already-shipped one; the blast radius of
-- the residual widening is one timestamp column.
--
-- Every OTHER table here already carries an RLS policy keyed off
-- sbci_current_account() with no role list in its USING/WITH CHECK clause
-- (0004/0013/0037 — cloud_projects and cloud_sessions are both in 0004's
-- tenant_tables array, ENABLE + FORCE), so for those a plain GRANT is the
-- whole fix: RLS still confines every row to the account the worker's
-- transaction is scoped to.
--
-- sbci_app (the single-role dev/test/operator fallback, 0001) already holds
-- every one of these grants — this migration only widens the split-role
-- sbci_worker (E2 / W6rs, 0015) to match what its own runtime path needs.
--
-- No existence guard. Unlike 0015/0022's staging-window blocks (which grant
-- role MEMBERSHIP to the possibly-absent LOGIN service principals sbci_svc /
-- sbci_worker_svc, wrapped in `IF EXISTS (SELECT 1 FROM pg_roles WHERE
-- rolname = ...)`), sbci_worker itself is a cluster role created
-- unconditionally by 0015 — every migration reaching this point has already
-- run 0015 — so a plain GRANT needs no such wrapper here, exactly like every
-- other direct `TO sbci_worker` grant already in the lineage: 0018's
-- analysis_results column grant, 0023's community_band_snapshots grant, and
-- 0037/0038's sbci_sweep_results_retention / sbci_project_digest_candidates
-- EXECUTE grants are all unconditional too — none of them guard the
-- sbci_worker target's existence, only the separately-named service roles
-- get that treatment.

-- Read path (LoadProjectDigestEvidence).
GRANT SELECT ON cloud_sessions TO sbci_worker;

-- Plan resolution (resolvePlanTx / loadPlanTx, reached from
-- reserveDigestAllowanceTx).
GRANT SELECT ON account_plans TO sbci_worker;
GRANT SELECT ON plans         TO sbci_worker;

-- The FE4 deletion-fence row lock (SubmitDigestJob's `... FOR UPDATE`) needs
-- UPDATE privilege beyond plain SELECT to acquire the lock at all. accounts
-- has NO RLS, so this is deliberately COLUMN-level — the narrowest grant that
-- still permits the lock (see the header comment).
GRANT UPDATE (updated_at) ON accounts TO sbci_worker;

-- Reservation + job + evidence writes (SubmitDigestJob's own transaction).
GRANT INSERT ON analysis_jobs      TO sbci_worker;
GRANT INSERT ON usage_reservations TO sbci_worker;
GRANT INSERT ON usage_cycles       TO sbci_worker;
GRANT INSERT ON evidence_objects   TO sbci_worker;
GRANT INSERT ON evidence_blobs     TO sbci_worker;

-- The COMPLETION half of the same worker lease: ensureProjectTx's
-- INSERT ... ON CONFLICT DO UPDATE ... RETURNING id needs all three
-- (INSERT for the new row, UPDATE for the conflict branch, SELECT for
-- RETURNING and for the RLS policy's own USING read). RLS-confined.
GRANT SELECT, INSERT, UPDATE ON cloud_projects TO sbci_worker;

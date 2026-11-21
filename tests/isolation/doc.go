// Package isolation is the cross-tenant isolation suite (managed SaaS plan 06
// section 12.1, plan 07 M5.10), the suite the GO-2 gate runs. It has no
// non-test code: every test runs against a pooled-mode PostgreSQL template
// clone of its own (dbtest.NewPostgresDSN, then sbo_tenancy_pool(), as
// `observer-org migrate` converts a new pooled database), with two team orgs
// (org-a, org-b) and one personal org (org-p). Each org acts through the
// tenant runtime login (a throwaway member of <p>_rt, so it holds exactly the
// runtime role's privileges and policies), on connections tagged
// application_name = 'org:<id>'; the tag is bookkeeping, the signed context
// is the only authority. Every test owns its database, and every test is
// parallel except the three that set the environment or count goroutines
// (see the end of this comment); the suite takes its time from seeding
// (about 5 s per clone), the sweep and the pooled server boots.
// The tests need OBSERVER_CONTROL_STORE_DSN like every dbtest fixture, so the
// package is an @pg unit of testrunner gate (scripts/ci/org-postgres-suite.tsv
// derives it from its dbtest.NewPostgresDSN call).
//
// # Built
//
// Window 1 (wave 10):
//
//   - Group 1, fixtures (seed_test.go, gaps_test.go, TestFixtureGaps): a
//     generator reads the tenancy manifest and the live catalog and seeds one
//     row of every T table for each org with no per-table SQL (types, CHECK
//     literals, foreign-key parents), plus a small table of hand-written rules
//     for tables whose CHECKs tie columns together (fixtureRules). A table
//     with no rule fails; fixtureGaps is the shrinking list of tables still
//     without one and it is kept here, never in the manifest: a table that
//     cannot be seeded and is not listed fails, and so does a listed table
//     that now seeds.
//   - Group 2, table sweep (sweep_test.go, TestTableSweep): for every T table
//     and every attacker org, reads return only the attacker's rows,
//     UPDATE and DELETE aimed at another org's rows touch none, moving a row
//     to another org and INSERT / INSERT ON CONFLICT (nothing, update) of a
//     copy as another org are refused by row-level security (42501), a
//     connection with no context reads nothing, the runtime login holds no
//     TRUNCATE, REFERENCES or TRIGGER privilege, row-level security is
//     enabled and forced, and the superuser's counts do not move.
//     TestSweepDetectsABrokenPolicy is the negative control (an open policy
//     must be reported).
//   - Group 3, role attacks (roles_test.go): the shared attack kit
//     (tenantctx/attacktest) against a real tenant table, every forged,
//     expired and cross-kind token across every T table, the runtime login's
//     escalation attempts on the real schema, and the SECURITY DEFINER
//     functions' posture and callability.
//   - Group 6, workers, the stale-leader half (fence_test.go): a writer with an
//     old lease_gen is refused through tenantdb.Fenced on the real
//     tenant_job_state table and periodic.PGStore, an expired lease is
//     refused, and an org's fence cannot borrow another org's claim.
//   - Group 8, object store (orgobj_test.go): read, list, delete, replace, put
//     and presign across orgs in every namespace through orgobj.Handle,
//     look-alike org ids, hand-crafted key spellings and a backend that
//     answers outside the request.
//
// Window 2 (wave 11; handback docs/plans/managed-saas/w11/
// isolation-handback.md):
//
//   - Group 4, the route walker (server_test.go, routes_test.go): the real
//     pooled org server (orgserver.New, [platform].tenancy = pooled, role
//     api) on a seeded clone, every route of the pooled inventory
//     (pooledroutes.Routes) walked as org A's admin on org A's host under
//     cookie and bearer authentication with org B's and org P's ids in the
//     path, query and body; a response carrying another org's value, or any
//     change to another org's rows, fails. TestRouteWalker holds the
//     on-seam, platform and refused rows; TestRouteWalkerNotYetOnSeam (ISO-1)
//     and TestRouteWalkerRefusedInPooled (ISO-2) require every not-yet-on-seam
//     and refused-in-pooled route to answer the pooled route gate's refusal
//     (internal/orgserver/pooledgate, wave 12) or not to be mounted at all.
//     TestWalkerDetectsALeak is the negative control. The write-leak digest
//     window holds the server's clock-driven writers of class T rows (the
//     quota pass and the availability reconciler,
//     orgserver.Server.HoldPeriodicWriters) and keeps every column of every
//     T table: TestRouteWalkerHoldsPeriodicWriters (walker_hold_test.go)
//     forces a quota pass inside the window and requires it to stay out
//     while a leaking route's write is still reported (the 2026-11-19 ops
//     gate flake, org_quota_state in TestRouteWalkerSecurityFamilies).
//     TestPooledServerBootsOnTheHostLogin proves the server's control and
//     data stores run on a member of <p>_host, never a login past row-level
//     security (ISO-1's boot half, wave 12).
//   - Group 5, token crossings (tokens_test.go, TestTokenCrossings): AS-1
//     (host-scoped per-org session cookies refused on every other org's
//     host, forged and shared-key cookies too), AS-2 (no node bearer served
//     across hosts on any node-rail route), AS-11b (an invitation is unknown
//     to every other org; one platform subject bound in two orgs resolves
//     per org) and AS-21 (the shared single-use sign-in transaction across
//     two replicas, concurrent callbacks, replays and other orgs).
//   - Group 6, workers, the org-assertion half (scheduler_test.go): two
//     replicas of the real scheduler run instrumented ticks asserting the
//     context org, own-only visibility over every T table and refused
//     foreign writes, plus a hostile job; each (org, job) runs once.
//   - Group 7, the log (log_test.go): the log refuses a record whose org and
//     subject disagree; an org's apply worker parks every other org's record
//     under that org with an org-mismatch reason and applies none of it. The
//     pooled sharded apply (plan 07 M5.6) applies each org's own record in
//     that org's tenant transaction (a row claiming another org lands under
//     the record's), quarantines poison in the org's own quarantine and drops
//     a purged org's record; a record that cannot apply parks in apply_parked
//     (host login only), the org's next record parks behind it, and the
//     operator's re-drive applies them oldest first under their own order
//     positions once the fault heals; a blocked org leaves the others
//     applying and the trim floor reaches the stream's end once it parks.
//   - Group 9, caches, global state and leaks (caches_test.go): one keyring
//     keeps each org's session key apart through a rotation; the org
//     identity cache answers no tenant another's identity and pins nothing on
//     a pooled database; per-org runtimes on real pools leave no goroutine or
//     connection after eviction (settle-and-compare: goleak is not in
//     go.mod).
//   - Group 10, lifecycle (lifecycle_test.go): the move and admin exports
//     carry only org A's rows and the allow-listed columns; the real purge
//     removes org A from every T table and object namespace while org B and
//     org P stay byte for byte; a restore never merges into the shared
//     database, restores exactly onto a fresh pooled one, and the re-run
//     purge leaves nothing.
//   - Group 11, revoked-state races (lifecycle_test.go, runtime_test.go): a
//     purge whose lifecycle generation moves stops at its next batch, and an
//     in-flight request is drained before the purge deletes, with a runtime
//     built below the new generation refused.
//
// Later windows (each test file names its lane; not parallel unless it says
// otherwise):
//
//   - The node rail on the pooled seam: wave 14 (node-rail, per-organization
//     bearer keys, enrolment, push, update) and wave 15 (node-rail-2,
//     agentpolicy_test.go: the agent policy pull with its auto-halt, the
//     ack and the version probe). Group 5's AS-2 (crossBearer) now runs
//     against per-organization bearers on every node-rail route.
//   - Wave 16 (node-rail-3, noderail3_test.go): the node-rail leftovers
//     (POOLRT-47). The fleet boards and the machine identities on the
//     request seam (each org's admin served its own rows only, its session
//     refused on the other org's host), the collector rail, the
//     vendor-export receiver and the cloud-session ship token on the node
//     rail's binding (each credential resolved on its own org's host only),
//     data-version as a platform route and server-info refused in pooled.
//   - The pooled worker's per-org jobs (job_*_test.go, collector*_test.go,
//     worker_test.go), including wave 16's hot-window, pricing feed,
//     stream engines and intel digest mail jobs.
//   - Wave 16 (pricing-window, pricing_test.go): the pricing family and the
//     signed GET /api/agent/pricing per org. Wave 16 (support-oplog-2,
//     support_test.go): support sign-in on a pooled api with two orgs
//     through the real issuer.
//   - Wave 16 (iso-oracle, oracle_test.go and oracle_registry_test.go): the
//     per-route count oracle. Every on-seam GET has a registry row, judged
//     against org A's totals or listed Blind or NotServed with a reason;
//     the wave 16 and wave 17 lanes' moved routes got their rows at the
//     integration merge (2026-11-16).
//   - Wave 17 (pooled-security, security_test.go): the security families
//     on the walker and a session refused on another org's host. The other
//     wave 17 route lanes (agent-access, integrations, sandbox, coding,
//     messaging, scim) are covered by the route walker and the oracle.
//
// # Not yet built (skipped with the reason)
//
//   - Group 10: the org-server deletion journal read by the restore-time
//     reconciliation (plan 06 5.3.10 step 5).
//   - Group 11: suspension enforcement on the request path, and a purge with
//     no drain in front of it (purge step 1 is not wired).
//   - Group 5, AS-2 for the node-rail families still on the allow-list
//     (agent-intel, the security and sandbox node routes): their rows answer
//     the pooled route gate's refusal on every host until they move.
//   - The hostile-org load case.
//
// # The hosted sign-in journey (not an isolation group)
//
// TestHostedSignInJourney (hosted_signin_journey_test.go) lives here because
// this package holds the pooled org server harness: it walks a new person
// from the website's "Get started" through the real console (cloudtestpg,
// a fake AuthKit, the platform issuer) to a personal and a team dashboard on
// the pooled server, plus a degraded account rail and a self-hosted org's
// rail set, and checks the /auth/rails views web2's sign-in page is tested on
// (web2/src/lib/testdata/hosted-signin/auth-rails.json). Without
// SBCI_TEST_PG_DSN its console uses this package's DSN.
//
// The tests that boot the pooled server (TestRouteWalker*,
// TestPooledServerBootsOnTheHostLogin, TestTokenCrossings,
// TestAgentPolicyRailStaysInTheHostOrg, TestNodeRail3RoutesStayInTheHostOrg,
// TestSupportSignInPooledTwoOrgs, TestHostedSignInJourney, TestCountOracle,
// TestSecurityRoutesRefuseAnotherOrgsSession, the pooled collector and
// worker tests)
// and the leak row (TestCachesAndGlobalState) are not
// parallel: orgserver.New reads its store DSNs and the tenant-context key
// from the environment (t.Setenv), and the leak row reads the process-wide
// goroutine count. They run before the parallel tests start.
package isolation

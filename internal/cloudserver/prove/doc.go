// Package prove is the OPERATOR-ONLY, FIXTURE-ONLY Foundry proving lane
// (remediation plan §3 W3a / divergence E3, FA3).
//
// # What it is for
//
// Before any real developer evidence may reach the provider, the operator must
// be able to demonstrate that the whole inference path actually works end to
// end: route resolve → ContentLogging attestation → dialect verification →
// Foundry call → normalize/scrub/ground. That demonstration cannot be done with
// customer evidence (there is no approval yet), and it must not be done with a
// parallel re-implementation (a copy proves the copy, not the shipped path).
//
// So this package drives the SAME pipeline stages the production worker runs —
// jobs.BuildLunaPrompt, jobs.BuildLunaRequest, jobs.ProcessLunaCompletion, the
// real jobs.ProviderAttestor, the real store route/dialect reads — over a
// SERVER-MINTED fixture catalog compiled into the binary.
//
// # The compliance boundary (review finding 4)
//
//   - The fixture catalog is COMPILED IN. No fixture is ever accepted from any
//     client, request body, file path, or environment variable. There is no
//     `accounts.proving` flag and no request attribute that selects this lane:
//     an ordinary account's admission path is untouched and REMAINS
//     credential-absent pre-approval.
//
//   - The provider credential is an EXPLICIT parameter (Options.FoundryAPIKey).
//     This package never constructs or consults the worker's credential seam,
//     and reads NO environment at all (it does not import "os"), so it cannot
//     pick up the worker's own key variable — the production worker's
//     credential-ABSENCE boundary is untouched while a proving run is in
//     flight. The separation is structural, not procedural, and is pinned by
//     the credential-separation tests in prove_test.go (a source scan for the
//     worker's seam plus a reflective check that Options can carry only a
//     plain string credential).
//
//   - A proving run is NOT a job. It leases nothing, reserves nothing, writes no
//     analysis_jobs / evidence_objects / results row, and touches no tenant
//     table at all. Its own only write is one content-free, system-scoped
//     security_audit_events row through the injected Auditor.
//
//   - The lane can only ever act on a NON-PRODUCTION route. Step 2 fails closed
//     unless route_registry.environment = 'nonproduction', and the production
//     worker's own revalidate() refuses exactly that value. The column DEFAULTS
//     to 'production' (migration 0014), so a route nobody classified — including
//     the real one — is provable by nobody and serviceable by the worker. The two
//     lanes' route sets are therefore DISJOINT BY CONSTRUCTION, not by
//     convention.
//
//     That disjointness is what makes the next bullet acceptable.
//
//     One system-table write does happen INSIDE an injected dependency, and it
//     is deliberate: in production the Attestor is the worker's own
//     jobs.AttestationGate, which persists the ARM ContentLogging verdict to
//     route_attestations (and may serve a fresh cached one). That is the point
//     of reusing the real gate rather than a copy — the proving run attests the
//     same way the worker does, with the same code, against the same table.
//
//     The cache is SHARED, and stays shared, for one reason only: its rows are
//     keyed by route_id, and after the environment partition above no route_id is
//     readable by both lanes. A proving run therefore cannot write an attestation
//     record that a production execution will ever read, or read one a production
//     execution wrote. A separate cache would add a second owner of the same
//     state to buy a property the partition already guarantees. If that partition
//     is ever weakened, this reasoning goes with it and the lane needs its own
//     cache. Both tables are system tables; no tenant row is involved either way.
//
//   - Every gate is fail-closed exactly as the worker's is: an unresolvable,
//     INACTIVE, or production-classified route, an unverified attestation, or a
//     missing dialect verification record stops the run before any provider call.
package prove

// Package secassesssvc is the I/O half of the agent-run security assessments
// module (docs/plans/security-assessments-module-plan-2026-11-13.md): the one
// owner of the node's record of assessment runs (secassess-runs.json beside
// the node database), the confined reader of the result files an agent writes
// into the project, and the import of a run's findings through an injected
// function that is the existing SARIF import seam.
//
// It has no HTTP and no dashboard types: the dashboard's routes
// (internal/intelligence/dashboard/security_assess.go) call it through the
// functions here and hand it plain values. It imports the standard library,
// internal/secassess (the pure core) and internal/fsatomic only, so it adds
// no edge to the security component or to security.dast.
//
// The run record is a file, not a table, for the internal/secfixstate reasons:
// nothing joins against it, a lost file only loses the history (the findings
// an import recorded stay), it needs no migration, and it is node-local by
// construction (nothing here is reachable from the org push seam).
package secassesssvc

// Package secfixstate is the ONE owner of the node's record of "Fix with an
// agent" launches (docs/plans/fix-findings-with-agent-plan-2026-11-13.md
// section 6): which agent was started in which project on which findings, so
// the Code security page can show whether those findings cleared on a later
// rescan. A small JSON file beside the node database, secfix-attempts.json,
// written atomically (internal/fsatomic).
//
// It is a file, not a table, for the internal/firstrunstate reasons: nothing
// joins against it, a lost file only loses the history, it needs no
// migration, and it is node-local by construction (nothing here is reachable
// from the org push seam). An attempt never changes a finding: its state is
// read live from the findings store, so the scan and fix-observation loop
// stays the only thing that closes one.
package secfixstate

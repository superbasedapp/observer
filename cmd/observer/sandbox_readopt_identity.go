//go:build !sbo_omit_terminals_sandbox_oci_readopt && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import "github.com/marmutapp/superbased-observer/internal/sandboxrelayd"

// sandbox_readopt_identity.go resolves the stored terminal run a re-keyed
// relay record carries (tracker F-053). The compose keeps the run's relay
// facts (readoptKeep) before the launcher binds the relay run to the
// terminal run it spawns (bindSandboxRelayRun), so the kept facts name no
// terminal run. A re-key built from them alone wrote a record with none,
// and the daemon then keyed the run's refusal rows, drop counts and capture
// health by the container's run id with no backend or tier, so one run's
// rows before and after a re-adoption could not be joined. The re-key is
// the one seam that writes the re-adopted record; it asks this resolver.

// readoptTerminalRun is the terminal run a re-keyed record of runID
// carries: the kept one when the compose saw a bound record, else the one
// the run's current relay record was bound to (it is still on disk when the
// re-adoption claims the run: the dead-run hold keeps it), else none.
func readoptTerminalRun(observerDir, runID, kept string) string {
	if kept != "" {
		return kept
	}
	if rec, err := sandboxrelayd.ReadRun(observerDir, runID); err == nil {
		return rec.TerminalRunID
	}
	return ""
}

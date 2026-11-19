//go:build (linux || darwin) && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

// sandboxLocalLedgerPathForTest is the host helper's own ledger path.
func sandboxLocalLedgerPathForTest(observerDir, runID string) string {
	return placeholderLedgerPath(observerDir, runID)
}

//go:build !linux && !darwin && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

// sandboxLocalLedgerPathForTest is "" where no host helper writes a ledger.
func sandboxLocalLedgerPathForTest(string, string) string { return "" }

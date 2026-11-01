//go:build darwin && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

// recordMac writes what the macOS host helper created into its ledger (a nil
// ledger records nothing); the ledger itself, its format and the start sweep
// are sandbox_placeholder_ledger_unix.go, shared with Linux (ledger
// SBX-MAC-4).
func (l *placeholderLedger) recordMac(made []macPlaceholder) error {
	entries := make([]placeholderLedgerEntry, 0, len(made))
	for _, m := range made {
		entries = append(entries, placeholderLedgerEntry{Path: m.path, Dir: m.dir, Dev: m.dev, Ino: m.ino, Content: m.content})
	}
	return l.recordEntries(entries)
}

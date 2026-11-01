//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

// record writes what the Linux host helper created into its ledger (a nil
// ledger records nothing); the ledger itself is
// sandbox_placeholder_ledger_unix.go.
func (l *placeholderLedger) record(created []createdPlaceholder) error {
	entries := make([]placeholderLedgerEntry, 0, len(created))
	for _, c := range created {
		entries = append(entries, placeholderLedgerEntry{Path: c.path, Dir: c.dir, Dev: c.dev, Ino: c.ino, Content: c.content})
	}
	return l.recordEntries(entries)
}

//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

// [terminal.sandbox.setup] (sandbox installation lifecycle plan, P-250) is
// the developer's own consent to type their password into a setup
// terminal: an organization has no fleet-wide value for it and can never
// turn it on, so it is local-only. Its node home is the Sandbox isolation
// card (lane ui: the card edits draft.setup).
func init() {
	sandboxSettingsInventory["setup"] = adminHome{Local: "the developer's own consent to run an elevated setup step in a setup terminal where they type their password; an org has no fleet-wide value and can never turn it on"}
}

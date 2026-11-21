//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import "github.com/marmutapp/superbased-observer/internal/sandbox"

// sandbox_cred_local_reopen_seam_linux.go is the re-adoption seam of
// credential injection for local runs (tracker row F-004, finding F-N3-2):
// a re-adopted oci run's new helper re-opens the lane the run's own helper
// opened, so its model-proxy forward stamps the run again and the box's
// sentinel keeps being swapped for the key. The hook is nil unless the
// credentials files are compiled (sandbox_cred_local_linux.go sets it).

// localCredReopenHook re-opens a re-adopted run's lane from its injection
// record. It returns "" when the lane is open again or the run had no
// local lane, and otherwise the reason it stays closed (the box's sentinel
// then reaches the provider unswapped and is refused, fail closed).
var localCredReopenHook func(h sandbox.HostArgs) string

// localCredReopen applies localCredReopenHook ("" when unset).
func localCredReopen(h sandbox.HostArgs) string {
	if localCredReopenHook == nil {
		return ""
	}
	return localCredReopenHook(h)
}

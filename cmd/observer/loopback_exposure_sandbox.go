//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import "github.com/marmutapp/superbased-observer/internal/sandboxbackend"

// sandboxRowHostLoopbackRelay reports the registry capability the loopback
// exposure rule X3 reads (loopback_exposure.go, ledger LAUNCH-1): the
// backend row's relay rides the host's loopback, so its box reaches every
// loopback listener of the host (the MXC rows). Looked up here, behind the
// sandbox component's build tag, so a build without the sandbox does not
// link the registry; terminal_sandbox_omit.go answers false there (no box
// can be live).
func sandboxRowHostLoopbackRelay(backend string) bool {
	row, ok := sandboxbackend.Get(backend)
	return ok && row.Capture.Relay == sandboxbackend.RelaySingleLoopbackPortToken
}

// sandboxRowDeniesObserverPorts reports the registry capability the
// exposure rule X2 reads: the row's own enforcement refuses every Observer
// listener (the Landlock row), so its box cannot reach the dashboard.
func sandboxRowDeniesObserverPorts(backend string) bool {
	row, ok := sandboxbackend.Get(backend)
	return ok && row.Net.DeniesObserverPorts
}

// sandboxRowTreeContained reports the registry capability the caller check
// reads (loopback_caller.go): the row DECLARES that its box's processes
// stay descendants of its root (sandboxbackend.Capability.TreeContained,
// the bwrap row only); it is never inferred from the /proc view, which the
// OCI rows share with bwrap although their processes run under a shim.
func sandboxRowTreeContained(backend string) bool {
	row, ok := sandboxbackend.Get(backend)
	return ok && row.TreeContained
}

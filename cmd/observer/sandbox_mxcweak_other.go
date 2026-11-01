//go:build !windows && !sbo_omit_terminals_sandbox_mxc_appcontainer && !sbo_omit_terminals_sandbox_mxc && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"

	"github.com/marmutapp/superbased-observer/internal/sandboxmxc"
)

// mxcWeakGather off Windows stops at the ladder's platform row.
func mxcWeakGather(context.Context, *sandboxRuntime) sandboxmxc.ProbeResult {
	return sandboxmxc.Probe(sandboxmxc.HostFacts{Windows: false, Active: true}, sandboxmxc.ManifestX64)
}

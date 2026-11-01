//go:build windows && !sbo_omit_terminals_sandbox_mxc_appcontainer && !sbo_omit_terminals_sandbox_mxc && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxmxc"
)

// mxcWeakGather runs mxc-process's own probe helper (the library is loaded
// there, never in the daemon) and keeps the tier it reports.
func mxcWeakGather(ctx context.Context, r *sandboxRuntime) sandboxmxc.ProbeResult {
	timeout := mxcDefaultProbeTimeout
	if s := r.cfg.MXC.ProbeTimeoutSeconds; s > 0 {
		timeout = time.Duration(s) * time.Second
	}
	return mxcProbeRunner(ctx, r.observerBin, r.observerDir, timeout)
}

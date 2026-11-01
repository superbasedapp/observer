//go:build !sbo_omit_terminals_sandbox_mxc_appcontainer && !sbo_omit_terminals_sandbox_mxc && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxmxc"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
)

// sandbox_mxcweak.go is the mxc-appcontainer row (lane GATES-SBX decision
// 5): MXC's weaker AppContainer tier, through the same probe helper and
// files as mxc-process (whose code is unchanged), judged by
// internal/sandboxmxc's per-row tier set (exactly appcontainer-bfs; the
// DACL tier refused). Probe-only in this release.

const mxcWeakComponent = "terminals.sandbox.mxc.appcontainer"

func init() {
	registerSandboxDriver(sandboxDriverReg{
		backend: sandboxbackend.BackendMXCAppContainer, component: mxcWeakComponent,
		build: func(r *sandboxRuntime, _ config.Config) sandboxDriver {
			return &gatesProbeOnlyDriver{
				r: r, id: sandboxbackend.BackendMXCAppContainer, probeFn: mxcWeakProbe,
				notBuilt: "the run path for MXC's appcontainer-bfs tier is not built in this release (beta, probe only; register WIN-4, WIN-9)",
			}
		},
	})
}

// mxcWeakJudge turns the MXC probe helper's answer into the row's verdict:
// the organization's windows.mxc_tier pin first, then the tier rule, then
// the probe-only refusal.
func mxcWeakJudge(pin sandboxmxc.TierPin, res sandboxmxc.ProbeResult) sandboxselect.Probe {
	if !sandboxmxc.PinAllowsRow(pin, sandboxbackend.BackendMXCAppContainer) {
		return sandboxselect.Probe{Verdict: sandboxselect.VerdictBackendNotAllowed, Reason: "terminal.sandbox.windows.mxc_tier is " + string(pin) + " (set here or pinned by your organization), which keeps this machine off MXC's weaker AppContainer tier"}
	}
	if res.Tier == "" {
		return sandboxselect.Probe{Verdict: res.Verdict.Code, Reason: res.Verdict.Reason}
	}
	no := false
	if v := sandboxmxc.TierVerdict(sandboxmxc.RowMXCAppContainer, sandboxmxc.ProbeOutput{Tier: res.Tier, NeedsDaclAugmentation: &no}); !v.OK() {
		return sandboxselect.Probe{Verdict: v.Code, Reason: v.Reason}
	}
	return sandboxselect.Probe{
		Verdict: sandboxselect.VerdictBackendVersionUntested, Version: res.Version,
		Reason: "MXC offers its appcontainer-bfs tier on this host (weaker than ProcessContainer); the run path for it is not built in this release (probe only; register WIN-4, WIN-9)",
	}
}

// mxcTierPinInForce is the windows.mxc_tier floor in force on this node
// (R-034): [terminal.sandbox.windows].mxc_tier after config.Load applied
// any organization pin on its governance row (restrictive-only, so an org
// can only hold it on process_container). "" is no floor.
func mxcTierPinInForce(cfg config.TerminalSandboxConfig) sandboxmxc.TierPin {
	return sandboxmxc.TierPin(cfg.Windows.MXCTier)
}

// mxcWeakProbe runs the probe helper (on Windows) and judges its answer.
func mxcWeakProbe(ctx context.Context, r *sandboxRuntime) (sandboxselect.Probe, string) {
	res := mxcWeakGather(ctx, r)
	return mxcWeakJudge(mxcTierPinInForce(r.cfg), res), res.Version
}

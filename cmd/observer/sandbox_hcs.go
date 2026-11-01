//go:build !sbo_omit_terminals_sandbox_hcs && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxhcs"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
)

// sandbox_hcs.go is the hcs row (lane GATES-SBX decision 7): Hyper-V
// isolated containers through the HCS v2 compute system API. The daemon's
// probe reads only the edition, the two feature services and the configured
// image; computecore.dll is loaded only by a per-run helper, which this
// release never starts: no utility VM image can be pinned and verified
// without a release artifact, so the ladder refuses image_missing first.

const hcsComponent = "terminals.sandbox.hcs"

func init() {
	registerSandboxDriver(sandboxDriverReg{
		backend: sandboxbackend.BackendHCS, component: hcsComponent,
		build: func(r *sandboxRuntime, _ config.Config) sandboxDriver {
			return &gatesProbeOnlyDriver{
				r: r, id: sandboxbackend.BackendHCS, probeFn: hcsProbe,
				notBuilt: "the hcs run path is not built in this release (beta, probe only: no utility VM image is published yet; register WIN-10)",
			}
		},
	})
}

// hcsProbe gathers the daemon-side facts and walks the ladder.
func hcsProbe(_ context.Context, r *sandboxRuntime) (sandboxselect.Probe, string) {
	f := hcsGather(r.cfg.HCS)
	f.Active = true
	v := sandboxhcs.Probe(f)
	return sandboxselect.Probe{Verdict: v.Code, Reason: v.Reason}, ""
}

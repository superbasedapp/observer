//go:build !sbo_omit_terminals_sandbox_wslc && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"crypto/rand"
	"io"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote/relaymux"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
	"github.com/marmutapp/superbased-observer/internal/sandboxwslc"
)

// sandbox_wslc.go is the wslc row (lane GATES-SBX decision 6): WSL
// containers through the wslc CLI, tier none only, the capture relay over
// the run exec's stdio through relaymux (the hosted exec_stdio precedent:
// relaymux is called, never changed), the PTY under an Observer ConPTY with
// resize claimed until WIN-5. Probe-only in this release: the pinned wslc
// version's help and JSON are not recorded yet, so internal/sandboxwslc's
// ladder refuses every version.

const wslcComponent = "terminals.sandbox.wslc"

func init() {
	registerSandboxDriver(sandboxDriverReg{
		backend: sandboxbackend.BackendWSLC, component: wslcComponent,
		build: func(r *sandboxRuntime, _ config.Config) sandboxDriver {
			return &gatesProbeOnlyDriver{
				r: r, id: sandboxbackend.BackendWSLC, probeFn: wslcProbe,
				notBuilt: "the wslc run path is not built in this release (beta, probe only; register WIN-5 records the pinned version's help and JSON first)",
			}
		},
	})
}

// wslcProbe gathers the facts (on Windows) and walks the ladder.
func wslcProbe(ctx context.Context, r *sandboxRuntime) (sandboxselect.Probe, string) {
	f := wslcGather(ctx, r.cfg.WSLC)
	f.Active = true
	v := sandboxwslc.Probe(f)
	return sandboxselect.Probe{Verdict: v.Code, Reason: v.Reason, Version: f.Version}, f.Version
}

// wslcRelayKinds are the relay kinds a tier opens over the exec's stdio:
// none opens the capture relay only.
func wslcRelayKinds(tier vocab.Tier) map[string]bool {
	if tier == vocab.TierNone {
		return map[string]bool{relaymux.KindRelay: true}
	}
	return map[string]bool{}
}

// wslcServeRelay serves the home side of the run's capture relay over the
// run exec's stdio (stdio is `wslc exec --interactive <name> observer
// sandbox-guest ...`'s stdin and stdout), framed like the hosted rows'.
func wslcServeRelay(ctx context.Context, stdio io.ReadWriteCloser, runID string, secret []byte, tier vocab.Tier, dial func(context.Context, string) (io.ReadWriteCloser, error)) (*relaymux.Host, error) {
	return relaymux.ServeHost(ctx, wslcMuxConn(stdio), relaymux.HostOptions{
		Options: relaymux.Options{RunID: runID, Secret: secret}, Rand: rand.Reader,
		Kinds: wslcRelayKinds(tier), Dial: dial,
	})
}

// wslcMuxConn frames stdio as the relaymux line codec under the deadline
// adapter.
func wslcMuxConn(stdio io.ReadWriteCloser) sandboxrelay.Conn {
	return relaymux.NewDeadlineConn(relaymux.NewLineReader(stdio), relaymux.NewLineWriter(stdio), stdio.Close)
}

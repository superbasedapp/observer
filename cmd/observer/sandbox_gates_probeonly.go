//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// sandbox_gates_probeonly.go is the shared shape of lane GATES-SBX's three
// Windows rows (mxc-appcontainer, wslc, hcs; operator ruling P-129): each is
// a registered driver whose probe walks its own pure ladder on this host,
// and whose run is refused by name in this release (their run paths need
// the live checks of register WIN-4, WIN-5, WIN-9 and WIN-10 first). Nothing
// is probed while the row is not listed in [terminal.sandbox].backends.

// gatesProbeOnlyDriver is one probe-only row.
type gatesProbeOnlyDriver struct {
	r  *sandboxRuntime
	id string
	// probeFn walks the row's ladder (only while the row is listed).
	probeFn func(ctx context.Context, r *sandboxRuntime) (sandboxselect.Probe, string)
	// notBuilt is why a run is refused.
	notBuilt string
	ver      string
}

func (d *gatesProbeOnlyDriver) listed() bool {
	return slices.Contains(sandboxEnabledBackends(d.r.cfg), d.id) || d.r.forceBackend == d.id
}

func (d *gatesProbeOnlyDriver) probe(ctx context.Context) sandboxselect.Probe {
	if !d.listed() {
		return sandboxselect.Probe{Compiled: true, Verdict: sandboxselect.VerdictDisabledByConfig, Reason: d.id + " is not in [terminal.sandbox].backends"}
	}
	p, ver := d.probeFn(ctx, d.r)
	p.Compiled = true
	d.ver = ver
	return p
}

func (d *gatesProbeOnlyDriver) version() string { return d.ver }

// Create refuses every run: the row is probe-only in this release.
func (d *gatesProbeOnlyDriver) Create(context.Context, termsvc.PrepareRequest) (termsvc.CreateResult, error) {
	return termsvc.CreateResult{}, fmt.Errorf("terminal_sandbox: %s: %s", d.id, d.notBuilt)
}

func (d *gatesProbeOnlyDriver) Attach(context.Context, termsvc.CreateResult) (termsvc.AttachResult, error) {
	return termsvc.AttachResult{}, fmt.Errorf("terminal_sandbox: %s: %s", d.id, d.notBuilt)
}

func (d *gatesProbeOnlyDriver) notSupported() (termsvc.LifecycleResult, error) {
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictNotSupported, Detail: d.id + ": " + d.notBuilt}, nil
}

func (d *gatesProbeOnlyDriver) Resize(context.Context, termsvc.SandboxRun, uint16, uint16) (termsvc.LifecycleResult, error) {
	return d.notSupported()
}

func (d *gatesProbeOnlyDriver) Signal(context.Context, termsvc.SandboxRun, string) (termsvc.LifecycleResult, error) {
	return d.notSupported()
}

func (d *gatesProbeOnlyDriver) Copy(context.Context, termsvc.CopyRequest) (termsvc.LifecycleResult, error) {
	return d.notSupported()
}

func (d *gatesProbeOnlyDriver) Checkpoint(context.Context, termsvc.SandboxRun) (termsvc.LifecycleResult, error) {
	return d.notSupported()
}

func (d *gatesProbeOnlyDriver) Stop(context.Context, termsvc.SandboxRun, time.Duration) (termsvc.LifecycleResult, error) {
	return d.notSupported()
}

func (d *gatesProbeOnlyDriver) Destroy(context.Context, termsvc.SandboxRun) (termsvc.LifecycleResult, error) {
	return d.notSupported()
}

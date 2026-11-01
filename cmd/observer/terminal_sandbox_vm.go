//go:build !sbo_omit_terminals_sandbox_vm && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	"github.com/marmutapp/superbased-observer/internal/sandboxvm"
)

// terminal_sandbox_vm.go is the Cloud Hypervisor microVM driver (sandbox
// plan v2 sections 4.6, 11.3 and 13 P4; lane SBX-P4; beta, Verification =
// doc): each run is its own microVM with no network device, booted from
// Observer's signed guest image set, the guest helper holding the PTY over
// vsock on the relay mux's framing. The pure decisions (probe ladder, VM
// config, read-back, handshake, disk plans, sweep) are internal/sandboxvm's;
// the REST client is internal/sandboxvmm's; the Linux host helper and the
// guest init are terminal_sandbox_vm_linux.go; terminal_sandbox_vm_other.go
// refuses everywhere else. The driver registers from init, so no core
// function names it.
//
// The opt-in decision: the driver is its own component
// (terminals.sandbox.vm, inactive in every distro and with no [components]
// block, sandboxDriverOptIn); until the user selects it, turns
// [terminal.sandbox] on and lists "cloud-hypervisor" in backends, nothing
// opens /dev/kvm, stats a binary, reads the content store or touches the
// network.

// The driver's ids.
const (
	vmComponent  = "terminals.sandbox.vm"
	vmDriverName = "vm"
)

func init() {
	registerSandboxDriver(sandboxDriverReg{
		backend: sandboxbackend.BackendCloudHypervisor, component: vmComponent,
		build: newVMDriver,
	})
	registerVMHelpers()
	sandboxDaemonStartHooks = append(sandboxDaemonStartHooks, vmDaemonStartSweep)
}

// vmDaemonStartSweep sweeps at daemon start whenever the driver's runs dir
// exists, independent of the probe and of the driver's selection: a run
// left by a SIGKILLed helper is removed even after the driver was
// deselected or the host lost /dev/kvm, the VMM or the image set.
func vmDaemonStartSweep(observerDir string) {
	fi, err := os.Lstat(filepath.Join(vmStateRoot(observerDir), "runs")) //nolint:gosec // G703: the VM driver's own state dir under the observer dir
	if err != nil || !fi.IsDir() {
		return
	}
	go vmSweepFn(observerDir)
}

// vmSweepFn is the orphan sweep (a variable so a test can count it).
var vmSweepFn = vmSweep

// vmSweepEvery is how often a passing probe in the daemon sweeps again (a
// SIGKILLed helper's VMM dies with it by PR_SET_PDEATHSIG, but its run dir
// stays until a sweep).
const vmSweepEvery = 2 * time.Minute

// vmProbeEnvFn builds the probe ladder's I/O (a variable so a test can
// count its calls and stand the host in).
var vmProbeEnvFn = vmProbeEnv

// vmDriver is the microVM lifecycle service over one runtime.
type vmDriver struct {
	r   *sandboxRuntime
	cfg config.TerminalSandboxVMConfig

	mu     sync.Mutex
	last   sandboxvm.ProbeResult
	lastAt time.Time
	// sweptAt is when the orphan sweep last ran (zero: never).
	sweptAt time.Time
	// sources maps a created run to its workspace source until Attach
	// plans its return.
	sources sync.Map
}

func newVMDriver(r *sandboxRuntime, full config.Config) sandboxDriver {
	return &vmDriver{r: r, cfg: full.Terminal.Sandbox.VM}
}

// vmRow is the registry row.
func vmRow() sandboxbackend.Capability {
	row, _ := sandboxbackend.Get(sandboxbackend.BackendCloudHypervisor)
	return row
}

// listed reports whether cloud-hypervisor is among the enabled backends.
func (d *vmDriver) listed() bool {
	return slices.Contains(sandboxEnabledBackends(d.r.cfg), sandboxbackend.BackendCloudHypervisor)
}

// probe walks the ladder (cached for the probe TTL). Nothing runs while
// cloud-hypervisor is not listed.
func (d *vmDriver) probe(context.Context) sandboxselect.Probe {
	if !d.listed() {
		return sandboxselect.Probe{Compiled: true, Verdict: sandboxselect.VerdictDisabledByConfig, Reason: "cloud-hypervisor is not in [terminal.sandbox].backends"}
	}
	return vmSelectProbe(d.probeResult(), sourceIDs(d.r.sources()))
}

// vmSelectProbe maps a ladder answer onto the selection input (a refusal
// carries the row's minimum so S4 reports the probe's own verdict).
func vmSelectProbe(res sandboxvm.ProbeResult, sources []string) sandboxselect.Probe {
	p := sandboxselect.Probe{Compiled: true, Verdict: res.Verdict.Code, Reason: res.Verdict.Reason, Sources: sources}
	if res.Verdict.OK() {
		p.Version = res.Version
		return p
	}
	p.Version = vmRow().Control.Pins.RequiredMin
	return p
}

// version is the VMM major version the last probe read.
func (d *vmDriver) version() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.last.Version
}

// probeResult runs (or reuses) the ladder.
func (d *vmDriver) probeResult() sandboxvm.ProbeResult {
	d.mu.Lock()
	if !d.lastAt.IsZero() && time.Since(d.lastAt) < sandboxProbeTTL {
		res := d.last
		d.mu.Unlock()
		return res
	}
	d.mu.Unlock()
	env := vmProbeEnvFn(d.r, d.cfg)
	env.Active = d.listed()
	res := sandboxvm.Probe(env)
	d.mu.Lock()
	d.last, d.lastAt = res, time.Now()
	sweep := res.Verdict.OK() && d.r.inDaemon && (d.sweptAt.IsZero() || time.Since(d.sweptAt) >= vmSweepEvery)
	if sweep {
		d.sweptAt = time.Now()
	}
	d.mu.Unlock()
	if sweep {
		go vmSweepFn(d.r.observerDir)
	}
	return res
}

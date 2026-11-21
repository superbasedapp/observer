//go:build !sbo_omit_terminals_sandbox_seatbelt && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxenv"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/sandboxsbpl"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// terminal_sandbox_seatbelt.go is the macOS Seatbelt driver (sandbox plan v2
// sections 4.6, 11.3 and 13 P5; lane SBX-P5; beta, Verification = doc). The
// pure decisions (the profile, its checker, N6, the probe ladder and the
// self-test judge) are internal/sandboxsbpl's; the real sysctl, stat and
// process calls live in terminal_sandbox_seatbelt_darwin.go, and
// terminal_sandbox_seatbelt_other.go refuses on every other OS. The driver
// registers itself from init (registerSandboxDriver), so no core function
// names it; terminal_sandbox_seatbelt_omit.go is its twin in a build
// without it.
//
// What runs where: the daemon's runtime probes (only when the driver is
// selected, the sandbox is on and "seatbelt" is in
// [terminal.sandbox].backends: the macOS version and a stat of
// /usr/bin/sandbox-exec, nothing executed), prepares the workspace with the
// shared step and writes a per-run plan file; the PTY child is `observer
// sandbox-seatbelt-host --plan <file> -- observer sandbox-host <the relay
// and network flags> -- observer-seatbelt-inner observer <verb> ...`. The
// helper starts the capture relay on a unix socket and (internet tier) the
// egress gateway on a loopback port, builds the profile, runs the self-test
// under it and only then runs the agent under sandbox-exec, the agent
// staying the PTY's own child (the host PTY, section 4.6).

// The driver's ids and helper verbs.
const (
	seatbeltComponent    = "terminals.sandbox.seatbelt"
	seatbeltDriverName   = "seatbelt"
	seatbeltHostVerb     = "sandbox-seatbelt-host"
	seatbeltSelfTestVerb = "sandbox-seatbelt-selftest"
	seatbeltInnerMarker  = "observer-seatbelt-inner"
)

func init() {
	registerSandboxDriver(sandboxDriverReg{
		backend: sandboxbackend.BackendSeatbelt, component: seatbeltComponent,
		build: newSeatbeltDriver,
		// The daemon serves the capture relay on macOS while this driver is
		// selected: the box's hooks reach Observer only through it.
		relayOS: "darwin",
	})
	sandboxHelperFuncs[seatbeltHostVerb] = runSeatbeltHost
	sandboxHelperFuncs[seatbeltSelfTestVerb] = runSeatbeltSelfTest
}

// seatbeltProbeEnvFn builds the probe ladder's I/O (a variable so a test can
// count its calls).
var seatbeltProbeEnvFn = seatbeltProbeEnv

// seatbeltDriver is the Seatbelt lifecycle service over one runtime.
type seatbeltDriver struct {
	r   *sandboxRuntime
	cfg config.TerminalSandboxSeatbeltConfig

	mu     sync.Mutex
	last   sandboxsbpl.ProbeResult
	lastAt time.Time

	// natives holds each created run's N6 environment switch (run id ->
	// []string) until Attach writes it into the plan.
	natives sync.Map
}

func newSeatbeltDriver(r *sandboxRuntime, full config.Config) sandboxDriver {
	return &seatbeltDriver{r: r, cfg: full.Terminal.Sandbox.Seatbelt}
}

// seatbeltRow is the registry row.
func seatbeltRow() sandboxbackend.Capability {
	row, _ := sandboxbackend.Get(sandboxbackend.BackendSeatbelt)
	return row
}

// listed reports whether seatbelt is among the enabled backends.
func (d *seatbeltDriver) listed() bool {
	return slices.Contains(sandboxEnabledBackends(d.r.cfg), sandboxbackend.BackendSeatbelt)
}

// probe walks the Seatbelt ladder (cached for the probe TTL). Nothing is
// read while seatbelt is not listed.
func (d *seatbeltDriver) probe(context.Context) sandboxselect.Probe {
	if !d.listed() {
		return sandboxselect.Probe{Compiled: true, Verdict: sandboxselect.VerdictDisabledByConfig, Reason: "seatbelt is not in [terminal.sandbox].backends"}
	}
	res := d.probeResult()
	return seatbeltSelectProbe(res, sourceIDs(d.r.sources()))
}

// seatbeltSelectProbe maps a ladder answer onto the selection input. A
// refusal fills the version with the row's minimum only so the probe's own
// verdict reaches S4 unmasked by S2b (the oci-runc driver's rule).
func seatbeltSelectProbe(res sandboxsbpl.ProbeResult, sources []string) sandboxselect.Probe {
	p := sandboxselect.Probe{Compiled: true, Verdict: res.Verdict.Code, Reason: res.Verdict.Reason, Sources: sources}
	if res.Verdict.OK() {
		p.Version = res.OSVersion
		if res.Note != "" {
			p.Reason = res.Note
		}
		return p
	}
	p.Version = seatbeltRow().Control.Pins.RequiredMin
	return p
}

// version is the macOS version the last probe read.
func (d *seatbeltDriver) version() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.last.OSVersion
}

// probeResult runs (or reuses) the ladder.
func (d *seatbeltDriver) probeResult() sandboxsbpl.ProbeResult {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.lastAt.IsZero() && time.Since(d.lastAt) < sandboxProbeTTL {
		return d.last
	}
	env := seatbeltProbeEnvFn()
	env.Active = d.listed()
	d.last, d.lastAt = sandboxsbpl.Probe(env), time.Now()
	// D-MU7: every fresh probe also clears the plans and run dirs of
	// Seatbelt runs whose helper is gone, off the probe's path.
	if d.r != nil {
		go sweepStaleSeatbeltPlans(d.r.observerDir, d.r.logger)
	}
	return d.last
}

// seatbeltNative reduces the tool's native-sandbox row to N6's facts at the
// boundary (no rule names a tool): a switch is passed as per run only when
// it is grounded (integration.NativeSwitch.PerRun), a flag switch with its
// validated tokens, and the vendor managed policy facts (lane SBX-P3D).
func seatbeltNative(tool string) sandboxsbpl.Native {
	n, ok := integration.NativeSandboxFor(tool)
	if !ok {
		return sandboxsbpl.Native{}
	}
	out := sandboxsbpl.Native{
		Seatbelt: n.NeedsAny(integration.NeedSeatbelt), DefaultOn: n.DefaultOn,
		Switch: sandboxsbpl.SwitchGlobalSetting, Value: n.Disable.Value,
	}
	if n.Disable.PerRun() {
		out.Switch = sandboxsbpl.SwitchKind(n.Disable.Kind)
		if args, err := integration.NativeSwitchArgs(n.Disable); err == nil {
			out.Args = args
		}
	}
	if out.Seatbelt {
		f := nativeFactsFor(n)
		out.VendorForced, out.ForcedPolicy = f.forced, f.policy
	}
	return out
}

// seatbeltNativeState is the evidence an N6 decision records: the switch
// Observer applies (environment or command line) is disabled_by_observer,
// the one the launch composition reads back to append a flag switch.
func seatbeltNativeState(tool string, dec sandboxsbpl.NativeDecision) vocab.NativeSandboxState {
	if _, ok := integration.NativeSandboxFor(tool); !ok {
		return vocab.NativeNotApplicable
	}
	if dec.Outcome == sandboxsbpl.NativeDisableEnv || dec.Outcome == sandboxsbpl.NativeDisableFlag {
		return vocab.NativeDisabledByObserver
	}
	return ""
}

// Create checks the floors, N6 and the probe, then prepares the workspace
// with the shared step.
func (d *seatbeltDriver) Create(ctx context.Context, req termsvc.PrepareRequest) (termsvc.CreateResult, error) {
	if err := macDriverFloor(seatbeltRow(), launchFloorConfig(d.r.cfg, string(d.r.egress.Mode)), d.r.forceBackend); err != nil {
		return termsvc.CreateResult{}, err
	}
	dec := sandboxsbpl.DecideNative(seatbeltNative(req.Tool))
	if dec.Outcome == sandboxsbpl.NativeRefuse {
		return termsvc.CreateResult{}, fmt.Errorf("terminal_sandbox: %s (%s): %s: %s", sandboxselect.VerdictToolConflict, dec.Rule, req.Tool, dec.Reason)
	}
	if res := d.probeResult(); !res.Verdict.OK() {
		return termsvc.CreateResult{}, fmt.Errorf("terminal_sandbox: seatbelt is not available: %s", res.Verdict.Error())
	}
	spec, err := macToolSpec(req.Tool)
	if err != nil {
		return termsvc.CreateResult{}, err
	}
	ws, err := d.r.prepareWorkspace(ctx, req)
	if err != nil {
		return termsvc.CreateResult{}, err
	}
	d.natives.Store(ws.id, dec.Env)
	routed, _ := d.r.launchRouted(req.Tool, ws.dir, req.ToolArgs)
	note := fmt.Sprintf("sandbox: backend=seatbelt (beta) source=%s workspace=%s egress=%s", ws.src, ws.dir, d.r.egress.Mode)
	if dec.Outcome == sandboxsbpl.NativeUnjudged || dec.Outcome == sandboxsbpl.NativeDisableEnv || dec.Outcome == sandboxsbpl.NativeDisableFlag {
		note += " native=" + string(dec.Outcome) + " (" + dec.Rule + ")"
	}
	if lim := spec.OSNote("darwin"); lim != "" {
		// D-MU6: a known limitation of the tool in this box, said up front.
		note += " limitation: " + lim
	}
	return termsvc.CreateResult{
		Run:         termsvc.SandboxRun{ID: ws.id, Tool: req.Tool, Dir: ws.dir, ProjectRoot: req.ProjectRoot, Copy: !ws.live},
		Note:        note,
		Isolation:   macIsolation(seatbeltRow(), vocab.Tier(d.r.egress.Mode), routed, seatbeltNativeState(req.Tool, dec), d.r.cfg.EffectiveProviderDirect()),
		ProxyRouted: routed,
	}, nil
}

// seatbeltPlanFile is the per-run plan the host helper reads. It holds no
// secret by rule (TestSeatbeltPlanFileHoldsNoSecrets): the relay secrets
// stay in the run record.
type seatbeltPlanFile struct {
	Version int `json:"version"`
	// Profile is the profile request without the gateway port and the
	// terminal, which only the helper knows.
	Profile sandboxsbpl.Request `json:"profile"`
	Dirs    macRunDirs          `json:"dirs"`
	// NativeEnv is N6's per-run switch (NAME=value), added to the agent's
	// environment.
	NativeEnv []string `json:"native_env,omitempty"`
	// TempDirEnv names the variables the tool reads for its own temp folder
	// (sandboxenv.TempDirEnv, D-UC1): the agent gets each set to the run's
	// TMPDIR, since the profile hides /private/tmp.
	TempDirEnv []string `json:"temp_dir_env,omitempty"`
	// TempDirJVMEnv names the variables holding JVM options in which the
	// run's TMPDIR is set as -Djava.io.tmpdir (sandboxenv.TempDirJVMEnv,
	// D-MU6): a JVM ignores TMPDIR.
	TempDirJVMEnv []string `json:"temp_dir_jvm_env,omitempty"`
}

// Attach writes the run record and the plan file and returns the helper
// argv the PTY child runs.
func (d *seatbeltDriver) Attach(_ context.Context, created termsvc.CreateResult) (termsvc.AttachResult, error) {
	if res := d.probeResult(); !res.Verdict.OK() {
		return termsvc.AttachResult{}, fmt.Errorf("terminal_sandbox: seatbelt is not available: %s", res.Verdict.Error())
	}
	if err := d.r.writeRunRecord(created.Run); err != nil {
		return termsvc.AttachResult{}, err
	}
	wrap, err := d.compose(created)
	if err != nil {
		_ = sandboxrelayd.RemoveRun(d.r.observerDir, created.Run.ID)
		return termsvc.AttachResult{}, err
	}
	d.r.unattached.Delete(created.Run.ID)
	return termsvc.AttachResult{WrapArgv: wrap}, nil
}

// compose builds and checks the profile request, writes the plan file and
// returns the argv.
func (d *seatbeltDriver) compose(created termsvc.CreateResult) ([]string, error) {
	r := d.r
	run := created.Run
	home, err := macRealHome()
	if err != nil {
		return nil, err
	}
	spec, err := macToolSpec(run.Tool)
	if err != nil {
		return nil, err
	}
	// The tool's macOS-only state rows (D-MU6, integration StateRWByOS).
	spec = spec.ForOS("darwin")
	if err := macCheckRWBinds(r, home); err != nil {
		return nil, err
	}
	dirs, err := macDirsFor(run.ID)
	if err != nil {
		return nil, err
	}
	tier := vocab.Tier(r.egress.Mode)
	netReq := sandbox.NetRequest{Egress: r.egress.Mode, ProxyPort: r.proxyPort, EgressAllowCIDRs: r.cfg.EgressAllowCIDRs, HostSocketDir: dirs.SocketDir}
	if capture := sandboxRunCaptureFor(seatbeltRow(), created.ProxyRouted, tier, r.cfg.EffectiveProviderDirect()); capture.ProviderBlock {
		netReq.ProviderBlock, netReq.ProviderHosts = true, r.providerHostList()
	}
	host, err := sandbox.RelayHostArgv(r.observerBin, netReq, nil, sandbox.RelayRequest{RunID: run.ID, HostObserverDir: r.observerDir})
	if err != nil {
		return nil, err
	}
	overlays, pins, err := r.protection(home, run.Dir, spec)
	if err != nil {
		return nil, err
	}
	req := sandboxsbpl.Request{
		Home: home, HomeMode: r.homeMode(), ObserverDir: r.observerDir, WorkspaceRoot: run.Dir,
		ObserverBin: r.observerBin, ObserverRealDir: r.observerRealDir,
		TempDir: dirs.TempDir, SocketParent: dirs.SocketParent, SocketDir: dirs.SocketDir,
		ToolBinDirs: r.toolBinDirs(run.Tool), StateRW: spec.StateRW, StateRO: spec.StateRO,
		RuntimeLadder: sandboxRuntimeLadder, ExtraRO: r.cfg.ExtraROBinds, ExtraRW: r.cfg.ExtraRWBinds,
		Overlays: overlays, Pins: pins, TempRoots: macTempRoots(),
		Net: sandboxsbpl.Net{Egress: r.egress.Mode, ProxyPort: r.proxyPort},
	}
	if d.cfg.AllowKeychain {
		req.MachServices = sandboxsbpl.KeychainMachServices
	}
	// Every path the profile names is resolved here (Seatbelt matches the
	// resolved path), and Build refuses any that is not.
	req, err = sandboxsbpl.Canonicalize(req, sandboxCanonicalPath)
	if err != nil {
		return nil, fmt.Errorf("terminal_sandbox: %w", err)
	}
	// Built and checked now with a stand-in gateway port, so a request the
	// profile cannot express refuses the launch here, not in the helper.
	if err := seatbeltCheckRequest(req, sandboxCanonicalPath); err != nil {
		return nil, err
	}
	var native []string
	if v, ok := d.natives.LoadAndDelete(run.ID); ok {
		native, _ = v.([]string)
	}
	planPath, err := writeMacPlan(r.observerDir, seatbeltDriverName, run.ID, seatbeltPlanFile{
		Version: macPlanVersion, Profile: req, Dirs: dirs, NativeEnv: native,
		TempDirEnv: sandboxenv.TempDirEnv(run.Tool), TempDirJVMEnv: sandboxenv.TempDirJVMEnv(run.Tool),
	})
	if err != nil {
		return nil, err
	}
	wrap := []string{r.observerBin, seatbeltHostVerb, "--plan", planPath, "--"}
	wrap = append(wrap, host...)
	return append(wrap, seatbeltInnerMarker), nil
}

// seatbeltCheckRequest builds the profile with a stand-in gateway port and
// runs the strict checker over it.
func seatbeltCheckRequest(req sandboxsbpl.Request, resolve func(string) string) error {
	req.Resolve = resolve
	req.Net.GatewayPort = seatbeltStandInPort(req.Net.ProxyPort)
	p, err := sandboxsbpl.Build(req)
	if err != nil {
		return fmt.Errorf("terminal_sandbox: %w", err)
	}
	if _, err := sandboxsbpl.Check(p.Text, p.ParamMap()); err != nil {
		return fmt.Errorf("terminal_sandbox: the Seatbelt profile failed its own check: %w", err)
	}
	return nil
}

// seatbeltStandInPort is a valid gateway port distinct from the proxy's.
func seatbeltStandInPort(proxy int) int {
	if proxy == 3128 {
		return 3129
	}
	return 3128
}

// Resize is owned by the PTY: the agent is the PTY's own child.
func (d *seatbeltDriver) Resize(context.Context, termsvc.SandboxRun, uint16, uint16) (termsvc.LifecycleResult, error) {
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictPTYOwned, Detail: "seatbelt: the agent is the PTY's own child"}, nil
}

// Signal is owned by the PTY.
func (d *seatbeltDriver) Signal(context.Context, termsvc.SandboxRun, string) (termsvc.LifecycleResult, error) {
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictPTYOwned, Detail: "seatbelt: signals reach the agent through the PTY and the host helper"}, nil
}

// Copy is not offered: the workspace is a host directory.
func (d *seatbeltDriver) Copy(context.Context, termsvc.CopyRequest) (termsvc.LifecycleResult, error) {
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictNotSupported, Detail: "seatbelt: the workspace is a host directory; copy on the host"}, nil
}

// Checkpoint is not offered; the agent's native resume applies.
func (d *seatbeltDriver) Checkpoint(context.Context, termsvc.SandboxRun) (termsvc.LifecycleResult, error) {
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictNotSupported, Detail: "seatbelt: no checkpoint; the agent's native resume applies"}, nil
}

// Stop is owned by the PTY: closing the terminal hangs up the helper.
func (d *seatbeltDriver) Stop(context.Context, termsvc.SandboxRun, time.Duration) (termsvc.LifecycleResult, error) {
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictPTYOwned, Detail: "seatbelt: closing the terminal ends the run"}, nil
}

// Destroy releases a run that never started: its plan file, run record and
// unattached workspace.
func (d *seatbeltDriver) Destroy(_ context.Context, run termsvc.SandboxRun) (termsvc.LifecycleResult, error) {
	d.natives.Delete(run.ID)
	_ = removeMacPlan(d.r.observerDir, seatbeltDriverName, run.ID)
	return d.r.destroyBwrap(run)
}

// seatbeltAgentEnv is the agent's environment under the profile: the
// helper's own (the launch environment) without the host socket and interop
// variables bwrap drops and without any proxy or TMPDIR the host set, plus
// the run's TMPDIR, its socket dir for the hook client, the sandbox marker,
// the gateway's proxy variables (internet tier) and N6's switch. It also sets
// xcrun_db to a file in the run's own TMPDIR (MAC-38): on a full-Xcode Mac the
// xcrun shim cannot write its default cache under the box's temp dir, so every
// `git`/`python3` call re-runs xcodebuild (the live run measured 6.97s vs
// 0.10s for five `git --version` calls); a cache in the run's private TMPDIR
// needs no profile grant and is removed with the run's temp dir. Last, every
// name in tempEnv (the tool's own temp-dir variables, sandboxenv.TempDirEnv)
// is set to the run's TMPDIR, replacing any value the user passed: the
// profile hides /private/tmp, so a tool that would make its own folder there
// (Claude Code's /tmp/claude-<uid>, D-UC1) could not start.
func seatbeltAgentEnv(environ []string, dirs macRunDirs, gatewayPort int, native, tempEnv []string) []string {
	// The allow-list first (WINFIX2, ledger SBX-WIN-ENV-1); the drops below stay.
	environ = sandboxBoxEnv("darwin", environ)
	drop := map[string]bool{"TMPDIR": true, "xcrun_db": true, sandboxsbpl.EnvSocketDir: true, sandboxEnvMarker: true}
	for _, k := range sandbox.GuestUnsetEnv {
		drop[k] = true
	}
	for _, kv := range sandbox.GuestProxyEnv(1) {
		k, _, _ := cutEnv(kv)
		drop[k] = true
	}
	for _, kv := range native {
		k, _, _ := cutEnv(kv)
		drop[k] = true
	}
	out := make([]string, 0, len(environ)+12)
	for _, kv := range environ {
		k, _, ok := cutEnv(kv)
		if !ok || k == "" || drop[k] {
			continue
		}
		out = append(out, kv)
	}
	out = append(out, "TMPDIR="+dirs.TempDir+"/", "xcrun_db="+filepath.Join(dirs.TempDir, "xcrun_db"), sandboxsbpl.EnvSocketDir+"="+dirs.SocketDir, sandboxEnvMarker+"=1")
	if gatewayPort > 0 {
		out = append(out, sandbox.GuestProxyEnv(gatewayPort)...)
	}
	return sandboxenv.WithTempDir(append(out, native...), tempEnv, dirs.TempDir)
}

// cutEnv splits NAME=value.
func cutEnv(kv string) (string, string, bool) {
	for i := 0; i < len(kv); i++ {
		if kv[i] == '=' {
			return kv[:i], kv[i+1:], true
		}
	}
	return kv, "", false
}

// seatbeltHomeBlinded reports whether the profile keeps the home unlisted:
// tmpfs home mode, unless the workspace is the home or holds it (a project
// at the home, the workspace_is_home golden), where the workspace grant
// lists the home by design and only the observer dir stays hidden.
func seatbeltHomeBlinded(req sandboxsbpl.Request) bool {
	if req.HomeMode != "" && req.HomeMode != sandboxsbpl.HomeModeTmpfs {
		return false
	}
	home, ws := filepath.Clean(req.Home), filepath.Clean(req.WorkspaceRoot)
	return ws != home && !strings.HasPrefix(home, ws+"/") && ws != "/"
}

// seatbeltSelfTestArgv is the self-test's argv inside the profile.
func seatbeltSelfTestArgv(observerBin string, req sandboxsbpl.Request) []string {
	blinded := seatbeltHomeBlinded(req)
	return []string{
		observerBin, seatbeltSelfTestVerb,
		"--obs", req.ObserverDir, "--sockp", req.SocketParent, "--home", req.Home,
		"--home-blinded", strconv.FormatBool(blinded), "--ws", req.WorkspaceRoot, "--tmp", req.TempDir,
	}
}

// seatbeltSelfTestFlags parses the self-test's flags.
func seatbeltSelfTestFlags(args []string) (map[string]string, error) {
	out := map[string]string{}
	allowed := map[string]bool{"--obs": true, "--sockp": true, "--home": true, "--home-blinded": true, "--ws": true, "--tmp": true}
	for i := 0; i < len(args); i += 2 {
		if !allowed[args[i]] || i+1 >= len(args) || !filepath.IsAbs(args[i+1]) && args[i] != "--home-blinded" {
			return nil, fmt.Errorf("%s: bad argument %q", seatbeltSelfTestVerb, args[i])
		}
		out[args[i]] = args[i+1]
	}
	if len(out) != len(allowed) {
		return nil, fmt.Errorf("%s: every flag is required", seatbeltSelfTestVerb)
	}
	return out, nil
}

// bindsToolState: the Seatbelt profile grants the tool's own state directory, so the box shares the tool's sign-in
// (sandboxStateBinder, operator ruling P-183).
func (*seatbeltDriver) bindsToolState() bool { return true }

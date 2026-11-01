//go:build !sbo_omit_terminals_sandbox_landlock && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/marmutapp/superbased-observer/internal/attachsock"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxenv"
	"github.com/marmutapp/superbased-observer/internal/sandboxlandlock"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// terminal_sandbox_landlock.go is the process_lite driver (sandbox plan v2
// sections 4.1, 4.6, 11.3 and 13 P3; lane SBX-P3B; beta, register entry
// LIN-1): Landlock alone, for Linux hosts that block the user namespaces
// bwrap needs. The pure decisions (the ABI table, the probe ladder, the
// ruleset mirrored from the bind plan, the TCP allow-list) are
// internal/sandboxlandlock's; the Landlock syscalls, the self-test and the
// exec live in terminal_sandbox_landlock_linux.go, and
// terminal_sandbox_landlock_other.go refuses on every other OS. The driver
// registers itself from init (registerSandboxDriver), so no core function
// names it; terminal_sandbox_landlock_omit.go is its twin in a build
// without it.
//
// What runs where: the daemon's runtime probes (only when the driver is
// selected, the sandbox is on and "process_lite" is in
// [terminal.sandbox].backends: one landlock_create_ruleset VERSION query),
// prepares the workspace with the shared step and writes a per-run plan
// file; the PTY child is `observer sandbox-host <relay flags> -- observer
// sandbox-landlock-exec --plan <file> -- observer <verb> ...`. The host
// helper starts the capture relay on the run's socket dir; the exec step
// creates the run's TMPDIR, builds and applies the ruleset to itself,
// checks it (the observer directory must be unreadable), and execs the
// agent, which stays the PTY's own child (the host PTY, section 4.6). The
// row is explicit-only: a launch uses it only when it names it.

// The driver's ids and helper verb.
const (
	landlockComponent = "terminals.sandbox.landlock"
	landlockExecVerb  = "sandbox-landlock-exec"
	// landlockPlanVersion is the plan file's schema version.
	landlockPlanVersion = 1
)

func init() {
	registerSandboxDriver(sandboxDriverReg{
		backend: sandboxbackend.BackendProcessLite, component: landlockComponent,
		build: newLandlockDriver,
	})
	sandboxHelperFuncs[landlockExecVerb] = runLandlockExec
}

// landlockProbeEnvFn builds the probe ladder's I/O (a variable so a test can
// count its calls and feed facts).
var landlockProbeEnvFn = landlockProbeEnv

// landlockDriver is the process_lite lifecycle service over one runtime.
type landlockDriver struct {
	r   *sandboxRuntime
	cfg config.TerminalSandboxLandlockConfig
	// full is the daemon's config, read at each launch for Observer's own
	// TCP listeners (landlockListeners).
	full config.Config
	// attachSocket is the daemon's attach socket (never reachable).
	attachSocket string

	mu     sync.Mutex
	last   sandboxlandlock.ProbeResult
	lastAt time.Time
}

func newLandlockDriver(r *sandboxRuntime, full config.Config) sandboxDriver {
	return &landlockDriver{
		r: r, cfg: full.Terminal.Sandbox.Landlock,
		full:         full,
		attachSocket: attachsock.SocketPath(full.Observer.DBPath),
	}
}

// landlockListener is one of Observer's own TCP listeners: a row of the table
// the TCP deny list is built from.
type landlockListener struct {
	name string
	// addr is the listener's host:port ("" when it binds nothing).
	addr string
	// on: the config switches the listener on.
	on bool
}

// landlockListeners is the table of Observer's own TCP listeners a
// process_lite box has no business with (audit SBX-P3B F3): the dashboard at
// the address this process resolved (dashboard, which carries a
// --dashboard-addr or --addr override; "" falls back to the env, config and
// default precedence), and every other listener the config switches on. The
// model proxy is left out on purpose: a host-tier agent routes through it
// (SBX-BE-17). The attach socket and the relay endpoint are unix sockets,
// denied by the filesystem rules and checked by the exec step's self-test,
// not by port.
func landlockListeners(full config.Config, dashboard string) []landlockListener {
	if dashboard == "" {
		dashboard = resolveDashboardAddr("", full.Dashboard.Addr, "127.0.0.1:8081")
	}
	otel, browser, etw, remote := full.Ingest.OTel, full.Browser, full.Observer.Process.ETW, full.Remote
	return []landlockListener{
		{name: "dashboard", addr: dashboard, on: true},
		{name: "OTLP/gRPC receiver", addr: otel.GRPCAddr, on: otel.Enabled},
		{name: "OTLP/HTTP receiver", addr: otel.HTTPAddr, on: otel.Enabled},
		{name: "browser ingest listener", addr: browser.Listener.ListenAddr, on: browser.Enabled && browser.Listener.Enabled},
		{name: "MCP relay listener", addr: full.MCPRelay.Listen, on: full.MCPRelay.Enabled},
		{name: "process feed listener", addr: etw.ListenAddr, on: etw.Enabled},
		{name: "remote access bind", addr: remote.BindAddr, on: remote.Enabled},
		{name: "remote access tailnet backend", addr: remote.TailscaleBackendAddr, on: remote.Enabled},
	}
}

// landlockDeniedPorts is the deny list: the port of every listener that is
// on, sorted, never the model proxy's port. An address without a usable port
// is skipped (it binds nothing a box could reach by port).
func landlockDeniedPorts(ls []landlockListener, proxyPort int) []int {
	seen := map[int]bool{}
	var out []int
	for _, l := range ls {
		if !l.on || l.addr == "" {
			continue
		}
		_, p, err := net.SplitHostPort(l.addr)
		if err != nil {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 || n == proxyPort || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	sort.Ints(out)
	return out
}

// deniedPorts is the deny list for a launch now, so a dashboard address
// resolved after the driver was built still counts.
func (d *landlockDriver) deniedPorts() []int {
	return landlockDeniedPorts(landlockListeners(d.full, resolvedDashboardListen()), d.full.Proxy.Port)
}

// landlockRow is the registry row.
func landlockRow() sandboxbackend.Capability {
	row, _ := sandboxbackend.Get(sandboxbackend.BackendProcessLite)
	return row
}

// listed reports whether process_lite is among the enabled backends.
func (d *landlockDriver) listed() bool {
	return slices.Contains(sandboxEnabledBackends(d.r.cfg), sandboxbackend.BackendProcessLite)
}

// probe walks the ladder (cached for the probe TTL). Nothing is read while
// process_lite is not listed.
func (d *landlockDriver) probe(context.Context) sandboxselect.Probe {
	if !d.listed() {
		return sandboxselect.Probe{Compiled: true, Verdict: sandboxselect.VerdictDisabledByConfig, Reason: "process_lite is not in [terminal.sandbox].backends"}
	}
	res := d.probeResult()
	p := sandboxselect.Probe{Compiled: true, Verdict: res.Verdict.Code, Reason: res.Verdict.Reason, Sources: sourceIDs(d.r.sources())}
	if res.Verdict.OK() {
		// The version a pin reads is the kernel's Landlock ABI, answered by
		// the kernel itself.
		p.Version, p.VersionAuthenticated = strconv.Itoa(res.ABI), true
		return p
	}
	p.Version, p.VersionAuthenticated = landlockRow().Control.Pins.RequiredMin, true
	return p
}

// version is the ABI the last probe read.
func (d *landlockDriver) version() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.last.ABI == 0 {
		return ""
	}
	return strconv.Itoa(d.last.ABI)
}

// probeResult runs (or reuses) the ladder.
func (d *landlockDriver) probeResult() sandboxlandlock.ProbeResult {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.lastAt.IsZero() && time.Since(d.lastAt) < sandboxProbeTTL {
		return d.last
	}
	env := landlockProbeEnvFn()
	env.Active = d.listed()
	env.MinABI = d.cfg.MinABI
	d.last, d.lastAt = sandboxlandlock.Probe(env), time.Now()
	return d.last
}

// floor refuses a launch the local config or an org floor does not allow
// on this row: it must be listed (or named), its one tier is host, and the
// org floors apply (a min_egress floor refuses it).
func (d *landlockDriver) floor(cfg config.TerminalSandboxConfig) error {
	row := landlockRow()
	if cfg.PinnedNoBackend != "" {
		return fmt.Errorf("terminal_sandbox: your organization's pin of %s allows none of the sandbox backends this machine is set to use, so no backend is enabled; the sandboxed terminal is refused, never run without it", cfg.PinnedNoBackend)
	}
	if !slices.Contains(sandboxEnabledBackends(cfg), row.ID) && d.r.forceBackend != row.ID {
		return fmt.Errorf("terminal_sandbox: %s is not in [terminal.sandbox].backends %v", row.ID, cfg.Backends)
	}
	if floor := vocab.IsoClass(cfg.MinIsolation); floor != "" && row.Iso.Class.Rank() < floor.Rank() {
		return fmt.Errorf("terminal_sandbox: %s builds %s isolation, below [terminal.sandbox].min_isolation = %s", row.ID, row.Iso.Class, floor)
	}
	tier := vocab.Tier(cfg.Egress)
	if !row.OffersTier(tier) {
		return fmt.Errorf("terminal_sandbox: process_lite (Landlock) shares the host's network, so its only tier is host (its TCP rules match ports, not addresses); set [terminal.sandbox].egress = \"host\" to use it, or use bwrap")
	}
	floors := sandboxOrgFloors()
	if !floors.InForce() {
		return nil
	}
	beta := true
	if v, ok := row.VerificationOn(sandboxHostKind()); ok {
		beta = v.Kind.IsBeta()
	}
	in := sandboxselect.Input{
		Request: sandboxselect.Request{Backend: row.ID, Tier: tier, Interactive: true, Custody: vocab.CustodyHostBound, AcceptReducedCapture: true, ProviderDirect: cfg.EffectiveProviderDirect()},
		Host:    sandboxHostKind(), Floors: floors,
		Tool: sandboxselect.Tool{Mapped: true, ProxyRouted: true, CredentialInReach: true},
	}
	if drop, dropped := sandboxselect.FloorDrop(row, in, beta); dropped {
		return sandboxRefusalError{msg: isolationFloorMessage(drop)}
	}
	return nil
}

// Create checks the floors and the probe, then prepares the workspace with
// the shared step.
func (d *landlockDriver) Create(ctx context.Context, req termsvc.PrepareRequest) (termsvc.CreateResult, error) {
	if err := d.floor(launchFloorConfig(d.r.cfg, string(d.r.egress.Mode))); err != nil {
		return termsvc.CreateResult{}, err
	}
	if res := d.probeResult(); !res.Verdict.OK() {
		return termsvc.CreateResult{}, fmt.Errorf("terminal_sandbox: process_lite is not available: %s", res.Verdict.Error())
	}
	if _, err := macToolSpec(req.Tool); err != nil {
		return termsvc.CreateResult{}, err
	}
	ws, err := d.r.prepareWorkspace(ctx, req)
	if err != nil {
		return termsvc.CreateResult{}, err
	}
	routed, _ := d.r.launchRouted(req.Tool, ws.dir, req.ToolArgs)
	return termsvc.CreateResult{
		Run:         termsvc.SandboxRun{ID: ws.id, Tool: req.Tool, Dir: ws.dir, ProjectRoot: req.ProjectRoot, Copy: !ws.live},
		Note:        fmt.Sprintf("sandbox: backend=process_lite (Landlock, beta) source=%s workspace=%s egress=host", ws.src, ws.dir),
		Isolation:   macIsolation(landlockRow(), vocab.TierHost, routed, "", d.r.cfg.EffectiveProviderDirect()),
		ProxyRouted: routed,
	}, nil
}

// landlockPlanFile is the per-run plan the exec step reads. It holds no
// secret by rule (TestLandlockPlanFileHoldsNoSecrets).
type landlockPlanFile struct {
	Version int                       `json:"version"`
	MinABI  int                       `json:"min_abi"`
	Plan    sandboxlandlock.PlanInput `json:"plan"`
	// TempDirEnv names the variables the tool reads for its own temp folder
	// (sandboxenv.TempDirEnv, D-UC1): the ruleset grants only the run's
	// TMPDIR, so the agent gets each set to it.
	TempDirEnv []string `json:"temp_dir_env,omitempty"`
}

// Attach writes the run record and the plan file and returns the argv the
// PTY child runs.
func (d *landlockDriver) Attach(_ context.Context, created termsvc.CreateResult) (termsvc.AttachResult, error) {
	res := d.probeResult()
	if !res.Verdict.OK() {
		return termsvc.AttachResult{}, fmt.Errorf("terminal_sandbox: process_lite is not available: %s", res.Verdict.Error())
	}
	if err := d.r.writeRunRecord(created.Run); err != nil {
		return termsvc.AttachResult{}, err
	}
	wrap, err := d.compose(created, res.ABI)
	if err != nil {
		_ = sandboxrelayd.RemoveRun(d.r.observerDir, created.Run.ID)
		return termsvc.AttachResult{}, err
	}
	d.r.unattached.Delete(created.Run.ID)
	return termsvc.AttachResult{WrapArgv: wrap}, nil
}

// compose builds and checks the ruleset plan, writes the plan file and
// returns the argv.
func (d *landlockDriver) compose(created termsvc.CreateResult, abi int) ([]string, error) {
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
	for _, rel := range spec.StateRW {
		if err := sandbox.CheckObserverDirBind("state rw bind", filepath.Join(home, rel), r.observerDir, resolveSandboxBindPath); err != nil {
			return nil, fmt.Errorf("terminal_sandbox: %w", err)
		}
	}
	for _, x := range append(append([]string(nil), r.cfg.ExtraROBinds...), r.cfg.ExtraRWBinds...) {
		if err := sandbox.CheckObserverDirBind("extra bind", x, r.observerDir, resolveSandboxBindPath); err != nil {
			return nil, fmt.Errorf("terminal_sandbox: %w", err)
		}
	}
	if err := macCheckRWBinds(r, home); err != nil {
		return nil, err
	}
	sockDir := filepath.Join(os.TempDir(), "observer-sbx-"+run.ID)
	tempDir := filepath.Join(os.TempDir(), "observer-sbx-tmp-"+run.ID)
	host, err := sandbox.RelayHostArgv(r.observerBin, sandbox.NetRequest{Egress: sandbox.EgressHost, ProxyPort: r.proxyPort, HostSocketDir: sockDir},
		nil, sandbox.RelayRequest{RunID: run.ID, HostObserverDir: r.observerDir})
	if err != nil {
		return nil, err
	}
	abs := func(rels []string) []string {
		out := make([]string, 0, len(rels))
		for _, rel := range rels {
			out = append(out, filepath.Join(home, rel))
		}
		return out
	}
	runtimes := make([]string, 0, len(sandboxRuntimeLadder))
	for _, rel := range sandboxRuntimeLadder {
		runtimes = append(runtimes, filepath.Join(home, rel))
	}
	in := sandboxlandlock.PlanInput{
		ABI: abi, Workspace: run.Dir,
		StateRW: abs(spec.StateRW), StateRO: abs(spec.StateRO),
		ToolBinDirs: r.toolBinDirs(run.Tool), RuntimeDirs: runtimes,
		ObserverBin: r.observerBin, ObserverRealDir: r.observerRealDir,
		SocketDir: sockDir, TempDir: tempDir,
		ExtraRO: r.cfg.ExtraROBinds, ExtraRW: r.cfg.ExtraRWBinds,
		ConfigRO:      landlockConfigView(r.observerDir, landlockDaemonConfigFile()),
		ObserverDir:   r.observerDir,
		DaemonSockets: landlockDaemonSockets(r.observerDir, d.attachSocket),
		DeniedPorts:   d.deniedPorts(),
	}
	// Validate now, so a bad plan refuses the launch here rather than in
	// the exec step.
	if _, err := sandboxlandlock.BuildRuleset(in); err != nil {
		return nil, fmt.Errorf("terminal_sandbox: %w", err)
	}
	planPath, err := writeLandlockPlan(r.observerDir, run.ID, landlockPlanFile{Version: landlockPlanVersion, MinABI: sandboxlandlock.Floor(d.cfg.MinABI), Plan: in, TempDirEnv: sandboxenv.TempDirEnv(run.Tool)})
	if err != nil {
		return nil, err
	}
	return append(host, r.observerBin, landlockExecVerb, "--plan", planPath, "--"), nil
}

// landlockDaemonConfigFile is the daemon's resolved config file ("" when it
// cannot be resolved).
func landlockDaemonConfigFile() string {
	p, err := config.ResolveGlobalPath(daemonConfigPath())
	if err != nil {
		return ""
	}
	return p
}

// landlockConfigView is the inner launcher's read-only view of its config
// (LIN-1 F3): the daemon's config file and every row of the observer
// directory's executed-state table (sandboxObserverExecState: config.toml,
// the governance sidecars, the org lock, the guard policies), the set the
// bwrap and container rows bind read-only. Without it the launcher could
// not read config.toml and exited 1 with no message. Only what exists as a
// plain file or directory is granted, never a symlink, so a planted link
// cannot turn the grant onto the database or a secret; the secrets table
// (sandboxObserverSecrets) and the database are not in it.
func landlockConfigView(observerDir, configFile string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		if p == "" || !filepath.IsAbs(p) {
			return
		}
		p = filepath.Clean(p)
		if seen[p] {
			return
		}
		fi, err := os.Lstat(p) //nolint:gosec // G703: a grant path from the run's own plan, cleaned above
		if err != nil || !(fi.Mode().IsRegular() || fi.IsDir()) {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	add(configFile)
	for _, row := range sandboxObserverExecState {
		add(filepath.Join(observerDir, row.Rel))
	}
	return out
}

// landlockDaemonSockets are the daemon's own unix sockets no grant may let
// the box connect to: the relay's link endpoint and the attach socket.
func landlockDaemonSockets(observerDir, attach string) []string {
	out := []string{}
	if ep, err := sandboxRelayEndpoint(observerDir); err == nil && filepath.IsAbs(ep) {
		out = append(out, filepath.Clean(ep))
	}
	if filepath.IsAbs(attach) {
		out = append(out, filepath.Clean(attach))
	}
	return out
}

// landlockConnectTarget is one unix socket the exec step's self-test must
// fail to connect to once the ruleset applies (audit SBX-P3B F2).
type landlockConnectTarget struct {
	// what names the socket in a refusal.
	what string
	path string
}

// landlockEngineSockets are the container engine sockets the self-test also
// tries when they exist: rootless under XDG_RUNTIME_DIR, then rootful.
func landlockEngineSockets(runtimeDir string) []string {
	var out []string
	if filepath.IsAbs(runtimeDir) {
		out = append(out, filepath.Join(runtimeDir, "docker.sock"), filepath.Join(runtimeDir, "podman", "podman.sock"))
	}
	return append(out, "/run/docker.sock", "/run/podman/podman.sock")
}

// landlockConnectTargets lists the self-test's connect checks, decided before
// the ruleset applies: every daemon socket (the relay endpoint and the attach
// socket) that exists as a socket, and every engine socket that does. A
// daemon socket that does not exist has nothing listening to reach and is
// skipped, but at least one must exist: with none the right that keeps the
// box off them is unproven, and the launch is refused.
func landlockConnectTargets(daemon, engines []string, isSocket func(string) bool) ([]landlockConnectTarget, error) {
	var out []landlockConnectTarget
	for _, s := range daemon {
		if isSocket(s) {
			out = append(out, landlockConnectTarget{what: "the daemon socket", path: s})
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("none of the daemon's sockets %v exists, so the self-test cannot prove the box is denied connecting to them", daemon)
	}
	for _, s := range engines {
		if isSocket(s) {
			out = append(out, landlockConnectTarget{what: "the container engine socket", path: s})
		}
	}
	return out, nil
}

// landlockCheckConnects connects to every target through connect (the
// syscall seam) and requires the kernel to refuse each with EACCES or EPERM.
// Any other answer (a connection, ECONNREFUSED, ENOENT) means the ruleset
// did not deny the connect, so the launch is refused naming the socket. This
// is what proves the unverified AccessFSResolveUnix bit (abi.go) on the
// running kernel, launch by launch.
func landlockCheckConnects(targets []landlockConnectTarget, connect func(path string) error) error {
	for _, t := range targets {
		err := connect(t.path)
		if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
			continue
		}
		if err == nil {
			return fmt.Errorf("the box could connect to %s %s under the ruleset", t.what, t.path)
		}
		return fmt.Errorf("connecting to %s %s was not denied by the ruleset (%w)", t.what, t.path, err)
	}
	return nil
}

// The lifecycle operations other than Create and Attach are the PTY's, as
// for bwrap: the agent is the PTY's own child.

// Resize is owned by the PTY.
func (d *landlockDriver) Resize(context.Context, termsvc.SandboxRun, uint16, uint16) (termsvc.LifecycleResult, error) {
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictPTYOwned, Detail: "process_lite: the agent is the PTY's own child"}, nil
}

// Signal is owned by the PTY.
func (d *landlockDriver) Signal(context.Context, termsvc.SandboxRun, string) (termsvc.LifecycleResult, error) {
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictPTYOwned, Detail: "process_lite: signals reach the agent through the PTY"}, nil
}

// Copy is not offered: the workspace is a host directory.
func (d *landlockDriver) Copy(context.Context, termsvc.CopyRequest) (termsvc.LifecycleResult, error) {
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictNotSupported, Detail: "process_lite: the workspace is a host directory; copy on the host"}, nil
}

// Checkpoint is not offered.
func (d *landlockDriver) Checkpoint(context.Context, termsvc.SandboxRun) (termsvc.LifecycleResult, error) {
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictNotSupported, Detail: "process_lite: no checkpoint; the agent's native resume applies"}, nil
}

// Stop is owned by the PTY.
func (d *landlockDriver) Stop(context.Context, termsvc.SandboxRun, time.Duration) (termsvc.LifecycleResult, error) {
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictPTYOwned, Detail: "process_lite: closing the terminal ends the agent"}, nil
}

// Destroy releases a run that never started.
func (d *landlockDriver) Destroy(_ context.Context, run termsvc.SandboxRun) (termsvc.LifecycleResult, error) {
	_ = os.Remove(landlockPlanPath(d.r.observerDir, run.ID))
	return d.r.destroyBwrap(run)
}

// landlockPlanPath is a run's plan file, under the daemon's own observer
// dir (never granted to any box).
func landlockPlanPath(observerDir, runID string) string {
	return filepath.Join(observerDir, "sandbox-landlock", "plans", runID+".json")
}

// writeLandlockPlan writes a run's plan file (0600, created fresh, never
// over an existing path or a link).
func writeLandlockPlan(observerDir, runID string, plan landlockPlanFile) (string, error) {
	p := landlockPlanPath(observerDir, runID)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return "", fmt.Errorf("terminal_sandbox: landlock plan dir: %w", err)
	}
	b, err := json.Marshal(plan)
	if err != nil {
		return "", err
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: a fixed run-id name under the observer dir
	if err != nil {
		return "", fmt.Errorf("terminal_sandbox: write landlock plan: %w", err)
	}
	_, werr := f.Write(b)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(p)
		return "", werr
	}
	return p, nil
}

// errLandlockUsage is the exec step's usage refusal.
var errLandlockUsage = errors.New("usage: sandbox-landlock-exec [--block-fd <n>] --plan <file> -- <launch>")

// parseLandlockExecArgs reads `--plan <file> -- <launch...>`.
func parseLandlockExecArgs(args []string) (string, []string, error) {
	if len(args) < 4 || args[0] != "--plan" || args[2] != "--" {
		return "", nil, errLandlockUsage
	}
	return args[1], args[3:], nil
}

// bindsToolState: Landlock grants the tool's own state directory, so the box shares the tool's sign-in
// (sandboxStateBinder, operator ruling P-183).
func (*landlockDriver) bindsToolState() bool { return true }

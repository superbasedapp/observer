//go:build !sbo_omit_terminals_sandbox_apple_container && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxapple"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// terminal_sandbox_applecontainer.go is the Apple container driver (sandbox
// plan v2 sections 4.6, 11.3 and 13 P5; lane SBX-P5; beta, Verification =
// doc): Apple's own container CLI on macOS 26 with Apple silicon, each run
// a lightweight Linux VM. The pure decisions (argv, the JSON parsers, the
// read-back, the orphan sweep, the probe ladder, the environment) are
// internal/sandboxapple's; the CLI calls live in
// terminal_sandbox_applecontainer_darwin.go; the in-image init runs inside
// the container's Linux VM (terminal_sandbox_applecontainer_linux.go);
// terminal_sandbox_applecontainer_other.go refuses everywhere else. The
// driver registers from init, so no core function names it.
//
// What runs where: the daemon probes (only when the driver is selected,
// the sandbox is on and "apple-container" is listed), prepares the
// workspace and writes the plan; the PTY child is `observer
// sandbox-apple-host --plan <file> -- observer sandbox-host <relay and
// network flags> -- observer-apple-inner <inner>`. The helper serves the
// relay, the proxy forward and the gateway on unix sockets in the run's
// socket dir, writes the per-run tunnel secret to a 0600 env file, and runs
// `container run -it` in the host PTY: the agent is the container's main
// process (through the in-image init and guest helper). The init checks its
// own mounts against the plan and serves the guest's sockets over a tunnel
// it publishes with --publish-socket, which the helper dials (a host unix
// socket mounted with -v does not connect from the guest); the launch
// environment travels inside that tunnel. The container is also read back
// with `container inspect` while it starts.

// The driver's ids and helper verbs.
const (
	appleComponent   = "terminals.sandbox.apple-container"
	appleDriverName  = "apple-container"
	appleHostVerb    = "sandbox-apple-host"
	appleInnerMarker = "observer-apple-inner"
)

func init() {
	registerSandboxDriver(sandboxDriverReg{
		backend: sandboxbackend.BackendAppleContainer, component: appleComponent,
		build: newAppleDriver,
		// The daemon serves the capture relay on macOS while this driver is
		// selected: the box's hooks reach Observer only through it.
		relayOS: "darwin",
	})
	sandboxHelperFuncs[appleHostVerb] = runAppleHost
	sandboxHelperFuncs[sandboxapple.InitVerb] = runAppleInit
}

// appleProbeEnvFn builds the probe ladder's I/O (a variable so a test can
// count its calls).
var appleProbeEnvFn = appleProbeEnv

// appleSweepFn is the orphan sweep (a variable so a test can count it).
var appleSweepFn = appleSweep

// appleDriver is the Apple container lifecycle service over one runtime.
type appleDriver struct {
	r   *sandboxRuntime
	cfg config.TerminalSandboxAppleContainerConfig

	mu     sync.Mutex
	last   sandboxapple.ProbeResult
	lastAt time.Time
	// sweptAt is when the orphan sweep last ran (zero: never).
	sweptAt time.Time
}

// appleSweepEvery is how often a passing probe in the daemon sweeps again:
// a SIGKILLed helper's `--rm` container keeps running (live 2026-10-23,
// MAC-17), so the sweep runs at the daemon's first passing probe and again
// at a later probe refresh, not only once per daemon.
const appleSweepEvery = 2 * time.Minute

func newAppleDriver(r *sandboxRuntime, full config.Config) sandboxDriver {
	return &appleDriver{r: r, cfg: full.Terminal.Sandbox.AppleContainer}
}

// appleRow is the registry row.
func appleRow() sandboxbackend.Capability {
	row, _ := sandboxbackend.Get(sandboxbackend.BackendAppleContainer)
	return row
}

// listed reports whether apple-container is among the enabled backends.
func (d *appleDriver) listed() bool {
	return slices.Contains(sandboxEnabledBackends(d.r.cfg), sandboxbackend.BackendAppleContainer)
}

// probe walks the ladder (cached for the probe TTL). Nothing runs while
// apple-container is not listed.
func (d *appleDriver) probe(context.Context) sandboxselect.Probe {
	if !d.listed() {
		return sandboxselect.Probe{Compiled: true, Verdict: sandboxselect.VerdictDisabledByConfig, Reason: "apple-container is not in [terminal.sandbox].backends"}
	}
	return appleSelectProbe(d.probeResult(), sourceIDs(d.r.sources()))
}

// appleSelectProbe maps a ladder answer onto the selection input (a refusal
// carries the row's minimum so S4 reports the probe's own verdict).
func appleSelectProbe(res sandboxapple.ProbeResult, sources []string) sandboxselect.Probe {
	p := sandboxselect.Probe{Compiled: true, Verdict: res.Verdict.Code, Reason: res.Verdict.Reason, Sources: sources}
	if res.Verdict.OK() {
		p.Version = res.Version
		return p
	}
	p.Version = appleRow().Control.Pins.RequiredMin
	return p
}

// version is the CLI version the last probe read.
func (d *appleDriver) version() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.last.Version
}

// probeResult runs (or reuses) the ladder; in the daemon a passing probe
// also sweeps this install's orphaned containers, at most once per
// appleSweepEvery.
func (d *appleDriver) probeResult() sandboxapple.ProbeResult {
	d.mu.Lock()
	if !d.lastAt.IsZero() && time.Since(d.lastAt) < sandboxProbeTTL {
		res := d.last
		d.mu.Unlock()
		return res
	}
	d.mu.Unlock()
	env := appleProbeEnvFn(d.cfg)
	env.Active = d.listed()
	res := sandboxapple.Probe(env)
	d.mu.Lock()
	d.last, d.lastAt = res, time.Now()
	sweep := res.Verdict.OK() && d.r.inDaemon && (d.sweptAt.IsZero() || time.Since(d.sweptAt) >= appleSweepEvery)
	if sweep {
		d.sweptAt = time.Now()
	}
	d.mu.Unlock()
	if sweep {
		if id, err := appleInstallID(d.r.observerDir); err == nil {
			go appleSweepFn(res.CLI, id, d.r.observerDir)
		}
	}
	return res
}

// Create checks the floors, the agent's own sandbox (the guest is Linux,
// so the shared nesting rows apply) and the probe, then prepares the
// workspace with the shared step.
func (d *appleDriver) Create(ctx context.Context, req termsvc.PrepareRequest) (termsvc.CreateResult, error) {
	row := appleRow()
	if err := macDriverFloor(row, launchFloorConfig(d.r.cfg, string(d.r.egress.Mode)), d.r.forceBackend); err != nil {
		return termsvc.CreateResult{}, err
	}
	tier := vocab.Tier(d.r.egress.Mode)
	var nativeState vocab.NativeSandboxState
	if v, judged := sandboxNativeVerdictFor(row, req.Tool, tier); judged {
		if err := sandboxNativeRefusal(req.Tool, v); err != nil {
			return termsvc.CreateResult{}, err
		}
		nativeState = sandboxselect.NativeStateFor(v)
	}
	if res := d.probeResult(); !res.Verdict.OK() {
		return termsvc.CreateResult{}, fmt.Errorf("terminal_sandbox: apple-container is not available: %s", res.Verdict.Error())
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
		Note:        fmt.Sprintf("sandbox: backend=apple-container (beta) source=%s workspace=%s egress=%s", ws.src, ws.dir, d.r.egress.Mode),
		Isolation:   macIsolation(row, tier, routed, nativeState, d.r.cfg.EffectiveProviderDirect()),
		ProxyRouted: routed,
	}, nil
}

// applePlanFile is the per-run plan the host helper reads. It holds no
// secret by rule (TestApplePlanFileHoldsNoSecrets): the relay secrets stay
// in the run record and the environment is written by the helper itself.
type applePlanFile struct {
	Version int `json:"version"`
	// Run is the container plan without its command and env file, which the
	// helper completes.
	Run  sandboxapple.RunPlan `json:"run"`
	Dirs macRunDirs           `json:"dirs"`
	// Guest is the in-box guest helper prefix (the tier's forwards).
	Guest []string `json:"guest"`
	// HostBin is the host observer path the agent's hooks name.
	HostBin string `json:"host_bin"`
	// Hidden are the protect table's hidden paths visible through a mount:
	// the helper mounts an empty file or directory over each, read-only.
	Hidden []appleHidden `json:"hidden,omitempty"`
}

// appleHidden is one hidden path.
type appleHidden struct {
	Path string `json:"path"`
	Dir  bool   `json:"dir"`
}

// Attach writes the run record and the plan file and returns the argv.
func (d *appleDriver) Attach(_ context.Context, created termsvc.CreateResult) (termsvc.AttachResult, error) {
	res := d.probeResult()
	if !res.Verdict.OK() {
		return termsvc.AttachResult{}, fmt.Errorf("terminal_sandbox: apple-container is not available: %s", res.Verdict.Error())
	}
	if err := d.r.writeRunRecord(created.Run); err != nil {
		return termsvc.AttachResult{}, err
	}
	wrap, err := d.compose(created, res.CLI)
	if err != nil {
		_ = sandboxrelayd.RemoveRun(d.r.observerDir, created.Run.ID)
		return termsvc.AttachResult{}, err
	}
	d.r.unattached.Delete(created.Run.ID)
	return termsvc.AttachResult{WrapArgv: wrap}, nil
}

// compose builds the container plan from the same inputs the bwrap plan
// reads, writes the plan file and returns the argv.
func (d *appleDriver) compose(created termsvc.CreateResult, cli string) ([]string, error) {
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
	if err := macCheckRWBinds(r, home); err != nil {
		return nil, err
	}
	for _, x := range append(append([]string(nil), r.cfg.ExtraROBinds...), r.cfg.ExtraRWBinds...) {
		if err := sandbox.CheckObserverDirBind("extra bind", x, r.observerDir, resolveSandboxBindPath); err != nil {
			return nil, fmt.Errorf("terminal_sandbox: %w", err)
		}
	}
	for _, rel := range spec.StateRW {
		if err := sandbox.CheckObserverDirBind("state rw bind", filepath.Join(home, rel), r.observerDir, resolveSandboxBindPath); err != nil {
			return nil, fmt.Errorf("terminal_sandbox: %w", err)
		}
	}
	installID, err := appleInstallID(r.observerDir)
	if err != nil {
		return nil, err
	}
	dirs, err := macDirsFor(run.ID)
	if err != nil {
		return nil, err
	}
	tier := vocab.Tier(r.egress.Mode)
	netReq := sandbox.NetRequest{Egress: r.egress.Mode, ProxyPort: r.proxyPort, EgressAllowCIDRs: r.cfg.EgressAllowCIDRs, HostSocketDir: dirs.SocketDir}
	if capture := sandboxRunCaptureFor(appleRow(), created.ProxyRouted, tier, r.cfg.EffectiveProviderDirect()); capture.ProviderBlock {
		netReq.ProviderBlock, netReq.ProviderHosts = true, r.providerHosts
	}
	overlays, pins, err := r.protection(home, run.Dir, spec)
	if err != nil {
		return nil, err
	}
	mp := appleMounts(home, run.Dir, spec, r.cfg, overlays, pins)
	host, err := sandbox.RelayHostArgv(r.observerBin, netReq, mp.Placeholders, sandbox.RelayRequest{RunID: run.ID, HostObserverDir: r.observerDir})
	if err != nil {
		return nil, err
	}
	guest, err := sandbox.GuestArgv(sandboxapple.GuestObserverPath, netReq)
	if err != nil {
		return nil, err
	}
	plan := sandboxapple.RunPlan{
		CLI: cli, Name: sandboxapple.ContainerName(installID, run.ID), RunID: run.ID, InstallID: installID,
		Image: strings.TrimSpace(d.cfg.Image), MemoryMiB: d.cfg.MemoryMiB, CPUs: d.cfg.CPUs,
		UID: os.Getuid(), GID: os.Getgid(), WorkDir: run.Dir, Mounts: mp.Mounts, ReadOnlyPaths: mp.ReadOnly,
		// The capture relay's tunnel: the guest's init listens, the host
		// helper dials the published host end (D-A4).
		PublishSockets: []sandboxapple.PublishSocket{{Host: filepath.Join(dirs.SocketDir, sandboxapple.TunnelSocketName), Guest: sandboxapple.GuestTunnelPath}},
	}
	// Checked now with a stand-in command and env file, so a plan the CLI
	// cannot carry refuses the launch here, not in the helper.
	check := appleWithHidden(plan, mp.Hidden, dirs)
	check.EnvFile = filepath.Join(dirs.TempDir, "env")
	if check.Command, err = sandboxapple.GuestCommand(appleInitSpec(check, r.observerBin, run.ID), guest, []string{r.observerBin}); err != nil {
		return nil, fmt.Errorf("terminal_sandbox: %w", err)
	}
	if _, err := sandboxapple.RunArgv(check); err != nil {
		return nil, fmt.Errorf("terminal_sandbox: %w", err)
	}
	planPath, err := writeMacPlan(r.observerDir, appleDriverName, run.ID, applePlanFile{
		Version: macPlanVersion, Run: plan, Dirs: dirs, Guest: guest, HostBin: r.observerBin, Hidden: mp.Hidden,
	})
	if err != nil {
		return nil, err
	}
	wrap := []string{r.observerBin, appleHostVerb, "--plan", planPath, "--"}
	wrap = append(wrap, host...)
	return append(wrap, appleInnerMarker), nil
}

// appleInitSpec is the in-image init's half of the plan: the host user, the
// relay tunnel's run and the in-guest check derived from the final plan
// (the hidden stand-ins included).
func appleInitSpec(p sandboxapple.RunPlan, hostBin, relayRun string) sandboxapple.InitSpec {
	mounts, ro := sandboxapple.ExpectedGuestMounts(p)
	return sandboxapple.InitSpec{HostBin: hostBin, UID: p.UID, GID: p.GID, Relay: relayRun, Mounts: mounts, ReadOnly: ro}
}

// appleMountPlan is what appleMounts composed.
type appleMountPlan struct {
	// Mounts are the -v mounts, each source at its own path.
	Mounts []sandboxapple.Mount
	// ReadOnly are the paths inside the mounts the guest makes read-only
	// (--read-only-path).
	ReadOnly []string
	// Hidden are the protect table's hidden paths a mount shows.
	Hidden []appleHidden
	// Placeholders are the read-only paths the host helper must create
	// first (a missing one would be skipped by the guest).
	Placeholders []sandbox.Overlay
}

// appleMounts composes the container's mounts from the bwrap plan's
// inputs: the workspace and the tool's writable state read-write at their
// own paths, its read-only state and the operator's binds; the protect
// table's read-only overlays that a mount shows are made read-only inside
// the guest with --read-only-path (a missing one through a host-made
// placeholder), and its hidden ones are returned for the helper. No file is
// ever mounted with -v under a directory that is itself a mount's source:
// Apple container 1.6.0 shares a file mount through its parent directory
// and then drops that directory's own mount (live 2026-10-23, D-A3: the
// .git pin vanished from the guest while inspect still listed it), so a
// read-only file under a mount becomes a read-only path too. There is no
// socket dir mount: a host unix socket does not connect over virtiofs
// (D-A4); the guest's init serves the run's sockets over the published
// tunnel instead. Tool binaries are not mounted: the host's are macOS
// programs, the image provides the agent. pins (sandboxRuntime.protection:
// the repository folders and .git under a write mount) are mounted
// read-write onto themselves after the write mounts, as the bwrap and oci
// paths do (lane SHR-FOLLOWUPS, ledger SBX-BE-10), so the box cannot rename
// a .git aside under the read-only paths; a pin that is a file (a .git
// gitfile) becomes a read-only path, so it can be neither renamed nor
// rewritten; a pin whose nearest enclosing mount is not a write mount
// (sandbox.PinWritable: outside every write mount, or under a read-only
// mount nested in one, such as an extra_ro_binds repository inside an org
// write bind; audit finding 1 of lane SHR-FOLLOWUPS), missing or a symlink
// is left out.
func appleMounts(home, workDir string, spec integration.SandboxSpec, cfg config.TerminalSandboxConfig, overlays []sandbox.Overlay, pins []string) appleMountPlan {
	var out []sandboxapple.Mount
	var ro []string
	seen := map[string]bool{}
	visible := func(p string) bool {
		for _, m := range out {
			if macWithin(p, m.Target) {
				return true
			}
		}
		return false
	}
	add := func(src string, readOnly, mustExist bool) {
		src = filepath.Clean(src)
		if src == "" || seen[src] {
			return
		}
		fi, err := os.Stat(src)
		if mustExist && err != nil {
			return
		}
		seen[src] = true
		if readOnly && err == nil && !fi.IsDir() && visible(src) {
			ro = append(ro, src)
			return
		}
		out = append(out, sandboxapple.Mount{Source: src, Target: src, ReadOnly: readOnly})
	}
	add(workDir, false, false)
	for _, rel := range spec.StateRW {
		add(filepath.Join(home, rel), false, true)
	}
	for _, x := range cfg.ExtraRWBinds {
		add(x, false, true)
	}
	for _, x := range cfg.ExtraROBinds {
		add(x, true, true)
	}
	for _, rel := range spec.StateRO {
		add(filepath.Join(home, rel), true, true)
	}
	for _, pin := range pins {
		pin = filepath.Clean(pin)
		fi, err := os.Lstat(pin)
		if err != nil || fi.Mode()&os.ModeSymlink != 0 || seen[pin] {
			continue
		}
		mounts := make([]sandbox.PinMount, 0, len(out))
		for _, m := range out {
			mounts = append(mounts, sandbox.PinMount{Target: m.Target, Writable: !m.ReadOnly})
		}
		if !sandbox.PinWritable(pin, mounts) {
			continue
		}
		if fi.IsDir() {
			add(pin, false, false)
			continue
		}
		seen[pin] = true
		ro = append(ro, pin)
	}
	var hidden []appleHidden
	var placeholders []sandbox.Overlay
	for _, o := range overlays {
		if !visible(o.Path) || seen[o.Path] {
			continue
		}
		switch o.Kind {
		case sandbox.OverlayReadOnly:
			if o.Placeholder == sandbox.PlaceholderNone {
				if _, err := os.Stat(o.Path); err != nil {
					continue
				}
			} else {
				placeholders = append(placeholders, o)
			}
			seen[o.Path] = true
			ro = append(ro, o.Path)
		case sandbox.OverlayHideDir, sandbox.OverlayHideFile:
			seen[o.Path] = true
			hidden = append(hidden, appleHidden{Path: o.Path, Dir: o.Kind == sandbox.OverlayHideDir})
		}
	}
	return appleMountPlan{Mounts: out, ReadOnly: ro, Hidden: hidden, Placeholders: placeholders}
}

// appleWithHidden adds the hidden paths' empty stand-ins (made by the
// helper under the run's TMPDIR) as read-only mounts.
func appleWithHidden(p sandboxapple.RunPlan, hidden []appleHidden, dirs macRunDirs) sandboxapple.RunPlan {
	p.Mounts = append([]sandboxapple.Mount(nil), p.Mounts...)
	for i, h := range hidden {
		p.Mounts = append(p.Mounts, sandboxapple.Mount{Source: appleHiddenSource(dirs, i, h.Dir), Target: h.Path, ReadOnly: true})
	}
	return p
}

// appleHiddenSource is the empty stand-in of hidden path i.
func appleHiddenSource(dirs macRunDirs, i int, dir bool) string {
	kind := "file"
	if dir {
		kind = "dir"
	}
	return filepath.Join(dirs.TempDir, fmt.Sprintf("hidden-%d-%s", i, kind))
}

// macWithin reports whether p is root or inside it.
func macWithin(p, root string) bool {
	p, root = filepath.Clean(p), filepath.Clean(root)
	return p == root || strings.HasPrefix(p, root+string(filepath.Separator))
}

// appleEnvDir is the launcher-only directory of a run's env file: under the
// observer dir (hidden from every Seatbelt box, never in the shared temp
// space), 0700.
func appleEnvDir(observerDir, runID string) string {
	return filepath.Join(macStateDir(observerDir, appleDriverName), "env", runID)
}

// writeAppleEnvFile writes body (the launch environment, keys included) to
// a fresh 0600 file in a fresh 0700 dir only the launcher reads, and
// returns its path and a remove func (idempotent; the helper calls it as
// soon as the container has started, and again on its way out).
func writeAppleEnvFile(observerDir, runID string, body []byte) (string, func(), error) {
	noop := func() {}
	if !tokenLike(runID) {
		return "", noop, fmt.Errorf("run id %q is not a plain token", runID)
	}
	dir := appleEnvDir(observerDir, runID)
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return "", noop, err
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return "", noop, err
	}
	var once sync.Once
	remove := func() { once.Do(func() { _ = os.RemoveAll(dir) }) } //nolint:gosec // G703: the run's own dir under the observer dir, created fresh above
	p := filepath.Join(dir, "env")
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: a fixed name in the dir created above
	if err != nil {
		remove()
		return "", noop, err
	}
	_, werr := f.Write(body)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		remove()
		return "", noop, werr
	}
	return p, remove, nil
}

// tokenLike accepts a run id as a single plain path segment.
func tokenLike(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// appleRunEnv is the container's environment: the launch environment
// without the host socket and interop variables, the trusted launcher
// channel and the host-only paths, plus the sandbox marker.
func appleRunEnv(environ []string) []string {
	// The allow-list first (WINFIX2 R-167): the container runs Linux.
	environ = sandboxBoxEnv("linux", environ)
	drop := []string{"XDG_RUNTIME_DIR", envOOBFD, envOOBAuth, sandboxEnvMarker}
	drop = append(drop, sandbox.GuestUnsetEnv...)
	return append(sandboxapple.ContainerEnv(environ, drop), sandboxEnvMarker+"=1")
}

// Resize is owned by the PTY: the container CLI carries the size.
func (d *appleDriver) Resize(context.Context, termsvc.SandboxRun, uint16, uint16) (termsvc.LifecycleResult, error) {
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictPTYOwned, Detail: "apple-container: the container CLI in the PTY passes the size on"}, nil
}

// Signal is owned by the PTY.
func (d *appleDriver) Signal(context.Context, termsvc.SandboxRun, string) (termsvc.LifecycleResult, error) {
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictPTYOwned, Detail: "apple-container: signals reach the agent through the container's TTY"}, nil
}

// Copy is not offered: the workspace is a host directory.
func (d *appleDriver) Copy(context.Context, termsvc.CopyRequest) (termsvc.LifecycleResult, error) {
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictNotSupported, Detail: "apple-container: the workspace is a host directory; copy on the host"}, nil
}

// Checkpoint is not offered.
func (d *appleDriver) Checkpoint(context.Context, termsvc.SandboxRun) (termsvc.LifecycleResult, error) {
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictNotSupported, Detail: "apple-container: no checkpoint; the agent's native resume applies"}, nil
}

// Stop is owned by the PTY: closing the terminal ends the CLI, and the
// container is removed (--rm, then the helper's own removal).
func (d *appleDriver) Stop(context.Context, termsvc.SandboxRun, time.Duration) (termsvc.LifecycleResult, error) {
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictPTYOwned, Detail: "apple-container: closing the terminal ends and removes the container"}, nil
}

// Destroy releases a run that never started.
func (d *appleDriver) Destroy(_ context.Context, run termsvc.SandboxRun) (termsvc.LifecycleResult, error) {
	_ = removeMacPlan(d.r.observerDir, appleDriverName, run.ID)
	return d.r.destroyBwrap(run)
}

// appleInstallID is this node's install id for the driver, minted once:
// every container carries it, so the sweep never touches another install's.
func appleInstallID(observerDir string) (string, error) {
	dir := macStateDir(observerDir, appleDriverName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("terminal_sandbox: apple-container state dir: %w", err)
	}
	p := filepath.Join(dir, "install-id")
	if fi, err := os.Lstat(p); err == nil {
		if !fi.Mode().IsRegular() || fi.Size() > 128 || !ownedByMe(fi) {
			return "", fmt.Errorf("terminal_sandbox: %s is not a small regular file this user owns", p)
		}
		b, err := os.ReadFile(p) //nolint:gosec // G304: a fixed path under the observer dir
		if err != nil {
			return "", err
		}
		if id := strings.TrimSpace(string(b)); sandboxapple.ValidToken(id) {
			return id, nil
		}
		return "", fmt.Errorf("terminal_sandbox: %s does not hold an install id", p)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	id := hex.EncodeToString(raw[:])
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: a fixed path under the observer dir
	if errors.Is(err, fs.ErrExist) {
		return appleInstallID(observerDir)
	}
	if err != nil {
		return "", err
	}
	_, werr := f.WriteString(id + "\n")
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return id, werr
}

// appleRunLive reports whether a run is still live: its relay run record
// exists after the records of dead helpers were pruned.
func appleRunLive(observerDir string) func(string) bool {
	_, _ = sandboxrelayd.PruneDeadRuns(observerDir)
	return func(runID string) bool {
		_, err := sandboxrelayd.ReadRun(observerDir, runID)
		return err == nil
	}
}

// The capture relay's tunnel helpers are shared with the microVM driver
// (sandbox_relaytunnel.go, one owner); the Apple names are kept so this
// driver's calls and tests are unchanged.

// appleTunnelKinds is relayTunnelKinds.
func appleTunnelKinds(sockDir string, gateway bool) map[string]bool {
	return relayTunnelKinds(sockDir, gateway)
}

// bindsToolState: the Apple container binds the tool's own state directory, so the box shares the tool's sign-in
// (sandboxStateBinder, operator ruling P-183).
func (*appleDriver) bindsToolState() bool { return true }

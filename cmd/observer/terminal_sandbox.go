//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/proxyroute"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxnet"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
	"github.com/marmutapp/superbased-observer/internal/scrub"
	"github.com/marmutapp/superbased-observer/internal/termrun"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
	"github.com/marmutapp/superbased-observer/internal/toolresolve"
	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// terminal_sandbox.go is the ONE place bwrap and git are actually exec'd (B9
// plan §1/§3/§4). It hosts sandboxRuntime, the single cmd-side type that
// implements BOTH B9 seams over the committed pure packages:
//
//   - termsvc.Sandboxer      (Prepare): host-side git workspace prep +
//     sandbox.BuildPlan → the bwrap WrapArgv prefix.
//   - dashapi.SandboxProber (ProbeSandbox): the fail-soft availability probe
//     the New Terminal dialog + the fail-closed launch validation read.
//
// Neither the pure planner (internal/sandbox) nor the workspace planner
// (internal/workspace) ever execs anything — this file injects the real I/O
// (exec.LookPath, exec.CommandContext, os.MkdirAll, filepath.EvalSymlinks) and
// maps their results across the two plain-data seams. All the bwrap vocabulary
// and every path/URL injection guard live in the pure packages; this file only
// resolves absolute host paths and runs the composed argv.

// sandboxRuntimeLadder is the plan §2 HOME-relative runtime probe ladder: the
// dirs a launchable tool's binary/runtime legitimately resolves through under
// $HOME (node/nvm/bun/etc). They are ro-bind-try'd (tolerate missing) so a
// tmpfs'd home still exposes the interpreter the tool's shim needs, without
// re-declaring a static per-tool list. It mirrors toolresolve's own probe
// table. Package-level so the set has one owner (plan §2).
var sandboxRuntimeLadder = []string{
	".local/bin",
	".local/share",
	".nvm",
	".npm-global",
	".npm",
	".bun",
	".volta",
	".local/share/pnpm",
	".cargo/bin",
	".deno",
	".config/nvm",
}

// sandboxProbeTTL is how long a probe result is cached (plan §7 "cached 60s").
// Short enough that a mid-session `apt install bubblewrap` is noticed on the
// next dialog open, long enough that repeated dialog opens / launch attempts
// don't re-run the version+canary exec each time.
const sandboxProbeTTL = 60 * time.Second

// sandboxHolder is the HOT-SWAPPABLE B9 sandbox seam: one long-lived value
// wired into termsvc (as the Sandboxer) and into the dashboard (as the
// SandboxProber) for the daemon's whole life, holding the *sandboxRuntime
// that actually does the work behind an atomic pointer.
//
// WHY IT EXISTS. Before this, buildTerminalStack resolved
// [terminal.sandbox].enabled exactly once, at construction. Turning the
// sandbox on from Terminals → Settings wrote config.toml and changed
// nothing else: the probe kept answering "disabled_by_config" and the New
// Terminal dialog kept the "Run in a sandbox" checkbox greyed out until the
// operator restarted the daemon — with no copy anywhere saying so. The
// holder makes the seam swappable so a save binds on the next launch.
//
// The swap discipline is the one-owner rule (CLAUDE.md #4): the holder is
// the only thing that ever constructs a sandboxRuntime after startup, the
// runtime itself stays immutable, and every reader takes ONE atomic load —
// so an in-flight Prepare keeps running against the runtime it started
// with instead of observing a half-rebuilt one. internal/sandbox stays
// pure; nothing about the exec seam moves.
type sandboxHolder struct {
	// configPath is the daemon's resolved config.toml. Empty disables the
	// self-refresh (nothing to stat), leaving the holder pinned to its
	// boot-time runtime.
	configPath string
	// observerDir / observerBin are the rebuild inputs that CANNOT change
	// without a restart (the DB path and the running executable), so they
	// are resolved once here rather than re-read per reload.
	observerDir string
	observerBin string
	logger      *slog.Logger
	// managedRoot is the workspaces root handed to termsvc.Options.
	// SandboxWorkspacesDir at construction. termsvc holds its own copy for
	// the daemon's life, so a reload that MOVES workspaces_dir cannot take
	// effect for managed (non-"live") sources — reload warns instead of
	// silently validating against the wrong root.
	managedRoot string

	// rt is the live runtime, or nil when the feature is off. initErr is
	// the last rebuild failure (nil when the last rebuild succeeded), which
	// is what turns an enabled-but-broken sandbox into its OWN verdict
	// instead of being flattened into "disabled_by_config".
	rt      atomic.Pointer[sandboxRuntime]
	initErr atomic.Pointer[string]

	// mu guards the config-file stamp + serializes rebuilds so two
	// concurrent probes can't both construct a runtime.
	mu       sync.Mutex
	stampMod time.Time
	stampLen int64
	stamped  bool
	// managedGen is the managed sandbox overlay generation the runtime was
	// built from (sandbox_managed.go), so a new managed body rebuilds it.
	managedGen uint64
}

// newSandboxHolder builds the holder and performs its FIRST resolve, so a
// daemon that boots with [terminal.sandbox].enabled = true has a live
// runtime before the first dialog opens. It never fails: a broken runtime
// is a verdict (runtime_init_failed), not a reason to refuse to build the
// terminal stack.
func newSandboxHolder(cfg config.Config, configPath, observerDir, observerBin string, logger *slog.Logger) *sandboxHolder {
	h := &sandboxHolder{
		configPath:  strings.TrimSpace(configPath),
		observerDir: observerDir,
		observerBin: observerBin,
		logger:      logger,
		managedRoot: defaultWorkspacesDir(cfg.Terminal.Sandbox, observerDir),
	}
	// Canonicalize the managed root the same way newSandboxRuntime does, so
	// termsvc's ValidateManagedWorkspace and the runtime agree on a
	// symlink-free prefix when the directory already exists. When it does
	// not (the feature is off and nothing has created it), the plain joined
	// path is the honest answer and the first enable-reload creates it.
	if resolved, err := filepath.EvalSymlinks(h.managedRoot); err == nil {
		h.managedRoot = resolved
	}
	h.reload(cfg)
	h.stampConfig()
	for _, hook := range sandboxDaemonStartHooks {
		hook(observerDir)
	}
	// A worktree run whose daemon stopped or crashed is ended at daemon
	// start, under the same keep rules as a run's own end, not only at the
	// next worktree launch (SBX-WORKTREE-SOURCE). It runs off the start path.
	go sweepSandboxWorktrees(context.Background(), observerDir, h.managedRoot, time.Now().UTC(), logger)
	// The protected-path placeholders of a host helper killed with SIGKILL
	// (its own exit removes them otherwise) go at daemon start too, proven
	// by the helper's ledger (Linux live re-check 2026-10-23, N3).
	go sweepStaleSandboxPlaceholders(observerDir, logger)
	return h
}

// reload swaps in a runtime built from the supplied [terminal.sandbox]
// block. Disabling clears the runtime AND the error (an off switch is not a
// failure). Enabling with a runtime that will not initialize KEEPS the
// previous seam — an operator mid-edit should not lose a working sandbox to
// a typo — and records the error so the probe reports it verbatim.
func (h *sandboxHolder) reload(full config.Config) {
	cfg := effectiveSandboxConfig(full)
	if !cfg.Enabled {
		h.rt.Store(nil)
		h.initErr.Store(nil)
		releaseSandboxDrivers()
		return
	}
	rt, err := newSandboxRuntime(cfg, full.Launch.Tools, h.observerDir, h.observerBin, h.logger)
	if err == nil {
		rt.inDaemon = true
		rt.applyDaemonConfig(full)
		org := effectiveSandboxOrgBinds(full)
		rt.orgRWBinds, rt.orgSkipScan = org.rw, org.skipScan
	}
	if err != nil {
		msg := err.Error()
		h.initErr.Store(&msg)
		if h.logger != nil {
			h.logger.Warn("terminal sandbox: could not initialize the sandbox runtime - keeping the previous seam", "err", err)
		}
		return
	}
	if rt.workspacesDir() != h.managedRoot && h.logger != nil {
		h.logger.Warn("terminal sandbox: [terminal.sandbox].workspaces_dir changed since daemon start - "+
			"live-source launches are unaffected, but a managed workspace (clone/worktree) needs a daemon restart",
			"boot", h.managedRoot, "config", rt.workspacesDir())
	}
	h.rt.Store(rt)
	h.initErr.Store(nil)
}

// refresh re-resolves the seam when config.toml has changed on disk since
// the last look. It is the hot-reload trigger: the dashboard's sandbox PUT
// writes the file (and fires Options.OnConfigSaved), `observer config
// reload` fires the same hook, and a hand-edit fires nothing at all — a
// mtime+size stamp catches all three, from the two seams that matter
// (ProbeSandbox and Prepare) and nowhere else.
//
// Cost is one os.Stat per probe/prepare; the rebuild itself runs only when
// the stamp actually moved. Best-effort: an unreadable config path leaves
// the current seam in place rather than tearing down a working sandbox.
func (h *sandboxHolder) refresh() {
	if h.configPath == "" {
		return
	}
	info, err := os.Stat(h.configPath)
	if err != nil {
		return
	}
	h.mu.Lock()
	changed := !h.stamped || !info.ModTime().Equal(h.stampMod) || info.Size() != h.stampLen
	changed = sandboxManagedChanged(&h.managedGen) || changed
	h.stampMod, h.stampLen, h.stamped = info.ModTime(), info.Size(), true
	h.mu.Unlock()
	if !changed {
		return
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: h.configPath})
	if err != nil {
		if h.logger != nil {
			h.logger.Warn("terminal sandbox: config changed but could not be reloaded - keeping the previous seam", "err", err)
		}
		return
	}
	h.reload(cfg)
}

// stampConfig records the config file's identity without rebuilding, so the
// first refresh() after construction is a no-op rather than an immediate
// second resolve.
func (h *sandboxHolder) stampConfig() {
	if h.configPath == "" {
		return
	}
	info, err := os.Stat(h.configPath)
	if err != nil {
		return
	}
	h.mu.Lock()
	h.stampMod, h.stampLen, h.stamped = info.ModTime(), info.Size(), true
	h.mu.Unlock()
}

// workspacesDir returns the boot-time managed-workspaces root termsvc holds
// for the daemon's life (see sandboxHolder.managedRoot).
func (h *sandboxHolder) workspacesDir() string { return h.managedRoot }

// ProbeSandbox implements dashapi.SandboxProber over the live runtime,
// distinguishing the THREE honest "no sandbox" states the dialog used to
// flatten into one string:
//
//   - disabled_by_config — [terminal.sandbox].enabled is false. The switch
//     is in the dashboard and the save binds immediately, which is what the
//     reason says.
//   - runtime_init_failed — enabled, but the runtime could not be built
//     (an unwritable workspaces_dir, a non-absolute path). Carries the
//     construction error verbatim; it is an operator-fixable config fault,
//     not a missing capability.
//   - the probe verdicts (available / backend_missing / backend_too_old /
//     userns_denied / unsupported_platform) from the runtime itself.
func (h *sandboxHolder) ProbeSandbox(ctx context.Context) dashapi.SandboxAvailability {
	h.refresh()
	if msg := h.initErr.Load(); msg != nil {
		return dashapi.SandboxAvailability{
			Available: false,
			Verdict:   dashapi.VerdictRuntimeInitFailed,
			Reason:    *msg,
		}
	}
	rt := h.rt.Load()
	if rt == nil {
		return dashapi.SandboxAvailability{
			Available: false,
			Verdict:   dashapi.VerdictDisabledByConfig,
			Reason:    "[terminal.sandbox].enabled is false on this daemon",
		}
	}
	return rt.ProbeSandbox(ctx)
}

// Prepare implements termsvc.Sandboxer over the live runtime. With no
// runtime it returns termsvc.ErrSandboxUnavailable — the SAME fail-closed
// error a nil Sandboxer produces, so wiring the holder unconditionally
// never widens what a sandboxed launch is allowed to do.
func (h *sandboxHolder) Prepare(ctx context.Context, req termsvc.PrepareRequest) (termsvc.PrepareResult, error) {
	h.refresh()
	rt := h.rt.Load()
	if rt == nil {
		return termsvc.PrepareResult{}, termsvc.ErrSandboxUnavailable
	}
	return rt.Prepare(ctx, req)
}

// sandboxRuntime implements termsvc.Sandboxer and dashapi.SandboxProber over
// internal/sandbox + internal/workspace. It is constructed once per daemon in
// buildTerminalStack, ONLY when [terminal.sandbox].enabled is true — a nil
// runtime is the honest "feature absent" state both seams fail closed on
// (termsvc returns ErrSandboxUnavailable; the dashboard 501s / reports
// disabled_by_config).
type sandboxRuntime struct {
	cfg config.TerminalSandboxConfig
	// launchTools is a copy of [launch.tools] so toolBinDirs can honour a
	// pinned tool-binary path (parity with resolveToolBin) without reloading
	// config on the launch path.
	launchTools map[string]config.LaunchToolConfig
	// observerDir is ~/.observer (canonical, symlinks resolved) — bound rw
	// inside the sandbox (the observed-invariant: hook DB writes).
	observerDir string
	// managedRoot is the canonical managed-workspaces dir
	// (<observerDir>/workspaces or [terminal.sandbox].workspaces_dir). It is
	// also what termsvc holds as SandboxWorkspacesDir, so the two
	// ValidateManagedWorkspace checks agree.
	managedRoot string
	// observerBin is the daemon binary path (== the spawned spec's BinPath, so
	// argv[0] resolves inside the sandbox); observerRealDir is its EvalSymlinks
	// target dir (bound ro too, in case argv[0] is a symlink into a versioned
	// install dir).
	observerBin     string
	observerRealDir string
	logger          *slog.Logger
	// egress is the resolved [terminal.sandbox].egress tier row
	// (SR27-SBX-1); an unknown value fails runtime construction.
	egress sandbox.EgressProfile
	// proxyPort is the daemon's model proxy port ([proxy].port, default
	// 8820), forwarded into a private-namespace sandbox under the same
	// number.
	proxyPort int
	// guardPolicyPaths are the daemon-config-derived guard policy paths a
	// sandboxed agent must not rewrite (the user policy file and the
	// trusted per-project policy dir); Rel is ABSOLUTE here, Dir marks the
	// directory. May be empty.
	guardPolicyPaths []sandbox.ProtectedPath
	// providerHosts are the proxy's own configured upstream hosts, added to
	// the egress gateway's model-provider block (section 7.3).
	providerHosts []string
	// proxyServing is whether this node serves the API proxy
	// (proxyServingReason is empty), set by applyDaemonConfig. False until
	// then, so a runtime that never saw the daemon config computes every
	// launch unrouted (the conservative answer).
	proxyServing bool
	// inspectRoutes reads the tools' persisted proxy routes
	// (proxyroute.InspectRoutes over the daemon's home); nil skips the
	// persisted-elsewhere rule.
	inspectRoutes func() []proxyroute.RouteStatus
	// effectiveRoute reads the tool's effective route over the run's
	// workspace (readEffectiveRoute, set by applyDaemonConfig); nil skips
	// the effective-route rows (P-017 (a)).
	effectiveRoute func(spec integration.Capability, proxyURL, dir string, args []string) effectiveRouteClass
	// orgRWBinds are the write binds of cfg the in-force managed body set
	// (sandboxManagedOrgRWBinds): each one's repository hooks and config
	// are re-bound read-only (ruling P-054).
	orgRWBinds []string
	// orgSkipScan are the org write binds the organization asserts hold no
	// repositories (node.skip_repo_scan, ruling P-060): the repository walk
	// below each is skipped (sandboxOrgBindGitRows).
	orgSkipScan []string

	// unattached holds the managed workspace dir of each run Create made
	// and Attach has not taken yet (run id -> <managedRoot>/<id>). Destroy
	// removes such a workspace: no agent ever ran in it, so it holds none
	// of the user's work (P-017 (f)).
	unattached sync.Map

	// drivers are the non-bwrap isolation drivers active on this node
	// (sandbox plan v2 section 11.3), built by applyDaemonConfig from the
	// drivers that registered themselves from their own build-tagged files
	// (registerSandboxDriver); empty on a node that selects none, where
	// every launch takes the bwrap path exactly as before.
	drivers map[string]sandboxDriver
	// inactiveDrivers are registered drivers whose component is not
	// selected (backend id -> component id): listed as module_inactive and
	// never probed.
	inactiveDrivers map[string]string
	// runDrivers maps a run id to the driver that created it, so the
	// lifecycle operations of that run reach the same driver.
	runDrivers sync.Map
	// forceBackend is a backend the CLI named explicitly (never
	// substituted, I1); empty for the selection's own choice.
	forceBackend string
	// inDaemon marks the daemon's own runtime (the holder's), the only one
	// that may start daemon-lifetime driver work such as an orphan sweep;
	// a CLI launch's runtime never does.
	inDaemon bool

	// worktreePinOnce guards worktreePinned, the org pin on
	// allow_worktree_source read once per runtime (worktreeOrgPinned).
	worktreePinOnce sync.Once
	worktreePinned  bool

	mu       sync.Mutex
	cached   dashapi.SandboxAvailability
	cachedAt time.Time
	now      func() time.Time
}

// sandboxDriver is one isolation driver other than bwrap: the lifecycle
// service of section 4.6 plus the probe that feeds the selection table.
// probe must not dial, exec or start anything while the driver's backend is
// not in [terminal.sandbox].backends (the opt-in rule of section 10.1).
type sandboxDriver interface {
	termsvc.SandboxLifecycle
	// probe is this driver's selection input on this host.
	probe(ctx context.Context) sandboxselect.Probe
	// version is the version the last probe read, for the legacy fields.
	version() string
}

// driverBackend is the backend row id d is registered under in r.drivers
// ("" when it is not one of them).
func (r *sandboxRuntime) driverBackend(d sandboxDriver) string {
	for id, have := range r.drivers {
		if have == d {
			return id
		}
	}
	return ""
}

// sandboxDriverReg is one registered driver: its backend row id, its
// component id and how to build it over a runtime.
type sandboxDriverReg struct {
	backend   string
	component string
	build     func(r *sandboxRuntime, full config.Config) sandboxDriver
	// relayOS is the operating system (a GOOS value) other than Linux on
	// which the daemon serves the capture relay while this driver is
	// selected (sandboxRelayOnOS); empty for a driver that runs on Linux
	// only, where the relay is always served.
	relayOS string
	// release stops whatever the driver runs for the daemon's life (an
	// orphan sweep) when the daemon's runtime no longer has the driver
	// active; nil when it runs nothing.
	release func()
	// cliConsoleHost: the driver's box shows its output only through the
	// standard handles its host helper inherits, so a CLI launch on a
	// console window runs the helper on a pseudo console of the launcher's
	// own (sandbox_cli_console.go, RERUN2 D1).
	cliConsoleHost bool
}

// releaseSandboxDrivers releases every registered driver's daemon-lifetime
// work (the sandbox was turned off).
func releaseSandboxDrivers() {
	for _, reg := range sandboxDriverRegs {
		if reg.release != nil {
			reg.release()
		}
	}
}

// sandboxDriverRegs is the driver registry. A driver's own build-tagged file
// adds its row from init (registerSandboxDriver); its omit twin adds none,
// so no core function ever names a driver (section 11.3).
var sandboxDriverRegs = map[string]sandboxDriverReg{}

// registerSandboxDriver adds a driver. It is called from init only.
func registerSandboxDriver(reg sandboxDriverReg) { sandboxDriverRegs[reg.backend] = reg }

// sandboxDaemonStartHooks run once when the daemon builds its sandbox
// holder (newSandboxHolder), with the observer dir, whether or not the
// sandbox, the driver or its probe is on: work that must never wait for a
// selection or a passing probe (the microVM orphan sweep). Each must be
// cheap and start its own goroutine for anything slow.
var sandboxDaemonStartHooks []func(observerDir string)

// sandboxDriversRebuildHooks run at the start of every driver rebuild, so a
// driver family's process-wide state does not outlive the driver that set it
// (a driver's build sets it again). Filled from init only.
var sandboxDriversRebuildHooks []func()

// buildSandboxDrivers builds the drivers whose component this node selects
// (sandboxDriverSelected: the opt-in rule) and records the others.
func (r *sandboxRuntime) buildSandboxDrivers(full config.Config) {
	r.drivers, r.inactiveDrivers = nil, nil
	for _, hook := range sandboxDriversRebuildHooks {
		hook()
	}
	if len(sandboxDriverRegs) == 0 {
		return
	}
	snap := componentSnapshotForConfig(full)
	for id, reg := range sandboxDriverRegs {
		if !sandboxDriverSelected(snap, reg.component) {
			if r.inDaemon && reg.release != nil {
				reg.release()
			}
			if r.inactiveDrivers == nil {
				r.inactiveDrivers = map[string]string{}
			}
			r.inactiveDrivers[id] = reg.component
			continue
		}
		if r.drivers == nil {
			r.drivers = map[string]sandboxDriver{}
		}
		r.drivers[id] = reg.build(r, full)
	}
}

// driverProbes are the selection inputs of the registered drivers: an
// active driver's own probe, an inactive one's module_inactive. Nil when
// none is registered.
func (r *sandboxRuntime) driverProbes(ctx context.Context) map[string]sandboxselect.Probe {
	if len(r.drivers) == 0 && len(r.inactiveDrivers) == 0 {
		return nil
	}
	out := map[string]sandboxselect.Probe{}
	for id, d := range r.drivers {
		out[id] = d.probe(ctx)
	}
	for id, comp := range r.inactiveDrivers {
		out[id] = sandboxselect.Probe{
			Compiled: true, Verdict: verdictModuleInactive,
			Reason: "the " + comp + " component is not selected on this node; select it in Settings > Components",
		}
	}
	return out
}

// verdictModuleInactive is section 4.7's module_inactive.
const verdictModuleInactive = "module_inactive"

// sandboxPick is a launch's walk over the enabled backends.
type sandboxPick struct {
	// chosen is the row the launch takes ("" when none).
	chosen string
	// first is the first enabled row (for a refusal naming it).
	first *dashapi.SandboxBackendAvail
	// skipped is the first available row the automatic-choice rules
	// dropped, with its drop (ruling P-062: a beta row).
	skipped *dashapi.SandboxBackendAvail
	drop    sandboxselect.Drop
}

// sandboxLaunchPick walks the enabled backends in preference order: the
// first available row the launch can use wins, except that a launch that
// names no backend (auto) skips a row the selection table's
// automatic-choice rules drop (sandboxselect.AutoDrop: an explicit-only
// row, or a row whose verification is documentation only, ruling P-062 as
// clarified in P-067; a tested row outside its tested versions is still
// taken). One table, no row named here.
func sandboxLaunchPick(enabled []string, rows map[string]dashapi.SandboxBackendAvail, auto bool, usable func(id string) bool) sandboxPick {
	var p sandboxPick
	for _, id := range enabled {
		b, ok := rows[id]
		if !ok {
			continue
		}
		if p.first == nil {
			bb := b
			p.first = &bb
		}
		if !b.Available || !usable(id) {
			continue
		}
		if auto {
			if row, ok := sandboxbackend.Get(id); ok {
				if d, dropped := sandboxselect.AutoDrop(row, vocab.Verification(b.Verification)); dropped {
					if p.skipped == nil {
						bb := b
						p.skipped, p.drop = &bb, d
					}
					continue
				}
			}
		}
		p.chosen = id
		return p
	}
	return p
}

// betaRefusal is the refusal for a launch whose only available enabled
// rows the automatic choice may not take, or nil when bwrap stays the
// fallback (it is enabled and available: the legacy path, unchanged).
func (p sandboxPick) betaRefusal(enabled []string, rows map[string]dashapi.SandboxBackendAvail) error {
	if p.chosen != "" || p.skipped == nil {
		return nil
	}
	if slices.Contains(enabled, sandboxbackend.BackendBwrap) && rows[sandboxbackend.BackendBwrap].Available {
		return nil
	}
	return fmt.Errorf("terminal_sandbox: %s is available but not chosen (%s): %s", p.skipped.ID, p.drop.Verdict, p.drop.Reason)
}

// chosenDriver is the driver a launch uses, or nil for the bwrap path. With
// no active driver among the enabled backends it is always nil, so a node
// that lists only bwrap (every node before lane SBX-P3A) launches exactly as
// before. Otherwise the first enabled backend whose row is available wins
// (the selection table's auto walk, sandboxLaunchPick: a launch that names
// no backend never takes a beta row, ruling P-062), an explicit CLI backend
// is never substituted, and bwrap is the fallback only when it is itself
// enabled.
func (r *sandboxRuntime) chosenDriver(ctx context.Context, chosen string) (sandboxDriver, error) {
	enabled := sandboxEnabledBackends(r.cfg)
	// A backend the CLI named, else the one the New Terminal picker chose
	// for this launch (lane SBX-P3B): either is never substituted.
	force := r.forceBackend
	if force == "" {
		force = chosen
	}
	if force != "" {
		if force == sandboxbackend.BackendBwrap {
			return nil, nil
		}
		enabled = []string{force}
	}
	listed := false
	for _, id := range enabled {
		_, ok := r.drivers[id]
		listed = listed || ok
	}
	if !listed {
		if force != "" {
			return nil, fmt.Errorf("terminal_sandbox: the %s backend has no active driver on this node", force)
		}
		return nil, nil
	}
	av := r.ProbeSandbox(ctx)
	rows := map[string]dashapi.SandboxBackendAvail{}
	for _, b := range av.Backends {
		rows[b.ID] = b
	}
	p := sandboxLaunchPick(enabled, rows, force == "", r.launchUsable)
	if p.chosen == sandboxbackend.BackendBwrap {
		return nil, nil
	}
	if d, ok := r.drivers[p.chosen]; ok {
		return d, nil
	}
	if err := p.betaRefusal(enabled, rows); err != nil {
		return nil, err
	}
	if slices.Contains(enabled, sandboxbackend.BackendBwrap) {
		return nil, nil
	}
	if first := p.first; first != nil {
		return nil, fmt.Errorf("terminal_sandbox: %s is not available: %s (%s)", first.ID, first.Verdict, first.Reason)
	}
	return nil, fmt.Errorf("terminal_sandbox: no enabled sandbox backend is available")
}

// launchUsable reports whether a launch can take row id: bwrap's path or an
// active driver.
func (r *sandboxRuntime) launchUsable(id string) bool {
	if id == sandboxbackend.BackendBwrap {
		return true
	}
	_, ok := r.drivers[id]
	return ok
}

// runDriver returns the driver that created run id, if any.
func (r *sandboxRuntime) runDriver(id string) (sandboxDriver, bool) {
	v, ok := r.runDrivers.Load(id)
	if !ok {
		return nil, false
	}
	d, ok := v.(sandboxDriver)
	return d, ok
}

// newSandboxRuntime constructs the runtime, resolving (and creating) the
// managed-workspaces directory and canonicalizing the observer dir + binary.
// observerBin must be the SAME path the launcher spawns as spec.BinPath (the
// daemon's os.Executable()) so argv[0] resolves to a bound file inside the
// sandbox. It never returns a partial runtime: any path it cannot resolve is an
// error (the caller then leaves both seams nil → fail closed).
func newSandboxRuntime(cfg config.TerminalSandboxConfig, launchTools map[string]config.LaunchToolConfig, observerDir, observerBin string, logger *slog.Logger) (*sandboxRuntime, error) {
	if observerDir == "" {
		return nil, fmt.Errorf("newSandboxRuntime: empty observer dir")
	}
	// Canonicalize the observer dir so the managed-workspaces tmpfs
	// (filepath.Join(observerDir, "workspaces") inside sandbox.BuildPlan) and
	// the punched-back workspace bind agree on a symlink-free prefix.
	if err := os.MkdirAll(observerDir, 0o700); err != nil {
		return nil, fmt.Errorf("newSandboxRuntime: create observer dir: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(observerDir); err == nil {
		observerDir = resolved
	}

	managed := defaultWorkspacesDir(cfg, observerDir)
	if !filepath.IsAbs(managed) {
		return nil, fmt.Errorf("newSandboxRuntime: [terminal.sandbox].workspaces_dir %q must be absolute", managed)
	}
	if err := os.MkdirAll(managed, 0o700); err != nil {
		return nil, fmt.Errorf("newSandboxRuntime: create workspaces dir: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(managed); err == nil {
		managed = resolved
	}

	egress, err := sandbox.ResolveEgress(cfg.Egress)
	if err != nil {
		return nil, fmt.Errorf("newSandboxRuntime: [terminal.sandbox].egress: %w", err)
	}
	if _, err := sandboxnet.ParseAllowCIDRs(cfg.EgressAllowCIDRs); err != nil {
		return nil, fmt.Errorf("newSandboxRuntime: [terminal.sandbox].egress_allow_cidrs: %w", err)
	}

	var realDir string
	if observerBin != "" {
		if real, err := filepath.EvalSymlinks(observerBin); err == nil && real != observerBin {
			realDir = filepath.Dir(real)
		}
	}

	return &sandboxRuntime{
		cfg:             cfg,
		launchTools:     launchTools,
		observerDir:     observerDir,
		managedRoot:     managed,
		observerBin:     observerBin,
		observerRealDir: realDir,
		logger:          logger,
		egress:          egress,
		proxyPort:       defaultSandboxProxyPort,
		now:             func() time.Time { return time.Now().UTC() },
	}, nil
}

// defaultSandboxProxyPort mirrors resolveProxyURL's default.
const defaultSandboxProxyPort = 8820

// applyDaemonConfig copies the non-sandbox daemon settings the sandbox needs
// (the proxy port it forwards, the guard policy files it protects) onto a
// freshly built runtime, before the runtime is published.
func (r *sandboxRuntime) applyDaemonConfig(full config.Config) {
	if p := full.Proxy.Port; p > 0 && p <= 65535 {
		r.proxyPort = p
	}
	r.providerHosts = proxyUpstreamHosts(full.Proxy)
	r.proxyServing = proxyServingReason(full, componentSnapshotForConfig(full).Active("capture.proxy")) == ""
	home, _ := os.UserHomeDir()
	if resolved, err := filepath.EvalSymlinks(home); err == nil {
		home = resolved
	}
	routeHome := home
	r.inspectRoutes = func() []proxyroute.RouteStatus { return proxyroute.InspectRoutes(routeHome) }
	r.effectiveRoute = readEffectiveRoute
	r.buildSandboxDrivers(full)
	r.guardPolicyPaths = nil
	for _, gp := range []sandbox.ProtectedPath{
		{Rel: full.Guard.Rules.UserPolicy},
		{Rel: full.Guard.Rules.TrustedProjectDir, Dir: true},
	} {
		if abs := expandSandboxHome(gp.Rel, home); abs != "" {
			r.guardPolicyPaths = append(r.guardPolicyPaths, sandbox.ProtectedPath{Rel: abs, Dir: gp.Dir})
		}
	}
}

// requireLiveProxy lowers proxyServing to false unless the proxy answers
// its liveness probe now (P-017 (b)). The daemon path does not need it (the
// daemon IS the proxy when its config says it serves); the CLI path runs
// outside the daemon, so a config that says "serving" with no daemon
// running is an unrouted launch, and its evidence must say so. live is
// proxyServing (route_maintenance.go): the proxy's own /-/healthz answers
// 200 and no update drain is in progress, so another program listening on
// the port does not count.
func (r *sandboxRuntime) requireLiveProxy(live func(port int) bool) {
	if r.proxyServing && (live == nil || !live(r.proxyPort)) {
		r.proxyServing = false
	}
}

// expandSandboxHome resolves a "~/"-prefixed or absolute config path to an
// absolute one; anything else (empty, relative) yields "".
func expandSandboxHome(p, home string) string {
	p = strings.TrimSpace(p)
	switch {
	case strings.HasPrefix(p, "~/") && home != "":
		return filepath.Join(home, p[2:])
	case filepath.IsAbs(p):
		return filepath.Clean(p)
	}
	return ""
}

// workspacesDir returns the canonical managed-workspaces root, so buildTerminal
// Stack can hand termsvc.Options.SandboxWorkspacesDir the SAME value this
// runtime validates prepared workspaces against.
func (r *sandboxRuntime) workspacesDir() string { return r.managedRoot }

// homeMode returns the configured home mode, defaulting to "tmpfs".
func (r *sandboxRuntime) homeMode() string {
	if r.cfg.HomeMode == "readonly" {
		return "readonly"
	}
	return "tmpfs"
}

// ---- dashapi.SandboxProber ------------------------------------------------

// ProbeSandbox implements dashapi.SandboxProber. It never returns an error: a
// probe failure IS a verdict. The bwrap platform/backend verdict comes from the
// pure sandbox.Probe over real I/O (LookPath / `bwrap --version` / the ms-scale
// user-namespace canary); this method adds the config HomeMode, the per-source
// availability list, and the per-tool sandbox-launchability map, then caches the
// whole result ~60s so the dialog is snappy but still notices a mid-session
// `apt install`.
func (r *sandboxRuntime) ProbeSandbox(ctx context.Context) dashapi.SandboxAvailability {
	// enabled=false is defensive here (buildTerminalStack only constructs the
	// runtime when enabled), but keeps the seam honest if wired differently.
	if !r.cfg.Enabled {
		return dashapi.SandboxAvailability{
			Available: false,
			Verdict:   sandbox.VerdictDisabledByConfig,
			Reason:    "[terminal.sandbox].enabled is false on this daemon",
			HomeMode:  r.homeMode(),
			Egress:    string(r.egress.Mode),
			DefaultOn: r.cfg.DefaultOn,
			Sources:   r.sources(),
			Tools:     r.tools(),
			// The master switch off enables no backend: every row drops at S2.
			Backends: sandboxBackendList(r.cfg, sandbox.Availability{}, nil, vocab.Tier(r.egress.Mode)),
			Org:      sandboxOrgView(),
		}
	}

	r.mu.Lock()
	if !r.cachedAt.IsZero() && r.now().Sub(r.cachedAt) < sandboxProbeTTL {
		cached := r.cached
		r.mu.Unlock()
		return cached
	}
	r.mu.Unlock()

	av := sandbox.Probe(r.sandboxEnv(ctx))
	drivers := r.driverProbes(ctx)
	backends := sandboxBackendListWith(r.cfg, av, sourceIDs(r.sources()), vocab.Tier(r.egress.Mode), drivers)
	av = reconcileLegacyProbe(av, backends)
	av = r.preferDriverInLegacy(av, backends)
	av = sandboxPlatformOverall(av, backends, sandboxHostKind())
	out := dashapi.SandboxAvailability{
		Available:      av.Available,
		Verdict:        av.Verdict,
		Reason:         av.Reason,
		Backend:        av.Backend,
		BackendVersion: av.BackendVersion,
		HomeMode:       r.homeMode(),
		Egress:         string(r.egress.Mode),
		DefaultOn:      r.cfg.DefaultOn,
		Sources:        r.sources(),
		Tools:          r.tools(),
	}
	out.Backends = backends
	out.Org = sandboxOrgView()

	r.mu.Lock()
	r.cached = out
	r.cachedAt = r.now()
	r.mu.Unlock()
	return out
}

// preferDriverInLegacy makes the legacy top-level probe fields describe the
// backend a launch would take when that is a driver (the first available
// enabled backend, lane SBX-P3A), so a node that lists only oci-runc is not
// shown "unavailable" because bwrap is missing. With no driver enabled (every
// node before the lane) av is returned unchanged.
func (r *sandboxRuntime) preferDriverInLegacy(av sandbox.Availability, backends []dashapi.SandboxBackendAvail) sandbox.Availability {
	rows := map[string]dashapi.SandboxBackendAvail{}
	for _, b := range backends {
		rows[b.ID] = b
	}
	enabled := sandboxEnabledBackends(r.cfg)
	if r.forceBackend != "" {
		enabled = []string{r.forceBackend}
	}
	if len(r.drivers) == 0 {
		return legacyWithinEnabled(av, enabled, rows)
	}
	// The same walk a launch takes (chosenDriver), so the legacy fields
	// never call a beta row available for a launch that names no backend.
	p := sandboxLaunchPick(enabled, rows, r.forceBackend == "", func(string) bool { return true })
	if p.chosen != "" {
		if _, isDriver := r.drivers[p.chosen]; !isDriver {
			return av
		}
		return sandbox.Availability{Available: true, Verdict: sandbox.VerdictAvailable, Backend: p.chosen, BackendVersion: rows[p.chosen].Version}
	}
	if err := p.betaRefusal(enabled, rows); err != nil {
		return sandbox.Availability{Available: false, Verdict: p.drop.Verdict, Reason: err.Error(), Backend: p.skipped.ID, BackendVersion: p.skipped.Version}
	}
	return legacyWithinEnabled(av, enabled, rows)
}

// legacyWithinEnabled keeps the legacy probe's answer (bwrap's) only while
// bwrap is among the enabled backends: a launch never takes bwrap when it is
// not listed (sandboxLocalFloor refuses it), so an available legacy answer
// then gives way to the first listed row's own verdict, the refusal the
// launch prints (Linux live re-check on the Docker sandbox 2026-10-23, N4:
// `backends = ["process_lite"]` with no Landlock printed "Overall:
// available" while `--observer-sandbox auto` refused). Nothing enabled (the
// master switch off) keeps av.
func legacyWithinEnabled(av sandbox.Availability, enabled []string, rows map[string]dashapi.SandboxBackendAvail) sandbox.Availability {
	if !av.Available || len(enabled) == 0 || slices.Contains(enabled, sandboxbackend.BackendBwrap) {
		return av
	}
	for _, id := range enabled {
		if b, ok := rows[id]; ok && b.Verdict != "" {
			return sandbox.Availability{Available: false, Verdict: b.Verdict, Reason: b.Reason, Backend: b.ID, BackendVersion: b.Version}
		}
	}
	return sandbox.Availability{Available: false, Verdict: sandbox.VerdictBackendMissing, Reason: "no enabled sandbox backend is available (backends: " + strings.Join(enabled, ", ") + ")", Backend: enabled[0]}
}

// sandboxEnv builds the injected I/O surface for sandbox.Probe. LookBwrap
// records the resolved path so Version/Canary reuse it; each subprocess runs
// under a short child context so a wedged bwrap can never stall the dialog.
func (r *sandboxRuntime) sandboxEnv(ctx context.Context) sandbox.Env {
	bwrapPath := ""
	resolve := func() string {
		if bwrapPath != "" {
			return bwrapPath
		}
		return "bwrap"
	}
	var netCanary func() error
	if r.egress.UnshareNet {
		netCanary = func() error {
			cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			//nolint:gosec // fixed, server-derived smoke argv; the binary
			// path came from exec.LookPath, never client input.
			return runBwrapCanary(exec.CommandContext(cctx, resolve(),
				"--ro-bind", "/", "/", "--unshare-pid", "--proc", "/proc", "--tmpfs", "/tmp", "--unshare-net", "--die-with-parent", "--", "true"))
		}
	}
	return sandbox.Env{
		NetCanary:  netCanary,
		GOOS:       runtime.GOOS,
		ReadSysctl: readSysctl,
		LookBwrap: func() (string, error) {
			p, err := exec.LookPath("bwrap")
			if err == nil {
				bwrapPath = p
			}
			return p, err
		},
		Version: func() (string, error) {
			cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			//nolint:gosec // fixed, server-derived argv (`bwrap --version`); the
			// binary path came from exec.LookPath, never client input.
			out, err := exec.CommandContext(cctx, resolve(), "--version").Output()
			return string(out), err
		},
		Canary: func() error {
			cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			//nolint:gosec // fixed, server-derived smoke argv (plan §7); the
			// binary path came from exec.LookPath, never client input.
			return runBwrapCanary(exec.CommandContext(cctx, resolve(),
				"--ro-bind", "/", "/", "--unshare-pid", "--proc", "/proc", "--tmpfs", "/tmp", "--die-with-parent", "--", "true"))
		},
	}
}

// runBwrapCanary runs a canary and keeps bwrap's stderr (bounded) in the
// error, so sandbox.Probe can name why it failed instead of guessing
// (live checks 2026-10-22).
func runBwrapCanary(c *exec.Cmd) error {
	var stderr boundedBuffer
	c.Stderr = &stderr
	if err := c.Run(); err != nil {
		return &sandbox.CanaryFailure{Err: err, Stderr: stderr.String()}
	}
	return nil
}

// boundedBuffer keeps the first 4 KiB written to it.
type boundedBuffer struct{ b []byte }

func (w *boundedBuffer) Write(p []byte) (int, error) {
	if room := 4096 - len(w.b); room > 0 {
		if len(p) < room {
			room = len(p)
		}
		w.b = append(w.b, p[:room]...)
	}
	return len(p), nil
}

func (w *boundedBuffer) String() string { return string(w.b) }

// readSysctl reads a kernel sysctl by its dotted name from /proc/sys.
func readSysctl(key string) (string, bool) {
	if key == "" || strings.Contains(key, "/") || strings.Contains(key, "..") {
		return "", false
	}
	b, err := os.ReadFile(filepath.Join("/proc/sys", strings.ReplaceAll(key, ".", "/"))) //nolint:gosec // G304: a fixed sysctl name from the probe's own table
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(b)), true
}

// sources reports per-workspace-source availability with honest reasons. live
// and clone-local are always available; clone-remote and worktree are the
// authority-expanding sources gated by their opt-in config flags (plan §4/§5).
func (r *sandboxRuntime) sources() []dashapi.SandboxSourceAvail {
	out := []dashapi.SandboxSourceAvail{
		{ID: string(workspace.SourceLive), Available: true},
		{ID: string(workspace.SourceCloneLocal), Available: true},
	}
	remote := dashapi.SandboxSourceAvail{ID: string(workspace.SourceCloneRemote), Available: r.cfg.AllowRemoteClone}
	if !remote.Available {
		remote.Reason = "allow_remote_clone is not set - the daemon would run `git clone <url>` with your ambient auth, so it is opt-in"
	}
	// The worktree row (lane SBX-WORKTREE-SOURCE): off by default, the
	// org note when an org pin keeps it off, bwrap only.
	return append(out, remote, r.worktreeSourceAvail())
}

// tools reports the per-tool sandbox-launchability map, keyed by tool name. A
// tool is sandbox-launchable iff its SandboxSpec declares grounded writable
// state (StateRW); otherwise the honest zero note (SandboxSpec.Note) is the
// reason. Branches on the capability SHAPE (a grounded row), never a tool name
// (CLAUDE.md #3): v1 grounds only claude-code, every other launchable row
// carries the Note fallback. Launchability itself is
// integration.TerminalLaunchable, so a deprecated/dead product never appears
// in the sandbox tool table either.
func (r *sandboxRuntime) tools() map[string]dashapi.SandboxToolAvail {
	out := map[string]dashapi.SandboxToolAvail{}
	for _, c := range integration.Capabilities() {
		if !integration.TerminalLaunchable(c) {
			continue
		}
		if len(c.Sandbox.StateRW) > 0 {
			out[c.Tool] = dashapi.SandboxToolAvail{Available: true}
			continue
		}
		reason := c.Sandbox.Note
		if reason == "" {
			reason = "no grounded sandbox state-dir row for this tool"
		}
		out[c.Tool] = dashapi.SandboxToolAvail{Available: false, Reason: reason}
	}
	// The plain shell is listed where an active driver runs one as its own
	// launch (the microVM row; its first live run found the dashboard
	// answering 400 "tool shell cannot be sandboxed", D2). The launch is
	// still judged on the backend it resolves to (shellRefusal).
	if len(r.shellHosts()) > 0 {
		out[termsvc.ShellTool] = dashapi.SandboxToolAvail{Available: true}
	}
	return out
}

// sandboxShellHost is implemented by a driver whose sandbox runs a plain
// shell as the launch itself (the microVM row: its guest image set carries
// a shell and no agent tool). Every other backend runs named tools only.
type sandboxShellHost interface {
	hostsPlainShell() bool
}

// shellHosts are the backend ids of the active drivers that run a plain
// shell, sorted.
func (r *sandboxRuntime) shellHosts() []string {
	var out []string
	for id, d := range r.drivers {
		if h, ok := d.(sandboxShellHost); ok && h.hostsPlainShell() {
			out = append(out, id)
		}
	}
	slices.Sort(out)
	return out
}

// shellRefusal refuses a plain shell on the backend a launch resolved to
// (d, nil for bwrap) when that backend runs named tools only, naming the
// backend and the ones that run a shell.
func (r *sandboxRuntime) shellRefusal(d sandboxDriver) error {
	if h, ok := d.(sandboxShellHost); ok && h.hostsPlainShell() {
		return nil
	}
	backend := sandboxbackend.BackendBwrap
	for id, dd := range r.drivers {
		if d != nil && dd == d {
			backend = id
		}
	}
	hosts := "no active backend on this node runs one"
	if ids := r.shellHosts(); len(ids) > 0 {
		hosts = "choose " + strings.Join(ids, " or ") + ", or launch a tool"
	}
	return sandboxRefusalError{msg: fmt.Sprintf("terminal_sandbox: a plain shell is sandboxed only by a backend that runs one as its launch, and this launch resolved to %s, which runs named tools only; %s", backend, hosts)}
}

// ---- termsvc.Sandboxer ------------------------------------------------------

// Prepare implements termsvc.Sandboxer: it prepares the workspace (host-side
// git) and composes the bwrap WrapArgv prefix for a sandboxed launch (plan
// §1/§3/§4). It is the ONLY exec site for git (workspace prep) and the composer
// of the bwrap argv the launcher prepends.
//
// Flow: parse+validate the source → mint a workspace id → workspace.Plan the
// git steps + dest → exec each step under the prep timeout → write meta.json →
// EvalSymlinks + ValidateManagedWorkspace the dest (fail closed) → resolve the
// bwrap Request (home/observer/tool/state/mask paths) → sandbox.BuildPlan →
// prepend the resolved bwrap path → return {Dir, WrapArgv}. For the LIVE source
// the workspace IS the project root (Dir=ProjectRoot, bound rw) — still wrapped.
func (r *sandboxRuntime) Prepare(ctx context.Context, req termsvc.PrepareRequest) (termsvc.PrepareResult, error) {
	res, err := termsvc.ComposePrepare(ctx, r, req)
	if err == nil {
		// The names the box gets beyond the OS table (WINFIX2 R-167).
		res.EnvAllow = sandboxEnvAllowNames(req.Tool, r.cfg.PassEnv)
		res.EnvPassed = append([]string(nil), r.cfg.PassEnv...)
		res.AllowOSC52Clipboard = r.cfg.AllowOSC52Clipboard
	}
	return res, err
}

// ---- termsvc.SandboxLifecycle (sandbox plan v2 section 4.6) ------------------

// Create is the first half of Prepare: it prepares the workspace and
// computes the run's evidence and route, without composing any argv.
func (r *sandboxRuntime) Create(ctx context.Context, req termsvc.PrepareRequest) (termsvc.CreateResult, error) {
	// A driver other than bwrap, when the enabled backends name an active
	// one (lane SBX-P3A); nil keeps the bwrap path below unchanged.
	d, err := r.chosenDriver(ctx, req.Backend)
	if err != nil {
		return termsvc.CreateResult{}, err
	}
	if req.Tool == termsvc.ShellTool {
		if err := r.shellRefusal(d); err != nil {
			return termsvc.CreateResult{}, err
		}
	}
	if d != nil {
		// The worktree source runs only on bwrap: a launch that asks for it
		// on a driver is refused here, before the driver asks its engine
		// anything (lane LEFT-SBX; before, the container row's loader probe
		// created a container first).
		if src, _ := workspace.ParseSource(req.WorkspaceSource); src == workspace.SourceWorktree && r.cfg.AllowWorktreeSource {
			return termsvc.CreateResult{}, fmt.Errorf("terminal_sandbox: %s", worktreeDriverReason(r.driverBackend(d)))
		}
		// A hosted row never gets a sign-in (lane BOXSIGNIN): it is never
		// offered, and an explicit yes is refused by name.
		if row, ok := sandboxbackend.Get(r.driverBackend(d)); ok && row.Iso.Location == vocab.LocationRemote {
			if err := signInGate(req, r.signInDecision(req, false, true)); err != nil {
				return termsvc.CreateResult{}, err
			}
		}
		res, err := d.Create(ctx, req)
		if err == nil {
			r.runDrivers.Store(res.Run.ID, d)
			// A driver that binds the tool's own state shares its sign-in
			// with the box, said on every launch (operator ruling P-183).
			if b, ok := d.(sandboxStateBinder); ok && b.bindsToolState() {
				res.SignInShared = sandboxSignInSharedTool(req.Tool)
			}
		}
		return res, err
	}
	// The local backend list and isolation floor (sandbox plan v2 section
	// 10) are checked before any workspace is made.
	if err := sandboxLocalFloor(launchFloorConfig(r.cfg, string(r.egress.Mode))); err != nil {
		return termsvc.CreateResult{}, err
	}
	// The agent's own sandbox inside this layer (nesting rows N11 to N14).
	if v, judged := sandboxNativeVerdict(req.Tool, vocab.Tier(r.egress.Mode)); judged {
		if err := sandboxNativeRefusal(req.Tool, v); err != nil {
			return termsvc.CreateResult{}, err
		}
	}
	ws, err := r.prepareWorkspace(ctx, req)
	if err != nil {
		return termsvc.CreateResult{}, err
	}

	// The route this launch will actually get decides both the capture level
	// and the provider block (audit finding P-006 (2)); it is computed once
	// here and carried to Attach, so the two can never disagree.
	routed, _ := r.launchRouted(req.Tool, ws.dir, req.ToolArgs)
	return termsvc.CreateResult{
		Run:         termsvc.SandboxRun{ID: ws.id, Tool: req.Tool, Dir: ws.dir, ProjectRoot: req.ProjectRoot, Copy: !ws.live},
		Note:        fmt.Sprintf("sandbox: source=%s workspace=%s egress=%s", ws.src, ws.dir, r.egress.Mode),
		Isolation:   r.runIsolation(req.Tool, routed),
		ProxyRouted: routed,
		// bubblewrap binds the tool's own state (operator ruling P-183).
		SignInShared: sandboxSignInSharedTool(req.Tool),
	}, nil
}

// preparedWorkspace is the workspace one launch runs in.
type preparedWorkspace struct {
	id   string
	dir  string
	src  workspace.Source
	live bool
}

// prepareWorkspace parses the source, mints the run id and prepares the
// workspace (host-side git for a managed copy), shared by every driver
// (section 6: the sources do not depend on the backend). A managed
// workspace it made is recorded as unattached until Attach takes it; a
// failure removes what it made.
func (r *sandboxRuntime) prepareWorkspace(ctx context.Context, req termsvc.PrepareRequest) (preparedWorkspace, error) {
	source := strings.TrimSpace(req.WorkspaceSource)
	if source == "" {
		source = string(workspace.SourceLive)
	}
	src, err := workspace.ParseSource(source)
	if err != nil {
		return preparedWorkspace{}, err
	}

	id, err := newWorkspaceID()
	if err != nil {
		return preparedWorkspace{}, err
	}

	// A worktree's main repository is checked and its base read first
	// (terminal_sandbox_worktree.go).
	var startPoint string
	if src == workspace.SourceWorktree {
		if startPoint, err = r.worktreeBeforeAdd(ctx, req, id); err != nil {
			return preparedWorkspace{}, err
		}
	}

	plan, err := workspace.Plan(workspace.Request{
		Source:              src,
		StartPoint:          startPoint,
		ProjectRoot:         req.ProjectRoot,
		RemoteURL:           req.WorkspaceRemote,
		Branch:              req.WorkspaceBranch,
		ManagedRoot:         r.managedRoot,
		ID:                  id,
		AllowRemoteClone:    r.cfg.AllowRemoteClone,
		AllowWorktreeSource: r.cfg.AllowWorktreeSource,
		RemoteAllowedHosts:  r.cfg.RemoteAllowedHosts,
	})
	if err != nil {
		return preparedWorkspace{}, err
	}

	dest := plan.Dir
	live := src == workspace.SourceLive

	if !live {
		// Ensure <managedRoot>/<id> exists so git (and meta.json) can write into
		// it, then run the git steps under the prep timeout.
		runDir := filepath.Dir(dest)
		if err := os.MkdirAll(runDir, 0o700); err != nil {
			return preparedWorkspace{}, fmt.Errorf("terminal_sandbox: create workspace dir: %w", err)
		}
		// A Create that fails after this point removes what it made, so a
		// failed launch leaves nothing behind (P-017 (f)); runDir is
		// <managedRoot>/<id>, minted fresh above.
		created := false
		defer func() {
			if !created {
				_ = os.RemoveAll(runDir) //nolint:gosec // G703: runDir is the freshly minted <managedRoot>/<id>
			}
		}()
		prepCtx := ctx
		if secs := r.cfg.PrepTimeoutSeconds; secs > 0 {
			var cancel context.CancelFunc
			prepCtx, cancel = context.WithTimeout(ctx, time.Duration(secs)*time.Second)
			defer cancel()
		}
		for _, step := range plan.Steps {
			if err := r.runGitStep(prepCtx, step); err != nil {
				return preparedWorkspace{}, err
			}
		}
		if err := r.writeMeta(dest, src, req, id); err != nil {
			return preparedWorkspace{}, err
		}

		// EvalSymlinks the created dest and require it strictly under the managed
		// root (fail closed): a symlink planted inside a clone could otherwise
		// point the bind (and the run's project root) outside the daemon's tree.
		resolved, err := filepath.EvalSymlinks(dest)
		if err != nil {
			return preparedWorkspace{}, fmt.Errorf("terminal_sandbox: resolve workspace path: %w", err)
		}
		if err := workspace.ValidateManagedWorkspace(resolved, r.managedRoot); err != nil {
			return preparedWorkspace{}, err
		}
		dest = resolved
		r.unattached.Store(id, filepath.Dir(dest))
		created = true
	}
	return preparedWorkspace{id: id, dir: dest, src: src, live: live}, nil
}

// Attach is the second half of Prepare: the bwrap argv prefix the PTY child
// runs, composed from the same route fact Create computed the evidence from.
func (r *sandboxRuntime) Attach(ctx context.Context, created termsvc.CreateResult) (termsvc.AttachResult, error) {
	if d, ok := r.runDriver(created.Run.ID); ok {
		return d.Attach(ctx, created)
	}
	// The run record is the host copy of the run's launch facts and relay
	// secrets (lane sbx-p2); the host helper reads it, and removes it when
	// the run ends.
	if err := r.writeRunRecord(created.Run); err != nil {
		return termsvc.AttachResult{}, err
	}
	wrapArgv, err := r.buildWrapArgv(created.Run.Tool, created.Run.Dir, created.Run.ID, created.ProxyRouted)
	if err != nil {
		_ = sandboxrelayd.RemoveRun(r.observerDir, created.Run.ID)
		return termsvc.AttachResult{}, err
	}
	r.unattached.Delete(created.Run.ID)
	return termsvc.AttachResult{WrapArgv: wrapArgv}, nil
}

// resolveSandboxBindPath resolves every symlink in a bind path for the
// planner's relay bind check; a path that does not resolve is checked as
// written.
func resolveSandboxBindPath(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return p
}

// writeRunRecord writes the run's relay record: the facts the run's channel
// supplies (tool, project, workspace, the roots a relayed payload path may
// be read under, the workspace delivery) and two fresh secrets.
func (r *sandboxRuntime) writeRunRecord(run termsvc.SandboxRun) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("terminal_sandbox: resolve home: %w", err)
	}
	if resolved, rerr := filepath.EvalSymlinks(home); rerr == nil {
		home = resolved
	}
	spec, _ := integration.For(run.Tool)
	roots := []string{run.Dir}
	for _, rel := range spec.Sandbox.StateRW {
		roots = append(roots, filepath.Join(home, rel))
	}
	delivery, copyPath := sandboxrelayd.DeliveryLive, ""
	if run.Copy {
		delivery, copyPath = sandboxrelayd.DeliveryCopy, run.Dir
	}
	project := run.ProjectRoot
	if project == "" {
		project = run.Dir
	}
	// The daemon's own config, so the host helper reads the hook
	// registration the daemon wrote (relayHookProbe).
	cfgPath, _ := config.ResolveGlobalPath(daemonConfigPath())
	rec, err := sandboxrelayd.NewRunRecord(sandboxrelayd.RunRecord{
		RunID: run.ID, Tool: run.Tool, ProjectRoot: project, WorkspaceDir: run.Dir,
		Roots: roots, Delivery: delivery, CopyHostPath: copyPath, ConfigPath: cfgPath,
	})
	if err != nil {
		return fmt.Errorf("terminal_sandbox: %w", err)
	}
	if err := sandboxrelayd.WriteRun(r.observerDir, rec); err != nil {
		return fmt.Errorf("terminal_sandbox: %w", err)
	}
	return nil
}

// Resize is owned by the PTY: bwrap keeps the agent a direct child of the
// daemon's PTY, so termsession's resize already reaches it.
func (r *sandboxRuntime) Resize(ctx context.Context, run termsvc.SandboxRun, rows, cols uint16) (termsvc.LifecycleResult, error) {
	if d, ok := r.runDriver(run.ID); ok {
		return d.Resize(ctx, run, rows, cols)
	}
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictPTYOwned, Detail: "bwrap: the terminal resize reaches the agent through the PTY"}, nil
}

// Signal is owned by the PTY for the same reason.
func (r *sandboxRuntime) Signal(ctx context.Context, run termsvc.SandboxRun, sig string) (termsvc.LifecycleResult, error) {
	if d, ok := r.runDriver(run.ID); ok {
		return d.Signal(ctx, run, sig)
	}
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictPTYOwned, Detail: "bwrap: signals reach the agent through the PTY and the host helper"}, nil
}

// Copy is not offered by bwrap: the workspace is a host directory bound into
// the run, so files are reached on the host directly.
func (r *sandboxRuntime) Copy(ctx context.Context, req termsvc.CopyRequest) (termsvc.LifecycleResult, error) {
	if d, ok := r.runDriver(req.Run.ID); ok {
		return d.Copy(ctx, req)
	}
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictNotSupported, Detail: "bwrap: the workspace is a host directory; copy on the host"}, nil
}

// Checkpoint is not offered by bwrap.
func (r *sandboxRuntime) Checkpoint(ctx context.Context, run termsvc.SandboxRun) (termsvc.LifecycleResult, error) {
	if d, ok := r.runDriver(run.ID); ok {
		return d.Checkpoint(ctx, run)
	}
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictNotSupported, Detail: "bwrap: no checkpoint; the agent's native resume applies"}, nil
}

// Stop is owned by the PTY: ending the PTY child ends bwrap, and bwrap's
// pid namespace takes every process of the run with it.
func (r *sandboxRuntime) Stop(ctx context.Context, run termsvc.SandboxRun, grace time.Duration) (termsvc.LifecycleResult, error) {
	if d, ok := r.runDriver(run.ID); ok {
		return d.Stop(ctx, run, grace)
	}
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictPTYOwned, Detail: "bwrap: stopping the terminal ends the run"}, nil
}

// Destroy releases what the run holds. The host helper removes the per-run
// sockets and placeholders on exit, and a managed workspace an agent ran in
// is the user's work, kept for `observer workspaces` to list and remove. A
// managed workspace that Create made and Attach never took (a failed
// launch) is removed, so a failed launch leaves nothing behind (P-017 (f)).
func (r *sandboxRuntime) Destroy(ctx context.Context, run termsvc.SandboxRun) (termsvc.LifecycleResult, error) {
	if d, ok := r.runDriver(run.ID); ok {
		r.runDrivers.Delete(run.ID)
		return d.Destroy(ctx, run)
	}
	return r.destroyBwrap(run)
}

// destroyBwrap is bwrap's Destroy, also the shared release of a run a
// driver created on this runtime (its run record and unattached workspace).
func (r *sandboxRuntime) destroyBwrap(run termsvc.SandboxRun) (termsvc.LifecycleResult, error) {
	// A run record whose run never attached is released with it.
	_ = sandboxrelayd.RemoveRun(r.observerDir, run.ID)
	v, ok := r.unattached.LoadAndDelete(run.ID)
	if !ok {
		return termsvc.LifecycleResult{Verdict: termsvc.VerdictNothingToRelease, Detail: "bwrap: the host helper already released the run; managed workspaces are kept"}, nil
	}
	dir, _ := v.(string)
	if err := workspace.ValidateManagedWorkspace(dir, r.managedRoot); err != nil {
		return termsvc.LifecycleResult{}, fmt.Errorf("terminal_sandbox: refusing to remove an unattached workspace outside the managed root: %w", err)
	}
	if err := os.RemoveAll(dir); err != nil {
		return termsvc.LifecycleResult{}, fmt.Errorf("terminal_sandbox: remove the unattached workspace: %w", err)
	}
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictDone, Detail: "bwrap: removed the workspace of a launch that never started"}, nil
}

// runIsolation is the G19 evidence of a bwrap launch of tool (sandbox plan
// v2 section 8.4): the planned class and tier, the computed capture level
// and the rule that decided it, this host's verification, and the native
// sandbox state the nesting rows established (left unrecorded for an
// agent sandbox that is off by default).
func (r *sandboxRuntime) runIsolation(tool string, routed bool) termrun.Isolation {
	tier := vocab.Tier(r.egress.Mode)
	capture := sandboxRunCapture(routed, tier, r.cfg.EffectiveProviderDirect())
	row, _ := sandboxbackend.Get(sandboxbackend.BackendBwrap)
	iso := termrun.Isolation{
		Class:         string(row.Iso.Class),
		Stack:         []string{row.ID},
		EgressTier:    string(tier),
		CaptureLevel:  string(capture.Level),
		CaptureRule:   capture.Rule,
		CaptureOrigin: string(vocab.OriginSandboxed),
		KeyCustody:    string(vocab.CustodyHostBound),
	}
	if v, judged := sandboxNativeVerdict(tool, tier); judged {
		iso.NativeSandboxState = string(sandboxselect.NativeStateFor(v))
	}
	if v, ok := row.VerificationOn(sandboxHostKind()); ok {
		iso.Verification = string(v.Kind)
	}
	return iso
}

// buildWrapArgv resolves the bwrap Request for tool operating in workspaceRoot,
// composes the plan via sandbox.BuildPlan, and returns the launch-ready wrapper
// prefix: [bwrapPath, <flags...>, "--"]. termsession.Spec.argv() prepends this
// before [BinPath, Subcommand, ...ExtraArgs], yielding
// `bwrap <flags...> -- observer <verb> ...` (D2 seam).
func (r *sandboxRuntime) buildWrapArgv(tool, workspaceRoot, runID string, routed bool) ([]string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("terminal_sandbox: resolve home: %w", err)
	}
	if resolved, rerr := filepath.EvalSymlinks(home); rerr == nil {
		home = resolved
	}

	spec, _ := integration.For(tool)
	if len(spec.Sandbox.StateRW) == 0 {
		// Defence in depth: the dashboard already refused an unmapped tool
		// (400), but never build a sandbox with no writable tool state.
		note := spec.Sandbox.Note
		if note == "" {
			note = "no grounded sandbox state-dir row"
		}
		return nil, fmt.Errorf("terminal_sandbox: tool %q is not sandbox-launchable: %s", tool, note)
	}

	toolBinDirs := r.toolBinDirs(tool)
	if r.observerRealDir != "" {
		toolBinDirs = append(toolBinDirs, r.observerRealDir)
	}

	bwrapPath, err := exec.LookPath("bwrap")
	if err != nil {
		return nil, fmt.Errorf("terminal_sandbox: bwrap not found on PATH: %w", err)
	}

	netReq := sandbox.NetRequest{Egress: r.egress.Mode, ProxyPort: r.proxyPort, EgressAllowCIDRs: r.cfg.EgressAllowCIDRs}
	// The capture level of this run is computed (sandbox plan v2 section
	// 4.4); when it is full only because the gateway guards it (rule C6),
	// the gateway refuses the model-provider hosts and every literal IP for
	// the run (section 7.3), so the agent's bound credential cannot be used
	// outside the proxy.
	if capture := sandboxRunCapture(routed, vocab.Tier(r.egress.Mode), r.cfg.EffectiveProviderDirect()); capture.ProviderBlock {
		netReq.ProviderBlock = true
		netReq.ProviderHosts = r.providerHosts
	}
	// Per-run socket dir in the HOST temp dir: invisible inside the sandbox
	// (its /tmp is a private tmpfs) except where BuildPlan binds it
	// read-only. The host helper creates it (refusing a pre-existing path)
	// and removes it on exit. The random run id makes it unguessable. Since
	// lane sbx-p2 every run has one: it holds the capture relay's socket and
	// the box's launch record, whatever the tier forwards.
	netReq.HostSocketDir = filepath.Join(os.TempDir(), "observer-sbx-"+runID)

	overlays, pins, err := r.protection(home, workspaceRoot, spec.Sandbox)
	if err != nil {
		return nil, err
	}
	// A worktree run's binds into the main repository's .git folder
	// (terminal_sandbox_worktree.go); nothing for any other source.
	wt, err := r.worktreeBox(runID, workspaceRoot, r.rwRoots(home, workspaceRoot, spec.Sandbox))
	if err != nil {
		return nil, err
	}
	hostMasks, err := hostSocketMasks(os.Getuid())
	if err != nil {
		return nil, err
	}
	sweeps, err := socketSweeps()
	if err != nil {
		return nil, err
	}

	plan, err := sandbox.BuildPlan(sandbox.Request{
		Net:           netReq,
		Overlays:      append(overlays, wt.overlays...),
		SocketSweeps:  sweeps,
		HostMasks:     hostMasks,
		HostMaskKeep:  hostMaskKeep(hostMasks),
		Home:          home,
		ObserverDir:   r.observerDir,
		WorkspaceRoot: workspaceRoot,
		ObserverBin:   r.observerBin,
		ToolBinDirs:   toolBinDirs,
		StateRW:       spec.Sandbox.StateRW,
		StateRO:       spec.Sandbox.StateRO,
		RuntimeLadder: sandboxRuntimeLadder,
		MaskPaths:     r.maskPaths(),
		HomeMode:      r.homeMode(),
		ExtraRO:       append(slices.Clip(r.cfg.ExtraROBinds), wt.ro...),
		ExtraRW:       append(slices.Clip(r.cfg.ExtraRWBinds), wt.rw...),
		Pins:          pins,
		Relay:         sandbox.RelayRequest{RunID: runID, HostObserverDir: r.observerDir},
		ResolvePath:   resolveSandboxBindPath,
	})
	if err != nil {
		return nil, err
	}

	// Argv(inner) renders [flags..., "--", inner...]. We want the wrapper prefix
	// [bwrapPath, flags..., "--"] so Spec.argv() can append the real inner
	// ([observer, verb, ...]) after the "--". Render with a one-element sentinel
	// and drop it, keeping the flags-through-"--" prefix.
	const sentinel = "OBSERVER_SANDBOX_INNER_SENTINEL"
	composed := plan.Argv([]string{sentinel})
	if len(composed) < 2 || composed[len(composed)-1] != sentinel {
		return nil, fmt.Errorf("terminal_sandbox: bwrap plan composition failed")
	}
	flags := composed[:len(composed)-1] // [flags..., "--", (guest helper...)]
	// A tier that forwards anything, or a launch with protected paths that do
	// not exist yet, runs bwrap under the host-side helper, which owns the
	// per-run sockets and the placeholders: [observer sandbox-host ... --]
	// bwrap ...
	host, err := plan.HostArgv(r.observerBin)
	if err != nil {
		return nil, err
	}
	wrap := make([]string, 0, len(host)+len(flags)+1)
	wrap = append(wrap, host...)
	wrap = append(wrap, bwrapPath)
	wrap = append(wrap, flags...)
	return wrap, nil
}

// sandboxObserverSecrets are observer-dir entries a sandboxed process never
// needs and must never read (SR27-SBX-1): remote-access + standing-terminal
// secrets, the org bearer and cloud credential fallback stores, the VS Code
// LOC editor token, and the session-attach control socket (whose dir would
// let a sandboxed agent attach to, and type into, an UNSANDBOXED terminal).
// Hidden unconditionally: nothing inside the sandbox uses them (a
// daemon-launched launcher never dials the attach socket), so it costs
// nothing. A missing entry gets a placeholder (SR27-SBX-2): the sandboxed
// process must not be able to plant a secret the daemon would later adopt.
var sandboxObserverSecrets = []sandbox.ProtectedPath{
	{Rel: "remote-secret"},
	{Rel: "remote-standing-terminal-secret"},
	{Rel: "org-bearer", Dir: true},
	{Rel: "cloud-cred", Dir: true},
	{Rel: "loc-editor-token"},
	{Rel: "attach", Dir: true},
}

// sandboxObserverExecState are observer-dir entries the DAEMON (or the
// operator's shell, or a later hook) trusts or executes and a sandboxed
// process only ever reads: the daemon config, the user guard policy and
// trusted per-project guard policies, the hook integrity registry, the
// shell-wrap PATH shims, the browser native-messaging host, and the org
// governance sidecars (features-effective.json, and governance-effective.json,
// whose pins every later config load applies, guard mode included, plus its
// governance-exceptions.json, which lifts pins).
// Re-bound read-only unless [terminal.sandbox].allow_tool_config_writes. The
// node DB and hook logs stay writable (hook capture writes them).
var sandboxObserverExecState = []sandbox.ProtectedPath{
	{Rel: "config.toml"},
	{Rel: "guard-policy.toml"},
	{Rel: "guard-project-policies", Dir: true},
	{Rel: "hook_checksums.json"},
	{Rel: "shims", Dir: true},
	{Rel: "browser-host", Dir: true},
	{Rel: "features-effective.json"},
	{Rel: "governance-effective.json"},
	{Rel: "governance-exceptions.json"},
	// The daemon's MAC'd org lock (T-839 / T-844 / T-845): every config
	// load floors [guard] from it and reads its verified governance copy.
	{Rel: "guard-org-lock.json"},
	{Rel: "policy-resource", Dir: true},
	{Rel: "policy-state-seq"},
}

// remedyToolConfigWrites is appended to a symlink refusal for a path whose
// protection allow_tool_config_writes lifts.
const remedyToolConfigWrites = ", or set [terminal.sandbox].allow_tool_config_writes = true"

// protectedRow is one resolved row of the protection table for one launch.
type protectedRow struct {
	path   string
	kind   sandbox.OverlayKind
	dir    bool
	remedy string
}

// overlays composes the protective overlays for one launch: secrets hidden
// always; executed state re-bound read-only unless the operator opted into
// tool config writes. bwrap applies them after every rw bind, so no rw bind
// can re-open them. Each row is resolved by protectPath: an existing path is
// protected in place, a missing one under a writable bind gets a placeholder
// the host helper creates first, and a symlink under a writable bind refuses
// the launch (a symlink cannot be mounted read-only, and replacing it is
// exactly the escape).
func (r *sandboxRuntime) overlays(home, workspaceRoot string, spec integration.SandboxSpec) ([]sandbox.Overlay, error) {
	ovs, _, err := r.protection(home, workspaceRoot, spec)
	return ovs, err
}

// protection is overlays plus the pins the bwrap path binds onto
// themselves (sandbox.Request.Pins): every repository folder and .git the
// walk under an org write bind found, and a live workspace's own .git, and
// inside each git dir the folders that hold a protected path
// (sandboxGitDirParentPins), so
// the box cannot rename a .git aside and plant a replacement under the
// overlays (SBX-WORKTREE-SOURCE audit finding 4). A pin outside the
// workspace and the extra write binds is dropped (it would make a
// read-only path writable). The oci and Apple container drivers mount the
// same pins onto themselves and the Seatbelt profile write-denies each at
// its literal (lane SHR-FOLLOWUPS); the Landlock, MXC and hosted rows take
// overlays only.
func (r *sandboxRuntime) protection(home, workspaceRoot string, spec integration.SandboxSpec) ([]sandbox.Overlay, []string, error) {
	var rows []protectedRow
	for _, pp := range sandboxObserverSecrets {
		kind := sandbox.OverlayHideFile
		if pp.Dir {
			kind = sandbox.OverlayHideDir
		}
		rows = append(rows, protectedRow{path: filepath.Join(r.observerDir, pp.Rel), kind: kind, dir: pp.Dir})
	}
	// The executed-state files under the observer dir are bound read-only
	// whatever allow_tool_config_writes says: with the capture relay
	// (lane sbx-p2) the observer dir is a tmpfs in the box, and these
	// read-only binds are exactly what the inner launcher reads from it.
	for _, pp := range sandboxObserverExecState {
		rows = append(rows, protectedRow{path: filepath.Join(r.observerDir, pp.Rel), kind: sandbox.OverlayReadOnly, dir: pp.Dir})
	}
	if !r.cfg.AllowToolConfigWrites {
		ro := func(p string, dir bool) {
			rows = append(rows, protectedRow{path: p, kind: sandbox.OverlayReadOnly, dir: dir, remedy: remedyToolConfigWrites})
		}
		for _, gp := range r.guardPolicyPaths {
			ro(gp.Rel, gp.Dir)
		}
		for _, rel := range spec.ProtectRO {
			ro(filepath.Join(home, rel), false)
		}
		for _, rel := range spec.ProtectRODirs {
			ro(filepath.Join(home, rel), true)
		}
		for _, pp := range sandbox.WorkspaceExecState {
			ro(filepath.Join(workspaceRoot, pp.Rel), pp.Dir)
		}
	}
	// The workspace repository's linked-worktree git dirs
	// (.git/worktrees/<name>, ledger SBX-BE-21 residual, lane LEFT-SBX): a
	// host git command in one of those worktrees reads that folder, so each
	// gets the same rows as the .git itself, yielding to
	// allow_tool_config_writes the same way, and is pinned below on a live
	// workspace. A worktrees folder that cannot be listed refuses.
	var wtPins []string
	if fi, lerr := os.Lstat(filepath.Join(workspaceRoot, ".git")); lerr == nil && fi.IsDir() && !r.cfg.AllowToolConfigWrites {
		wtRows, pins, err := sandboxLinkedWorktreeRows(filepath.Join(workspaceRoot, ".git"), remedyToolConfigWrites, nil)
		if err != nil {
			return nil, nil, err
		}
		rows = append(rows, wtRows...)
		wtPins = pins
	}
	// An org-set write bind holding a repository: its hooks and config are
	// read-only whatever allow_tool_config_writes says (ruling P-054).
	orgRows, orgPins, err := sandboxOrgBindGitRows(r.orgRWBinds, r.orgSkipScan)
	if err != nil {
		return nil, nil, err
	}
	rows = append(rows, orgRows...)

	rw := r.rwRoots(home, workspaceRoot, spec)
	var out []sandbox.Overlay
	seen := map[string]bool{}
	for _, row := range rows {
		o, ok, err := protectPath(row, rw)
		if err != nil {
			return nil, nil, err
		}
		if !ok || o.Path == "" || seen[o.Path] {
			continue
		}
		seen[o.Path] = true
		out = append(out, o)
	}
	return out, r.repoPins(workspaceRoot, orgPins, wtPins), nil
}

// repoPins is the pin list of one launch: the org-bind pins plus, for a
// live-source workspace (outside the managed workspaces root), the
// workspace's own .git directory or file and its linked-worktree git dirs
// (wtPins, sandboxLinkedWorktreeRows). Only paths inside the workspace or
// an extra write bind are kept, each once.
func (r *sandboxRuntime) repoPins(workspaceRoot string, orgPins, wtPins []string) []string {
	candidates := append([]string(nil), orgPins...)
	if r.managedRoot == "" || !isWithinPath(workspaceRoot, r.managedRoot) {
		dotGit := filepath.Join(workspaceRoot, ".git")
		if fi, err := os.Lstat(dotGit); err == nil && (fi.IsDir() || fi.Mode().IsRegular()) {
			candidates = append(candidates, dotGit)
			if fi.IsDir() {
				candidates = append(candidates, sandboxGitDirParentPins(dotGit)...)
				candidates = append(candidates, wtPins...)
			}
		}
	}
	roots := append([]string{workspaceRoot}, r.cfg.ExtraRWBinds...)
	var out []string
	seen := map[string]bool{}
	for _, p := range candidates {
		p = filepath.Clean(p)
		if seen[p] {
			continue
		}
		within := false
		for _, root := range roots {
			within = within || (root != "" && isWithinPath(p, root))
		}
		if within {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// sandboxGitDirParentPins are the existing real folders between gitDir and
// its protected execution-state paths (sandbox.GitDirExecParents: info,
// objects, objects/info), parents first, to be pinned after gitDir itself.
// Without them the box renames such a folder aside, the read-only overlay
// inside moves with it, and a fresh folder takes the protected path (Linux
// live re-check 3, D2). A missing folder is left out (its protected path's
// topmost missing component is then a read-only placeholder), and so is a
// symlink (the protect rows refuse it).
func sandboxGitDirParentPins(gitDir string) []string {
	var out []string
	for _, p := range sandbox.GitDirExecParents(gitDir) {
		if fi, err := os.Lstat(p); err == nil && fi.IsDir() && fi.Mode()&os.ModeSymlink == 0 {
			out = append(out, p)
		}
	}
	return out
}

// rwRoots lists the bind targets a sandboxed process can write through: the
// observer dir, the workspace, the tool's writable state and the operator's
// extra rw binds.
func (r *sandboxRuntime) rwRoots(home, workspaceRoot string, spec integration.SandboxSpec) []string {
	// The observer dir is a tmpfs in the box (the capture relay, lane
	// sbx-p2), so nothing a sandboxed process writes reaches it.
	out := []string{workspaceRoot}
	for _, rel := range spec.StateRW {
		out = append(out, filepath.Join(home, rel))
	}
	return append(out, r.cfg.ExtraRWBinds...)
}

// protectPath resolves one protected row against the filesystem. It returns
// the overlay to apply, ok=false when nothing needs protecting (a missing
// path that no writable bind could create), or an error that refuses the
// launch.
//
//   - existing file or dir: protected in place (hide or read-only);
//   - symlink under a writable bind: refused, naming the path and the fix;
//   - missing: walk up to the first existing ancestor. If that ancestor is
//     not under a writable bind, nothing inside can create the path. If it
//     is a directory, the topmost missing component becomes a placeholder
//     (a directory when it has children below it or the row is a dir); if
//     it is a file (a .git gitfile, say), that file is protected instead.
func protectPath(row protectedRow, rw []string) (sandbox.Overlay, bool, error) {
	fi, err := os.Lstat(row.path)
	switch {
	case err == nil:
		if fi.Mode()&os.ModeSymlink != 0 {
			if !withinAny(row.path, rw) {
				return sandbox.Overlay{}, false, nil
			}
			return sandbox.Overlay{}, false, symlinkRefusal(row.path, row.remedy)
		}
		return sandbox.Overlay{Path: row.path, Kind: fitOverlayKind(row.kind, fi.IsDir())}, true, nil
	case errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR):
	default:
		return sandbox.Overlay{}, false, fmt.Errorf("terminal_sandbox: cannot inspect protected path %s: %w", row.path, err)
	}

	missing := row.path
	for {
		parent := filepath.Dir(missing)
		if parent == missing {
			return sandbox.Overlay{}, false, nil
		}
		pfi, perr := os.Lstat(parent)
		if perr != nil {
			if errors.Is(perr, fs.ErrNotExist) || errors.Is(perr, syscall.ENOTDIR) {
				missing = parent
				continue
			}
			return sandbox.Overlay{}, false, fmt.Errorf("terminal_sandbox: cannot inspect %s (for protected path %s): %w", parent, row.path, perr)
		}
		if !withinAny(parent, rw) {
			// Nothing a sandboxed process can write reaches here: in a
			// tmpfs home the path would land in the tmpfs, in a read-only
			// home it cannot be created at all.
			return sandbox.Overlay{}, false, nil
		}
		isDir := pfi.IsDir()
		if pfi.Mode()&os.ModeSymlink != 0 {
			if !equalsAny(parent, rw) {
				return sandbox.Overlay{}, false, symlinkRefusal(parent, row.remedy)
			}
			// A bind target itself: the mount pins it, it cannot be
			// replaced. Resolve it to learn what it is.
			sfi, serr := os.Stat(parent)
			if serr != nil {
				return sandbox.Overlay{}, false, fmt.Errorf("terminal_sandbox: cannot resolve %s (for protected path %s): %w", parent, row.path, serr)
			}
			isDir = sfi.IsDir()
		}
		if !isDir {
			if equalsAny(parent, rw) {
				return sandbox.Overlay{}, false, nil
			}
			return sandbox.Overlay{Path: parent, Kind: fitOverlayKind(row.kind, false)}, true, nil
		}
		dir := row.dir || missing != row.path
		ph := sandbox.PlaceholderFile
		if dir {
			ph = sandbox.PlaceholderDir
		}
		return sandbox.Overlay{Path: missing, Kind: fitOverlayKind(row.kind, dir), Placeholder: ph}, true, nil
	}
}

// fitOverlayKind adapts a hide kind to the shape of what it covers (a dir
// is hidden with a tmpfs, a file with /dev/null); read-only fits both.
func fitOverlayKind(kind sandbox.OverlayKind, isDir bool) sandbox.OverlayKind {
	switch {
	case kind == sandbox.OverlayHideFile && isDir:
		return sandbox.OverlayHideDir
	case kind == sandbox.OverlayHideDir && !isDir:
		return sandbox.OverlayHideFile
	}
	return kind
}

// symlinkRefusal is the honest launch refusal for a protected symlink.
func symlinkRefusal(path, remedy string) error {
	return fmt.Errorf("terminal_sandbox: protected path %s is a symlink inside a writable bind; "+
		"a sandboxed process could replace it and a later unsandboxed session would trust the replacement, "+
		"and a symlink cannot be mounted read-only. Replace the symlink with the file or directory it points to%s", path, remedy)
}

// equalsAny reports whether p is exactly one of roots.
func equalsAny(p string, roots []string) bool {
	p = filepath.Clean(p)
	for _, r := range roots {
		if r != "" && pathSame(filepath.Clean(r), p, hostPathsFold) {
			return true
		}
	}
	return false
}

// toolBinDirs resolves the directories a tool's binary + its real (symlink)
// target live in, so they can be ro-bound inside the tmpfs'd home. It honours a
// pinned [launch.tools.<tool>].path (parity with resolveToolBin) first, then the
// toolresolve registry ladder over the tool's Binary row (Bin + Chosen.Real).
// Deduped; empty when the tool has no grounded binary spec (the sandbox then
// relies on the runtime ladder + StateRO alone).
func (r *sandboxRuntime) toolBinDirs(tool string) []string {
	seen := map[string]bool{}
	var dirs []string
	add := func(p string) {
		if p == "" {
			return
		}
		d := filepath.Dir(p)
		if d == "" || d == "." || seen[d] {
			return
		}
		seen[d] = true
		dirs = append(dirs, d)
	}

	if tc, ok := r.launchTools[tool]; ok && tc.Path != "" {
		add(tc.Path)
		if real, err := filepath.EvalSymlinks(tc.Path); err == nil {
			add(real)
		}
	}
	if ic, ok := integration.For(tool); ok && ic.Binary != nil {
		res := toolresolve.Resolve(*ic.Binary, dashResolveEnv())
		add(res.Bin)
		if res.Chosen != nil {
			add(res.Chosen.Real)
		}
	}
	return dirs
}

// maskPaths is the A1 foreign-OS mount mask set: the detected foreign-OS mount
// roots (e.g. /mnt/c on WSL — the whole Windows drive `--ro-bind / /` would
// otherwise leave readable) plus the operator's [terminal.sandbox].mask_paths.
// Computed in cmd (crossmount knowledge) so the pure planner stays source-
// agnostic. Deduped.
func (r *sandboxRuntime) maskPaths() []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	for _, root := range foreignMountRoots() {
		add(root)
	}
	for _, p := range r.cfg.MaskPaths {
		add(p)
	}
	return out
}

// runGitStep execs one workspace.Step (a `git ...` invocation), capturing
// stderr for a scrubbed, capped error tail on failure. The subprocess env
// disables interactive prompts (GIT_TERMINAL_PROMPT=0) and strips GIT_ASKPASS
// while keeping the operator's ambient auth (SSH agent / credential helpers)
// for a clone-remote — the plan's deliberate posture (§4).
func (r *sandboxRuntime) runGitStep(ctx context.Context, step workspace.Step) error {
	if len(step.Argv) == 0 {
		return fmt.Errorf("terminal_sandbox: empty git step")
	}
	//nolint:gosec // argv is server-derived from workspace.Plan: every path is
	// validated absolute / no "..", no leading '-', control-char-rejected, and
	// a remote URL passes ValidateRemoteURL's transport allow-list. Never client
	// argv (the client supplies only a source enum + a validated URL/branch).
	cmd := exec.CommandContext(ctx, step.Argv[0], step.Argv[1:]...)
	cmd.Dir = step.Dir
	cmd.Env = gitPrepEnv()
	if step.Hardened {
		cmd.Env = hardenedGitEnv(cmd.Env)
	}
	cmd.Stdin = nil
	cmd.Stdout = io.Discard
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("terminal_sandbox: %s failed: %w: %s",
			strings.Join(step.Argv[:min(2, len(step.Argv))], " "), err, tailStderr(stderr.String()))
	}
	return nil
}

// writeMeta writes the per-workspace meta.json (plan §4 — no DB change; B7 reads
// the same file) into <managedRoot>/<id>/meta.json.
func (r *sandboxRuntime) writeMeta(dest string, src workspace.Source, req termsvc.PrepareRequest, id string) error {
	origin := req.ProjectRoot
	if src == workspace.SourceCloneRemote {
		origin = req.WorkspaceRemote
	}
	data, err := workspace.MarshalMeta(workspace.Meta{
		Source:    src,
		Origin:    origin,
		Branch:    req.WorkspaceBranch,
		RunID:     id,
		CreatedAt: r.now(),
	})
	if err != nil {
		return fmt.Errorf("terminal_sandbox: marshal meta: %w", err)
	}
	metaPath := filepath.Join(filepath.Dir(dest), "meta.json")
	if err := os.WriteFile(metaPath, data, 0o600); err != nil {
		return fmt.Errorf("terminal_sandbox: write meta: %w", err)
	}
	return nil
}

// newWorkspaceID mints the 16-random-byte base64url managed-workspace id (plan
// §4). It regenerates on the rare value whose leading char is '-' (base64url's
// alphabet includes it), which workspace.mintDest's clean-token guard rejects.
func newWorkspaceID() (string, error) {
	for i := 0; i < 8; i++ {
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", fmt.Errorf("terminal_sandbox: mint workspace id: %w", err)
		}
		id := base64.RawURLEncoding.EncodeToString(b[:])
		if !strings.HasPrefix(id, "-") {
			return id, nil
		}
	}
	return "", fmt.Errorf("terminal_sandbox: could not mint a workspace id")
}

// gitPrepEnv builds the workspace-prep subprocess env: the daemon env with
// GIT_ASKPASS + any inherited GIT_TERMINAL_PROMPT removed, plus a forced
// GIT_TERMINAL_PROMPT=0. Ambient auth (SSH_AUTH_SOCK, credential helpers, HOME)
// is deliberately preserved so a clone-remote works with the operator's own
// credentials (plan §4), while interactive prompts can never hang the daemon.
func gitPrepEnv() []string {
	parent := os.Environ()
	out := make([]string, 0, len(parent)+1)
	for _, kv := range parent {
		if strings.HasPrefix(kv, "GIT_ASKPASS=") || strings.HasPrefix(kv, "GIT_TERMINAL_PROMPT=") {
			continue
		}
		out = append(out, kv)
	}
	return append(out, "GIT_TERMINAL_PROMPT=0")
}

// hardenedGitEnv is env without any inherited GIT_* variable (a GIT_DIR,
// GIT_INDEX_FILE or GIT_CONFIG_PARAMETERS of the daemon's own) plus the
// extrun git hardening environment (no system or global config, no
// fsmonitor, no hooks, no prompt, no LFS smudge): the environment of every
// host git step of the worktree source (workspace.Step.Hardened,
// SBX-WORKTREE-SOURCE audit finding 1).
func hardenedGitEnv(env []string) []string {
	out := make([]string, 0, len(env)+5)
	for _, kv := range env {
		if strings.HasPrefix(kv, "GIT_") {
			continue
		}
		out = append(out, kv)
	}
	return append(out, extrun.GitHardeningEnv(runtime.GOOS)...)
}

// tailStderr returns the last ~2 non-empty lines of a subprocess stderr,
// scrubbed of secrets and capped at 512 bytes — the plan §7 error-tail shape.
func tailStderr(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	// Keep the last two lines.
	if len(lines) > 2 {
		lines = lines[len(lines)-2:]
	}
	tail := strings.TrimSpace(strings.Join(lines, "; "))
	tail = scrub.New().String(tail)
	if len(tail) > 512 {
		tail = tail[:512]
	}
	return tail
}

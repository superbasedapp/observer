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
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/intelligence/dashboard"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxnet"
	"github.com/marmutapp/superbased-observer/internal/scrub"
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
//   - dashboard.SandboxProber (ProbeSandbox): the fail-soft availability probe
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
	return h
}

// reload swaps in a runtime built from the supplied [terminal.sandbox]
// block. Disabling clears the runtime AND the error (an off switch is not a
// failure). Enabling with a runtime that will not initialize KEEPS the
// previous seam — an operator mid-edit should not lose a working sandbox to
// a typo — and records the error so the probe reports it verbatim.
func (h *sandboxHolder) reload(full config.Config) {
	cfg := full.Terminal.Sandbox
	if !cfg.Enabled {
		h.rt.Store(nil)
		h.initErr.Store(nil)
		return
	}
	rt, err := newSandboxRuntime(cfg, full.Launch.Tools, h.observerDir, h.observerBin, h.logger)
	if err == nil {
		rt.applyDaemonConfig(full)
	}
	if err != nil {
		msg := err.Error()
		h.initErr.Store(&msg)
		if h.logger != nil {
			h.logger.Warn("terminal sandbox: could not initialize the sandbox runtime — keeping the previous seam", "err", err)
		}
		return
	}
	if rt.workspacesDir() != h.managedRoot && h.logger != nil {
		h.logger.Warn("terminal sandbox: [terminal.sandbox].workspaces_dir changed since daemon start — "+
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
	h.stampMod, h.stampLen, h.stamped = info.ModTime(), info.Size(), true
	h.mu.Unlock()
	if !changed {
		return
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: h.configPath})
	if err != nil {
		if h.logger != nil {
			h.logger.Warn("terminal sandbox: config changed but could not be reloaded — keeping the previous seam", "err", err)
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

// ProbeSandbox implements dashboard.SandboxProber over the live runtime,
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
func (h *sandboxHolder) ProbeSandbox(ctx context.Context) dashboard.SandboxAvailability {
	h.refresh()
	if msg := h.initErr.Load(); msg != nil {
		return dashboard.SandboxAvailability{
			Available: false,
			Verdict:   dashboard.VerdictRuntimeInitFailed,
			Reason:    *msg,
		}
	}
	rt := h.rt.Load()
	if rt == nil {
		return dashboard.SandboxAvailability{
			Available: false,
			Verdict:   dashboard.VerdictDisabledByConfig,
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

// sandboxRuntime implements termsvc.Sandboxer and dashboard.SandboxProber over
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

	mu       sync.Mutex
	cached   dashboard.SandboxAvailability
	cachedAt time.Time
	now      func() time.Time
}

// defaultWorkspacesDir resolves the managed-workspaces root: the explicit
// [terminal.sandbox].workspaces_dir when set, else <observerDir>/workspaces.
// The one owner of that default, shared by the runtime and the `observer
// workspaces` CLI (no symlink resolution here — callers canonicalize when they
// need to).
func defaultWorkspacesDir(cfg config.TerminalSandboxConfig, observerDir string) string {
	if d := strings.TrimSpace(cfg.WorkspacesDir); d != "" {
		return d
	}
	return filepath.Join(observerDir, "workspaces")
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
	home, _ := os.UserHomeDir()
	if resolved, err := filepath.EvalSymlinks(home); err == nil {
		home = resolved
	}
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

// ---- dashboard.SandboxProber ------------------------------------------------

// ProbeSandbox implements dashboard.SandboxProber. It never returns an error: a
// probe failure IS a verdict. The bwrap platform/backend verdict comes from the
// pure sandbox.Probe over real I/O (LookPath / `bwrap --version` / the ms-scale
// user-namespace canary); this method adds the config HomeMode, the per-source
// availability list, and the per-tool sandbox-launchability map, then caches the
// whole result ~60s so the dialog is snappy but still notices a mid-session
// `apt install`.
func (r *sandboxRuntime) ProbeSandbox(ctx context.Context) dashboard.SandboxAvailability {
	// enabled=false is defensive here (buildTerminalStack only constructs the
	// runtime when enabled), but keeps the seam honest if wired differently.
	if !r.cfg.Enabled {
		return dashboard.SandboxAvailability{
			Available: false,
			Verdict:   sandbox.VerdictDisabledByConfig,
			Reason:    "[terminal.sandbox].enabled is false on this daemon",
			HomeMode:  r.homeMode(),
			Egress:    string(r.egress.Mode),
			DefaultOn: r.cfg.DefaultOn,
			Sources:   r.sources(),
			Tools:     r.tools(),
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
	out := dashboard.SandboxAvailability{
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

	r.mu.Lock()
	r.cached = out
	r.cachedAt = r.now()
	r.mu.Unlock()
	return out
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
			return exec.CommandContext(cctx, resolve(),
				"--ro-bind", "/", "/", "--unshare-pid", "--proc", "/proc", "--tmpfs", "/tmp", "--unshare-net", "--die-with-parent", "--", "true").Run()
		}
	}
	return sandbox.Env{
		NetCanary: netCanary,
		GOOS:      runtime.GOOS,
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
			return exec.CommandContext(cctx, resolve(),
				"--ro-bind", "/", "/", "--unshare-pid", "--proc", "/proc", "--tmpfs", "/tmp", "--die-with-parent", "--", "true").Run()
		},
	}
}

// sources reports per-workspace-source availability with honest reasons. live
// and clone-local are always available; clone-remote and worktree are the
// authority-expanding sources gated by their opt-in config flags (plan §4/§5).
func (r *sandboxRuntime) sources() []dashboard.SandboxSourceAvail {
	out := []dashboard.SandboxSourceAvail{
		{ID: string(workspace.SourceLive), Available: true},
		{ID: string(workspace.SourceCloneLocal), Available: true},
	}
	remote := dashboard.SandboxSourceAvail{ID: string(workspace.SourceCloneRemote), Available: r.cfg.AllowRemoteClone}
	if !remote.Available {
		remote.Reason = "allow_remote_clone is not set — the daemon would run `git clone <url>` with your ambient auth, so it is opt-in"
	}
	worktree := dashboard.SandboxSourceAvail{ID: string(workspace.SourceWorktree), Available: r.cfg.AllowWorktreeSource}
	if !worktree.Available {
		worktree.Reason = "allow_worktree_source is not set — a worktree needs the main repo's .git bound read-write and attributes the run to the main repo (off by default)"
	}
	return append(out, remote, worktree)
}

// tools reports the per-tool sandbox-launchability map, keyed by tool name. A
// tool is sandbox-launchable iff its SandboxSpec declares grounded writable
// state (StateRW); otherwise the honest zero note (SandboxSpec.Note) is the
// reason. Branches on the capability SHAPE (a grounded row), never a tool name
// (CLAUDE.md #3): v1 grounds only claude-code, every other launchable row
// carries the Note fallback. Launchability itself is
// integration.TerminalLaunchable, so a deprecated/dead product never appears
// in the sandbox tool table either.
func (r *sandboxRuntime) tools() map[string]dashboard.SandboxToolAvail {
	out := map[string]dashboard.SandboxToolAvail{}
	for _, c := range integration.Capabilities() {
		if !integration.TerminalLaunchable(c) {
			continue
		}
		if len(c.Sandbox.StateRW) > 0 {
			out[c.Tool] = dashboard.SandboxToolAvail{Available: true}
			continue
		}
		reason := c.Sandbox.Note
		if reason == "" {
			reason = "no grounded sandbox state-dir row for this tool"
		}
		out[c.Tool] = dashboard.SandboxToolAvail{Available: false, Reason: reason}
	}
	return out
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
	source := strings.TrimSpace(req.WorkspaceSource)
	if source == "" {
		source = string(workspace.SourceLive)
	}
	src, err := workspace.ParseSource(source)
	if err != nil {
		return termsvc.PrepareResult{}, err
	}

	id, err := newWorkspaceID()
	if err != nil {
		return termsvc.PrepareResult{}, err
	}

	plan, err := workspace.Plan(workspace.Request{
		Source:              src,
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
		return termsvc.PrepareResult{}, err
	}

	dest := plan.Dir
	live := src == workspace.SourceLive

	if !live {
		// Ensure <managedRoot>/<id> exists so git (and meta.json) can write into
		// it, then run the git steps under the prep timeout.
		if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
			return termsvc.PrepareResult{}, fmt.Errorf("terminal_sandbox: create workspace dir: %w", err)
		}
		prepCtx := ctx
		if secs := r.cfg.PrepTimeoutSeconds; secs > 0 {
			var cancel context.CancelFunc
			prepCtx, cancel = context.WithTimeout(ctx, time.Duration(secs)*time.Second)
			defer cancel()
		}
		for _, step := range plan.Steps {
			if err := r.runGitStep(prepCtx, step); err != nil {
				return termsvc.PrepareResult{}, err
			}
		}
		if err := r.writeMeta(dest, src, req, id); err != nil {
			return termsvc.PrepareResult{}, err
		}

		// EvalSymlinks the created dest and require it strictly under the managed
		// root (fail closed): a symlink planted inside a clone could otherwise
		// point the bind (and the run's project root) outside the daemon's tree.
		resolved, err := filepath.EvalSymlinks(dest)
		if err != nil {
			return termsvc.PrepareResult{}, fmt.Errorf("terminal_sandbox: resolve workspace path: %w", err)
		}
		if err := workspace.ValidateManagedWorkspace(resolved, r.managedRoot); err != nil {
			return termsvc.PrepareResult{}, err
		}
		dest = resolved
	}

	wrapArgv, err := r.buildWrapArgv(req.Tool, dest, id)
	if err != nil {
		return termsvc.PrepareResult{}, err
	}

	return termsvc.PrepareResult{
		Dir:      dest,
		WrapArgv: wrapArgv,
		Note:     fmt.Sprintf("sandbox: source=%s workspace=%s egress=%s", src, dest, r.egress.Mode),
	}, nil
}

// buildWrapArgv resolves the bwrap Request for tool operating in workspaceRoot,
// composes the plan via sandbox.BuildPlan, and returns the launch-ready wrapper
// prefix: [bwrapPath, <flags...>, "--"]. termsession.Spec.argv() prepends this
// before [BinPath, Subcommand, ...ExtraArgs], yielding
// `bwrap <flags...> -- observer <verb> ...` (D2 seam).
func (r *sandboxRuntime) buildWrapArgv(tool, workspaceRoot, runID string) ([]string, error) {
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
	if r.egress.ForwardProxy || r.egress.Gateway {
		// Per-run socket dir in the HOST temp dir: invisible inside the
		// sandbox (its /tmp is a private tmpfs) except where BuildPlan binds
		// it read-only. The host helper creates it (refusing a pre-existing
		// path) and removes it on exit. The random run id makes it
		// unguessable.
		netReq.HostSocketDir = filepath.Join(os.TempDir(), "observer-sbx-"+runID)
	}

	overlays, err := r.overlays(home, workspaceRoot, spec.Sandbox)
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
		Overlays:      overlays,
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
		ExtraRO:       r.cfg.ExtraROBinds,
		ExtraRW:       r.cfg.ExtraRWBinds,
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
// whose pins every later config load applies, guard mode included).
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
	var rows []protectedRow
	for _, pp := range sandboxObserverSecrets {
		kind := sandbox.OverlayHideFile
		if pp.Dir {
			kind = sandbox.OverlayHideDir
		}
		rows = append(rows, protectedRow{path: filepath.Join(r.observerDir, pp.Rel), kind: kind, dir: pp.Dir})
	}
	if !r.cfg.AllowToolConfigWrites {
		ro := func(p string, dir bool) {
			rows = append(rows, protectedRow{path: p, kind: sandbox.OverlayReadOnly, dir: dir, remedy: remedyToolConfigWrites})
		}
		for _, pp := range sandboxObserverExecState {
			ro(filepath.Join(r.observerDir, pp.Rel), pp.Dir)
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

	rw := r.rwRoots(home, workspaceRoot, spec)
	var out []sandbox.Overlay
	seen := map[string]bool{}
	for _, row := range rows {
		o, ok, err := protectPath(row, rw)
		if err != nil {
			return nil, err
		}
		if !ok || o.Path == "" || seen[o.Path] {
			continue
		}
		seen[o.Path] = true
		out = append(out, o)
	}
	return out, nil
}

// rwRoots lists the bind targets a sandboxed process can write through: the
// observer dir, the workspace, the tool's writable state and the operator's
// extra rw binds.
func (r *sandboxRuntime) rwRoots(home, workspaceRoot string, spec integration.SandboxSpec) []string {
	out := []string{r.observerDir, workspaceRoot}
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

// withinAny reports whether p equals or lies under any root.
func withinAny(p string, roots []string) bool {
	p = filepath.Clean(p)
	for _, r := range roots {
		if r == "" {
			continue
		}
		r = filepath.Clean(r)
		if p == r || r == "/" || strings.HasPrefix(p, r+"/") {
			return true
		}
	}
	return false
}

// equalsAny reports whether p is exactly one of roots.
func equalsAny(p string, roots []string) bool {
	p = filepath.Clean(p)
	for _, r := range roots {
		if r != "" && filepath.Clean(r) == p {
			return true
		}
	}
	return false
}

// hostSocketMasks resolves sandbox.HostSocketPaths for uid into hide_dir
// overlays: each path resolved through symlinks, kept only when it exists and
// is a directory (socket FILES are dropped by socketSweeps instead).
func hostSocketMasks(uid int) ([]sandbox.Overlay, error) {
	var out []sandbox.Overlay
	seen := map[string]bool{}
	for _, p := range sandbox.ExpandHostSocketPaths(uid) {
		real, err := filepath.EvalSymlinks(p)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
				continue
			}
			return nil, fmt.Errorf("terminal_sandbox: cannot resolve host socket path %s: %w", p, err)
		}
		if seen[real] {
			continue
		}
		fi, err := os.Stat(real)
		if err != nil {
			return nil, fmt.Errorf("terminal_sandbox: cannot inspect host socket path %s: %w", real, err)
		}
		if !fi.IsDir() {
			continue
		}
		seen[real] = true
		out = append(out, sandbox.Overlay{Path: real, Kind: sandbox.OverlayHideDir})
	}
	return out, nil
}

// socketSweeps lists each existing, non-symlink sandbox.SocketSweepDirs
// directory with the entries to put back: directories and regular files are
// re-bound, symlinks are recreated unless they resolve to a socket, FIFO or
// device, and every socket, FIFO or device is dropped. An entry whose name
// could not be passed to bwrap safely is dropped too (hidden, never an
// error).
func socketSweeps() ([]sandbox.DirRebuild, error) {
	var out []sandbox.DirRebuild
	for _, dir := range sandbox.SocketSweepDirs {
		fi, err := os.Lstat(dir)
		if err != nil || !fi.IsDir() {
			continue
		}
		ents, err := os.ReadDir(dir)
		if err != nil {
			return nil, fmt.Errorf("terminal_sandbox: cannot list %s to drop its sockets: %w", dir, err)
		}
		d := sandbox.DirRebuild{Path: dir}
		for _, e := range ents {
			name := e.Name()
			if badSweepName(name) {
				continue
			}
			full := filepath.Join(dir, name)
			lfi, err := os.Lstat(full)
			if err != nil {
				continue // vanished since the listing
			}
			switch mode := lfi.Mode(); {
			case mode.IsDir(), mode.IsRegular():
				d.Keep = append(d.Keep, sandbox.RebuildEntry{Name: name})
			case mode&os.ModeSymlink != 0:
				target, err := os.Readlink(full)
				if err != nil || badSweepName(strings.ReplaceAll(target, "/", "x")) || strings.HasPrefix(target, "-") {
					continue
				}
				if tfi, err := os.Stat(full); err == nil && tfi.Mode()&(os.ModeSocket|os.ModeNamedPipe|os.ModeDevice|os.ModeCharDevice) != 0 {
					continue
				}
				d.Keep = append(d.Keep, sandbox.RebuildEntry{Name: name, Symlink: target})
			}
		}
		out = append(out, d)
	}
	return out, nil
}

// badSweepName reports a directory entry name that is not a plain single
// component safe to hand to bwrap.
func badSweepName(name string) bool {
	if name == "" || name == "." || name == ".." || strings.HasPrefix(name, "-") || strings.Contains(name, "/") {
		return true
	}
	for _, r := range name {
		if r <= ' ' || r == 0x7f {
			return true
		}
	}
	return false
}

// hostMaskKeep returns the files a host mask would hide that the sandboxed
// process still needs read-only: today the resolver config, which WSL points
// into /mnt/wsl.
func hostMaskKeep(masks []sandbox.Overlay) []string {
	real, err := filepath.EvalSymlinks("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	for _, m := range masks {
		if withinAny(real, []string{m.Path}) && real != m.Path {
			return []string{real}
		}
	}
	return nil
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

// foreignMountRoots returns the foreign-OS mount roots (`/mnt/<drive>`) derived
// from crossmount's detected non-native homes, so A1 can `--tmpfs`-mask the
// whole foreign drive `--ro-bind / /` would otherwise expose. Only homes whose
// logical OS differs from the daemon's (e.g. Windows homes on a WSL host)
// contribute; the native home is never masked. Deduped.
func foreignMountRoots() []string {
	seen := map[string]bool{}
	var out []string
	for _, h := range crossmount.ExtraHomes() {
		if h.OS == crossmount.OSLinux && runtime.GOOS == "linux" {
			continue // a same-OS extra home is not a foreign mount
		}
		root := mntDriveRoot(h.Path)
		if root == "" || seen[root] {
			continue
		}
		seen[root] = true
		out = append(out, root)
	}
	return out
}

// mntDriveRoot extracts the `/mnt/<drive>` prefix of a WSL foreign-home path
// (e.g. "/mnt/c/Users/me" → "/mnt/c"), or "" when the path is not under /mnt.
func mntDriveRoot(p string) string {
	const prefix = "/mnt/"
	if !strings.HasPrefix(p, prefix) {
		return ""
	}
	rest := p[len(prefix):]
	if slash := strings.IndexByte(rest, '/'); slash >= 0 {
		rest = rest[:slash]
	}
	if rest == "" {
		return ""
	}
	return prefix + rest
}

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/intelligence/dashboard"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
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
		now:             func() time.Time { return time.Now().UTC() },
	}, nil
}

// workspacesDir returns the canonical managed-workspaces root, so buildTerminal
// Stack can hand termsvc.Options.SandboxWorkspacesDir the SAME value this
// runtime validates prepared workspaces against.
func (r *sandboxRuntime) workspacesDir() string { return r.managedRoot }

// sandboxSeamProber returns the runtime as a dashboard.SandboxProber, or a NIL
// interface (not a non-nil interface over a nil pointer) when rt is nil, so a
// disabled sandbox leaves dashboard.Options.SandboxProber == nil and the
// fail-closed / disabled-report paths fire correctly.
func sandboxSeamProber(rt *sandboxRuntime) dashboard.SandboxProber {
	if rt == nil {
		return nil
	}
	return rt
}

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
	return sandbox.Env{
		GOOS: runtime.GOOS,
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
				"--ro-bind", "/", "/", "--tmpfs", "/tmp", "--die-with-parent", "--", "true").Run()
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

	wrapArgv, err := r.buildWrapArgv(req.Tool, dest)
	if err != nil {
		return termsvc.PrepareResult{}, err
	}

	return termsvc.PrepareResult{
		Dir:      dest,
		WrapArgv: wrapArgv,
		Note:     fmt.Sprintf("sandbox: source=%s workspace=%s", src, dest),
	}, nil
}

// buildWrapArgv resolves the bwrap Request for tool operating in workspaceRoot,
// composes the plan via sandbox.BuildPlan, and returns the launch-ready wrapper
// prefix: [bwrapPath, <flags...>, "--"]. termsession.Spec.argv() prepends this
// before [BinPath, Subcommand, ...ExtraArgs], yielding
// `bwrap <flags...> -- observer <verb> ...` (D2 seam).
func (r *sandboxRuntime) buildWrapArgv(tool, workspaceRoot string) ([]string, error) {
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

	plan, err := sandbox.BuildPlan(sandbox.Request{
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
	flags := composed[:len(composed)-1] // [flags..., "--"]
	wrap := make([]string, 0, len(flags)+1)
	wrap = append(wrap, bwrapPath)
	wrap = append(wrap, flags...)
	return wrap, nil
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

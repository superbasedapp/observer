package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guilaunch"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/intelligence/dashboard"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/termrun"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
	"github.com/marmutapp/superbased-observer/internal/toolresolve"
)

// gui_launch.go is the cmd-side exec seam of the DETACHED IDE / desktop-app
// launch (docs/plans/ide-desktop-launch-plan-2026-09-03.md T2). It is the ONLY
// place in the feature that touches the filesystem, the config, or a process:
// resolution lives in internal/toolresolve, argv/env composition in
// internal/guilaunch, identity + authorization in internal/termsvc, and the
// wire shape in internal/intelligence/dashboard. This file joins them.
//
// It is the GUI sibling of ptyLauncher (terminal_launch.go) and follows the
// same discipline: the argv is server-derived in full, the child environment is
// the daemon's own minus the internal OOB/marker variables, and the per-launch
// audit line records variable NAMES and counts only — never a value.

// guiLauncher implements termsvc.GUILauncher. All of its inputs are wiring-time
// facts (the proxy port, the daemon's config path, the memoized resolver Env)
// so a launch performs no config discovery of its own.
type guiLauncher struct {
	// proxyPort is [proxy].port; the wrap's base URL is resolved from it
	// through the SAME resolveProxyURL every CLI launcher uses, so a GUI wrap
	// and an `observer claude` launch can never point at different proxies.
	proxyPort int
	// configPath is the daemon's --config, consulted for the
	// [launch.tools.<id>].path override. Read lazily (the setting is a
	// process-global the daemon installs at startup).
	configPath func() string
	// resolveEnv returns the memoized host resolution Env (dashResolveEnv), so
	// a GUI preflight and a GUI launch resolve against exactly the same view of
	// the machine.
	resolveEnv func() toolresolve.Env
	logger     *slog.Logger
}

// SpawnGUI resolves the row's binary, composes the launch, spawns it detached,
// and starts a reaper that reports the exit back through req.OnExit.
//
// The resolution ladder mirrors toolPreflightSeam's exactly — config override
// first, then toolresolve.ResolveGUI — so the verdict the operator saw in the
// dialog is the one the launch acts on. The one GUI-specific rung is the
// foreign_only → interop escape: a WSL daemon CAN exec a Windows .exe, so the
// launch proceeds with that path and the wrap honestly records as not-applied
// (the environment does not cross the boundary without WSLENV).
func (g *guiLauncher) SpawnGUI(req termsvc.GUISpawnRequest) (termsvc.GUISpawnResult, error) {
	configPath := ""
	if g.configPath != nil {
		configPath = g.configPath()
	}
	// GUI routing hints do not prove how an IDE's extensions or a desktop app
	// select their provider, so the route stays unknown and the same managed-
	// budget check as terminal AI launchers runs before resolution or spawn.
	//
	// What a GUI launch CAN state honestly is its surface: this table launches
	// IDE and desktop HOSTS, which contain unrelated work and therefore have
	// no process boundary a cutoff could bind to. That is a registry fact
	// (integration.GUILaunchSurfaceClass), not a GUI special case — the gate
	// reads the declared class and applies the org's existing partial-coverage
	// posture instead of refusing an under-cap launch at $0. An unknown launch
	// id resolves to nothing and keeps the fail-closed refusal.
	guiEvidence := budgetLaunchEvidence{Route: budgetLaunchRouteUnknown}
	if class, ok := integration.GUILaunchSurfaceClass(req.ID); ok {
		guiEvidence.SurfaceClass = class
	}
	if err := enforceBudgetControlledLaunch(context.Background(), configPath, req.ID,
		guiEvidence); err != nil {
		return termsvc.GUISpawnResult{}, err
	}
	bin, viaInterop, notes := g.resolveGUIBin(req.ID, req.Spec)

	plan, err := guilaunch.Compose(req.Spec, guilaunch.Inputs{
		GOOS:        runtime.GOOS,
		Bin:         bin,
		ProjectRoot: req.ProjectRoot,
		ProxyURL:    resolveProxyURL(g.proxyPort, ""),
		ViaInterop:  viaInterop,
	})
	if err != nil {
		return termsvc.GUISpawnResult{}, err
	}

	env := guiChildEnv(plan.Env)
	// The working directory follows the SAME rule as the argv: a row that takes
	// no project-directory argument ignores the requested directory entirely
	// (Compose notes "the requested directory was ignored"), so cmd.Dir must not
	// quietly apply it either.
	dir := ""
	if req.Spec.ProjectDirArgv {
		dir = req.ProjectRoot
	}
	proc, err := spawnDetached(plan.Argv, dir, env)
	if err != nil {
		return termsvc.GUISpawnResult{}, err
	}
	g.auditSpawn(req, proc.Pid, plan, env)

	// Reaper: a detached child still has to be waited on, or (on POSIX) it
	// becomes a zombie held by this daemon for as long as it runs. Waiting also
	// gives the run row an honest end. A launch the operator never closes
	// simply keeps this goroutine parked until the daemon exits — one goroutine
	// per live GUI app, which is the same order as one PTY per live terminal.
	go g.reap(req, proc)

	return termsvc.GUISpawnResult{
		PID:         proc.Pid,
		WrapApplied: plan.WrapApplied,
		WrapNote:    plan.WrapNote,
		Notes:       append(notes, plan.Notes...),
		Bin:         bin,
	}, nil
}

// reap waits for the detached child and reports its exit exactly once.
func (g *guiLauncher) reap(req termsvc.GUISpawnRequest, proc *os.Process) {
	state, err := proc.Wait()
	code := -1
	if err == nil && state != nil {
		code = state.ExitCode()
	}
	if g.logger != nil {
		g.logger.Info("gui launch: exited",
			"run", req.RunID, "id", req.ID, "pid", proc.Pid, "exit_code", code)
	}
	if req.OnExit != nil {
		req.OnExit(req.RunID, code)
	}
}

// resolveGUIBin runs the resolution ladder for one GUI row and reports the
// launch target, whether the launch crosses the WSL interop boundary, and any
// honest notes for the operator.
//
// Returning an EMPTY bin is not a failure here: a Windows packaged app is
// addressed by its AUMID and a macOS bundle by its name, both of which
// guilaunch.Compose turns into a real argv. Compose is the one place that
// decides there is nothing to launch.
func (g *guiLauncher) resolveGUIBin(id string, spec integration.GUILaunchSpec) (bin string, viaInterop bool, notes []string) {
	// Rung 1: the [launch.tools.<id>].path override, the same rung
	// resolveToolBin and toolPreflightSeam honour first. A broken config falls
	// open to the ladder — a config problem must never block a launch the
	// resolver could have satisfied on its own.
	if path, ok := g.configuredPath(id); ok {
		return path, false, []string{fmt.Sprintf("configured via [launch.tools.%s].path", id)}
	}

	res := toolresolve.ResolveGUI(spec, g.resolveEnv())
	if res.Bin != "" {
		return res.Bin, false, nil
	}
	// Rung 2: the interop escape. A WSL daemon that found only a Windows
	// install can still exec it — the launch works, the environment does not
	// cross. ViaInterop makes guilaunch record that honestly instead of
	// claiming a wrap that silently did nothing.
	if path, ok := toolresolve.ForeignInteropLaunchable(res); ok && crossmount.IsWSL() {
		return path, true, []string{
			"launched through WSL interop: the app is a Windows install, so routing environment does not propagate",
		}
	}
	// Nothing resolved. Hand back the empty bin and let Compose decide whether
	// the row still has a mechanism (AUMID / darwin bundle) or genuinely has
	// nothing to launch.
	return "", false, nil
}

// configuredPath reads the [launch.tools.<id>].path override, returning ok only
// when it names an existing regular file. A stale entry is treated as ABSENT
// here (the ladder continues) rather than as a hard failure: the preflight is
// where a stale override is reported to the operator, and refusing the launch
// as well would just double-report the same misconfiguration while denying a
// launch the resolver can still satisfy.
func (g *guiLauncher) configuredPath(id string) (string, bool) {
	if g.configPath == nil {
		return "", false
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: g.configPath()})
	if err != nil {
		return "", false
	}
	tc, ok := cfg.Launch.Tools[id]
	if !ok || strings.TrimSpace(tc.Path) == "" {
		return "", false
	}
	fi, statErr := os.Stat(tc.Path)
	if statErr != nil || fi.IsDir() {
		return "", false
	}
	return tc.Path, true
}

// guiChildEnv builds the detached child's environment: the daemon's own, minus
// the internal child variables (the OOB channel, the daemon-child marker, the
// sandbox marker), plus the wrap's additions layered LAST so they win.
//
// It reuses isInternalChildEnv — the same predicate launchChildEnv and
// setupChildEnv use — so there is one answer to "which variables are the
// daemon's private business" across every spawn path. The OOB variables are
// stripped because a GUI child has no OOB channel at all: inheriting a stale
// fd number and auth token would be meaningless at best.
func guiChildEnv(wrap []string) []string {
	parent := os.Environ()
	out := make([]string, 0, len(parent)+len(wrap))
	for _, kv := range parent {
		if isInternalChildEnv(kv) {
			continue
		}
		out = append(out, kv)
	}
	out = append(out, wrap...)
	if runtime.GOOS == "windows" {
		// Windows env keys are case-insensitive, so an inherited `Path=` and a
		// wrap-supplied `PATH=` would both survive and "last wins" would stop
		// being true. Same platform-capability branch launchChildEnv makes.
		return dedupEnvWindows(out)
	}
	return out
}

// auditSpawn logs one metadata-only line per GUI launch: the run identity, the
// row id, the pid, the argv LENGTH, and the environment variable count plus the
// NAMES the wrap contributed. Never a value — the wrap variables carry the
// proxy URL, and the inherited environment carries the operator's own provider
// credentials. This mirrors ptyLauncher.auditEnv's contract exactly.
func (g *guiLauncher) auditSpawn(req termsvc.GUISpawnRequest, pid int, plan guilaunch.Plan, env []string) {
	if g.logger == nil {
		return
	}
	names := make([]string, 0, len(plan.Env))
	for _, kv := range plan.Env {
		if i := strings.IndexByte(kv, '='); i > 0 {
			names = append(names, kv[:i])
		}
	}
	g.logger.Info("gui launch: spawned",
		"run", req.RunID, "id", req.ID, "pid", pid,
		"argv_len", len(plan.Argv),
		"env_vars", len(env),
		"wrap_applied", plan.WrapApplied,
		"wrap_vars", strings.Join(names, ","),
		"dir_set", req.ProjectRoot != "")
}

// --- dashboard.LaunchManager GUI half ---

// CreateGUI spawns a DETACHED IDE / desktop application through the terminal
// application service, which enforces the SAME [terminal.launch] opt-in as
// CreateFresh (keyed by the GUI id) plus its own advertised-row gate. The
// project root is translated for a cross-mount daemon exactly as CreateFresh
// does, so a Windows-spelled path from a browser on the Windows side resolves
// for a WSL daemon.
func (a *launchManagerAdapter) CreateGUI(spec dashboard.GUILaunchSpec) (dashboard.GUILaunchResult, error) {
	res, err := a.svc.LaunchGUI(context.Background(), termsvc.GUIRequest{
		ID:          spec.ID,
		ProjectRoot: crossmount.TranslateForeignPath(spec.ProjectRoot),
	})
	if err != nil {
		return dashboard.GUILaunchResult{}, mapGUIErr(err)
	}
	return dashboard.GUILaunchResult{
		RunID:       res.RunID,
		PID:         res.PID,
		ID:          res.ID,
		Label:       res.Label,
		WrapApplied: res.WrapApplied,
		WrapNote:    res.WrapNote,
		Notes:       res.Notes,
	}, nil
}

// GUIRuns projects the service's in-memory GUI run list onto the dashboard wire
// shape. A pure projection — this adapter adds no policy of its own.
func (a *launchManagerAdapter) GUIRuns() []dashboard.GUIRunInfo {
	runs := a.svc.GUIRuns()
	out := make([]dashboard.GUIRunInfo, 0, len(runs))
	for _, r := range runs {
		out = append(out, dashboard.GUIRunInfo{
			RunID:       r.RunID,
			ID:          r.ID,
			Label:       r.Label,
			PID:         r.PID,
			LaunchedAt:  r.LaunchedAt,
			WrapApplied: r.WrapApplied,
			// Always a real array on the wire (the dashboard type promises never-null).
			Notes:    append([]string{}, r.Notes...),
			WrapNote: r.WrapNote,
			Exited:   r.Exited,
			ExitCode: r.ExitCode,
		})
	}
	return out
}

// mapGUIErr maps termsvc's GUI-launch sentinels onto the dashboard's, keeping
// the service's own message by wrapping rather than replacing. The three shared
// gates (fresh disabled / tool not allowed / project root denied) reuse
// mapFreshErr's sentinels, because they ARE the same gates — a GUI launch is
// authorized by the same policy as a PTY fresh launch.
func mapGUIErr(err error) error {
	switch {
	case errors.Is(err, termsvc.ErrGUIUnsupported):
		return fmt.Errorf("%w: %w", dashboard.ErrLaunchGUIUnsupported, err)
	case errors.Is(err, termsvc.ErrGUINotLaunchable):
		return fmt.Errorf("%w: %w", dashboard.ErrLaunchGUINotLaunchable, err)
	default:
		return mapFreshErr(err)
	}
}

// --- store seam for the GUI post-spawn stamp ---

// RecordGUISpawn stamps a GUI run's pid + wrap verdict through the ONE store
// seam that owns terminal_run (internal/store/termrun.go). termsvc calls it
// after the spawn returns, because none of the three facts exists until the
// child does.
func (r termRunRecorder) RecordGUISpawn(ctx context.Context, run termrun.Run) error {
	if run.PID == nil {
		// Nothing to stamp. The row keeps the honest NULL pid the insert wrote
		// rather than recording a fabricated 0.
		return nil
	}
	return r.st.StampTerminalRunSpawn(ctx, run.RunID, *run.PID, run.WrapApplied, run.WrapNote)
}

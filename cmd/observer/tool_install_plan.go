package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/toolinstall"
	"github.com/marmutapp/superbased-observer/internal/toolresolve"
	"github.com/marmutapp/superbased-observer/internal/toolresolve/host"
	"github.com/marmutapp/superbased-observer/internal/watcher"
)

// tool_install_plan.go holds the tool preflight, install-plan and resolve-env
// seams the dashboard tool picker, the launch-time runtime preflight,
// `observer doctor` and the node tool gate share (lane MP-L1K, T-715, moved
// out of launch_dashboard.go). They plan and check only (internal/toolinstall
// is pure planning vocabulary); running an install is the terminals
// component's guided setup session, so a build without terminals still
// answers "is this tool installed, and how would it be installed".

// dashResolveEnvTTL bounds how long the dashboard reuses a captured
// toolresolve.Env before rebuilding it. A short window (not a forever-memoized
// value) is what keeps the "a fresh install becomes visible in a daemon-side
// preflight without a restart" story honest (F7): a rebuild is not free - the
// crossmount home walk, a login-shell PATH capture bounded at 3s PER ATTEMPT
// (bash/zsh try `-lic` first and fall back to `-lc`, so up to two), and the
// lazy `npm prefix -g` probe bounded at a further 3s on the first Resolve that
// reaches it - so per-call rebuilds would be wasteful, but a process-lifetime
// memo would pin the PATH snapshot taken at first launch forever. Each probe is
// memoized ON the Env, so those costs are paid once per rebuild, not per tool.
var dashResolveEnvTTL = 30 * time.Second

var (
	dashResolveEnvMu   sync.Mutex
	dashResolveEnvVal  toolresolve.Env
	dashResolveEnvAt   time.Time
	dashResolveEnvHave bool
	// dashResolveEnvNow + dashResolveEnvBuild are package-private seams a test
	// substitutes to drive TTL expiry deterministically (restore in a defer);
	// production keeps the real clock and the real host env capture.
	dashResolveEnvNow   = time.Now
	dashResolveEnvBuild = func() toolresolve.Env { return host.NewEnv(host.Options{}) }
)

// dashResolveEnv returns the toolresolve.Env driving the dashboard's tool-
// resolution seams (tool-binary-resolution arc §5), rebuilding it via
// host.NewEnv when the cached value is older than dashResolveEnvTTL so a
// daemon-side preflight reflects a freshly installed binary without a restart
// (F7). Concurrency-safe; the rebuild happens under the lock so a burst of
// preflights past the TTL rebuilds exactly once.
func dashResolveEnv() toolresolve.Env {
	dashResolveEnvMu.Lock()
	defer dashResolveEnvMu.Unlock()
	now := dashResolveEnvNow()
	if !dashResolveEnvHave || now.Sub(dashResolveEnvAt) >= dashResolveEnvTTL {
		dashResolveEnvVal = dashResolveEnvBuild()
		dashResolveEnvAt = now
		dashResolveEnvHave = true
	}
	return dashResolveEnvVal
}

// installOSForGOOS maps the daemon GOOS to an integration.InstallHint.OS token
// ("linux" | "darwin" | "windows"), the same convention toolresolve uses to
// filter hints. It is the ONE place the cmd-side install seam picks the OS a
// grounded hint must match.
func installOSForGOOS(goos string) string {
	switch goos {
	case "windows":
		return "windows"
	case "darwin":
		return "darwin"
	default:
		return "linux"
	}
}

// toolPreflightSeam builds the dashapi.Options.ToolPreflight closure: it
// resolves a launchable tool NAME to a dashapi.ToolPreflight verdict via the
// SAME ladder the actual launcher (cmd/observer/launch.go resolveToolBin)
// honors, so a preflight never diverges from the launch it predicts (F1). It
// reports ok=false for an unknown tool, a tool that is not
// integration.TerminalLaunchable (no grounded LaunchSpec, or a deprecated /
// dead product the harness lifecycle policy stops advertising), or one with no
// grounded Binary spec (the honest floor the endpoint turns into a 400).
//
// Ladder, mirroring resolveToolBin (the --<tool>-path FLAG has no dashboard
// equivalent, so only the config override is mirrored):
//
//  1. [launch.tools.<tool>].path config override - what the launcher checks
//     BEFORE the resolution ladder. Present + stats as a file ⇒ verdict "ok"
//     with Bin=that path and a note that it is configured; present + missing
//     (or a dir) ⇒ verdict "not_found" with a note NAMING the stale config key
//     (never a silent fall-through to the ladder - the launch would fail AT the
//     override, so preflighting past it would lie). A config that fails to load
//     falls open to the ladder (a broken config never blocks a preflight).
//  2. the pure internal/toolresolve ladder over the registry Binary row.
//
// InstallCommand is the same preferred + permission-safe plan the install
// endpoint will run: an exact-OS official channel wins over a generic one, and
// a Unix npm-global fallback is redirected to the user's ~/.local prefix.
// CanInstall is true only when such a plan exists AND the live allow_install
// kill-switch is on. The argv NEVER crosses this seam.
func toolPreflightSeam(configPath string, allowInstall func() bool) func(string) (dashapi.ToolPreflight, bool) {
	return func(tool string) (dashapi.ToolPreflight, bool) {
		ic, ok := integration.For(tool)
		if !ok || !integration.TerminalLaunchable(ic) || ic.Binary == nil {
			// ONE lookup ladder (T2): an id that is not a terminal-launchable
			// tool may still be an ADVERTISED GUI launch row. The dashboard
			// handler stays name-free - it asks this seam and renders whatever
			// comes back - so the decision about which registry the id belongs
			// to lives here, in one place, and never in an HTTP handler.
			return guiPreflight(tool, configPath, allowInstall)
		}
		// Step 1: config override parity with resolveToolBin. Fail open on a
		// config load error so a broken config never blocks the ladder.
		if cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath}); err == nil {
			if tc, ok := cfg.Launch.Tools[tool]; ok && tc.Path != "" {
				key := fmt.Sprintf("[launch.tools.%s].path", tool)
				if fi, statErr := os.Stat(tc.Path); statErr != nil || fi.IsDir() {
					return dashapi.ToolPreflight{
						Tool:           tool,
						Verdict:        string(toolresolve.VerdictNotFound),
						ConfigOverride: dashapi.PreflightOverrideMissing,
						Notes: []string{fmt.Sprintf(
							"%s = %q is set but no binary is there - fix the path or remove the entry",
							key, tc.Path,
						)},
					}, true
				}
				return dashapi.ToolPreflight{
					Tool:           tool,
					Verdict:        string(toolresolve.VerdictOK),
					Bin:            tc.Path,
					ConfigOverride: dashapi.PreflightOverrideUsed,
					Notes:          []string{fmt.Sprintf("configured via %s", key)},
				}, true
			}
		}
		// Step 2: registry-driven resolution ladder over the Binary row.
		env := dashResolveEnv()
		r := toolresolve.Resolve(*ic.Binary, env)
		pf := dashapi.ToolPreflight{
			Tool:    tool,
			Verdict: string(r.Verdict),
			Bin:     r.Bin,
			Notes:   r.Notes,
		}
		if r.InterpreterMissing {
			pf.MissingInterpreter = r.Interpreter
		}
		// The SAME minimum-runtime check resolveToolBin refuses a launch on
		// (runtime_preflight.go), dry-run here so Start is disabled with the
		// sentence the launcher would print.
		// "": the daemon does not know the directory the terminal will start
		// in, so a version-manager shim is left to the launcher (M3-18).
		if c, ok := launchRuntimeCheck(ic.Binary, r, env, runtime.GOOS, ""); ok {
			pf.LaunchRuntime = preflightRuntime(c)
		}
		if plan, ok := dashboardInstallPlanFor(ic.Binary.Installs, runtime.GOOS, dashboardInstallHome(), dashInstallArgv0); ok {
			applyInstallPlan(&pf, plan, allowInstall)
			if c, ok := installRuntimeCheck(ic.Binary, plan.Channel, env, runtime.GOOS, ""); ok {
				pf.InstallRuntime = preflightRuntime(c)
				if c.Blocking() {
					pf.CanInstall = false
				}
			}
		} else {
			// No guided plan for this OS - say WHY rather than letting the
			// dialog dead-end on "X is not installed." with no next step
			// (DI-03). The reason is registry-grounded when the row carries
			// one; otherwise it is the shared vendor-docs sentence.
			pf.InstallNote = installNoteFor(ic.Binary, runtime.GOOS)
			pf.UserInstallHint = ic.Binary.UserInstallHint
		}
		// T-685: a launch the org's hard budget will refuse says so, with
		// what to do, before Start; the launcher still makes the decision.
		if pf.Bin != "" {
			if advice, ok := budgetLaunchPreflightSeam(context.Background(), configPath, tool, pf.Bin); ok {
				pf.BudgetLaunch = advice
			}
		}
		pf.RouteSetup = routeSetupPreflight(tool)
		return pf, true
	}
}

// budgetLaunchPreflightSeam is the preflight's managed-budget dry run, a
// variable so the seam's own tests stay free of a managed-budget fixture.
var budgetLaunchPreflightSeam = budgetLaunchPreflight

// installNoteFor renders the honest reason a launchable tool has no guided
// install plan on this OS (audit DI-03). It is pure - no filesystem, no
// registry lookup - so the sentence the dialog shows is table-testable.
//
// Two grounded carriers feed it, in the order the operator needs them:
//
//   - Binary.WindowsNote, when running on Windows and the row has no Windows
//     binary spelling at all: that is the deeper "there is no Windows build"
//     fact, and stating it first stops the operator hunting for an installer
//     that cannot exist.
//   - Binary.InstallNote, the per-row reason no InstallHint covers this OS.
//
// When neither is set the shared vendor-docs sentence is the floor - never a
// fabricated channel, and never an empty string (the dialog would render
// nothing, which is the DI-03 dead end itself).
func installNoteFor(spec *integration.BinaryResolveSpec, goos string) string {
	if spec == nil {
		return toolresolve.NoGroundedInstallMsg
	}
	var parts []string
	if goos == "windows" && len(spec.Names.Windows) == 0 {
		if note := strings.TrimSpace(spec.WindowsNote); note != "" {
			parts = append(parts, note)
		}
	}
	if note := strings.TrimSpace(spec.InstallNote); note != "" {
		parts = append(parts, note)
	} else {
		parts = append(parts, toolresolve.NoGroundedInstallMsg)
	}
	return strings.Join(parts, " - ")
}

// toolInstallHintSeam builds the dashapi.Options.ToolInstallHint closure: it
// returns the SERVER-SIDE install argv + display for a tool NAME, sourced ONLY
// from the compile-time registry (tool-binary-resolution arc §Security - the
// request contributes only the map key, so the argv-injection surface is zero).
// Exact-OS hints win over generic hints. Unix npm-global hints are made
// permission-safe by installing beneath ~/.local instead of npm's frequently
// root-owned /usr/lib/node_modules prefix. A tool with no usable grounded hint
// yields ok=false (the endpoint's 400), as does a row the harness lifecycle
// policy no longer advertises (Capability.Advertised is false) - guided
// install must never push an operator into a sunset or dead product. It is
// deliberately gated on Advertised, not TerminalLaunchable: installing is not
// launching (operator decision 2026-09-02), so a non-launchable but active row
// keeps its install hint.
func toolInstallHintSeam() func(string) ([]string, string, bool) {
	return func(tool string) ([]string, string, bool) {
		installs, ok := installHintsFor(tool)
		if !ok {
			return nil, "", false
		}
		plan, ok := dashboardInstallPlanFor(installs, runtime.GOOS, dashboardInstallHome(), dashInstallArgv0)
		if !ok {
			return nil, "", false
		}
		return plan.Argv, plan.Display, true
	}
}

// installHintsFor is the ONE lookup ladder behind both install-facing seams: a
// registry ADAPTER row first, then a GUI launch row. It returns the grounded
// install hints for whichever carrier owns the id, gated on Advertised() in
// both cases - guided install must never push an operator into a sunset or dead
// product, nor into an UNVERIFIED GUI row whose executable was never grounded.
//
// Both rungs gate on Advertised() rather than launchability, because installing
// is not launching (operator decision 2026-09-02, pinned by
// TestTerminalInstallIsNotGatedByAllowedTools): a non-launchable but active row
// keeps its install hint.
func installHintsFor(id string) ([]integration.InstallHint, bool) {
	if ic, ok := integration.For(id); ok && ic.Advertised() && ic.Binary != nil {
		return ic.Binary.Installs, true
	}
	if g, ok := integration.GUILaunchFor(id); ok && g.Advertised() {
		return g.Spec.Binary.Installs, true
	}
	return nil, false
}

// guiPreflightLaunchable is the set of preflight verdicts a GUI launch would
// proceed on (a WSL interop launch is reported as ok_off_path). Data, not a
// branch ladder: a new launchable verdict is one row.
var guiPreflightLaunchable = map[toolresolve.Verdict]bool{
	toolresolve.VerdictOK:        true,
	toolresolve.VerdictOKOffPath: true,
	toolresolve.VerdictShadowed:  true,
}

// guiPreflightVerdict is the resolution half of guiPreflight: verdict, bin,
// install guidance and the structured facts behind the notes.
func guiPreflightVerdict(id, configPath string, allowInstall func() bool) (dashapi.ToolPreflight, bool) {
	g, ok := integration.GUILaunchFor(id)
	if !ok || !g.Advertised() {
		return dashapi.ToolPreflight{}, false
	}
	kind := string(integration.LaunchKindGUI)

	// Config-override parity with the launcher's own first rung, exactly as the
	// terminal arm above does it.
	if cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath}); err == nil {
		if tc, ok := cfg.Launch.Tools[id]; ok && tc.Path != "" {
			key := fmt.Sprintf("[launch.tools.%s].path", id)
			if fi, statErr := os.Stat(tc.Path); statErr != nil || fi.IsDir() {
				return dashapi.ToolPreflight{
					Tool: id, Kind: kind,
					Verdict:        string(toolresolve.VerdictNotFound),
					ConfigOverride: dashapi.PreflightOverrideMissing,
					Notes: []string{fmt.Sprintf(
						"%s = %q is set but no binary is there - fix the path or remove the entry",
						key, tc.Path)},
				}, true
			}
			return dashapi.ToolPreflight{
				Tool: id, Kind: kind,
				Verdict:        string(toolresolve.VerdictOK),
				Bin:            tc.Path,
				ConfigOverride: dashapi.PreflightOverrideUsed,
				Notes:          []string{fmt.Sprintf("configured via %s", key)},
			}, true
		}
	}

	r := toolresolve.ResolveGUI(g.Spec, dashResolveEnv())
	pf := dashapi.ToolPreflight{
		Tool: id, Kind: kind,
		Verdict: string(r.Verdict),
		Bin:     r.Bin,
		Notes:   r.Notes,
	}
	if _, interop := toolresolve.ForeignInteropLaunchable(r); interop && crossmount.IsWSL() {
		pf.Verdict = string(toolresolve.VerdictOKOffPath)
		pf.Notes = append(pf.Notes,
			"Windows app, launched through WSL interop; routing env will not propagate")
	}
	if r.Verdict == toolresolve.VerdictOK && r.Bin == "" && g.Spec.AppsFolderAUMID != "" {
		pf.InstallUnverified = true
		pf.Notes = append(pf.Notes, "packaged app (not probed)")
	}
	if plan, ok := dashboardInstallPlanFor(g.Spec.Binary.Installs, runtime.GOOS, dashboardInstallHome(), dashInstallArgv0); ok {
		applyInstallPlan(&pf, plan, allowInstall)
	} else {
		pf.InstallNote = installNoteFor(&g.Spec.Binary, runtime.GOOS)
		pf.UserInstallHint = g.Spec.Binary.UserInstallHint
	}
	return pf, true
}

// applyInstallPlan is the ONE place a usable install plan is folded into a
// preflight verdict, for terminal tools and GUI rows alike. A plan whose
// grounded prerequisites are missing keeps its command on display (the
// operator still sees what would run) but is NOT installable from here:
// CanInstall goes false and the prerequisite remedy says exactly what to
// install first, so the vendor script is never spawned just to fail.
func applyInstallPlan(pf *dashapi.ToolPreflight, plan dashboardInstallPlan, allowInstall func() bool) {
	pf.InstallCommand = plan.Display
	pf.CanInstall = allowInstall != nil && allowInstall()
	pf.InstallNeedsProgram = plan.NeedsProgram
	if plan.Note != "" {
		pf.Notes = append(pf.Notes, plan.Note)
	}
	if len(plan.Missing) > 0 {
		pf.CanInstall = false
		pf.InstallMissingPrereqs = append([]string(nil), plan.Missing...)
		pf.InstallPrereqRemedy = installPrereqRemedy(plan.Missing)
	}
}

type dashboardInstallPlan struct {
	Argv    []string
	Display string
	// Channel is the chosen hint's install channel (the registry's closed
	// InstallHint.Channel vocabulary). The dashboard-install record stores it
	// so the uninstall can be derived from internal/toolinstall's channel
	// table; it never reaches the client.
	Channel string
	// Note is an honest caveat about the plan itself (empty when there is
	// none) - today: the plan's program could not be resolved to an absolute
	// path on this daemon, so the spawn falls back to a PATH lookup that may
	// fail. It is surfaced through the preflight's Notes, never as an error:
	// the plan is still the right command to show the operator.
	Note string
	// NeedsProgram is the structured twin of Note: the program (argv[0]) that
	// could not be resolved, set at the same site. Empty when it resolved.
	NeedsProgram string
	// Missing lists the hint's grounded host prerequisites
	// (InstallHint.Requires entries) that do not resolve here. Non-empty
	// means the guided install is refused up front with installPrereqRemedy
	// rather than spawned to fail inside the vendor script.
	Missing []string
}

// installArgv0Lookup resolves an install plan's PROGRAM name (argv[0], e.g.
// "npm", "bash", "uv") to an absolute path, reporting ok=false when it is on
// neither the daemon's PATH nor the operator's login-shell PATH. It is injected
// so dashboardInstallPlanFor stays a pure, table-testable function (CLAUDE.md
// #1); nil disables the resolution and keeps the registry's bare name.
type installArgv0Lookup func(name string) (string, bool)

// dashInstallArgv0 is the production installArgv0Lookup: it walks the SAME
// merged PATH (process + login shell) internal/toolresolve resolves tools on,
// and accepts the first regular, executable file with that name.
//
// This is audit DI-04a. The install PTY execs argv[0] through exec.Command,
// which resolves it against the DAEMON's process PATH only - never the child
// env we hand it - so on a daemon whose PATH lacks the operator's node prefix
// every npm install plan failed before it started. Resolving the program here,
// server-side, is not a widened trust surface: argv[0] is a compile-time
// registry constant, never request-derived, and the request still contributes
// only the tool name.
func dashInstallArgv0(name string) (string, bool) {
	if name == "" {
		return "", false
	}
	if filepath.IsAbs(name) {
		return name, true
	}
	dirs, _ := toolresolve.MergedPathDirs(dashResolveEnv())
	for _, dir := range dirs {
		cand := filepath.Join(dir, name)
		fi, err := os.Stat(cand) //nolint:gosec // G703: a metadata read of a PATH entry joined with a catalog tool name
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		if runtime.GOOS != "windows" && fi.Mode().Perm()&0o111 == 0 {
			continue
		}
		return cand, true
	}
	return "", false
}

func dashboardInstallHome() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home
}

// dashboardInstallPlanFor selects and normalizes one registry-grounded install
// hint for the dashboard. Exact OS beats OS-agnostic, and an exact-OS vendor
// script beats an exact package-manager fallback: a user-local installer should
// not lose to a generic npm -g (or Linux Homebrew) row merely because the
// registry lists it first.
func dashboardInstallPlanFor(hints []integration.InstallHint, goos, home string, lookArgv0 installArgv0Lookup) (dashboardInstallPlan, bool) {
	want := installOSForGOOS(goos)
	var chosen *integration.InstallHint
	for i := range hints {
		if hints[i].OS == want && (chosen == nil || dashboardInstallChannelRank(hints[i].Channel) < dashboardInstallChannelRank(chosen.Channel)) {
			chosen = &hints[i]
		}
	}
	if chosen == nil {
		for i := range hints {
			if hints[i].OS == "" {
				chosen = &hints[i]
				break
			}
		}
	}
	if chosen == nil || len(chosen.Argv) == 0 {
		return dashboardInstallPlan{}, false
	}

	argv := append([]string(nil), chosen.Argv...)
	if chosen.Channel != "npm" || goos == "windows" || !hasNPMGlobalFlag(argv) {
		plan := resolvePlanArgv0(dashboardInstallPlan{Argv: argv, Display: chosen.Display, Channel: chosen.Channel}, goos, lookArgv0)
		return withMissingPrereqs(plan, chosen.Requires, goos, lookArgv0), true
	}
	if strings.TrimSpace(home) == "" {
		// Do not fall back to a likely root-owned global prefix. An absent home is
		// an honest inability to construct the permission-safe guided plan.
		return dashboardInstallPlan{}, false
	}

	prefix := filepath.Join(home, ".local")
	localized := make([]string, 0, len(argv)+2)
	insertedPrefix := false
	for _, arg := range argv {
		switch arg {
		case "-g", "--global":
			if !insertedPrefix {
				localized = append(localized, "--global", "--prefix", prefix)
				insertedPrefix = true
			}
		default:
			localized = append(localized, arg)
		}
	}
	plan := resolvePlanArgv0(
		dashboardInstallPlan{Argv: localized, Display: displayInstallArgv(localized), Channel: chosen.Channel},
		goos, lookArgv0,
	)
	return withMissingPrereqs(plan, chosen.Requires, goos, lookArgv0), true
}

// withMissingPrereqs stamps the plan with the hint's grounded host
// prerequisites (integration.InstallHint.Requires) that resolve on neither the
// daemon's PATH nor the login shell's - the same merged lookup argv[0] uses,
// which is also what the vendor script's own `command -v` sees inside the
// `bash -lc` the plan runs. Skipped on Windows (resolvePlanArgv0's rule: the
// spawner resolves there, and no Windows hint declares prerequisites) and when
// no lookup is injected, so an unknown never blocks an install.
func withMissingPrereqs(plan dashboardInstallPlan, requires []string, goos string, look installArgv0Lookup) dashboardInstallPlan {
	if goos == "windows" || look == nil || len(requires) == 0 {
		return plan
	}
	plan.Missing = toolinstall.MissingPrereqs(requires, func(p string) bool {
		_, ok := look(p)
		return ok
	})
	return plan
}

// installPrereqRemedy is the sentence for a plan whose prerequisites are
// missing ("" when none are): the missing programs plus the exact
// package-manager command for THIS host, decided from /etc/os-release. Observer
// only names the fix; it never runs it (it would need sudo).
func installPrereqRemedy(missing []string) string {
	if len(missing) == 0 {
		return ""
	}
	return toolinstall.PrereqRemedy(missing, hostPackageManager())
}

// hostPackageManager reads the host family once per call (os-release is a
// tiny file and this runs only on a preflight / install request). The file
// list is os-release(5)'s own lookup order.
func hostPackageManager() toolinstall.PackageManager {
	var rel map[string]string
	if runtime.GOOS == "linux" {
		for _, p := range []string{"/etc/os-release", "/usr/lib/os-release"} {
			if b, err := os.ReadFile(p); err == nil {
				rel = toolinstall.ParseOSRelease(string(b))
				break
			}
		}
	}
	return toolinstall.PackageManagerFor(runtime.GOOS, rel)
}

// toolInstallBlockedSeam builds dashapi.Options.ToolInstallBlocked: the
// prerequisite remedy for the plan POST /api/terminal/install would run (or,
// when every prerequisite is present, the minimum-runtime remedy for a channel
// that runs the tool on a too-old host runtime), or "" when the install may
// proceed. It walks the SAME installHintsFor ladder and
// plan selection as toolInstallHintSeam, so the refusal always describes the
// command that would have run.
func toolInstallBlockedSeam() func(string) string {
	return func(tool string) string {
		installs, ok := installHintsFor(tool)
		if !ok {
			return ""
		}
		plan, ok := dashboardInstallPlanFor(installs, runtime.GOOS, dashboardInstallHome(), dashInstallArgv0)
		if !ok {
			return ""
		}
		if remedy := installPrereqRemedy(plan.Missing); remedy != "" {
			return remedy
		}
		// A package that would run on a too-old host runtime installs fine
		// and then crashes at startup: refuse before installing.
		if c, ok := installRuntimeFor(tool, plan); ok && c.Blocking() {
			return c.Remedy
		}
		return ""
	}
}

// preflightRuntime maps a runtime check onto the dashboard wire shape.
func preflightRuntime(c toolinstall.RuntimeCheck) *dashapi.PreflightRuntime {
	return &dashapi.PreflightRuntime{
		Runtime:    c.Runtime,
		Display:    c.Display,
		Product:    c.Product,
		Min:        c.Min,
		Have:       c.Have,
		Path:       c.Path,
		Status:     string(c.Status),
		Remedy:     c.Remedy,
		Summary:    c.Summary,
		FixCommand: c.FixCommand,
		FixNote:    c.FixNote,
		FloorFrom:  c.FloorFrom,
		Range:      c.Range,
	}
}

// resolvePlanArgv0 rewrites a plan's argv[0] to the absolute program the merged
// PATH resolves it to (DI-04a). Display is left alone - the operator should see
// `npm install …`, not a 60-character absolute path - so the human command
// and the executed program deliberately differ in spelling only.
//
// It is a no-op on Windows, where the spawner itself does the PATHEXT-aware
// resolution (termsession.resolveSpawnArgv) and a bare name is correct. When
// nothing resolves, the bare name is KEPT (exec.LookPath on the daemon PATH
// stays the fallback) and the plan carries an honest Note instead of failing:
// the command is still the right one to show, and installing its program may
// well be the operator's next step.
func resolvePlanArgv0(plan dashboardInstallPlan, goos string, look installArgv0Lookup) dashboardInstallPlan {
	if goos == "windows" || look == nil || len(plan.Argv) == 0 || plan.Argv[0] == "" {
		return plan
	}
	abs, ok := look(plan.Argv[0])
	if !ok {
		plan.NeedsProgram = plan.Argv[0]
		plan.Note = fmt.Sprintf(
			"the install command runs %q, which is on neither the daemon's PATH nor the login shell's - install it first, or the guided install will fail",
			plan.Argv[0])
		return plan
	}
	argv := append([]string(nil), plan.Argv...)
	argv[0] = abs
	plan.Argv = argv
	return plan
}

// dashboardInstallChannelRank ranks install CHANNELS for the guided dialog: a
// vendor script (user-local, no privileges) beats a package manager, and a
// package manager beats the npm fallback. scoop sits with brew/winget - the
// same SHAPE (an OS package manager the operator already trusts); the row lists
// exactly the closed Channel vocabulary (integration.InstallHint.Channel:
// npm|script|brew|winget|uv|scoop - choco was deliberately NOT adopted), so a
// newly grounded channel is added HERE when it is added there (CLAUDE.md #5).
func dashboardInstallChannelRank(channel string) int {
	switch channel {
	case "script":
		return 0
	case "brew", "winget", "scoop":
		return 1
	default:
		return 2
	}
}

func hasNPMGlobalFlag(argv []string) bool {
	for _, arg := range argv {
		if arg == "-g" || arg == "--global" {
			return true
		}
	}
	return false
}

func displayInstallArgv(argv []string) string {
	out := make([]string, len(argv))
	for i, arg := range argv {
		if arg != "" && !strings.ContainsAny(arg, " \t\r\n\"'\\") {
			out[i] = arg
			continue
		}
		out[i] = strconv.Quote(arg)
	}
	return strings.Join(out, " ")
}

// recentModelsSeam builds the dashapi.Options.RecentModels closure: it
// resolves a tool NAME to its recently-used models by calling
// store.Store.LoadRecentModelsForTool over the daemon's own database
// (mirroring toolPreflightSeam's role - a plain func so the dashboard
// package never needs a live *store.Store, just the returned data struct).
// A nil database (no store wiring, e.g. an early boot path) is handled by
// the caller passing a nil seam instead of calling this constructor -
// dashapi.Options.RecentModels being nil is itself the honest disabled
// state (see modelSuggestionsFor).
func recentModelsSeam(database *sql.DB) func(context.Context, string) ([]store.RecentToolModel, error) {
	st := store.New(database)
	return func(ctx context.Context, tool string) ([]store.RecentToolModel, error) {
		return st.LoadRecentModelsForTool(ctx, tool, dashapi.RecentModelsWindow, dashapi.RecentModelsLimit)
	}
}

// allowToolInstallSeam builds the dashapi.Options.AllowToolInstall closure: a
// LIVE read of [terminal.launch].allow_install (default true) so a config edit
// flips the guided-install kill-switch with no daemon restart. A config-load
// error fails SAFE (returns false → the endpoint 403s), matching the honest
// "disabled" posture the dashboard prefers over spawning an install on a
// half-broken config.
func allowToolInstallSeam(configPath string) func() bool {
	return func() bool {
		cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
		if err != nil {
			return false
		}
		return cfg.Terminal.Launch.AllowInstall
	}
}

// refreshWatchRootsSeam builds dashapi.Options.RefreshWatchRoots: a
// fire-and-forget kick that re-detects adapters and hot-adds newly-
// existing session directories into the live watcher. Retries on a short
// schedule because Muse/Prime (and peers) typically create their
// sessions/ tree a moment AFTER LaunchFresh returns - a single
// immediate Scan would still miss. Fail-open: errors are logged, never
// surfaced to the launch/install HTTP response. Nil w → nil seam.
func refreshWatchRootsSeam(w *watcher.Watcher) func() {
	if w == nil {
		return nil
	}
	return func() {
		go refreshWatchRootsWithRetry(w, slog.Default())
	}
}

// refreshWatchRootsRetryDelays is the post-launch/install retry schedule.
// Attempt 0 is immediate; later attempts cover the "sessions dir appears
// after first tool write" window without waiting for the ~30s poller.
var refreshWatchRootsRetryDelays = []time.Duration{0, 2 * time.Second, 8 * time.Second}

func refreshWatchRootsWithRetry(w *watcher.Watcher, log *slog.Logger) {
	if log == nil {
		log = slog.Default()
	}
	for i, d := range refreshWatchRootsRetryDelays {
		if d > 0 {
			time.Sleep(d)
		}
		res, err := w.RefreshRoots(context.Background())
		if err != nil {
			log.Warn("watcher refresh after terminal install/launch",
				"attempt", i+1, "err", err)
			continue
		}
		log.Info("watcher refresh after terminal install/launch",
			"attempt", i+1, "files_processed", res.FilesProcessed)
	}
}

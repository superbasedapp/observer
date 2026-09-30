// ide.go — `observer ide <id> [project-dir] [-- app-args...]`: launch an IDE or
// desktop app WRAPPED, the CLI sibling of the dashboard's GUI launch.
//
// What "wrapped" means for an IDE is registry data, not a per-product branch
// (CLAUDE.md #3): the row's WrapSpec decides what environment is injected, and
// integration.HostedRoutes decides, per agent the app hosts, whether its model
// traffic can actually reach the proxy. The launch itself goes through the SAME
// seam the dashboard uses (guiLauncher.composeLaunch -> guilaunch.Compose), so
// `observer ide vscode .` and the dashboard's "IDE / desktop app" launch compose
// an identical argv and wrap.
//
// Honesty rules carried from the dashboard path: a row with no base-URL surface
// still launches and says why nothing was wrapped; a child-env wrap is at most
// plumbing-verified until the row's WrapSpec.TrafficProof records a live turn,
// and the launch says "live proof owed" rather than claim metering.

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guilaunch"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// ideDeps are the side-effecting seams of an `observer ide` launch, injectable
// so the whole flow is testable with a fake exec and no daemon, DB or network.
type ideDeps struct {
	// spawn starts the detached app (spawnDetached in production).
	spawn func(argv []string, dir string, env []string) (*os.Process, error)
	// admit is the managed-budget launch admission
	// (enforceBudgetControlledLaunch in production).
	admit func(ctx context.Context, configPath, id string, ev budgetLaunchEvidence) error
	// refuseDisallowed is the org tools.disallow gate
	// (refuseIfToolDisallowedDB in production).
	refuseDisallowed func(dbPath, tool string, stderr io.Writer) error
	// reachable is the proxy pre-flight (proxyReachable in production).
	reachable func(proxyURL string, timeout time.Duration) bool
	// environ is the caller's environment (os.Environ in production).
	environ func() []string
}

func defaultIDEDeps() ideDeps {
	return ideDeps{
		spawn:            spawnDetached,
		admit:            enforceBudgetControlledLaunch,
		refuseDisallowed: refuseIfToolDisallowedDB,
		reachable:        proxyReachable,
		environ:          os.Environ,
	}
}

// ideOptions is one parsed `observer ide` invocation.
type ideOptions struct {
	configPath string
	proxyURL   string // --proxy override ("" = derive from [proxy].port)
	id         string // GUI launch id, or a tool key carrying a GUI row
	projectDir string // "" = bare launch
	extraArgs  []string
	dryRun     bool
	stdout     io.Writer
	stderr     io.Writer
}

func newIDECmd() *cobra.Command {
	var (
		configPath string
		proxyURL   string
		dryRun     bool
	)
	cmd := &cobra.Command{
		Use:   integration.GUILaunchVerb + " [id] [project-dir] [-- app-args...]",
		Short: "Launch an IDE or desktop app wrapped for the observer proxy",
		Long: "Launches an IDE / desktop app DETACHED with Observer's routing wrap\n" +
			"applied - the CLI form of the dashboard's \"IDE / desktop app\" launch.\n\n" +
			"With no id, lists every launch row, its wrap mechanism and whether it is\n" +
			"offered. With an id (e.g. vscode, jetbrains-idea, cursor-ide; an adapter\n" +
			"key such as `cursor` also resolves to its app), launches it and prints,\n" +
			"per agent the app hosts, whether that agent's model traffic can reach\n" +
			"the proxy:\n\n" +
			"  persisted_config  routed by the agent's own config (`observer init`)\n" +
			"  launch_env        inherits the base-URL variable this launch exports\n" +
			"  launcher_only     routable only through its own `observer <verb>`\n" +
			"  manual            paste the proxy URL into the extension's settings\n" +
			"  unproven          a BYOK / base-URL path is not live-proven\n" +
			"  not_routable      vendor-hosted inference, no base-URL knob\n\n" +
			"A child-env wrap only reaches a COLD start: an already-running instance\n" +
			"(e.g. `code` handing off to an open window) never re-reads its\n" +
			"environment. Arguments after `--` are forwarded to the app.\n\n" +
			"Examples:\n" +
			"    observer ide                      # list launch rows\n" +
			"    observer ide vscode .             # VS Code on this directory\n" +
			"    observer ide vscode . -- --new-window\n" +
			"    observer ide cursor --dry-run     # show the plan, launch nothing",
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			positional, extra := splitDashArgs(args, cmd.ArgsLenAtDash())
			if len(positional) == 0 {
				listIDERows(cmd.OutOrStdout())
				return nil
			}
			if len(positional) > 2 {
				return fmt.Errorf("observer ide: expected at most <id> [project-dir], got %d positional arguments (forward app arguments after `--`)", len(positional))
			}
			opts := ideOptions{
				configPath: configPath,
				proxyURL:   proxyURL,
				id:         positional[0],
				extraArgs:  extra,
				dryRun:     dryRun,
				stdout:     cmd.OutOrStdout(),
				stderr:     cmd.ErrOrStderr(),
			}
			if len(positional) == 2 {
				opts.projectDir = positional[1]
			}
			return runIDELaunch(cmd.Context(), opts, defaultIDEDeps())
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "observer config.toml path (default ~/.observer/config.toml)")
	cmd.Flags().StringVar(&proxyURL, "proxy", "", "observer proxy base URL (default http://127.0.0.1:<[proxy].port>)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print the composed launch and per-agent routing, launch nothing")
	return cmd
}

// splitDashArgs splits cobra's args at the `--` position (dashAt from
// ArgsLenAtDash; -1 when there was none).
func splitDashArgs(args []string, dashAt int) (positional, extra []string) {
	if dashAt < 0 || dashAt > len(args) {
		return args, nil
	}
	return args[:dashAt], args[dashAt:]
}

// runIDELaunch resolves, gates, composes and (unless dry-run) spawns one
// wrapped GUI launch.
func runIDELaunch(ctx context.Context, opts ideOptions, deps ideDeps) error {
	if ctx == nil {
		ctx = context.Background()
	}
	row, ok := integration.GUIRowForID(opts.id)
	if !ok {
		return fmt.Errorf("observer ide: unknown IDE / desktop app id %q - run `observer ide` to list them", opts.id)
	}
	if !row.Advertised() {
		reason := row.Spec.Note
		if reason == "" {
			reason = "lifecycle " + string(row.Lifecycle)
		}
		return fmt.Errorf("observer ide: %s (%s) is not offered for launch: %s", row.Spec.Label, row.Spec.ID, reason)
	}
	id := row.Spec.ID

	projectDir, err := resolveIDEProjectDir(opts.projectDir)
	if err != nil {
		return err
	}

	cfg, cfgErr := config.Load(config.LoadOptions{GlobalPath: opts.configPath})
	port, dbPath := 0, ""
	if cfgErr == nil {
		port, dbPath = cfg.Proxy.Port, cfg.Observer.DBPath
	}
	proxyURL := resolveProxyURL(port, opts.proxyURL)

	if !opts.dryRun {
		// The org disallow list names registry tools; a pure editor host has no
		// adapter of its own and hosts many, so only an adapter-carried row is
		// gated on its adapter (a shape test: Adapter != "").
		if row.Adapter != "" {
			if err := deps.refuseDisallowed(dbPath, row.Adapter, opts.stderr); err != nil {
				return err
			}
		}
		if err := deps.admit(ctx, opts.configPath, id, guiBudgetEvidence(id)); err != nil {
			return err
		}
	}

	g := &guiLauncher{
		proxyPort:  port,
		configPath: func() string { return opts.configPath },
		resolveEnv: resolveEnv,
	}
	composed, err := g.composeLaunch(id, row.Spec, projectDir, proxyURL, opts.extraArgs)
	if err != nil {
		if errors.Is(err, guilaunch.ErrNoLaunchMechanism) {
			return fmt.Errorf("observer ide: %s is not installed where this machine can launch it (set [launch.tools.%s].path, or install it from the dashboard): %w",
				row.Spec.Label, id, err)
		}
		return fmt.Errorf("observer ide: %w", err)
	}
	env, applied, presets := ideChildEnv(deps.environ(), composed.plan.Env)

	out := opts.stderr
	fmt.Fprintf(out, "observer ide: %s %s\n", map[bool]string{true: "would launch", false: "launching"}[opts.dryRun], row.Spec.Label)
	fmt.Fprintf(out, "  argv: %s\n", strings.Join(composed.plan.Argv, " "))
	for _, n := range append(composed.notes, composed.plan.Notes...) {
		fmt.Fprintf(out, "  note: %s\n", n)
	}
	reachable := deps.reachable(proxyURL, 250*time.Millisecond)
	renderIDEWrap(out, ideWrapView{
		spec:      row.Spec,
		plan:      composed.plan,
		proxyURL:  proxyURL,
		applied:   applied,
		presets:   presets,
		reachable: reachable,
	})
	renderHostedRoutes(out, integration.HostedRoutes(row), composed.plan.WrapApplied)

	if opts.dryRun {
		return nil
	}
	proc, err := deps.spawn(composed.plan.Argv, composed.dir, env)
	if err != nil {
		return fmt.Errorf("observer ide: %w", err)
	}
	fmt.Fprintf(out, "observer ide: started %s (pid %d, detached)\n", row.Spec.Label, proc.Pid)
	// The CLI does not wait: the app outlives this process (setsid / a
	// detached Windows process), exactly like the vendor's own launcher.
	_ = proc.Release()
	return nil
}

// resolveIDEProjectDir validates an optional project directory and makes it
// absolute (an IDE resolves a relative path against ITS cwd, which a detached
// spawn does not share with the operator's shell).
func resolveIDEProjectDir(dir string) (string, error) {
	if strings.TrimSpace(dir) == "" {
		return "", nil
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("observer ide: project dir %q: %w", dir, err)
	}
	fi, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("observer ide: project dir %q: %w", dir, err)
	}
	if !fi.IsDir() {
		return "", fmt.Errorf("observer ide: project dir %q is not a directory", dir)
	}
	return abs, nil
}

// ideChildEnv composes the launched app's environment: the caller's own minus
// the daemon-internal child variables, plus the wrap's base-URL variables
// applied with the launcher family's rule that an operator-exported value wins
// (applyBaseURLEnv). Returns the env, the keys actually injected and the keys
// kept from the operator.
func ideChildEnv(parent, wrap []string) (env, applied, presets []string) {
	base := make([]string, 0, len(parent))
	for _, kv := range parent {
		if !isInternalChildEnv(kv) {
			base = append(base, kv)
		}
	}
	inject := make(map[string]string, len(wrap))
	for _, kv := range wrap {
		if i := strings.IndexByte(kv, '='); i > 0 {
			inject[kv[:i]] = kv[i+1:]
		}
	}
	env, applied, presets = applyBaseURLEnv(base, inject)
	env = scrubOOBEnv(env)
	if runtime.GOOS == "windows" {
		env = dedupEnvWindows(env)
	}
	return env, applied, presets
}

// ideWrapView is what renderIDEWrap needs; pure data so the render is
// table-testable.
type ideWrapView struct {
	spec      integration.GUILaunchSpec
	plan      guilaunch.Plan
	proxyURL  string
	applied   []string
	presets   []string
	reachable bool
}

// renderIDEWrap prints the wrap verdict: what was injected (or why nothing
// was), the proxy pre-flight, and the live-proof status.
func renderIDEWrap(w io.Writer, v ideWrapView) {
	if !v.plan.WrapApplied {
		note := v.plan.WrapNote
		if note == "" {
			note = "this app has no grounded base-URL mechanism"
		}
		fmt.Fprintf(w, "  wrap: none - %s\n", note)
		return
	}
	for _, k := range v.presets {
		fmt.Fprintf(w, "  wrap: %s already set in env; using yours\n", k)
	}
	if len(v.applied) > 0 {
		fmt.Fprintf(w, "  wrap: routing via %s (set %s)\n", v.proxyURL, strings.Join(v.applied, ", "))
	}
	if v.plan.WrapNote != "" {
		fmt.Fprintf(w, "  wrap caveat: %s\n", v.plan.WrapNote)
	}
	if !v.reachable {
		fmt.Fprintf(w, "  warning: proxy not reachable at %s - in-app turns are NOT captured through it (%s)\n",
			v.proxyURL, proxyDownAdvice(runningAsDaemonChild()))
	}
	if v.spec.Wrap.TrafficProof == "" {
		fmt.Fprintln(w, "  live proof owed: no in-app agent turn through this wrap has been verified yet -"+
			" send one message, then check `observer status` for a new api_turns row")
	} else {
		fmt.Fprintf(w, "  live proof: %s\n", v.spec.Wrap.TrafficProof)
	}
}

// hostedRouteText is the per-outcome copy (table-driven; one row per
// classified integration.HostedRoute value, pinned by
// TestHostedRouteTextCoversEveryOutcome).
var hostedRouteText = map[integration.HostedRoute]func(r integration.HostedRouteRow, wrapApplied bool) string{
	integration.HostedRoutePersisted: func(r integration.HostedRouteRow, _ bool) string {
		return "routed by its own config file once `observer init` has written the route (independent of this launch)"
	},
	integration.HostedRouteLaunchEnv: func(r integration.HostedRouteRow, wrapApplied bool) string {
		if !wrapApplied {
			return "would inherit this launch's base URL, but the wrap was not applied (see wrap above); use `" + r.Launcher + "`"
		}
		return "inherits this launch's base URL when the app spawns it (cold start; live proof owed)"
	},
	integration.HostedRouteLauncherOnly: func(r integration.HostedRouteRow, _ bool) string {
		if r.Launcher == "" {
			return "routable only through its own launcher, not through this app"
		}
		return "routable only through `" + r.Launcher + "`, not through this app"
	},
	integration.HostedRouteManual: func(integration.HostedRouteRow, bool) string {
		return "manual - a base-URL setting exists but Observer has no writer; paste the proxy URL into its provider settings (docs/proxy-routing.md)"
	},
	integration.HostedRouteUnproven: func(r integration.HostedRouteRow, _ bool) string {
		return "not proven - a BYOK / base-URL path is not live-verified (" + string(r.Routability) + ")"
	},
	integration.HostedRouteNotRoutable: func(integration.HostedRouteRow, bool) string {
		return "not routable - vendor-hosted inference, no base-URL knob"
	},
}

// renderHostedRoutes prints one line per hosted agent.
func renderHostedRoutes(w io.Writer, rows []integration.HostedRouteRow, wrapApplied bool) {
	if len(rows) == 0 {
		return
	}
	fmt.Fprintln(w, "  per hosted agent:")
	for _, r := range rows {
		text := "unclassified - no routability recorded"
		if f, ok := hostedRouteText[r.Outcome]; ok {
			text = f(r, wrapApplied)
		}
		fmt.Fprintf(w, "    %-16s %s\n", r.Tool, text)
	}
}

// listIDERows prints every GUI launch row: id, wrap mechanism, whether it is
// offered, and the label.
func listIDERows(w io.Writer) {
	rows := integration.GUILaunchables()
	sort.Slice(rows, func(i, j int) bool { return rows[i].Spec.ID < rows[j].Spec.ID })
	fmt.Fprintf(w, "%-26s %-13s %-9s %s\n", "ID", "WRAP", "OFFERED", "APP")
	for _, g := range rows {
		wrap := string(g.Spec.Wrap.Kind)
		if wrap == "" {
			wrap = "none"
		}
		offered := "yes"
		if !g.Advertised() {
			offered = "no"
		}
		fmt.Fprintf(w, "%-26s %-13s %-9s %s\n", g.Spec.ID, wrap, offered, g.Spec.Label)
	}
	fmt.Fprintln(w, "\nlaunch one with: observer ide <id> [project-dir] [-- app-args...]")
}

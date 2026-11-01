// service.go — `observer service` command group: a systemd unit on Linux, a
// per-user launchd LaunchAgent on macOS (service_launchd.go).

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/service"
	"github.com/marmutapp/superbased-observer/internal/toolresolve"
)

// errNoSystemd is returned when the host has neither systemd nor launchd
// (macOS is handled by service_launchd.go). The command surfaces it as a
// clear, actionable message.
var errNoSystemd = errors.New(
	"no supported service manager on this host (no systemd at /run/systemd/system, no launchd).\n" +
		"  `observer service` supports Linux systemd and macOS launchd.\n" +
		"  - On Windows, start at sign-in is `observer setup autostart on` (the Windows installer\n" +
		"    from superbased.app/download sets it up), or install the service inside WSL.\n" +
		"  - Otherwise run `observer start` in a tmux/screen session.",
)

// unitPathEnv joins the merged PATH dirs (toolresolve.MergedPathDirs —
// process PATH followed by the login-shell-only entries) into the value
// for the unit's Environment=PATH= line, colon-joined because the
// systemd unit is always Linux (never os.PathListSeparator, which would
// render ";" on a Windows build of this binary). It returns "" when there
// is nothing to join, so the caller can fall back to
// service.DefaultPath rather than write an empty/malformed Environment=
// line — the same "pass through or fall back" shape as
// UnitOptions.Path itself.
func unitPathEnv(dirs []string) string {
	if len(dirs) == 0 {
		return ""
	}
	return strings.Join(dirs, ":")
}

// lingerRunner executes `loginctl show-user <user> -p Linger --value` and
// returns its raw stdout. A package var so tests can fake loginctl's
// answer without a live systemd --user manager (or on a non-Linux dev
// box where loginctl does not exist at all).
var lingerRunner = func(username string) (string, error) {
	out, err := exec.Command("loginctl", "show-user", username, "-p", "Linger", "--value").Output() //nolint:gosec // fixed program name; username comes from os/user.Current, not request input
	return string(out), err
}

// lingerAdvice decides the note to print (or "" for none) given the raw
// result of a `loginctl show-user <user> -p Linger --value` lookup. It
// never execs anything itself — lingerNoticeFor below is the only caller
// that talks to loginctl — so the decision is a pure, table-testable
// function with three outcomes: Linger=yes prints nothing, Linger=no (or
// anything else loginctl might print) prints the actionable
// `loginctl enable-linger` note, and a lookup error (no loginctl, no
// systemd --user manager, permission denied) prints a softer warning
// that names the same command as a fallback rather than asserting the
// unit needs it — the install already detected no systemd --user
// manager and refused (runServiceInstall's systemdAvailable gate), so a
// lookup error here means loginctl itself is missing or misbehaving, not
// that linger is confirmed off.
func lingerAdvice(username, out string, err error) string {
	if err != nil {
		return fmt.Sprintf(
			"Warning: could not check linger status for %s (%v) - if `systemctl --user start\n"+
				"observer.service` stops working after you log out, run: loginctl enable-linger %s\n",
			username, err, username)
	}
	if strings.TrimSpace(out) == "yes" {
		return ""
	}
	return fmt.Sprintf(
		"Note: linger is not enabled for %s - a --user unit only starts at login and stops\n"+
			"at logout without it, and `systemctl --user` needs the user bus that linger keeps\n"+
			"alive across logout. Run:\n    loginctl enable-linger %s\n",
		username, username)
}

// lingerNoticeFor is the impure wrapper: run lingerRunner, hand the
// result to lingerAdvice. Never runs loginctl enable-linger itself — the
// operator runs the printed command.
func lingerNoticeFor(username string) string {
	out, err := lingerRunner(username)
	return lingerAdvice(username, out, err)
}

// newServiceCmd implements `observer service` — install and manage the
// observer daemon as a long-running systemd service instead of
// babysitting `observer start` under tmux.
func newServiceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "service",
		Short: "Install and manage observer as a long-running service (systemd on Linux, launchd on macOS)",
		Long: "Supervises `observer start` (proxy + watcher + dashboard) as a\n" +
			"systemd unit, so the daemon survives crashes and reboots without\n" +
			"a tmux/screen babysitter. On macOS the same commands manage a per-user\n" +
			"launchd LaunchAgent (~/Library/LaunchAgents/app.superbased.observer.plist)\n" +
			"that starts at login; its log is ~/Library/Logs/SuperBased/observer.log.\n\n" +
			"Default scope is --user (per-login, no root). Use --system on a\n" +
			"headless box (e.g. a worker node running as root) so the daemon\n" +
			"survives logout. Subcommands:\n" +
			"    observer service install [--now]   write the unit + reload\n" +
			"    observer service upgrade           point the unit at this binary after an upgrade\n" +
			"    observer service start|stop|status|restart\n" +
			"    observer service logs [-f]         journalctl for the unit\n" +
			"    observer service uninstall         stop + disable + remove\n\n" +
			"Note: `observer start` IS the proxy on :8820. Restarting the\n" +
			"service while a live session routes through the proxy will drop\n" +
			"that session - turn the route off first (see\n" +
			"docs/daemon-restart-runbook.md).",
	}
	cmd.AddCommand(
		newServiceInstallCmd(),
		newServiceUpgradeCmd(),
		newServiceLifecycleCmd("start", "Start the observer service"),
		newServiceLifecycleCmd("stop", "Stop the observer service"),
		newServiceRestartCmd(),
		newServiceLifecycleCmd("status", "Show the observer service status"),
		newServiceLogsCmd(),
		newServiceUninstallCmd(),
	)
	return cmd
}

// resolveScope maps the --system flag to a service.Scope (default user).
func resolveScope(system bool) service.Scope {
	if system {
		return service.ScopeSystem
	}
	return service.ScopeUser
}

// systemdAvailable reports whether a systemd manager is present. A package
// var so tests can stand in for a systemd host.
var systemdAvailable = func() bool {
	_, err := os.Stat("/run/systemd/system")
	return err == nil
}

// runSystemctl/journalctl exec a resolved service.Command with the
// terminal's stdio attached (status/logs are interactive).
func runServiceCommand(c service.Command) error {
	ec := exec.Command(c.Name, c.Args...) //nolint:gosec // fixed program names, args from the pure builder
	ec.Stdin = os.Stdin
	ec.Stdout = os.Stdout
	ec.Stderr = os.Stderr
	return ec.Run()
}

func newServiceInstallCmd() *cobra.Command {
	var (
		system     bool
		now        bool
		configPath string
		recipe     string
		port       int
		whenIdle   bool
		endRuns    bool
	)
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Write the systemd unit for `observer start` and reload systemd",
		Long: "Renders observer.service, writes it (~/.config/systemd/user/ for\n" +
			"--user, /etc/systemd/system/ for --system), and runs\n" +
			"daemon-reload. The --config/--recipe/--port you pass here are\n" +
			"baked into the unit's ExecStart so the service uses the same\n" +
			"configuration. Pass --now to enable + start immediately. On a\n" +
			"unit that is already running an older process (an upgraded binary,\n" +
			"new arguments), --now restarts it (systemctl try-restart) only when\n" +
			"nothing routes through the proxy; otherwise it prints the safe order\n" +
			"and leaves the running daemon alone (docs/daemon-restart-runbook.md).",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runServiceInstall(serviceInstallOptions{
				scope:      resolveScope(system),
				now:        now,
				configPath: configPath,
				recipe:     recipe,
				port:       port,
				stdout:     cmd.OutOrStdout(),
				liveRuns:   serviceLiveRunChoice(whenIdle, endRuns),
			})
		},
	}
	cmd.Flags().BoolVar(&system, "system", false, "Install a system unit (/etc/systemd/system, requires root) instead of a --user unit")
	cmd.Flags().BoolVar(&now, "now", false, "Enable + start the service immediately after installing (a running service is restarted only when nothing routes through the proxy)")
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml to bake into the unit (defaults to the daemon's own lookup)")
	cmd.Flags().StringVar(&recipe, "recipe", "", "Compression recipe to bake into the unit")
	cmd.Flags().IntVar(&port, "port", 0, "Proxy port to bake into the unit (0 = config default)")
	cmd.Flags().BoolVar(&whenIdle, "when-idle", false, "With --now: wait for live sandboxed runs to finish before restarting a running service")
	cmd.Flags().BoolVar(&endRuns, "end-sandboxed-runs", false, "With --now: end live sandboxed runs before restarting a running service")
	return cmd
}

type serviceInstallOptions struct {
	scope      service.Scope
	now        bool
	configPath string
	recipe     string
	port       int
	// upgrade is `observer service upgrade`: the unit must exist, its
	// ExecStart arguments are kept (only the executable becomes this
	// binary), and a stopped unit is left stopped.
	upgrade bool
	stdout  io.Writer
	// liveRuns is the answer to the live sandboxed run question a restart
	// of a running service asks (install --now, upgrade).
	liveRuns cliLiveRunChoice
	// deps are the injected I/O (zero value = production).
	deps serviceInstallDeps
}

// serviceInstallDeps are runServiceInstall's I/O seams, so tests can run it
// without systemd, a login shell or loginctl.
type serviceInstallDeps struct {
	// exe is the binary the unit names ("" = this process's own binary).
	exe string
	// pathDirs returns the unit's PATH dirs (nil = the merged login PATH).
	pathDirs func() []string
	// linger returns the linger note for the user scope (nil = loginctl).
	linger func() string
	// liveRuns asks the running daemon about its live sandboxed runs (zero
	// value = the loopback client for the config).
	liveRuns *daemonLiveRunsClient
	// probe is the systemctl / process / route I/O (nil = production).
	probe *serviceProbe
}

func runServiceInstall(opts serviceInstallOptions) error {
	if launchdAvailable() {
		return runLaunchdInstall(opts, launchdDeps{exe: opts.deps.exe, pathDirs: opts.deps.pathDirs})
	}
	if !systemdAvailable() {
		return errNoSystemd
	}
	if opts.scope == service.ScopeSystem && os.Geteuid() != 0 {
		verb := "installs to"
		if opts.upgrade {
			verb = "rewrites"
		}
		return fmt.Errorf("--system %s /etc/systemd/system and requires root; re-run with sudo, or drop --system for a per-user unit", verb)
	}
	probe := defaultServiceProbe()
	if opts.deps.probe != nil {
		probe = *opts.deps.probe
	}

	exe := opts.deps.exe
	if exe == "" {
		resolved, err := absoluteBinaryPath()
		if err != nil {
			return fmt.Errorf("resolve observer binary: %w", err)
		}
		exe = resolved
	}

	home, err := os.UserHomeDir()
	if err != nil && opts.scope == service.ScopeUser {
		return fmt.Errorf("resolve home dir: %w", err)
	}
	unitPath := service.UnitPath(opts.scope, home)
	oldExecStart := ""
	if old, rerr := os.ReadFile(unitPath); rerr == nil { //nolint:gosec // the unit path is fixed by scope
		oldExecStart = service.ExecStartLine(string(old))
	} else if opts.upgrade {
		return fmt.Errorf("%s", serviceUpgradeNoUnitMessage(service.UnitName, unitPath, scopeFlagSuffix(opts.scope)))
	}

	args, err := serviceUnitArgs(&opts, unitPath, oldExecStart, exe)
	if err != nil {
		return err
	}

	// The unit's PATH is the daemon's own merged (process + login-shell)
	// PATH, not systemd's bare manager default — a fresh systemd unit
	// otherwise reproduces the DI-04/DI-23 class of bug where every
	// npm-shim AI-tool exits 127 because ~/.local/bin and the npm global
	// prefix were never on it. resolveEnv() is the same memoized
	// toolresolve.Env every launcher in this process uses (launch.go);
	// reusing it here means `install` pays the up-to-~6s login-shell
	// capture at most once even if a future caller resolves a tool first.
	var pathDirs []string
	if opts.deps.pathDirs != nil {
		pathDirs = opts.deps.pathDirs()
	} else {
		pathDirs, _ = toolresolve.MergedPathDirs(resolveEnv())
	}
	pathEnv := unitPathEnv(pathDirs)
	if pathEnv == "" {
		fmt.Fprintf(opts.stdout, "unit PATH = %s (fallback: could not resolve the operator's PATH)\n", service.DefaultPath)
	} else {
		fmt.Fprintf(opts.stdout, "unit PATH = %s\n", pathEnv)
	}

	snap := componentSnapshotFor(opts.configPath)
	unit := service.RenderUnit(service.UnitOptions{ExecPath: exe, Args: args, Scope: opts.scope, Path: pathEnv, Runs: serviceRuns(snap.Active)})

	if mkErr := os.MkdirAll(filepath.Dir(unitPath), 0o755); mkErr != nil {
		return fmt.Errorf("create unit dir: %w", mkErr)
	}
	if wErr := os.WriteFile(unitPath, []byte(unit), 0o644); wErr != nil { //nolint:gosec // unit files are world-readable by design
		return fmt.Errorf("write unit %s: %w", unitPath, wErr)
	}
	fmt.Fprintf(opts.stdout, "Wrote %s\n", unitPath)

	// A --user unit's bus (/run/user/<uid>/bus) and its systemd --user
	// manager only start automatically at login when linger is enabled;
	// without it, `systemctl --user` below can already be running on
	// borrowed time (this interactive session's own bus), and the
	// Windows-companion schtasks logon trigger in the redeploy recipe
	// (docs/handovers/devbox-daemon-redeploy-recipe-2026-09-02.md) will
	// fail outright. Detected, never run — the operator runs the printed
	// command themselves.
	if opts.scope == service.ScopeUser {
		note := ""
		if opts.deps.linger != nil {
			note = opts.deps.linger()
		} else if u, uerr := user.Current(); uerr == nil {
			note = lingerNoticeFor(u.Username)
		}
		if note != "" {
			fmt.Fprint(opts.stdout, "\n"+note)
		}
	}

	if rErr := probe.run(service.Systemctl(opts.scope, "daemon-reload")); rErr != nil {
		return fmt.Errorf("systemctl daemon-reload: %w", rErr)
	}

	refresh := serviceRefresh{
		scope: opts.scope, exe: exe, oldExecStart: oldExecStart, newExecStart: service.ExecStartLine(unit),
		startIfInactive: opts.now && !opts.upgrade, port: serviceProxyPort(opts.configPath, opts.port), w: opts.stdout,
	}
	if opts.now || opts.upgrade {
		// A restart of a running daemon ends its live sandboxed runs: ask
		// first (install --now refuses naming them; upgrade leaves the old
		// process running and says why, like a live proxy route).
		if lerr := serviceInstallLiveRunCheck(opts, refresh, probe); lerr != nil {
			return lerr
		}
		if err := applyServiceRefresh(refresh, probe); err != nil {
			return err
		}
	} else {
		reportInstalledNotStarted(refresh, probe)
	}
	fmt.Fprintln(opts.stdout, serviceRestartNote(snap.Active("capture.proxy")))
	return nil
}

// serviceInstallLiveRunCheck runs the live-run gate before install --now or
// upgrade may restart a running service. The unit file is already written,
// so a refusal leaves the old process running on the new unit until the
// owner answers.
func serviceInstallLiveRunCheck(opts serviceInstallOptions, r serviceRefresh, p serviceProbe) error {
	if !serviceRefreshMayRestart(r, p) {
		return nil
	}
	c := opts.deps.liveRuns
	if c == nil {
		lc := newDaemonLiveRunsClient(opts.configPath)
		c = &lc
	}
	err := cliLiveRunCheck(context.Background(), opts.stdout, liveRunTriggerServiceInstall, *c, opts.liveRuns)
	if err == nil || (!errors.Is(err, errLiveSandboxedRuns) && !errors.Is(err, errLiveRunsUnknown)) {
		return err
	}
	if opts.upgrade {
		fmt.Fprintf(opts.stdout, "The unit was rewritten; the running service keeps its current process because %v.\n"+
			"Run `observer service install --now%s` with --when-idle or --end-sandboxed-runs to restart it.\n", err, scopeFlagSuffix(r.scope))
		return nil
	}
	return err
}

// serviceRefreshMayRestart reports whether applyServiceRefresh could
// restart the running unit (the same inputs it decides on): a running
// process whose executable or ExecStart changed, or is unknown. A stopped
// unit, or one already running this binary with the same arguments, is not
// restarted, so it ends nothing and asks nothing.
func serviceRefreshMayRestart(r serviceRefresh, p serviceProbe) bool {
	active, pid, err := p.show(r.scope)
	if err != nil || !active {
		return false
	}
	link, lerr := p.readExe(pid)
	if pid <= 0 || lerr != nil {
		return true
	}
	return runningExeDiffers(link, r.exe) || (r.oldExecStart != "" && r.oldExecStart != r.newExecStart)
}

// reportInstalledNotStarted is `install` without --now: it starts nothing and
// restarts nothing, but no longer says "not started" about a running unit
// (T-753).
func reportInstalledNotStarted(r serviceRefresh, p serviceProbe) {
	suffix := scopeFlagSuffix(r.scope)
	active, pid, err := p.show(r.scope)
	if err != nil || !active {
		fmt.Fprintf(r.w, "Installed (not started). Start it with:\n    observer service start%s\n", suffix)
		return
	}
	link, lerr := p.readExe(pid)
	if lerr == nil && !runningExeDiffers(link, r.exe) && (r.oldExecStart == "" || r.oldExecStart == r.newExecStart) {
		fmt.Fprintf(r.w, "Installed. The service is already running this binary (pid %d).\n", pid)
		return
	}
	fmt.Fprintf(r.w, "Installed. The service is running (pid %d) and keeps its current process until restarted:\n"+
		"    observer service install --now%s\n"+
		"restarts it now if no proxy route or proxied session is live, and otherwise says what to run.\n", pid, suffix)
}

// serviceUnitArgs returns the `observer start` arguments the unit runs. An
// upgrade keeps what `observer service install` baked in (only the
// executable moves to exe) and fills opts.configPath / opts.port from them;
// an install builds them from its flags.
func serviceUnitArgs(opts *serviceInstallOptions, unitPath, oldExecStart, exe string) ([]string, error) {
	if opts.upgrade {
		oldExe, kept, ok := service.SplitExecStart(oldExecStart)
		if !ok {
			return nil, fmt.Errorf("%s runs %q, not `<observer> start ...`; rewrite it with: observer service install --now%s", unitPath, oldExecStart, scopeFlagSuffix(opts.scope))
		}
		opts.configPath, opts.port = serviceArgValue(kept, "--config"), atoiOrZero(serviceArgValue(kept, "--port"))
		if filepath.Clean(oldExe) != filepath.Clean(exe) {
			fmt.Fprintf(opts.stdout, "The unit ran %s; it now runs %s.\n", oldExe, exe)
		}
		return kept, nil
	}
	var args []string
	if opts.configPath != "" {
		abs, aerr := filepath.Abs(opts.configPath)
		if aerr != nil {
			abs = opts.configPath
		}
		args = append(args, "--config", abs)
	}
	if opts.recipe != "" {
		args = append(args, "--recipe", opts.recipe)
	}
	if opts.port > 0 {
		args = append(args, "--port", strconv.Itoa(opts.port))
	}
	return args, nil
}

// serviceArgValue returns the value after flag in a unit's ExecStart
// arguments ("" when absent).
func serviceArgValue(args []string, flag string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag {
			return args[i+1]
		}
	}
	return ""
}

func atoiOrZero(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

// serviceProxyPort is the proxy port the unit's daemon listens on: the
// baked --port, else the config's [proxy] port, else 8820.
func serviceProxyPort(configPath string, port int) int {
	if port > 0 {
		return port
	}
	if cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath}); err == nil && cfg.Proxy.Port > 0 {
		return cfg.Proxy.Port
	}
	return 8820
}

// newServiceUpgradeCmd implements `observer service upgrade` (T-753): after
// an in-place upgrade (install.sh, npm, a copied binary) the unit is
// rewritten for this binary with its arguments kept, and a running service is
// restarted only when nothing routes through the proxy; otherwise the safe
// order is printed and the old process keeps running.
func newServiceUpgradeCmd() *cobra.Command {
	var system bool
	cmd := &cobra.Command{
		Use:   "upgrade",
		Short: "Point the installed unit at this binary and restart it if nothing routes through the proxy",
		Long: "After an upgrade replaced the observer binary, the running service keeps\n" +
			"the previous process. `upgrade` rewrites observer.service for THIS binary,\n" +
			"keeping the --config/--recipe/--port it was installed with, refreshes its\n" +
			"Description, runs daemon-reload, and then:\n" +
			"  - restarts the service (systemctl try-restart) when the daemon has no\n" +
			"    proxy listener, or no proxy route is active and no connection to the\n" +
			"    proxy is open;\n" +
			"  - otherwise leaves it running and prints the safe order: the daemon IS\n" +
			"    the proxy, so restart it when no AI session uses the proxy, with the\n" +
			"    route off first (docs/daemon-restart-runbook.md).\n" +
			"A stopped service is left stopped. install.sh runs this on an upgrade.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runServiceInstall(serviceInstallOptions{
				scope:   resolveScope(system),
				upgrade: true,
				stdout:  cmd.OutOrStdout(),
			})
		},
	}
	cmd.Flags().BoolVar(&system, "system", false, "Upgrade the system unit (/etc/systemd/system, requires root) instead of the --user unit")
	return cmd
}

// serviceRunParts is the unit Description's table (T-744): each part `observer
// start` runs and the component that must be active for it; "" is always on.
var serviceRunParts = []struct{ part, component string }{
	{"proxy", "capture.proxy"},
	{"watcher", ""},
	{"dashboard", "ui.dashboard"},
}

// serviceRuns lists what `observer start` runs on this node for the unit's
// Description, from the active components: a minimal build or a node with
// capture.proxy turned off is no longer described as a proxy.
func serviceRuns(active func(string) bool) []string {
	out := []string{}
	for _, p := range serviceRunParts {
		if p.component == "" || active(p.component) {
			out = append(out, p.part)
		}
	}
	return out
}

// serviceRestartNote is the closing note of `observer service install`. On a
// node whose proxy is not active (a minimal build, or capture.proxy turned
// off) the service runs no proxy, so the "the service IS the proxy" warning
// was untrue there (T-732).
func serviceRestartNote(proxyActive bool) string {
	if !proxyActive {
		return "\nNote: the API proxy (capture.proxy) is not active on this machine, so the service\n" +
			"runs the watcher and dashboard only and restarting it interrupts no AI tool session."
	}
	return "\nNote: the service IS the proxy on :8820. Before `observer service restart`\n" +
		"while a session routes through the proxy, turn the route off first\n" +
		"(see docs/daemon-restart-runbook.md)."
}

// newServiceLifecycleCmd builds the thin start/stop/restart/status
// wrappers that just exec `systemctl [--user] <verb> observer.service`.
func newServiceLifecycleCmd(verb, short string) *cobra.Command {
	var system bool
	cmd := &cobra.Command{
		Use:   verb,
		Short: short,
		RunE: func(_ *cobra.Command, _ []string) error {
			if launchdAvailable() {
				return runLaunchdLifecycle(verb, system, launchdDeps{})
			}
			if !systemdAvailable() {
				return errNoSystemd
			}
			scope := resolveScope(system)
			return runServiceCommand(service.Systemctl(scope, verb, service.UnitName))
		},
	}
	cmd.Flags().BoolVar(&system, "system", false, "Target the system unit instead of the --user unit")
	return cmd
}

// newServiceRestartCmd is `observer service restart`: before systemctl
// restarts the unit it asks the running daemon over loopback for its live
// sandboxed runs and refuses naming them, unless --when-idle (wait, then
// restart) or --end-sandboxed-runs (end them through the daemon, then
// restart). A daemon that does not answer restarts as before, with a
// warning (sandbox plan v2 section 5.5, SBX-UPD-1).
func newServiceRestartCmd() *cobra.Command {
	var (
		system, whenIdle, endRuns bool
		configPath                string
	)
	cmd := &cobra.Command{
		Use:   "restart",
		Short: "Restart the observer service (drops active proxy sessions; asks first when sandboxed runs are live)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !systemdAvailable() {
				return errNoSystemd
			}
			if whenIdle && endRuns {
				return fmt.Errorf("--when-idle and --end-sandboxed-runs are two different answers; pass one")
			}
			if err := cliLiveRunCheck(cmd.Context(), cmd.OutOrStdout(), liveRunTriggerServiceRestart,
				newDaemonLiveRunsClient(configPath), serviceLiveRunChoice(whenIdle, endRuns)); err != nil {
				return err
			}
			return serviceSystemctl(service.Systemctl(resolveScope(system), "restart", service.UnitName))
		},
	}
	cmd.Flags().BoolVar(&system, "system", false, "Target the system unit instead of the --user unit")
	cmd.Flags().BoolVar(&whenIdle, "when-idle", false, "Wait for the live sandboxed runs to finish, then restart")
	cmd.Flags().BoolVar(&endRuns, "end-sandboxed-runs", false, "End the live sandboxed runs (a tool with its own resume continues afterwards), then restart")
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml naming the daemon's dashboard address (defaults to the daemon's own lookup)")
	return cmd
}

// serviceLiveRunChoice is the service verbs' answer to the live-run
// question.
func serviceLiveRunChoice(whenIdle, endRuns bool) cliLiveRunChoice {
	return cliLiveRunChoice{whenIdle: whenIdle, endRuns: endRuns, flagHint: "--when-idle (restart when they finish) or --end-sandboxed-runs (end them now)"}
}

// serviceSystemctl runs a systemctl command (a seam for tests).
var serviceSystemctl = runServiceCommand

func newServiceLogsCmd() *cobra.Command {
	var (
		system bool
		follow bool
		lines  int
	)
	cmd := &cobra.Command{
		Use:   "logs",
		Short: "Show the observer service logs (journalctl; the agent log file on macOS)",
		RunE: func(_ *cobra.Command, _ []string) error {
			if launchdAvailable() {
				return runLaunchdLogs(system, follow, lines, launchdDeps{})
			}
			if !systemdAvailable() {
				return errNoSystemd
			}
			scope := resolveScope(system)
			return runServiceCommand(service.Journalctl(scope, follow, lines))
		},
	}
	cmd.Flags().BoolVar(&system, "system", false, "Target the system unit instead of the --user unit")
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "Follow the log (live tail)")
	cmd.Flags().IntVarP(&lines, "lines", "n", 200, "Number of past lines to show (ignored with -f)")
	return cmd
}

func newServiceUninstallCmd() *cobra.Command {
	var system bool
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Stop, disable, and remove the observer service unit",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if launchdAvailable() {
				return runLaunchdUninstall(cmd.OutOrStdout(), system, launchdDeps{})
			}
			if !systemdAvailable() {
				return errNoSystemd
			}
			scope := resolveScope(system)
			if scope == service.ScopeSystem && os.Geteuid() != 0 {
				return errors.New("--system uninstall requires root; re-run with sudo")
			}
			// Stop + disable are best-effort: the unit may already be
			// stopped or never enabled. Surface but don't fail on those.
			_ = runServiceCommand(service.Systemctl(scope, "stop", service.UnitName))
			_ = runServiceCommand(service.Systemctl(scope, "disable", service.UnitName))

			home, _ := os.UserHomeDir()
			unitPath := service.UnitPath(scope, home)
			if rmErr := os.Remove(unitPath); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
				return fmt.Errorf("remove unit %s: %w", unitPath, rmErr)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Removed %s\n", unitPath)
			if rErr := runServiceCommand(service.Systemctl(scope, "daemon-reload")); rErr != nil {
				return fmt.Errorf("systemctl daemon-reload: %w", rErr)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Service uninstalled. Local Observer DB and config were not touched.")
			return nil
		},
	}
	cmd.Flags().BoolVar(&system, "system", false, "Target the system unit instead of the --user unit")
	return cmd
}

// scopeFlagSuffix returns " --system" for system scope so printed
// next-step commands carry the right flag.
func scopeFlagSuffix(scope service.Scope) string {
	if scope == service.ScopeSystem {
		return " --system"
	}
	return ""
}

// serviceUpgradeNoUnitMessage is `observer service upgrade`'s answer when no
// unit is installed (U7, lane FIX-UPGRADE): that daemon was started with
// `observer start`, so the message gives that restart path first (the one
// the npm postinstall prints for it) and the service install second.
func serviceUpgradeNoUnitMessage(unit, unitPath, scopeFlag string) string {
	return fmt.Sprintf("no %s at %s, so there is no service to upgrade.\n"+
		"  A daemon started with `observer start`: when no AI session uses the proxy, turn the proxy route off,\n"+
		"    stop that process (Ctrl-C in its terminal, or kill its pid), then run `observer start` again (docs/daemon-restart-runbook.md).\n"+
		"  To run it as a service instead: observer service install --now%s", unit, unitPath, scopeFlag)
}

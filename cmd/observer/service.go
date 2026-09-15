// service.go — `observer service` systemd command group.

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/service"
	"github.com/marmutapp/superbased-observer/internal/toolresolve"
)

// errNoSystemd is returned when the host has no systemd manager. The
// command surfaces it as a clear, actionable message (macOS launchd /
// Windows-via-WSL are documented alternatives, not handled here yet).
var errNoSystemd = errors.New(
	"systemd not detected on this host (no /run/systemd/system).\n" +
		"  `observer service` currently supports Linux systemd only.\n" +
		"  - On macOS, run `observer start` under launchd, or use a tmux/screen session.\n" +
		"  - On Windows, the daemon runs inside WSL; install the service there.",
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
			"Warning: could not check linger status for %s (%v) — if `systemctl --user start\n"+
				"observer.service` stops working after you log out, run: loginctl enable-linger %s\n",
			username, err, username)
	}
	if strings.TrimSpace(out) == "yes" {
		return ""
	}
	return fmt.Sprintf(
		"Note: linger is not enabled for %s — a --user unit only starts at login and stops\n"+
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
		Short: "Install and manage observer as a long-running systemd service",
		Long: "Supervises `observer start` (proxy + watcher + dashboard) as a\n" +
			"systemd unit, so the daemon survives crashes and reboots without\n" +
			"a tmux/screen babysitter.\n\n" +
			"Default scope is --user (per-login, no root). Use --system on a\n" +
			"headless box (e.g. a worker node running as root) so the daemon\n" +
			"survives logout. Subcommands:\n" +
			"    observer service install [--now]   write the unit + reload\n" +
			"    observer service start|stop|status|restart\n" +
			"    observer service logs [-f]         journalctl for the unit\n" +
			"    observer service uninstall         stop + disable + remove\n\n" +
			"Note: `observer start` IS the proxy on :8820. Restarting the\n" +
			"service while a live session routes through the proxy will drop\n" +
			"that session — turn the route off first (see\n" +
			"docs/daemon-restart-runbook.md).",
	}
	cmd.AddCommand(
		newServiceInstallCmd(),
		newServiceLifecycleCmd("start", "Start the observer service"),
		newServiceLifecycleCmd("stop", "Stop the observer service"),
		newServiceLifecycleCmd("restart", "Restart the observer service (drops active proxy sessions)"),
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

// systemdAvailable reports whether a systemd manager is present.
func systemdAvailable() bool {
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
	)
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Write the systemd unit for `observer start` and reload systemd",
		Long: "Renders observer.service, writes it (~/.config/systemd/user/ for\n" +
			"--user, /etc/systemd/system/ for --system), and runs\n" +
			"daemon-reload. The --config/--recipe/--port you pass here are\n" +
			"baked into the unit's ExecStart so the service uses the same\n" +
			"configuration. Pass --now to enable + start immediately.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runServiceInstall(serviceInstallOptions{
				scope:      resolveScope(system),
				now:        now,
				configPath: configPath,
				recipe:     recipe,
				port:       port,
				stdout:     cmd.OutOrStdout(),
			})
		},
	}
	cmd.Flags().BoolVar(&system, "system", false, "Install a system unit (/etc/systemd/system, requires root) instead of a --user unit")
	cmd.Flags().BoolVar(&now, "now", false, "Enable + start the service immediately after installing")
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml to bake into the unit (defaults to the daemon's own lookup)")
	cmd.Flags().StringVar(&recipe, "recipe", "", "Compression recipe to bake into the unit")
	cmd.Flags().IntVar(&port, "port", 0, "Proxy port to bake into the unit (0 = config default)")
	return cmd
}

type serviceInstallOptions struct {
	scope      service.Scope
	now        bool
	configPath string
	recipe     string
	port       int
	stdout     interface{ Write([]byte) (int, error) }
}

func runServiceInstall(opts serviceInstallOptions) error {
	if !systemdAvailable() {
		return errNoSystemd
	}
	if opts.scope == service.ScopeSystem && os.Geteuid() != 0 {
		return errors.New("--system installs to /etc/systemd/system and requires root; re-run with sudo, or drop --system for a per-user unit")
	}

	exe, err := absoluteBinaryPath()
	if err != nil {
		return fmt.Errorf("resolve observer binary: %w", err)
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

	// The unit's PATH is the daemon's own merged (process + login-shell)
	// PATH, not systemd's bare manager default — a fresh systemd unit
	// otherwise reproduces the DI-04/DI-23 class of bug where every
	// npm-shim AI-tool exits 127 because ~/.local/bin and the npm global
	// prefix were never on it. resolveEnv() is the same memoized
	// toolresolve.Env every launcher in this process uses (launch.go);
	// reusing it here means `install` pays the up-to-~6s login-shell
	// capture at most once even if a future caller resolves a tool first.
	pathDirs, _ := toolresolve.MergedPathDirs(resolveEnv())
	pathEnv := unitPathEnv(pathDirs)
	if pathEnv == "" {
		fmt.Fprintf(opts.stdout, "unit PATH = %s (fallback: could not resolve the operator's PATH)\n", service.DefaultPath)
	} else {
		fmt.Fprintf(opts.stdout, "unit PATH = %s\n", pathEnv)
	}

	unit := service.RenderUnit(service.UnitOptions{ExecPath: exe, Args: args, Scope: opts.scope, Path: pathEnv})

	home, err := os.UserHomeDir()
	if err != nil && opts.scope == service.ScopeUser {
		return fmt.Errorf("resolve home dir: %w", err)
	}
	unitPath := service.UnitPath(opts.scope, home)
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
		if u, uerr := user.Current(); uerr == nil {
			if note := lingerNoticeFor(u.Username); note != "" {
				fmt.Fprint(opts.stdout, "\n"+note)
			}
		}
	}

	if rErr := runServiceCommand(service.Systemctl(opts.scope, "daemon-reload")); rErr != nil {
		return fmt.Errorf("systemctl daemon-reload: %w", rErr)
	}

	if opts.now {
		if eErr := runServiceCommand(service.Systemctl(opts.scope, "enable", service.UnitName)); eErr != nil {
			return fmt.Errorf("systemctl enable: %w", eErr)
		}
		if sErr := runServiceCommand(service.Systemctl(opts.scope, "start", service.UnitName)); sErr != nil {
			return fmt.Errorf("systemctl start: %w", sErr)
		}
		fmt.Fprintln(opts.stdout, "Service enabled + started.")
	} else {
		fmt.Fprintf(opts.stdout, "Installed (not started). Start it with:\n    observer service start%s\n",
			scopeFlagSuffix(opts.scope))
	}
	fmt.Fprintln(opts.stdout,
		"\nNote: the service IS the proxy on :8820. Before `observer service restart`\n"+
			"while a session routes through the proxy, turn the route off first\n"+
			"(see docs/daemon-restart-runbook.md).")
	return nil
}

// newServiceLifecycleCmd builds the thin start/stop/restart/status
// wrappers that just exec `systemctl [--user] <verb> observer.service`.
func newServiceLifecycleCmd(verb, short string) *cobra.Command {
	var system bool
	cmd := &cobra.Command{
		Use:   verb,
		Short: short,
		RunE: func(_ *cobra.Command, _ []string) error {
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

func newServiceLogsCmd() *cobra.Command {
	var (
		system bool
		follow bool
		lines  int
	)
	cmd := &cobra.Command{
		Use:   "logs",
		Short: "Show the observer service logs (journalctl)",
		RunE: func(_ *cobra.Command, _ []string) error {
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

// service_launchd.go: the macOS half of `observer service`. On a Mac the
// daemon is supervised by a per-user launchd LaunchAgent
// (~/Library/LaunchAgents/app.superbased.observer.plist), so it starts at
// login without an admin password. The plist text and launchctl argv come
// from internal/service (pure); this file writes the file and runs launchctl.
//
// Which supervisor a host has is detected once per command (launchdAvailable
// / systemdAvailable), a capability of the host rather than a branch on how
// observer was installed.

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/marmutapp/superbased-observer/internal/service"
	"github.com/marmutapp/superbased-observer/internal/toolresolve"
)

// launchdAvailable reports whether this host supervises per-user agents with
// launchd. A package var so tests can stand in for a Mac.
var launchdAvailable = func() bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	_, err := exec.LookPath("launchctl")
	return err == nil
}

// errLaunchdSystemScope: a LaunchDaemon (system scope) needs root and a
// different lifecycle; the Mac service is the per-user agent only.
var errLaunchdSystemScope = errors.New("--system applies to systemd only; on macOS the service is a per-user LaunchAgent (drop --system)")

// launchdDeps are the I/O seams of the launchd path (zero value = production).
type launchdDeps struct {
	home     string
	uid      int
	exe      string
	pathDirs func() []string
	// run executes a launchctl/tail command with the terminal attached;
	// quiet executes one and reports only success.
	run   func(service.Command) error
	quiet func(service.Command) error
	// output executes a command and returns its stdout (launchctl print).
	output func(service.Command) (string, error)
	// alive and kill reach the daemon's process for the stop escalation
	// (D-MU2); sleep and now drive its bounded waits.
	alive func(pid int) bool
	kill  func(pid int) error
	// ident returns a process's identity (its start time on macOS,
	// launchdProcessIdentity), false when it cannot be read; a stop never
	// SIGKILLs a pid whose identity changed since it read the pid (L1).
	ident func(pid int) (string, bool)
	sleep func(time.Duration)
	now   func() time.Time
	// out receives the stop report.
	out io.Writer
}

func (d launchdDeps) resolve() (launchdDeps, error) {
	if d.home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return d, fmt.Errorf("resolve home dir: %w", err)
		}
		d.home = h
	}
	if d.uid == 0 {
		d.uid = os.Getuid()
	}
	if d.run == nil {
		d.run = runServiceCommand
	}
	if d.quiet == nil {
		d.quiet = func(c service.Command) error {
			return exec.Command(c.Name, c.Args...).Run() //nolint:gosec // fixed program names, args from the pure builder
		}
	}
	if d.output == nil {
		d.output = func(c service.Command) (string, error) {
			b, err := exec.Command(c.Name, c.Args...).Output() //nolint:gosec // fixed program names, args from the pure builder
			return string(b), err
		}
	}
	if d.alive == nil {
		d.alive = func(pid int) bool {
			p, err := os.FindProcess(pid)
			if err != nil {
				return false
			}
			return p.Signal(syscall.Signal(0)) == nil
		}
	}
	if d.kill == nil {
		d.kill = func(pid int) error {
			p, err := os.FindProcess(pid)
			if err != nil {
				return err
			}
			return p.Kill()
		}
	}
	if d.ident == nil {
		d.ident = launchdProcessIdentity
	}
	if d.sleep == nil {
		d.sleep = time.Sleep
	}
	if d.now == nil {
		d.now = time.Now
	}
	if d.out == nil {
		d.out = os.Stdout
	}
	return d, nil
}

// launchdLoaded reports whether the agent is loaded in the user's domain.
func launchdLoaded(d launchdDeps) bool {
	return d.quiet(service.Launchctl("print", service.LaunchdTarget(d.uid))) == nil
}

// runLaunchdInstall writes the LaunchAgent for this binary. With --now it
// loads the agent when it is not loaded yet (RunAtLoad starts the daemon). A
// loaded agent keeps its running process: the daemon IS the proxy, so it is
// restarted only by the operator, at a moment no AI session routes through it.
func runLaunchdInstall(opts serviceInstallOptions, d launchdDeps) error {
	if opts.scope == service.ScopeSystem {
		return errLaunchdSystemScope
	}
	d, err := d.resolve()
	if err != nil {
		return err
	}
	plistPath := service.LaunchAgentPath(d.home)
	exe := d.exe
	if exe == "" {
		if exe, err = absoluteBinaryPath(); err != nil {
			return fmt.Errorf("resolve observer binary: %w", err)
		}
	}

	var args []string
	if opts.upgrade {
		old, rerr := os.ReadFile(plistPath) //nolint:gosec // fixed per-user path
		if rerr != nil {
			return fmt.Errorf("no LaunchAgent at %s, so there is no service to upgrade; install it with: observer service install --now", plistPath)
		}
		prog, ok := service.LaunchAgentProgramArguments(string(old))
		if !ok || len(prog) < 2 || prog[1] != "start" {
			return fmt.Errorf("%s does not run `<observer> start ...`; rewrite it with: observer service install --now", plistPath)
		}
		if filepath.Clean(prog[0]) != filepath.Clean(exe) {
			fmt.Fprintf(opts.stdout, "The agent ran %s; it now runs %s.\n", prog[0], exe)
		}
		args = prog[2:]
	} else if args, err = serviceUnitArgs(&opts, plistPath, "", exe); err != nil {
		return err
	}

	var pathDirs []string
	if d.pathDirs != nil {
		pathDirs = d.pathDirs()
	} else {
		pathDirs, _ = toolresolve.MergedPathDirs(resolveEnv())
	}
	logPath := service.LaunchdLogPath(d.home)
	plist := service.RenderLaunchAgent(service.LaunchAgentOptions{ExecPath: exe, Args: args, LogPath: logPath, Path: unitPathEnv(pathDirs)})
	for _, dir := range []string{filepath.Dir(plistPath), filepath.Dir(logPath)} {
		if mkErr := os.MkdirAll(dir, 0o755); mkErr != nil {
			return fmt.Errorf("create %s: %w", dir, mkErr)
		}
	}
	if wErr := os.WriteFile(plistPath, []byte(plist), 0o644); wErr != nil { //nolint:gosec // a LaunchAgent plist is not secret
		return fmt.Errorf("write %s: %w", plistPath, wErr)
	}
	fmt.Fprintf(opts.stdout, "Wrote %s (log: %s)\n", plistPath, logPath)

	loaded := launchdLoaded(d)
	switch {
	case loaded:
		fmt.Fprintln(opts.stdout, "The agent is loaded and keeps its current process until it is restarted.\n"+
			"The daemon is the proxy: restart it when no AI session uses the proxy, with the route off first\n"+
			"(docs/daemon-restart-runbook.md), with: observer service restart")
	case opts.now && !opts.upgrade:
		if err := d.run(service.Launchctl("bootstrap", service.LaunchdDomain(d.uid), plistPath)); err != nil {
			return fmt.Errorf("launchctl bootstrap: %w", err)
		}
		fmt.Fprintln(opts.stdout, "Loaded and started. SuperBased now starts when you log in.")
	default:
		fmt.Fprintln(opts.stdout, "Installed. SuperBased starts at your next login, or now with:\n    observer service start")
	}
	fmt.Fprintln(opts.stdout, serviceRestartNote(componentSnapshotFor(opts.configPath).Active("capture.proxy")))
	return nil
}

// runLaunchdLifecycle maps start/stop/restart/status onto launchctl.
func runLaunchdLifecycle(verb string, system bool, d launchdDeps) error {
	if system {
		return errLaunchdSystemScope
	}
	d, err := d.resolve()
	if err != nil {
		return err
	}
	target := service.LaunchdTarget(d.uid)
	plistPath := service.LaunchAgentPath(d.home)
	switch verb {
	case "start":
		if !launchdLoaded(d) {
			if _, serr := os.Stat(plistPath); serr != nil {
				return fmt.Errorf("no LaunchAgent at %s; install it with: observer service install --now", plistPath)
			}
			return d.run(service.Launchctl("bootstrap", service.LaunchdDomain(d.uid), plistPath))
		}
		return d.run(service.Launchctl("kickstart", target))
	case "stop":
		return runLaunchdStop(d, target)
	case "restart":
		return d.run(service.Launchctl("kickstart", "-k", target))
	case "status":
		return d.run(service.Launchctl("print", target))
	}
	return fmt.Errorf("unknown service verb %q", verb)
}

// runLaunchdStop stops the agent's daemon and reports what it took (D-MU2).
// SIGTERM first: the daemon drains and exits 0, which KeepAlive
// (SuccessfulExit=false) leaves stopped; it starts again at login. A daemon
// still alive after the bound (the report's case: stuck before it acted on
// the signal) is unloaded with bootout, so launchd does not restart it, and
// then killed. After the daemon exited the agent's state is read again for
// a bounded time (MACUSER merge M1): a daemon that exited non-zero (the stop
// watchdog, the startup stop guard) is restarted by KeepAlive, so a new pid
// there is unloaded and stopped too, and reported. A stop that leaves a
// daemon running is an error, never a silent success.
func runLaunchdStop(d launchdDeps, target string) error {
	pid := 0
	if out, err := d.output(service.Launchctl("print", target)); err == nil {
		pid = service.ParseLaunchdPID(out)
	}
	if pid == 0 {
		// launchd names no running process: send the stop anyway (it is
		// harmless when nothing runs) and say what is known.
		err := d.run(service.Launchctl("kill", "SIGTERM", target))
		fmt.Fprintln(d.out, "launchd reports no running daemon process for the agent; sent SIGTERM to be sure.")
		return err
	}
	rep := escalateLaunchdStop(d, target, pid, service.LaunchdStopSteps)
	if !rep.Exited {
		return fmt.Errorf("observer service stop: pid %d is still running after SIGTERM, launchctl bootout and SIGKILL", pid)
	}
	unloaded := len(rep.Steps) > 1
	newPID := service.WatchRelaunch(pid, service.LaunchdRelaunchWatch, service.RelaunchDeps{
		Print: func() (string, error) { return d.output(service.Launchctl("print", target)) },
		Sleep: d.sleep,
		Now:   d.now,
	})
	if newPID != 0 {
		fmt.Fprintf(d.out, "launchd started a new daemon (pid %d) after pid %d exited (the agent restarts a daemon that exits with an error); unloading the agent so it stays stopped.\n", newPID, pid)
		if again := escalateLaunchdStop(d, target, newPID, service.LaunchdRelaunchStopSteps); !again.Exited {
			return fmt.Errorf("observer service stop: launchd restarted the daemon as pid %d, which is still running after launchctl bootout and SIGKILL", newPID)
		}
		unloaded = true
	}
	if unloaded {
		fmt.Fprintln(d.out, "The agent was unloaded to stop it; `observer service start` loads it again (it also loads at your next login).")
	} else {
		fmt.Fprintln(d.out, "Stopped. It starts again at your next login, or now with: observer service start")
	}
	return nil
}

// escalateLaunchdStop walks steps for pid and prints one line per step.
// The process counts as the daemon only while its identity (start time) is
// the one read first: a pid the system reused for another process is the
// daemon gone, and SIGKILL is never sent to it (L1); with no readable
// identity the pid alone decides, as before.
func escalateLaunchdStop(d launchdDeps, target string, pid int, steps []service.StopStep) service.StopReport {
	identity, known := "", false
	if d.ident != nil {
		identity, known = d.ident(pid)
	}
	same := func() bool {
		if !known {
			return true
		}
		cur, ok := d.ident(pid)
		return ok && cur == identity
	}
	rep := service.EscalateStop(steps, service.StopDeps{
		Alive: func() bool { return d.alive(pid) && same() },
		Do: func(action string) error {
			switch action {
			case "sigterm":
				return d.run(service.Launchctl("kill", "SIGTERM", target))
			case "bootout":
				return d.run(service.Launchctl("bootout", target))
			case "sigkill":
				if !same() {
					return fmt.Errorf("skipped: pid %d is no longer the daemon (its start time changed)", pid)
				}
				return d.kill(pid)
			}
			return fmt.Errorf("unknown stop action %q", action)
		},
		Sleep: d.sleep,
		Now:   d.now,
	})
	for _, st := range rep.Steps {
		line := fmt.Sprintf("%s: ", launchdStopActionLabel(st.Action))
		switch {
		case st.Exited:
			line += fmt.Sprintf("pid %d exited after %s", pid, st.Waited.Round(time.Millisecond))
		default:
			line += fmt.Sprintf("pid %d still running after %s", pid, st.Waited.Round(time.Millisecond))
		}
		if st.Err != nil {
			line += fmt.Sprintf(" (the action reported: %v)", st.Err)
		}
		fmt.Fprintln(d.out, line)
	}
	return rep
}

// launchdStopActionLabel is the report wording for one escalation step.
func launchdStopActionLabel(action string) string {
	switch action {
	case "sigterm":
		return "SIGTERM"
	case "bootout":
		return "launchctl bootout"
	case "sigkill":
		return "SIGKILL"
	}
	return action
}

// runLaunchdLogs shows the agent's log file.
func runLaunchdLogs(system, follow bool, lines int, d launchdDeps) error {
	if system {
		return errLaunchdSystemScope
	}
	d, err := d.resolve()
	if err != nil {
		return err
	}
	return d.run(service.TailLog(service.LaunchdLogPath(d.home), follow, lines))
}

// runLaunchdUninstall unloads the agent (stopping the daemon) and removes the
// plist. Data and config are untouched.
func runLaunchdUninstall(out io.Writer, system bool, d launchdDeps) error {
	if system {
		return errLaunchdSystemScope
	}
	d, err := d.resolve()
	if err != nil {
		return err
	}
	plistPath := service.LaunchAgentPath(d.home)
	if launchdLoaded(d) {
		_ = d.run(service.Launchctl("bootout", service.LaunchdTarget(d.uid)))
	}
	if rmErr := os.Remove(plistPath); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
		return fmt.Errorf("remove %s: %w", plistPath, rmErr)
	}
	fmt.Fprintf(out, "Removed %s\n", plistPath)
	fmt.Fprintln(out, "Service uninstalled. Local Observer DB and config were not touched.")
	return nil
}

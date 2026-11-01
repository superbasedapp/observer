// service_refresh.go - what `observer service install --now` and
// `observer service upgrade` do about a unit that is ALREADY RUNNING when they
// rewrite it (T-753).
//
// The rc.3 roll (D-567) found that an in-place upgrade replaced the binary
// underneath the running daemon (the process kept running the deleted
// executable) and `observer service install --now` then said "Service enabled
// + started." because `systemctl start` on an active unit is a no-op. The
// daemon is the proxy on :8820, so a restart is only automatic when nothing
// can be routed through it; otherwise the old process keeps running and the
// safe order is printed (CLAUDE.md "never stop the daemon while the proxy
// route is active", docs/daemon-restart-runbook.md). The decision itself is
// internal/service.DecideRefresh; this file gathers its inputs and acts.

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/clientwire"
	"github.com/marmutapp/superbased-observer/internal/service"
)

// serviceProbe is the I/O a refresh needs, injected so tests never touch
// systemd, /proc or the AI tools' configs.
type serviceProbe struct {
	// run execs a systemctl command with the terminal's stdio.
	run func(service.Command) error
	// show reads the unit's ActiveState and MainPID.
	show func(scope service.Scope) (active bool, mainPID int, err error)
	// readExe reads a process's executable link (/proc/<pid>/exe).
	readExe func(pid int) (string, error)
	// proxySockets reports whether the proxy port is listening and how many
	// connections to it are open.
	proxySockets func(port int) (listening bool, established int, err error)
	// routes lists the proxy routes Observer wrote that are present.
	routes func(binary string, port int) ([]string, error)
}

// defaultServiceProbe is the production probe.
func defaultServiceProbe() serviceProbe {
	return serviceProbe{
		run:          runServiceCommand,
		show:         systemctlShow,
		readExe:      func(pid int) (string, error) { return os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe") },
		proxySockets: procNetProxySockets,
		routes:       presentProxyRoutes,
	}
}

// systemctlShow runs `systemctl [--user] show observer.service -p
// ActiveState -p MainPID` and parses its KEY=VALUE lines.
func systemctlShow(scope service.Scope) (bool, int, error) {
	c := service.Systemctl(scope, "show", service.UnitName, "-p", "ActiveState", "-p", "MainPID")
	out, err := exec.Command(c.Name, c.Args...).Output() //nolint:gosec // fixed program name, args from the pure builder
	if err != nil {
		return false, 0, fmt.Errorf("systemctl show: %w", err)
	}
	active, pid := parseSystemctlShow(string(out))
	return active, pid, nil
}

// parseSystemctlShow reads ActiveState / MainPID from `systemctl show`
// output. activating and reloading count as active: a process is (about to
// be) running.
func parseSystemctlShow(out string) (active bool, mainPID int) {
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "ActiveState":
			active = v == "active" || v == "reloading" || v == "activating"
		case "MainPID":
			mainPID, _ = strconv.Atoi(v)
		}
	}
	return active, mainPID
}

// procNetProxySockets reads /proc/net/tcp and /proc/net/tcp6.
func procNetProxySockets(port int) (bool, int, error) {
	listening, established, read := false, 0, 0
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(f) //nolint:gosec // fixed kernel paths
		if err != nil {
			continue
		}
		read++
		l, e := parseProcNetTCP(data, port)
		listening = listening || l
		established += e
	}
	if read == 0 {
		return false, 0, errors.New("cannot read /proc/net/tcp")
	}
	return listening, established, nil
}

// parseProcNetTCP scans one /proc/net/tcp[6] table for sockets whose LOCAL
// port is port: state 0A is LISTEN, 01 is ESTABLISHED (one per client
// connected to the proxy; the client's own end has an ephemeral local port
// and is not counted).
func parseProcNetTCP(data []byte, port int) (listening bool, established int) {
	want := fmt.Sprintf(":%04X", port)
	for i, line := range bytes.Split(data, []byte("\n")) {
		f := strings.Fields(string(line))
		if i == 0 || len(f) < 4 || !strings.HasSuffix(f[1], want) {
			continue
		}
		switch f[3] {
		case "0A":
			listening = true
		case "01":
			established++
		}
	}
	return listening, established
}

// presentProxyRoutes dry-runs the route removal `observer uninstall` performs
// (clientwire.Remover, the one removal seam): every route it WOULD remove is
// a route present now. Nothing is written.
func presentProxyRoutes(binary string, port int) ([]string, error) {
	rem, err := clientwire.NewRemover(clientwire.RemoveOptions{BinaryPath: binary, ProxyPort: port, DryRun: true})
	if err != nil {
		return nil, err
	}
	if rerr := rem.RouteRegistrarErr(); rerr != nil {
		return nil, rerr
	}
	var out []string
	for _, t := range rem.Installed() {
		m := rem.Remove(t, clientwire.PartRoute)
		if m.RouteErr != nil {
			return nil, m.RouteErr
		}
		if m.Route == nil {
			continue
		}
		if m.Route.Error != nil {
			return nil, fmt.Errorf("%s: %w", t, m.Route.Error)
		}
		if m.Route.Added {
			out = append(out, t+" ("+m.Route.ConfigPath+")")
		}
	}
	return out, nil
}

// runningExeDiffers reports whether a running process's executable link is
// not the binary the unit now names: replaced in place ("(deleted)", the
// installer's rename and npm's package swap) or another path.
func runningExeDiffers(link, exe string) bool {
	if strings.HasSuffix(link, " (deleted)") {
		return true
	}
	return filepath.Clean(link) != filepath.Clean(exe)
}

// serviceRefresh is one refresh request.
type serviceRefresh struct {
	scope service.Scope
	// exe is the binary the rewritten unit names (this process).
	exe string
	// oldExecStart / newExecStart are the ExecStart lines before and after
	// the rewrite ("" before = no unit existed).
	oldExecStart, newExecStart string
	// startIfInactive starts a stopped unit (install --now).
	startIfInactive bool
	// port is the proxy port.
	port int
	w    io.Writer
}

// applyServiceRefresh decides and acts. It never restarts a unit whose proxy
// may be in use; it says what it did, or what to run.
func applyServiceRefresh(r serviceRefresh, p serviceProbe) error {
	active, pid, serr := p.show(r.scope)
	if serr != nil {
		fmt.Fprintf(r.w, "WARN could not read the service state (%v); treating it as not running.\n", serr)
	}
	in := service.RefreshInputs{Active: active && serr == nil, StartIfInactive: r.startIfInactive}
	runningExe := ""
	if in.Active {
		link, rerr := p.readExe(pid)
		switch {
		case pid <= 0 || rerr != nil:
			in.ExecUnknown = true
		default:
			runningExe = link
			in.ExecChanged = runningExeDiffers(link, r.exe)
		}
		in.ExecStartChanged = r.oldExecStart != "" && r.oldExecStart != r.newExecStart
		if in.ExecChanged || in.ExecUnknown || in.ExecStartChanged {
			listening, established, perr := p.proxySockets(r.port)
			in.ProxyListening = listening || perr != nil
			in.ProxyClients = established
			var probeErrs []string
			if perr != nil {
				probeErrs = append(probeErrs, perr.Error())
			}
			if in.ProxyListening {
				routes, rerr := p.routes(r.exe, r.port)
				if rerr != nil {
					probeErrs = append(probeErrs, "proxy routes: "+rerr.Error())
				}
				in.Routes = routes
			}
			in.ProbeErr = strings.Join(probeErrs, "; ")
		}
	}
	d := service.DecideRefresh(in)
	suffix := scopeFlagSuffix(r.scope)
	switch d.Action {
	case service.RefreshStart:
		if err := p.run(service.Systemctl(r.scope, "enable", service.UnitName)); err != nil {
			return fmt.Errorf("systemctl enable: %w", err)
		}
		if err := p.run(service.Systemctl(r.scope, "start", service.UnitName)); err != nil {
			return fmt.Errorf("systemctl start: %w", err)
		}
		fmt.Fprintln(r.w, "Service enabled + started.")
	case service.RefreshLeaveStopped:
		fmt.Fprintf(r.w, "The service is not running; it was left stopped. Start it with:\n    observer service start%s\n", suffix)
	case service.RefreshNone:
		if r.startIfInactive {
			if err := p.run(service.Systemctl(r.scope, "enable", service.UnitName)); err != nil {
				return fmt.Errorf("systemctl enable: %w", err)
			}
		}
		fmt.Fprintf(r.w, "The service is already running this binary (pid %d); the unit was refreshed, no restart needed.\n", pid)
	case service.RefreshRestart:
		if r.startIfInactive {
			if err := p.run(service.Systemctl(r.scope, "enable", service.UnitName)); err != nil {
				return fmt.Errorf("systemctl enable: %w", err)
			}
		}
		if err := p.run(service.Systemctl(r.scope, "try-restart", service.UnitName)); err != nil {
			return fmt.Errorf("systemctl try-restart: %w", err)
		}
		now := ""
		if _, newPID, err := p.show(r.scope); err == nil && newPID > 0 {
			now = fmt.Sprintf(", now pid %d", newPID)
		}
		fmt.Fprintf(r.w, "Restarted the service onto this binary (was pid %d%s%s): %s.\n", pid, runningNote(runningExe), now, strings.Join(d.Reasons, "; "))
	case service.RefreshAdvise:
		fmt.Fprintf(r.w, "The service is still running the previous process (pid %d%s) and was NOT restarted, because the proxy may be in use:\n", pid, runningNote(runningExe))
		for _, reason := range d.Reasons {
			fmt.Fprintf(r.w, "  - %s\n", reason)
		}
		fmt.Fprintf(r.w, "The daemon is the proxy on :%d: restarting it cuts any AI request in flight through the proxy\n"+
			"and refuses new ones until it is back. When no AI session is using the proxy, run:\n"+
			"    observer service restart%s\n"+
			"To keep sessions running across it, take the proxy route off first and put it back after\n"+
			"(docs/daemon-restart-runbook.md).\n", r.port, suffix)
	}
	return nil
}

// runningNote describes the running executable for the messages.
func runningNote(link string) string {
	if link == "" {
		return ""
	}
	return ", " + link
}

package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/proxyroute"
	"github.com/marmutapp/superbased-observer/internal/routeprov"
	"github.com/marmutapp/superbased-observer/internal/supervisor"
)

// route_maintenance.go: the cmd/observer boundary of lane P1 (managed route
// maintenance). On a MANAGED node the daemon keeps every routable AI tool
// routed through its own proxy and puts a removed route back, or, when the
// admin turned that off, removes exactly the routes the organization wrote.
// Who decides is govern.Effective.RoutePosture: the admin's signed
// node.governance pin proxy.maintain_routes first, the enforce authorities as
// the default when it is unset (internal/govern/routeposture.go). It is one
// more step of the hook maintenance loop (one owner, one cadence: once at
// start when the proxy is serving, then every policy-state heartbeat), never
// a loop of its own.
//
// An INDIVIDUAL node is untouched: the step is only built with an org client,
// it runs only when the enrolment is managed, and RoutePosture is "none" off
// the managed plane, so `observer start` still writes no routes there.
//
// Safety: a route is written only while the proxy answers its liveness probe
// and is not draining for an update (proxyServing), re-checked right before
// each write (proxyroute.MaintainRoutes), because a tool routed at a dead port
// gets ConnectionRefused. A third-party-provider lane route is written only
// after its lane resolves in the running proxy (routeLaneInstaller).

// proxyHealthzPath is the proxy's unauthenticated liveness path
// (internal/proxy healthzPath).
const proxyHealthzPath = "/-/healthz"

// proxyServing reports whether the daemon's own proxy on 127.0.0.1:port is
// serving: its update drain gate is open and its liveness probe answers 200.
func proxyServing(ctx context.Context, port int) bool {
	if updateDrainGate().Draining() {
		return false
	}
	pctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	url := "http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) + proxyHealthzPath
	req, err := http.NewRequestWithContext(pctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	resp, err := (&http.Client{Timeout: 2 * time.Second}).Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// proxyPortFromAddr extracts the listen port from the proxy's address.
func proxyPortFromAddr(addr string) (int, bool) {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, false
	}
	n, err := strconv.Atoi(p)
	if err != nil || n <= 0 || n > 65535 {
		return 0, false
	}
	return n, true
}

// routeLaneProxy is the part of the daemon's proxy the route lanes need.
type routeLaneProxy interface {
	SetRouteLanes(lanes map[string]string) error
	ResolvableLanes() map[string]bool
}

// routeLaneInstaller owns the proxy's node-local route-lane set. The set is
// always rebuilt from the route-provenance file (the one owner of which
// lanes exist) plus, during a write, the one lane about to be addressed.
type routeLaneInstaller struct {
	mu    sync.Mutex
	proxy routeLaneProxy
	reg   *proxyroute.Registrar
}

// sync installs exactly the lanes provenance records, plus extra (may be
// nil), and verifies extra resolves afterwards.
func (l *routeLaneInstaller) sync(extraID, extraRoot string) error {
	if l == nil || l.proxy == nil || l.reg == nil {
		return fmt.Errorf("route lanes: no proxy to install into")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	lanes, err := l.reg.RouteLanes()
	if err != nil {
		// Keep the lanes already serving: an unreadable record must not drop
		// a lane a route still points at, and no new lane route is written
		// while its record could not be kept either.
		return err
	}
	if extraID != "" {
		lanes[extraID] = extraRoot
	}
	if err := l.proxy.SetRouteLanes(lanes); err != nil {
		return err
	}
	if extraID != "" && !l.proxy.ResolvableLanes()[extraID] {
		return fmt.Errorf("route lanes: lane %q does not resolve after install", extraID)
	}
	return nil
}

// installRouteLanesAtStart puts every recorded route lane into the proxy
// before its listener accepts a request, so a lane route written by an
// earlier run never meets a refused lane (HTTP 502). Every node runs it: the
// records exist only where the managed daemon wrote a lane route, and a
// route that still points at a lane must keep working until it is removed.
func installRouteLanesAtStart(p routeLaneProxy, port int, stderr io.Writer) *routeLaneInstaller {
	reg, err := proxyroute.NewRegistrar(proxyroute.RegisterOptions{ProxyPort: port, Writer: routeprov.WriterManaged, Lock: hook.LockSettingsFile})
	if err != nil {
		return nil
	}
	l := &routeLaneInstaller{proxy: p, reg: reg}
	if err := l.sync("", ""); err != nil {
		fmt.Fprintf(stderr, "WARN route lanes: %v\n", err)
	}
	return l
}

// routeMaintenanceStep is one route maintenance pass: it returns whether a
// route was written or removed, so the caller can report the
// managed-integrity probe at once.
type routeMaintenanceStep func(ctx context.Context, managed bool) bool

// newRouteMaintenance builds the step. posture is the live org posture
// (govern.Effective.RoutePosture through the governance handle). proxyAddr is
// the proxy's listen address; the route always names 127.0.0.1 and the same
// port, which is what the proxy accepts. lanes installs route lanes (nil: no
// lane route is ever written).
func newRouteMaintenance(configPath, proxyAddr string, posture func(context.Context) govern.RoutePostureVerdict, lanes *routeLaneInstaller, stdout, stderr io.Writer) routeMaintenanceStep {
	var mu sync.Mutex
	lastErr := map[string]string{}
	// OSH-R-009: the client token the daemon writes routes with, read once
	// (the switches are read at daemon start). "" writes the plain form.
	clientToken := ""
	if cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath}); err == nil {
		clientToken, _ = proxyClientToken(cfg, true)
	}
	warnedSupervisor := false
	return func(ctx context.Context, managed bool) bool {
		if !managed || ctx.Err() != nil || posture == nil {
			return false
		}
		port, ok := proxyPortFromAddr(proxyAddr)
		if !ok {
			return false
		}
		verdict := posture(ctx)
		switch verdict.Posture {
		case govern.RoutePostureMaintain, govern.RoutePostureRelease:
		default:
			return false
		}
		reg, err := proxyroute.NewRegistrar(proxyroute.RegisterOptions{
			ProxyPort: port,
			// The managed daemon owns what maintenance writes, so leaving the
			// organization, or the admin turning maintenance off, removes
			// exactly these routes (routeprov.Decide).
			Writer:      routeprov.WriterManaged,
			Lock:        hook.LockSettingsFile,
			ClientToken: clientToken,
		})
		if err != nil {
			return false
		}
		mu.Lock()
		defer mu.Unlock()
		if verdict.Posture == govern.RoutePostureRelease {
			return releaseManagedRoutes(reg, lanes, stdout, stderr, lastErr)
		}
		sel := routeSelection(componentSnapshotFor(configPath))
		if sel.RoutingOff {
			return false
		}
		if !warnedSupervisor {
			warnedSupervisor = true
			if !detectSupervisor().Detected {
				fmt.Fprintf(stderr, "WARN route maintenance: no process supervisor was found for this daemon; AI tools routed through its proxy get ConnectionRefused while it is down. To restart it automatically, %s\n", supervisor.TemplateHint)
			}
		}
		opts := proxyroute.MaintainOptions{
			Required:     true,
			ProxyHealthy: func() bool { return ctx.Err() == nil && proxyServing(ctx, port) },
			Allow:        sel.Tool,
		}
		if lanes != nil {
			opts.InstallLane = lanes.sync
		}
		results := reg.MaintainRoutes(opts)
		wrote := false
		for _, res := range results {
			reportRouteMaintenance(stdout, stderr, res, lastErr)
			wrote = wrote || res.Written
		}
		return wrote
	}
}

// routeWriterComponent is the component that writes AI tool proxy routes.
const routeWriterComponent = "integration.proxy-route"

// routeSelection is the ONE component selection of managed routes (T-915,
// operator decisions D-770 and D-771). Route maintenance writes nothing when
// the route writer component is not active (Selection.RoutingOff: switched
// off by policy, or not in this build, the minimal distro) and otherwise a
// route only for a tool whose adapter is active (Selection.Tool, as
// MaintainOptions.Allow). The managed-integrity probe reads the same value
// (proxyroute.DriftPolicy.Selection): with routing off no tool is drift and
// the installed ones are "routing switched off by policy"; an installed tool
// the policy did not select is "installed, not selected by policy". `observer
// doctor` says the same on its route row (diag.DoctorOptions.RouteSelection).
// All three take it from here, so they cannot disagree. Both questions are
// capabilities of the node's component state, never a tool name
// (CLAUDE.md #3).
func routeSelection(comps componentstate.Snapshot) proxyroute.Selection {
	return proxyroute.Selection{
		RoutingOff: !comps.Active(routeWriterComponent),
		Tool:       comps.AdapterActive,
	}
}

// releaseManagedRoutes is the admin-OFF pass: remove the organization's
// routes (proxyroute.ReleaseManagedRoutes), then drop their lanes from the
// proxy. It reports whether anything was removed.
func releaseManagedRoutes(reg *proxyroute.Registrar, lanes *routeLaneInstaller, stdout, stderr io.Writer, lastErr map[string]string) bool {
	out, err := reg.ReleaseManagedRoutes(true)
	if err != nil && lastErr["release"] != err.Error() {
		fmt.Fprintf(stderr, "WARN route maintenance: %v\n", err)
		lastErr["release"] = err.Error()
	}
	removed := false
	for _, lr := range out {
		switch {
		case lr.Error != "":
			if lastErr[lr.Tool] != lr.Error {
				fmt.Fprintf(stderr, "WARN route maintenance %s: %s\n", lr.Tool, lr.Error)
				lastErr[lr.Tool] = lr.Error
			}
		case lr.Removed:
			removed = true
			fmt.Fprintf(stdout, "route maintenance %s: removed the Observer proxy route from %s (your organization turned route maintenance off)\n", lr.Tool, lr.ConfigPath)
			delete(lastErr, lr.Tool)
		}
	}
	if removed && lanes != nil {
		if err := lanes.sync("", ""); err != nil {
			fmt.Fprintf(stderr, "WARN route lanes: %v\n", err)
		}
	}
	return removed
}

// reportRouteMaintenance logs one result: a write or a repair on stdout, a
// refused or failed write on stderr once per distinct error (the heartbeat
// would otherwise repeat it every five minutes). The writers' errors never
// quote a config value (credfile.SafeErrorf).
func reportRouteMaintenance(stdout, stderr io.Writer, res proxyroute.MaintainResult, lastErr map[string]string) {
	switch {
	case res.Error != nil:
		msg := res.Error.Error()
		if lastErr[res.Tool] != msg {
			fmt.Fprintf(stderr, "WARN route maintenance %s: %v\n", res.Tool, res.Error)
			lastErr[res.Tool] = msg
		}
		return
	case res.Repaired:
		fmt.Fprintf(stdout, "route maintenance %s: put the Observer proxy route back in %s (it had been removed; your organization requires it)\n", res.Tool, res.ConfigPath)
	case res.Written && res.Decision.Reason == proxyroute.ReasonPortMoved:
		fmt.Fprintf(stdout, "route maintenance %s: moved the Observer proxy route in %s to this daemon's proxy port (the proxy port changed; your organization requires the route)\n", res.Tool, res.ConfigPath)
	case res.Written && res.Decision.Reason == proxyroute.ReasonProviderLane:
		fmt.Fprintf(stdout, "route maintenance %s: routed its own provider through the Observer proxy in %s; requests still reach the same provider (your organization requires it)\n", res.Tool, res.ConfigPath)
	case res.Written:
		fmt.Fprintf(stdout, "route maintenance %s: routed through the Observer proxy in %s (your organization requires it)\n", res.Tool, res.ConfigPath)
	}
	delete(lastErr, res.Tool)
}

// detectSupervisor reports whether this daemon is kept running by a process
// supervisor (internal/supervisor). A package variable so tests can stand
// in for the machine.
var detectSupervisor = func() supervisor.Result { return supervisor.Detect(supervisor.OSProbe()) }

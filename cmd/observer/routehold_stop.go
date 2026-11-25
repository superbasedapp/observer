package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/proxyroute"
	"github.com/marmutapp/superbased-observer/internal/service"
)

// routehold_stop.go: operator ruling L-168 (i), 2026-11-24: a deliberate
// stop takes the routes off, and start puts them back.
//
// The daemon IS the proxy. `observer service stop` took the routes off
// before it stopped the unit, but every other way a daemon ends (Ctrl-C in
// its terminal, `systemctl stop` or `kill` run directly, `observer service
// uninstall`, a launchd bootout, a console close or logoff on Windows) left
// each AI tool's persistent route pointing at a port nobody serves, so the
// next session started there got ConnectionRefused. Now the daemon itself,
// at the end of its run, asks internal/service.DecideStopRoutes (an ordered
// table) whether to take its routes off, and when it says so runs the same
// route hold the verbs run (proxyroute.HoldRoutes: only routes that reach
// this proxy and can be put back exactly; never one the user pointed
// elsewhere, never the organization's or a provider lane's). The hold
// journal (~/.observer/route-hold.json) records exactly what came off, and
// the next daemon puts exactly those back once its own proxy serves
// (routehold_putback.go), however it was started, also after a crash; a
// route is never put back onto a port nobody serves.
//
// What the table leaves alone: a restart that hands its socket over
// (proxy_handover.go) or an update hand-over (the port keeps answering), a
// failure (nobody asked for a stop; a service manager starts it again), a
// daemon whose proxy never bound its port (another daemon may own it), a
// stop an `observer service` verb is running (it holds the route hold lock
// and decided for itself, --keep-routes included), and a managed node whose
// organization maintains the routes or whose posture cannot be read
// (fail-closed, today's behaviour).

// routeStopHoldBound bounds the hold at the end of a run. The daemon's whole
// stop is bounded at 20 seconds; a hold over local config files takes well
// under a second, and one cut short leaves a journal the next daemon reads
// (an entry is journaled before its route is removed).
const routeStopHoldBound = 8 * time.Second

// routeHoldOnStop is one daemon's hold at the end of its run. Every piece is
// a seam for tests.
type routeHoldOnStop struct {
	port      int
	registrar func(port int) (*proxyroute.Registrar, error)
	// event says how the run is ending; served whether this process's
	// proxy bound its port; owner who decides about the routes.
	event  func() service.StopEvent
	served func() bool
	owner  func() service.RouteOwner
	stdout io.Writer
	stderr io.Writer
}

// newRouteHoldOnStop is the production hold for the daemon's proxy on port.
func newRouteHoldOnStop(port int, event func() service.StopEvent, owner func() service.RouteOwner, stdout, stderr io.Writer) routeHoldOnStop {
	return routeHoldOnStop{
		port:      port,
		registrar: func(port int) (*proxyroute.Registrar, error) { return routeHoldRegistrar(port, false) },
		event:     event,
		served:    processProxyHandover.proxyServed,
		owner:     owner,
		stdout:    stdout, stderr: stderr,
	}
}

// waitAndRun waits for the run to end (ctx), then runs the hold once,
// bounded by routeStopHoldBound.
func (s routeHoldOnStop) waitAndRun(ctx context.Context) {
	<-ctx.Done()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.run()
	}()
	select {
	case <-done:
	case <-time.After(routeStopHoldBound):
		fmt.Fprintf(s.stderr, "WARN route hold: taking the proxy routes off did not finish within %s; what came off is journaled and goes back once a daemon's proxy answers (`observer doctor`)\n", routeStopHoldBound)
	}
}

// run decides and acts once. It returns the plan (for tests and the log).
func (s routeHoldOnStop) run() service.StopRoutesPlan {
	in := service.StopRoutesInputs{Event: s.event(), ProxyServed: s.served(), Owner: s.owner()}
	// Only a run that could take routes off reads the journal and the lock:
	// a restart hand-over or a failure touches nothing.
	if plan := service.DecideStopRoutes(in); plan.Action != service.StopRoutesTakeOff {
		s.report(in, plan)
		return plan
	}
	reg, err := s.registrar(s.port)
	if err != nil {
		fmt.Fprintf(s.stderr, "WARN route hold: %v; the proxy routes stay on\n", err)
		return service.StopRoutesPlan{Action: service.StopRoutesLeave, Rule: "registrar unavailable"}
	}
	release, acquired, err := reg.LockRouteHold()
	if err != nil {
		fmt.Fprintf(s.stderr, "WARN route hold: the lock beside %s could not be taken (%v); the proxy routes stay on\n", reg.RouteHoldPath(), err)
		return service.StopRoutesPlan{Action: service.StopRoutesLeave, Rule: "lock unavailable"}
	}
	defer release()
	in.VerbHolds = !acquired
	plan := service.DecideStopRoutes(in)
	if plan.Action != service.StopRoutesTakeOff {
		s.report(in, plan)
		return plan
	}
	_, results, herr := reg.HoldRoutes()
	s.reportHold(results)
	switch {
	case errors.Is(herr, proxyroute.ErrRouteHoldBusy):
		fmt.Fprintln(s.stderr, "route hold: another Observer command is changing the routes; it decides about them")
	case herr != nil:
		fmt.Fprintf(s.stderr, "WARN route hold: %v; the routes already off are journaled in %s and go back once a daemon's proxy answers\n", herr, reg.RouteHoldPath())
	}
	return plan
}

// report logs a stop that leaves the routes, when that is worth a line: a
// deliberate stop (or a restart without a hand-over) that left them on.
func (s routeHoldOnStop) report(in service.StopRoutesInputs, plan service.StopRoutesPlan) {
	if in.Event != service.StopEventStop && in.Event != service.StopEventRestart {
		return
	}
	switch plan.Rule {
	case "this proxy never served", "a service verb holds the routes":
		return
	}
	fmt.Fprintf(s.stdout, "route hold: the proxy routes stay on: %s.\n", plan.Reason)
}

// reportHold logs what came off, one line per route that reaches the proxy.
func (s routeHoldOnStop) reportHold(results []proxyroute.HoldResult) {
	for _, r := range results {
		switch {
		case r.Err != nil:
			fmt.Fprintf(s.stderr, "WARN route hold %s (%s): could not take the route off (%v); it stays on\n", r.Tool, r.ConfigPath, r.Err)
		case r.Action == proxyroute.HoldTakeOff && r.TakenOff:
			fmt.Fprintf(s.stdout, "route hold: off   %s (%s); it goes back once a daemon's proxy on :%d answers\n", r.Tool, r.ConfigPath, s.port)
		case r.Action == proxyroute.HoldKeep:
			fmt.Fprintf(s.stdout, "route hold: kept  %s (%s): %s\n", r.Tool, r.ConfigPath, proxyroute.HoldReasonText(r.Reason))
		}
	}
}

// daemonStopEvent says how the daemon's run is ending, from what this
// process knows once its components start to stop: a restart asked for
// (and whether its socket is handed over), an update that released the
// listeners, a stop signal (the signal context ended), or else a failure.
func daemonStopEvent(signalled, restart, handover, updateReleased bool) service.StopEvent {
	switch {
	case updateReleased:
		return service.StopEventUpdateHandover
	case restart && handover:
		return service.StopEventRestartHandover
	case restart:
		return service.StopEventRestart
	case signalled:
		return service.StopEventStop
	}
	return service.StopEventFailure
}

// daemonRouteOwner says who decides about this machine's proxy routes at
// the end of the daemon's run: the verified org lock answers for an
// individual node; otherwise the daemon's own live governance posture (the
// one route maintenance acts on). A lock that does not verify, or a config
// that did not load, is unknown, and a stop then leaves the routes on.
func daemonRouteOwner(lock config.GuardOrgLock, lockLoaded bool, posture func(context.Context) govern.RoutePostureVerdict) service.RouteOwner {
	switch {
	case !lockLoaded:
		return service.RouteOwnerUnknown
	case lock.TenancyKnown && !lock.Managed:
		return service.RouteOwnerNode
	case lock.State == "tampered" && !lock.TenancyKnown:
		return service.RouteOwnerUnknown
	case posture == nil:
		return service.RouteOwnerUnknown
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if posture(ctx).Posture == govern.RoutePostureMaintain {
		return service.RouteOwnerOrg
	}
	return service.RouteOwnerNode
}

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/marmutapp/superbased-observer/internal/proxyroute"
)

// routehold_putback.go: the daemon's own put-back of a route hold (review of
// lane sr-restart, finding 4). `observer service stop`, a restart that timed
// out, was killed, or whose in-place re-exec failed leave the routes they
// took off in the route hold journal. Before this, only `observer service
// restart` / `start` read it, so the routes stayed off through a plain
// `observer start`, a reboot or a login, and without a service manager there
// was no command that put them back at all.
//
// Now the daemon puts back a pending hold for its own proxy port once that
// proxy serves. It is the same put-back the verbs run
// (proxyroute.ReleasePendingRoutes), under the same route hold lock, so there
// is one owner of each put-back: while a verb holds the lock (the restart that
// started this daemon is still waiting for it), the daemon waits, and when
// the lock is free it reads the journal again, so a hold the verb already put
// back is never put back twice. A hold for another port is left alone (the
// doctor names it).

// routeHoldPutBackPoll is how often the daemon looks again while a verb holds
// the lock or its proxy does not answer yet.
const routeHoldPutBackPoll = time.Second

// routeHoldPutBack is one daemon's put-back. Every piece is a seam for tests.
type routeHoldPutBack struct {
	port      int
	registrar func(port int) (*proxyroute.Registrar, error)
	serving   func(ctx context.Context, port int) bool
	// wait sleeps for d, and reports false when ctx ended first.
	wait   func(ctx context.Context, d time.Duration) bool
	stdout io.Writer
	stderr io.Writer
}

// newRouteHoldPutBack is the production put-back for the daemon's proxy on
// port.
func newRouteHoldPutBack(port int, stdout, stderr io.Writer) routeHoldPutBack {
	return routeHoldPutBack{
		port:      port,
		registrar: func(port int) (*proxyroute.Registrar, error) { return routeHoldRegistrar(port, false) },
		serving:   proxyServing,
		wait: func(ctx context.Context, d time.Duration) bool {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return false
			case <-t.C:
				return true
			}
		},
		stdout: stdout, stderr: stderr,
	}
}

// run puts back a pending hold for this port, then returns. It returns at
// once when nothing is held, and when ctx ends.
func (p routeHoldPutBack) run(ctx context.Context) {
	reg, err := p.registrar(p.port)
	if err != nil {
		return
	}
	for ctx.Err() == nil {
		pending, err := reg.PendingRouteHold()
		switch {
		case err != nil:
			fmt.Fprintf(p.stderr, "WARN route hold: %v; the proxy routes a restart or stop took off stay off (`observer doctor`)\n", err)
			return
		case pending.Empty():
			return
		case pending.Port != p.port:
			fmt.Fprintf(p.stderr, "WARN route hold: %d proxy route(s) were taken off for a proxy on :%d, not this daemon's :%d, so they stay off (`observer doctor` lists them)\n",
				len(pending.Routes), pending.Port, p.port)
			return
		}
		if p.serving(ctx, p.port) {
			_, results, err := reg.ReleasePendingRoutes()
			switch {
			case errors.Is(err, proxyroute.ErrRouteHoldBusy):
				// A restart, stop or start owns the put-back right now.
			case err != nil:
				fmt.Fprintf(p.stderr, "WARN route hold: %v; the proxy routes a restart or stop took off stay off (`observer doctor`)\n", err)
				return
			default:
				reportDaemonRelease(p.stdout, p.stderr, results)
				return
			}
		}
		if !p.wait(ctx, routeHoldPutBackPoll) {
			return
		}
	}
}

// reportDaemonRelease logs the daemon's put-back, one line per route, in the
// verbs' words.
func reportDaemonRelease(stdout, stderr io.Writer, results []proxyroute.ReleaseResult) {
	for _, r := range results {
		switch {
		case r.Tool == "":
			fmt.Fprintf(stderr, "WARN route hold: the journal could not be updated: %v\n", r.Err)
		case r.Outcome == proxyroute.ReleaseFailed:
			fmt.Fprintf(stderr, "WARN route hold %s (%s): could not put the route back (%v); it stays listed for `observer service restart`\n", r.Tool, r.ConfigPath, r.Err)
		default:
			fmt.Fprintf(stdout, "route hold: "+releaseOutcomeText[r.Outcome]+"\n", r.Tool, r.ConfigPath)
		}
	}
}

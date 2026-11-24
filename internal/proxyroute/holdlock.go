package proxyroute

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/marmutapp/superbased-observer/internal/dblease"
)

// holdlock.go: the route hold lock. One Observer process at a time changes
// the proxy routes for a safe restart, stop or start, or puts back a hold
// for the daemon it runs in: two of them planning from one journal would
// each see the other's half-done state (a route off with no journal entry
// yet, or an entry already put back). The lock is an OS file lock
// (internal/dblease: flock on unix, LockFileEx on Windows) on
// route-hold.lock beside the journal, so it is released when the holder
// exits however it exits, and is never left stale.
//
// A verb takes it once for its whole run (LockRouteHold); every journal
// read-modify-write on a registrar that does not hold it takes it for that
// write (HoldRoutes, ReleaseRoutes).

// routeHoldLockName is the lock's name: route-hold.lock beside the journal.
const routeHoldLockName = "route-hold"

// ErrRouteHoldBusy means another Observer process holds the route hold lock.
var ErrRouteHoldBusy = errors.New("another Observer command (a service restart, stop or start, or a daemon putting routes back) is changing the proxy routes right now; try again when it has finished")

// LockRouteHold takes the route hold lock for this registrar's home without
// waiting. acquired=false with a nil error means another process holds it.
// While this registrar holds it, its HoldRoutes and ReleaseRoutes do not take
// it again. release gives it back (idempotent).
func (r *Registrar) LockRouteHold() (release func(), acquired bool, err error) {
	if r.holdLocked {
		return func() {}, true, nil
	}
	rel, ok, err := dblease.TryAcquire(filepath.Join(r.opts.HomeDir, ".observer"), routeHoldLockName)
	if err != nil {
		return func() {}, false, fmt.Errorf("proxyroute.LockRouteHold: %w", err)
	}
	if !ok {
		return func() {}, false, nil
	}
	r.holdLocked = true
	done := false
	return func() {
		if done {
			return
		}
		done = true
		r.holdLocked = false
		rel()
	}, true, nil
}

// holdLockForWrite takes the lock for one journal read-modify-write unless
// this registrar already holds it; ErrRouteHoldBusy when another process
// does.
func (r *Registrar) holdLockForWrite() (func(), error) {
	if r.holdLocked {
		return func() {}, nil
	}
	release, ok, err := r.LockRouteHold()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrRouteHoldBusy
	}
	return release, nil
}

//go:build !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxengine"
	"github.com/marmutapp/superbased-observer/internal/sandboxoci"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
)

// terminal_sandbox_oci_reaper.go is the oci-runc orphan sweep (sandbox
// plan v2 section 4.6): the daemon removes every container labelled with
// its own install id whose run is no longer live, once when the driver's
// first probe passes (daemon start) and on every container event of this
// install from the engine's label-filtered event stream. A run is live
// while its relay run record exists; the record of a host helper that died
// (even by SIGKILL) is pruned first (sandboxrelayd.PruneDeadRuns), so a
// terminated run, a killed helper or a killed daemon leaves no container
// behind. It runs only in the daemon, only while the driver is active and
// its socket passed validation, and talks only to that local socket.
//
// Events alone miss two cases (live check 2026-10-22, D6): a box whose host
// helper and launcher were SIGKILLed while the daemon lives raises no event
// (the agent inside keeps running), and after an engine restart the
// stream-end sweep runs while the engine is down. So the reaper also sweeps
// every ociPeriodicSweep while this install has a recorded run or a box
// (idle otherwise), and once after every reconnect of the event stream.

// ociSweepDebounce merges bursts of events into one sweep.
const ociSweepDebounce = time.Second

// ociPeriodicSweep is the bounded period of the sweep while a run is
// recorded or a box of this install was last seen (D6).
const ociPeriodicSweep = 30 * time.Second

// ociReaper is the one process-wide sweep; ensure (re)starts it for a
// socket, stop ends it.
type ociReaper struct {
	mu     sync.Mutex
	key    string
	cancel context.CancelFunc
	done   chan struct{}
	// sweeps counts completed sweeps (tests). Atomic, because stop holds
	// mu while it waits for the sweep goroutine.
	sweeps atomic.Int64
	// pending: the last sweep could not list (the engine was down) or saw a
	// box of this install, so the next tick sweeps even with no run record.
	pending atomic.Bool
	// failed: the last sweep could not list (the engine was down), so the
	// first connect of the stream sweeps again.
	failed atomic.Bool
	// every overrides ociPeriodicSweep (tests).
	every time.Duration
	// managedRoot is the runtime's managed workspaces root, where a run's
	// projected state lives (<managed>/<run>.state); set by ensure before
	// the sweep goroutine starts.
	managedRoot string
}

// processOCIReaper is the daemon's reaper.
var processOCIReaper = &ociReaper{}

// ociEngineClient builds a client with a fixed API version. A package
// variable so tests can point it at a fake engine.
var ociEngineClient = func(socket, api string) (*sandboxengine.Client, error) {
	c, err := sandboxengine.New(socket)
	if err != nil {
		return nil, err
	}
	if err := c.SetAPIVersion(api); err != nil {
		return nil, err
	}
	return c, nil
}

// ensure runs the sweep for socket (idempotent for the same arguments).
func (rp *ociReaper) ensure(socket, api, installID, observerDir, managedRoot string) {
	key := socket + "\x00" + api + "\x00" + installID + "\x00" + observerDir + "\x00" + managedRoot
	rp.mu.Lock()
	defer rp.mu.Unlock()
	if rp.key == key && rp.cancel != nil {
		return
	}
	rp.stopLocked()
	c, err := ociEngineClient(socket, api)
	if err != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	rp.key, rp.cancel, rp.done, rp.managedRoot = key, cancel, make(chan struct{}), managedRoot
	go rp.run(ctx, c, installID, observerDir, rp.done)
}

// stop ends the sweep and waits for it.
func (rp *ociReaper) stop() {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	rp.stopLocked()
}

func (rp *ociReaper) stopLocked() {
	if rp.cancel == nil {
		return
	}
	rp.cancel()
	<-rp.done
	rp.key, rp.cancel, rp.done = "", nil, nil
}

// run sweeps once, then on each event of this install, after each
// reconnect of the stream (reconnecting with a capped backoff) and on the
// periodic tick, until ctx ends.
func (rp *ociReaper) run(ctx context.Context, c *sandboxengine.Client, installID, observerDir string, done chan struct{}) {
	defer close(done)
	rp.sweep(ctx, c, installID, observerDir)
	every := rp.every
	if every <= 0 {
		every = ociPeriodicSweep
	}
	tick := time.NewTicker(every)
	defer tick.Stop()
	backoff := time.Second
	connected := false
	for ctx.Err() == nil {
		ev, err := c.Events(ctx, sandboxoci.InstallFilter(installID))
		if err != nil {
			wait := time.NewTimer(backoff)
			for waiting := true; waiting; {
				select {
				case <-ctx.Done():
					wait.Stop()
					return
				case <-wait.C:
					waiting = false
				case <-tick.C:
					rp.periodic(ctx, c, installID, observerDir)
				}
			}
			backoff = min(2*backoff, time.Minute)
			continue
		}
		backoff = time.Second
		// A reconnect sweeps at once: what ended while the stream was down
		// raised no event this stream will deliver, and the stream-end
		// sweep may have run while the engine was down (D6).
		if connected || rp.failed.Load() {
			rp.sweep(ctx, c, installID, observerDir)
		}
		connected = true
		rp.follow(ctx, ev, tick.C, c, installID, observerDir)
	}
}

// periodic is the tick's sweep: only while a run is recorded or the last
// sweep left something to look at again, so an idle install costs nothing.
func (rp *ociReaper) periodic(ctx context.Context, c *sandboxengine.Client, installID, observerDir string) {
	if rp.pending.Load() || ociRunsRecorded(observerDir) {
		rp.sweep(ctx, c, installID, observerDir)
	}
}

// ociRunsRecorded reports whether the relay holds any run record.
func ociRunsRecorded(observerDir string) bool {
	entries, err := os.ReadDir(sandboxrelayd.RunsDir(observerDir))
	if err != nil {
		return false
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			return true
		}
	}
	return false
}

// follow sweeps after each burst of events and on each tick until the
// stream ends.
func (rp *ociReaper) follow(ctx context.Context, ev <-chan sandboxengine.Event, tick <-chan time.Time, c *sandboxengine.Client, installID, observerDir string) {
	var timer <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
			rp.periodic(ctx, c, installID, observerDir)
		case _, ok := <-ev:
			if !ok {
				rp.sweep(ctx, c, installID, observerDir)
				return
			}
			if timer == nil {
				timer = time.After(ociSweepDebounce)
			}
		case <-timer:
			timer = nil
			rp.sweep(ctx, c, installID, observerDir)
		}
	}
}

// sweep ends the runs whose helper died (their records go and a killed
// CLI launch's stored row is ended, D7), then stops and removes this
// install's containers whose run is not live, then removes the run state
// of every run that is not live (its projection, a sign-in copy in it
// included, and its db copies: lane BOXSIGNIN audit finding 1, so a helper
// kill leaves no credential copy while the daemon runs). A dead helper's
// record is kept while the daemon's run ender is not set yet, so no row is
// left running; the box and its state then wait for a later sweep.
func (rp *ociReaper) sweep(ctx context.Context, c *sandboxengine.Client, installID, observerDir string) {
	if f := ociReadoptBeforeSweep; f != nil {
		f(ctx, c, installID, observerDir)
	}
	pruneGoneRelayRuns(observerDir)
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	list, err := c.ContainerList(cctx, sandboxoci.InstallFilter(installID))
	left := len(list)
	if err == nil {
		live := func(runID string) bool {
			_, rerr := sandboxrelayd.ReadRun(observerDir, runID)
			return rerr == nil
		}
		for _, id := range sandboxoci.Orphans(installID, list, live) {
			if c.ContainerRemove(cctx, id) == nil {
				left--
			}
		}
	}
	// A run whose record is gone has no helper and no box left to use its
	// state; a record that cannot be looked up counts as live.
	_, _ = ociSweepRunState(observerDir, rp.managedRoot, ociRunLive(observerDir))
	rp.failed.Store(err != nil)
	rp.pending.Store(err != nil || left > 0)
	rp.sweeps.Add(1)
}

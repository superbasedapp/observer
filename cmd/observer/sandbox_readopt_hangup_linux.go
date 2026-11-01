//go:build linux && !sbo_omit_terminals_sandbox_oci_readopt && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxadopt"
	"github.com/marmutapp/superbased-observer/internal/sandboxoci"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
)

// sandbox_readopt_hangup_linux.go closes audit F2 of lane GATES-SBX (R-033):
// a daemon restart can offer a live container run for re-adoption. Before
// its PTYs close, a daemon exiting while it routes a re-adoptable run (its
// plan kept, its helper alive) writes the run's daemon-exit mark; the
// helper, asked to stop by the hangup that follows, keeps the container
// when sandboxadopt.KeepOnHangup says so (the mark is fresh, the component
// on, the plan kept) and exits without its teardown, as a killed helper
// would. The daemon's next start sweeps it like any other run whose helper
// went away and offers it, within the re-adoption bound.

func init() {
	sandboxDaemonExitMark = readoptMarkDaemonExit
	ociReadoptKeepOnHangup = readoptHangupKeeper
	ociReadoptAwaitOffer = readoptAwaitOfferFor
}

// readoptMark is the daemon-exit mark's body.
type readoptMark struct {
	V        int       `json:"v"`
	RunID    string    `json:"run_id"`
	MarkedAt time.Time `json:"marked_at"`
}

// readoptMarkDaemonExit marks every live re-adoptable run of the daemon's
// observer dir. Best-effort: an unmarked run is stopped by its helper as
// before.
func readoptMarkDaemonExit() {
	p := readoptObserverDir.Load()
	if p == nil {
		return
	}
	readoptMarkDaemonExitIn(*p, readoptNow())
}

// readoptMarkDaemonExitIn is readoptMarkDaemonExit for one observer dir; it
// returns the runs it marked.
func readoptMarkDaemonExitIn(observerDir string, now time.Time) []string {
	entries, err := os.ReadDir(readoptDir(observerDir))
	if err != nil {
		return nil
	}
	var marked []string
	for _, de := range entries {
		run := de.Name()
		if !de.IsDir() || !sandboxoci.ValidToken(run) {
			continue
		}
		e := readoptRead(observerDir, run)
		if !e.keptOK || !e.planOK || e.hasOffer || readoptHelper(observerDir, run) != readoptHelperHeld {
			continue
		}
		// A CLI run is not the daemon's (LEFT2 audit S2): the same watch-file
		// test the sweep uses, so a hangup there always stops the container.
		if readoptCLIRun(observerDir, e) {
			continue
		}
		if readoptWriteFile(readoptRunDir(observerDir, run), sandboxadopt.DaemonExitMark, readoptMark{V: readoptVersion, RunID: run, MarkedAt: now}) == nil {
			marked = append(marked, run)
		}
	}
	return marked
}

// readoptHangupKeeper is the helper's hangup check for one run: it reads
// the facts once per hangup and consumes the mark.
func readoptHangupKeeper(observerDir, runID string) func() bool {
	if observerDir == "" || !sandboxoci.ValidToken(runID) {
		return nil
	}
	return func() bool {
		f := sandboxadopt.HangupFacts{Now: readoptNow()}
		f.Active = readoptLoadSettings(context.Background()).active
		e := readoptRead(observerDir, runID)
		f.Kept = e.keptOK && e.planOK
		mark := filepath.Join(readoptRunDir(observerDir, runID), sandboxadopt.DaemonExitMark)
		if b, err := readOwnedNoFollow(mark, 4096); err == nil {
			var m readoptMark
			if json.Unmarshal(b, &m) == nil && m.V == readoptVersion && m.RunID == runID {
				f.Marked, f.MarkedAt = true, m.MarkedAt
			}
		}
		_ = os.Remove(mark)
		keep, _ := sandboxadopt.KeepOnHangup(f)
		return keep
	}
}

// readoptOfferPoll is how often a kept helper looks for the next start's
// offer.
const readoptOfferPoll = 2 * time.Second

// readoptSleep is the kept helper's sleep (a test seam beside readoptNow).
var readoptSleep = time.Sleep

// readoptAwaitOfferFor is the kept helper's lifetime bound (LEFT2 audit S4):
// a container kept through a daemon hangup is not left running without its
// helper or capture until some later start. The helper drops its liveness
// lock (so the next start's sweep reads it as gone, exactly as for a killed
// helper), then waits at most the re-adoption bound for that start to offer
// the run. true: offered, the daemon owns the run now and the helper leaves
// it; false: no offer in time, and the helper stops the container.
func readoptAwaitOfferFor(observerDir, runID string) func() bool {
	if observerDir == "" || !sandboxoci.ValidToken(runID) {
		return nil
	}
	return func() bool {
		sandboxrelayd.DropRunLock(observerDir, runID)
		bound := readoptLoadSettings(context.Background()).bound
		return readoptAwaitOffer(observerDir, runID, bound, readoptNow, readoptSleep)
	}
}

// readoptAwaitOffer polls the run's re-adoption entry for an offer until
// the bound (clamped like the sweep's) runs out on the clock now.
func readoptAwaitOffer(observerDir, runID string, bound time.Duration, now func() time.Time, sleep func(time.Duration)) bool {
	deadline := now().Add(sandboxadopt.ClampBound(bound))
	for {
		if readoptRead(observerDir, runID).hasOffer {
			return true
		}
		left := deadline.Sub(now())
		if left <= 0 {
			return false
		}
		sleep(min(readoptOfferPoll, left))
	}
}

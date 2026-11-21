//go:build !sbo_omit_terminals_sandbox_credentials && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxcred"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// sandbox_cred_sweep.go is the daemon's sweep of the credential files of
// dead runs (tracker F-055): each run's injection record under
// sandbox-cred/runs and its kept fresh session ids under sandbox-cred/fresh.
// The run's host helper removes both at its clean end (credLocalEnd,
// credTeardown); a helper killed before a daemon restart, or a run ended in
// a way that skipped that end, left them for good. The relay runs this at
// start, after its prune of dead helpers' records, and after every sweep
// (sandboxrelayd.Daemon.OnSweep). sandboxcred.SweepRecord decides each
// file; this file only reads the facts and removes what it lets go.

func init() { sandboxRelaySweepHooks = append(sandboxRelaySweepHooks, credSweepDead) }

// credSweepGrace is how long a credential file is kept whatever else is
// true, so a run that is starting is never swept.
const credSweepGrace = time.Minute

// credSweepDeadRunHeld asks the relay's dead-run hold (a test seam).
var credSweepDeadRunHeld = sandboxrelayd.DeadRunHeld

// credSweepDead removes the credential files of dead runs under
// observerDir and logs how many it removed.
func credSweepDead(observerDir string) {
	if observerDir == "" {
		return
	}
	// The dead-run hold is asked at most once per run in one sweep, across
	// both directories (audit FU11-A3): the hold writes its own decision
	// line when it lets a kept run go.
	asked := map[string]bool{}
	held := func(runID string) bool {
		h, ok := asked[runID]
		if !ok {
			h = credSweepDeadRunHeld(observerDir, runID)
			asked[runID] = h
		}
		return h
	}
	n := credSweepDir(observerDir, credRunsDir(observerDir), held) + credSweepDir(observerDir, credFreshDir(observerDir), held)
	if n > 0 {
		slog.Default().Info("sandbox credentials: removed the credential files of ended runs", "count", n)
	}
}

// credSweepDir sweeps one of the two directories; it returns how many
// files it removed. Only regular "<run>.json" files with a valid run id
// are considered; anything else is left as it is.
func credSweepDir(observerDir, dir string, held func(runID string) bool) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	now := credNow()
	n := 0
	for _, e := range entries {
		id, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || !e.Type().IsRegular() || !vocab.ValidRelayRunID(id) {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		remove, _ := sandboxcred.SweepRecord(credSweepFacts(observerDir, id, fi.ModTime(), now, held))
		if !remove {
			continue
		}
		if os.Remove(filepath.Join(dir, e.Name())) == nil { //nolint:gosec // G703: a valid run id under the daemon's own sandbox-cred dir
			n++
		}
	}
	return n
}

// credSweepFacts reads what the sweep knows about one run.
func credSweepFacts(observerDir, runID string, mod, now time.Time, held func(runID string) bool) sandboxcred.SweepFacts {
	_, relayErr := os.Lstat(filepath.Join(sandboxrelayd.RunsDir(observerDir), runID+".json")) //nolint:gosec // G703: a fixed name under the daemon's own runs dir; the id passed ValidRelayRunID
	_, hostedErr := os.Lstat(hostedRecordPath(observerDir, runID))                            //nolint:gosec // G703: as above, under the daemon's own sandbox-hosted dir
	return sandboxcred.SweepFacts{
		Young:             now.Sub(mod) < credSweepGrace,
		HelperLive:        sandboxrelayd.RunLive(observerDir, runID),
		RelayRecord:       relayErr == nil,
		HostedRecord:      hostedErr == nil,
		HeldByDeadRunHold: func() bool { return held(runID) },
	}
}

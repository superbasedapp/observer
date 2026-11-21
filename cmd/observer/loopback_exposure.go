//go:build !sbo_omit_terminals

package main

import (
	"context"
	"fmt"
	"runtime"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/agentlaunch"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// loopback_exposure.go feeds the dashboard's loopback exposure gate
// (read by the caller check, loopback_caller.go; security ledger LAUNCH-1): the
// live sandboxed runs whose box can reach this daemon's loopback listener.
// Two sources, one rule (agentlaunch.LoopbackExposure): the daemon's own
// terminals (the PTY snapshot, exact liveness) and the sandboxed CLI
// launches (`observer <tool> --observer-sandbox`), which live outside the
// daemon and count only while their CLI still watches the run.

// sandboxCLIMarker is one sandboxed CLI launch's watch marker: the run it
// names, its path, and the CLI process it recorded (0 when unknown).
type sandboxCLIMarker struct {
	RunID string
	Path  string
	PID   int
	// Start names the CLI process's start ("" when the marker has none).
	Start string
}

// cliRunState is the end a sandboxed CLI launch's row records, as the
// marker sweep reads it.
type cliRunState struct {
	Ended     bool
	EndReason string
}

// endedForGood reports an end that proves the run is over. A graceful
// daemon stop stamps daemon_shutdown on every live non-attach row while a
// CLI launch and its box keep running (P-074), so that stamp alone does
// not (cli-1b fixes-4, N1).
func (r cliRunState) endedForGood() bool {
	return r.Ended && r.EndReason != store.EndReasonDaemonShutdown
}

// loopbackExposureSources are the inputs of the check, as functions so the
// tests drive them with fakes.
type loopbackExposureSources struct {
	snapshot func() []dashapi.LaunchInfo
	// markers lists the sandboxed CLI launches' watch markers (a directory
	// read, no database).
	markers func() []sandboxCLIMarker
	// runRows reads the sandboxed rows of the markers' runs, ended or not
	// (store.SandboxedTerminalRunsByID); read only when a marker exists.
	// Nil when no DB is wired, where no CLI launch can record its run.
	runRows func(ctx context.Context, runIDs []string) ([]store.TerminalRunSummary, error)
	// sweep drops the stale markers (sweepSandboxCLIMarkers) and returns
	// those that stay.
	sweep func(markers []sandboxCLIMarker, rows map[string]cliRunState) []sandboxCLIMarker
}

// check is the seam the dashboard calls on a gated route.
func (src loopbackExposureSources) check(ctx context.Context) (string, bool) {
	all, reason, failed := src.exposures(ctx)
	if failed {
		return reason, true
	}
	if len(all) == 0 {
		return "", false
	}
	return all[0].Reason() + markerHint(all[0].Run.Marker), true
}

// exposures is every live box that can reach this listener. failed is a
// read failure, with its refusal line (fail closed, fixes-2 N3).
func (src loopbackExposureSources) exposures(ctx context.Context) (all []agentlaunch.Exposure, reason string, failed bool) {
	var runs []agentlaunch.BoxRun
	if src.snapshot != nil {
		for _, s := range src.snapshot() {
			if s.Exited || s.Isolation == nil {
				continue
			}
			runs = append(runs, boxRun(s.RunID, s.Isolation.Class, s.Isolation.Backend, s.Isolation.EgressTier))
		}
	}
	cli, reason, failed := src.cliBoxes(ctx)
	if failed {
		return nil, reason, true
	}
	runs = append(runs, cli...)
	return agentlaunch.LoopbackExposures(runs), "", false
}

// cliBoxes is the sandboxed CLI launches that are live boxes: every watch
// marker that survives the sweep and names a sandboxed row, whatever end
// that row records (the sweep already dropped those proven over; a row
// ended by a daemon's graceful stop with its box still running is gated,
// fixes-4 N1). No
// marker means no CLI box and no database read (cli-1b fixes-3, C: a busy
// database cannot refuse New Terminal on a node that runs none). With a
// marker, a read error fails closed (fixes-2, N3).
func (src loopbackExposureSources) cliBoxes(ctx context.Context) (boxes []agentlaunch.BoxRun, reason string, failed bool) {
	if src.markers == nil || src.runRows == nil {
		return nil, "", false
	}
	markers := src.markers()
	if len(markers) == 0 {
		return nil, "", false
	}
	byID, states, err := src.markerRows(ctx, markers)
	if err != nil {
		return nil, fmt.Sprintf("refused because the live sandboxed runs could not be read (%v), so one that can reach this dashboard cannot be ruled out; "+
			"retry, or launch with `observer launch` from your own terminal (security ledger LAUNCH-1)", err), true
	}
	if src.sweep != nil {
		markers = src.sweep(markers, states)
	}
	for _, m := range markers {
		h, ok := byID[m.RunID]
		if !ok {
			continue
		}
		backend, _, _ := strings.Cut(h.Stack, ",")
		b := boxRun(h.RunID, h.IsolationClass, backend, h.EgressTier)
		b.Marker = m.Path
		boxes = append(boxes, b)
	}
	return boxes, "", false
}

// markerRows reads the sandboxed rows of markers' runs and their end states.
func (src loopbackExposureSources) markerRows(ctx context.Context, markers []sandboxCLIMarker) (map[string]store.TerminalRunSummary, map[string]cliRunState, error) {
	ids := make([]string, 0, len(markers))
	for _, m := range markers {
		ids = append(ids, m.RunID)
	}
	rows, err := src.runRows(ctx, ids)
	if err != nil {
		return nil, nil, err
	}
	byID := make(map[string]store.TerminalRunSummary, len(rows))
	states := make(map[string]cliRunState, len(rows))
	for _, r := range rows {
		byID[r.RunID] = r
		states[r.RunID] = cliRunState{Ended: r.EndedAt != nil, EndReason: r.EndReason}
	}
	return byID, states, nil
}

// markerHint is the refusal's last sentence for a CLI launch's box: the
// marker that keeps it counted, and how to remove it if the run is gone.
func markerHint(path string) string {
	if path == "" {
		return ""
	}
	rm := "rm -- '" + path + "'"
	if runtime.GOOS == "windows" {
		rm = `del "` + path + `"`
	}
	return fmt.Sprintf(" The run counts as live while its CLI's marker %s exists; if that run is gone, remove the marker: %s", path, rm)
}

// boxRun is one run's evidence for the rule, with the backend row's
// capabilities resolved here (sandboxRowHostLoopbackRelay,
// sandboxRowDeniesObserverPorts, sandboxRowTreeContained).
func boxRun(runID, class, backend, tier string) agentlaunch.BoxRun {
	return agentlaunch.BoxRun{
		RunID: runID, Class: class, Backend: backend, Tier: tier,
		HostLoopbackRelay:   sandboxRowHostLoopbackRelay(backend),
		DeniesObserverPorts: sandboxRowDeniesObserverPorts(backend),
		TreeContained:       sandboxRowTreeContained(backend),
	}
}

// loopbackExposureSources are the exposure rule's inputs over the shared
// terminal stack (the caller gate reads them too, loopback_caller.go).
func (s *terminalStack) loopbackExposureSources() loopbackExposureSources {
	a := s.launchManager()
	observerDir := s.observerDir
	return loopbackExposureSources{
		snapshot: a.Snapshot,
		markers:  func() []sandboxCLIMarker { return sandboxCLIMarkers(observerDir) },
		runRows:  s.sandboxedRunRows,
		sweep:    sandboxCLIMarkerSweeper(observerDir),
	}
}

// sweepStale runs the marker sweep once; a read error leaves the markers
// for the next sweep.
func (src loopbackExposureSources) sweepStale(ctx context.Context) {
	if src.markers == nil || src.runRows == nil || src.sweep == nil {
		return
	}
	markers := src.markers()
	if len(markers) == 0 {
		return
	}
	_, states, err := src.markerRows(ctx, markers)
	if err != nil {
		return
	}
	src.sweep(markers, states)
}

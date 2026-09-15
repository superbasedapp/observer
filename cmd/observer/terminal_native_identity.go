package main

import (
	"context"

	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/termrun"
)

// linkNativeAdapterSessions uses the native session ownership before the generic
// tool/root/time matching pass. Each uncertain supported run waits for the next
// tick without delaying terminals that have an identified primary writer.
// Uncertainty never falls back to guessing between terminals.
func (d *terminalDiscoverer) linkNativeAdapterSessions(ctx context.Context, runs []store.UncorrelatedTerminalRun) (int, map[string]bool) {
	handled := map[string]bool{}
	if d.nativeSession == nil {
		return 0, handled
	}
	candidates := map[string][]string{}
	identities := map[string]terminalNativeIdentity{}
	for _, run := range runs {
		if handle, live := d.handleForRun(run.RunID); !live || handle == "" {
			continue
		}
		cand, err := d.nativeSession(ctx, run.RunID)
		if err == nil && cand.sessionID == "" {
			continue // unavailable on this platform/backend; existing fallback
		}
		handled[run.RunID] = true
		if err != nil || (run.Kind == string(termrun.KindHandoff) && cand.sessionID == run.SourceSessionID) {
			continue
		}
		found, err := d.st.CapturedSessionForTool(ctx, cand.sessionID, canonicalToolForRun(run.Tool))
		if err != nil || !found {
			// Wait for the watcher to capture this exact session.
			continue
		}
		candidates[run.RunID] = []string{cand.sessionID}
		identities[run.RunID] = cand
	}
	pairs := uniqueRunSessionPairs(candidates)
	links := 0
	for runID, sessionID := range pairs {
		// Refresh the identity and liveness at the write boundary. A session
		// switch, exit, stronger correlation or competing live run wins.
		if _, live := d.handleForRun(runID); !live {
			continue
		}
		if _, _, linked := d.sessionLinkForRun(runID); linked {
			continue
		}
		claimed, err := d.st.LiveRunForSession(ctx, sessionID, termrun.MinLinkConfidence)
		if err != nil || claimed {
			continue
		}
		fresh, err := d.nativeSession(ctx, runID)
		if err != nil || fresh.sessionID != sessionID || fresh.evidence != identities[runID].evidence {
			continue
		}
		if err := d.correlate(ctx, runID, sessionID, termrun.SourceDiscovered, d.now().UTC()); err != nil {
			d.logger.Debug("terminal discovery: native adapter correlation failed", "err", err)
			continue
		}
		links++
	}
	return links, handled
}

// discoverNativeSessions removes inspected runs from the generic timing pass,
// including ambiguous/uncaptured runs which must wait for native evidence.
func (d *terminalDiscoverer) discoverNativeSessions(ctx context.Context, runs []store.UncorrelatedTerminalRun) (int, []store.UncorrelatedTerminalRun) {
	links, handled := d.linkNativeAdapterSessions(ctx, runs)
	remaining := make([]store.UncorrelatedTerminalRun, 0, len(runs))
	for _, run := range runs {
		if !handled[run.RunID] {
			remaining = append(remaining, run)
		} else {
			delete(d.pending, run.RunID)
		}
	}
	return links, remaining
}

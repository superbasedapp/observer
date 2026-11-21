//go:build !sbo_omit_terminals

package main

import (
	"context"
	"fmt"
	"net/netip"
	"os"

	"github.com/marmutapp/superbased-observer/internal/callerid"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/peerproc"
)

// loopback_caller.go is the daemon side of the dashboard's caller check
// (dashapi.Options.LoopbackCallerGate, security ledger LAUNCH-1, lane
// callerid). On every mutating request from a local peer, while a box that
// can reach this listener is live, it identifies the process at the other
// end of the connection (internal/peerproc) and asks the pure table
// (internal/callerid.Decide) whether that process runs inside a live
// Observer box: a strict descendant of a box root. Box roots are the child
// process of each live sandboxed daemon terminal (the host helper the PTY
// runs) and the CLI process of each watched sandboxed CLI launch (its
// marker's pid, checked against its start token). The owner's browser, a
// process outside every box, passes while a box runs; it is refused when it
// cannot be identified (unless its socket belongs to another uid, which no
// box can open, and every box process was read), or while a reachable box
// cannot be traced to a known root (its root pid
// is unknown, or its backend has no PID namespace of its own). With no
// reachable box live, nothing is looked up.

// callerGateSources are the gate's inputs, as functions so tests drive
// them with fakes.
type callerGateSources struct {
	// snapshot lists the daemon's terminals.
	snapshot func() []dashapi.LaunchInfo
	// pidFor is a terminal handle's child process.
	pidFor func(handle string) (int, bool)
	// markers lists the sandboxed CLI launches' watch markers.
	markers func() []sandboxCLIMarker
	// cliAlive reports whether a marker's CLI is still that process.
	cliAlive func(pid int, start string) bool
	// exposures is every live box that can reach this listener
	// (loopbackExposureSources.exposures).
	exposures func(ctx context.Context) (boxes []exposedBox, reason string, failed bool)
	// find identifies the peer process; roots are the live box roots, for
	// the fallback when the holder cannot be read (peerproc.Find).
	find func(ctx context.Context, client, server netip.AddrPort, roots map[int]string) (peerproc.Peer, error)
	// uid is this daemon's uid (os.Getuid when nil), to tell a socket
	// another uid owns (callerid.Facts.SocketOtherUID).
	uid func() int
}

// exposedBox is one live box that can reach this listener.
type exposedBox struct {
	RunID string
	// TreeContained: its processes stay descendants of its root
	// (agentlaunch.BoxRun.TreeContained).
	TreeContained bool
}

// boxRoots maps each live box root's pid to its run id.
func (g callerGateSources) boxRoots() map[int]string {
	roots := map[int]string{}
	if g.snapshot != nil && g.pidFor != nil {
		for _, s := range g.snapshot() {
			if s.Exited || !s.Sandboxed || s.RunID == "" {
				continue
			}
			if pid, ok := g.pidFor(s.ID); ok && pid > 0 {
				roots[pid] = s.RunID
			}
		}
	}
	if g.markers != nil && g.cliAlive != nil {
		for _, m := range g.markers() {
			if m.PID > 0 && g.cliAlive(m.PID, m.Start) {
				roots[m.PID] = m.RunID
			}
		}
	}
	return roots
}

// check is the seam the dashboard calls on every request. It returns the
// refusal line and true to refuse.
func (g callerGateSources) check(ctx context.Context, client, server netip.AddrPort, mutating bool) (string, bool) {
	// An address the request path could not parse is treated as a local
	// peer: the safe reading of a connection whose origin is unknown.
	f := callerid.Facts{Mutating: mutating, LocalPeer: !client.IsValid() || callerid.IsLocalPeer(client, server)}
	if !f.Mutating || !f.LocalPeer {
		return "", false
	}
	exposed, exposedReason, failed := g.exposures(ctx)
	f.ExposedBoxLive = failed || len(exposed) > 0
	if !f.ExposedBoxLive {
		return "", false // C3: no box can reach this listener, so no lookup
	}
	roots := g.boxRoots()
	rooted := map[string]bool{}
	for _, run := range roots {
		rooted[run] = true
	}
	for _, b := range exposed {
		if !rooted[b.RunID] || !b.TreeContained {
			f.UnrootedExposedBox = true
		}
	}
	var peer peerproc.Peer
	var ferr error
	if client.IsValid() {
		peer, ferr = g.find(ctx, client, server, roots)
	} else {
		ferr = fmt.Errorf("the connection's client address is unknown")
	}
	f.Identified = ferr == nil && !peer.Outside
	f.ProvenOutside = ferr == nil && peer.Outside
	ownUID := os.Getuid()
	if g.uid != nil {
		ownUID = g.uid()
	}
	f.SocketOtherUID = peer.SocketUID >= 0 && peer.SocketUID != ownUID
	var run string
	if f.Identified {
		run, f.InBox = callerid.InBox(peer.Ancestors, roots)
	}
	v, rule := callerid.Decide(f)
	switch v {
	case callerid.RefuseBox:
		return fmt.Sprintf("refused: this request comes from process %d inside sandboxed run %s, and a process in an Observer sandbox may not change this dashboard's settings, launch, approve or type into a terminal (security ledger LAUNCH-1, rule %s)", peer.PID, run, rule), true
	case callerid.RefuseUnrooted:
		return fmt.Sprintf("refused: a sandboxed run that can reach this dashboard is live and its processes cannot all be traced to a known root (its root process could not be located, or its backend has no PID namespace of its own, so a process can leave its tree), so this request cannot be shown to come from outside it (%s); stop that run, or use `observer launch` from your own terminal (security ledger LAUNCH-1, rule %s)", exposedReason, rule), true
	case callerid.RefuseUnidentified:
		if ferr == nil {
			ferr = fmt.Errorf("no process of this user holds the connection, which a process in a box can arrange")
		}
		return fmt.Sprintf("refused: the process behind this request could not be identified (%v) while a sandboxed run that can reach this dashboard is live (%s) (security ledger LAUNCH-1, rule %s)", ferr, exposedReason, rule), true
	}
	return "", false
}

// loopbackCallerGate builds the gate over the shared terminal stack.
func (s *terminalStack) loopbackCallerGate() func(ctx context.Context, client, server netip.AddrPort, mutating bool) (string, bool) {
	a := s.launchManager()
	observerDir := s.observerDir
	exp := s.loopbackExposureSources()
	// At daemon start, drop the markers a crash or a failed end left
	// behind (cli-1b fixes-3, B); every mutating request sweeps again.
	exp.sweepStale(context.Background())
	g := callerGateSources{
		snapshot: a.Snapshot,
		pidFor:   s.mgr.PIDForHandle,
		markers:  func() []sandboxCLIMarker { return sandboxCLIMarkers(observerDir) },
		cliAlive: sandboxCLIProcessAlive,
		exposures: func(ctx context.Context) ([]exposedBox, string, bool) {
			all, reason, failed := exp.exposures(ctx)
			if failed {
				return nil, reason, true
			}
			boxes := make([]exposedBox, 0, len(all))
			for _, e := range all {
				boxes = append(boxes, exposedBox{RunID: e.Run.RunID, TreeContained: e.Run.TreeContained})
			}
			if len(all) > 0 {
				reason = all[0].Describe() + "." + markerHint(all[0].Run.Marker)
			}
			return boxes, reason, false
		},
		find: peerproc.Find,
	}
	return g.check
}

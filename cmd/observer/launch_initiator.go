//go:build !sbo_omit_terminals

package main

import (
	"context"
	"database/sql"
	"net/netip"
	"os"

	"github.com/marmutapp/superbased-observer/internal/agentlaunch"
	"github.com/marmutapp/superbased-observer/internal/attachsock"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/peerproc"
	"github.com/marmutapp/superbased-observer/internal/pidbridge"
	"github.com/marmutapp/superbased-observer/internal/procmodel"
	"github.com/marmutapp/superbased-observer/internal/termrun"
)

// launch_initiator.go resolves who started a launch (lane cli-2, tracker
// PT-61, discovery docs/plans/discovery-cli-2026-11-03.md section 4.1
// "Recording"). It is the I/O half of internal/agentlaunch.Attribute: it
// takes the launching process (the attach endpoint's peer credentials, the
// dashboard connection's holder, or this CLI process itself), walks its
// ancestry ONCE through peerproc.Ancestors (the walk the dashboard's caller
// check uses; no second walker), and asks, nearest first, whether an
// ancestor is a live agent session: the child of a live daemon terminal that
// runs a registry tool, or a pid the session bridge (session_pid_bridge,
// written at an agent's SessionStart hook) holds a live row for. The answer
// is recorded on the run (migration 220) and shown by `observer terminals`
// and the dashboard; an agent's launch is held for a human's confirm
// (launch_pending.go), and the guard's ask on it is R-168, at the agent's
// own hook (docs/guard.md "Agent-initiated launches"). When no ancestor is a
// live agent, the daemon reads the agent session marker from the caller's
// and its ancestors' environment itself (envMarker, Linux).
//
// An attach-endpoint caller is read at accept as well (snapshotCaller,
// lane cli-2 fixes-3, audit M1), and a request whose caller is no longer
// the process that connected (it exited after handing the connection to a
// child, or its pid was reused) is refused, never judged by what the pid
// reads as now (attachCaller).
//
// What it cannot see: a caller that left its agent's process tree (a
// double fork that reparents it to init, a service the agent asked to run
// the launch) before it connected, and runs with an environment that
// carries no agent marker, reads as a human launch, or as unknown when it
// cannot be identified at all (agentlaunch row I3-unidentified). That is a
// named residual (security ledger LAUNCH-2 (0)); the attribution is
// governance, not a boundary, inside the documented same-user model.

// launchInitiator is the resolver's inputs, as functions so tests drive it
// with fakes.
type launchInitiator struct {
	// ancestors is peerproc.Ancestors.
	ancestors func(pid int) []int
	// agentRoots maps the child pid of each live daemon terminal that runs
	// a registry tool to its run id.
	agentRoots func() map[int]string
	// sessionFor is a run's correlated session (termsvc.SessionForRun).
	sessionFor func(runID string) (string, bool)
	// liveSession is the session bridge's live row for a pid
	// (pidbridge.Store.LiveSession); nil when no database is wired.
	liveSession func(ctx context.Context, pid int) (string, bool)
	// envMarker reads the agent session marker from the environment of the
	// first of pids that carries one (peerproc.EnvMarker over
	// procmodel.SessionTokenEnvKeys; lane cli-2 fixes-2, audit H-A): the
	// daemon reads it itself, so a caller that does not report its marker
	// (an agent running `observer terminals confirm`, a curl to the
	// dashboard) is still an agent's. nil reads nothing.
	envMarker func(pids []int) (string, bool)
	// startOf is the token naming the current start of a pid
	// (peerproc.StartToken; lane cli-2 fixes-3, audit M1): an attach
	// caller whose pid no longer holds the start the endpoint read at
	// accept is gone (attachCaller). nil reads nothing, so an identified
	// attach caller is judged gone.
	startOf func(pid int) (string, bool)
	// daemonPID is the daemon's own pid (lane cli-2 fixes-3, audit L4): a
	// caller's chain is judged up to the daemon, not past it, so the agent
	// whose shell started the daemon (its marker is in the daemon's
	// environment and its session in the daemon's ancestry) does not make
	// every process in a dashboard terminal an agent's. A daemon terminal
	// running an agent is still found below it (agentRoots). 0 (the
	// foreground CLI, whose caller is itself) judges the whole chain.
	daemonPID int
}

// belowDaemon is chain cut before the daemon's own pid (daemonPID), when
// the daemon is a strict ancestor of the caller.
func belowDaemon(chain []int, daemon int) []int {
	if daemon <= 0 {
		return chain
	}
	for i, p := range chain {
		if i > 0 && p == daemon {
			return chain[:i]
		}
	}
	return chain
}

// readSessionMarker is the production envMarker.
func readSessionMarker(pids []int) (string, bool) {
	return peerproc.EnvMarker(pids, procmodel.SessionTokenEnvKeys)
}

// withProcessReaders returns l with the platform's process readers: the
// ancestry walk, the daemon's own read of the agent session marker and the
// start token. Every production resolver is built through it, so none can
// lose one of the readers (pinned by TestProductionInitiatorReadsTheCaller).
func withProcessReaders(l launchInitiator) launchInitiator {
	l.ancestors, l.envMarker, l.startOf = peerproc.Ancestors, readSessionMarker, peerproc.StartToken
	return l
}

// callerSeen is what the daemon read about an attach caller when the
// endpoint accepted its connection (snapshotCaller; fixes-3, audit M1).
type callerSeen struct {
	pid int
	// chain is the caller and its ancestors, nearest first.
	chain []int
	// marker is the agent session marker found in their environment.
	marker   string
	markerOK bool
}

type callerSeenKey struct{}

// snapshotCaller reads the attach caller's ancestry and environment
// marker at accept (attachsock.CallerSnapshotter): a process that exits,
// or an ancestor that exits and reparents it, cannot shed them after it
// connected. facts merges them with what it reads when the request is
// judged.
func (l launchInitiator) snapshotCaller(ctx context.Context, pid int) context.Context {
	if pid <= 0 {
		return ctx
	}
	seen := callerSeen{pid: pid, chain: []int{pid}}
	if l.ancestors != nil {
		seen.chain = append(seen.chain, l.ancestors(pid)...)
	}
	seen.chain = belowDaemon(seen.chain, l.daemonPID)
	if l.envMarker != nil {
		seen.marker, seen.markerOK = l.envMarker(seen.chain)
	}
	return context.WithValue(ctx, callerSeenKey{}, seen)
}

// seenAtConnect is the snapshot of pid in ctx, if any.
func seenAtConnect(ctx context.Context, pid int) (callerSeen, bool) {
	s, ok := ctx.Value(callerSeenKey{}).(callerSeen)
	return s, ok && s.pid == pid
}

// facts resolves the caller facts for one launch. pid <= 0 means the
// caller was not identified; envSession is the agent session marker the
// caller reported ("" none). A snapshot of the caller taken at accept
// (snapshotCaller) widens the chain with the ancestors it had then and
// supplies the marker it carried then.
func (l launchInitiator) facts(ctx context.Context, front agentlaunch.Front, pid int, envAgent bool, envSession string) agentlaunch.CallerFacts {
	f := agentlaunch.CallerFacts{Front: front, Identified: pid > 0, AgentEnv: envAgent, EnvSession: envSession}
	if pid <= 0 {
		return f
	}
	chain := []int{pid}
	if l.ancestors != nil {
		chain = append(chain, l.ancestors(pid)...)
	}
	seen, haveSeen := seenAtConnect(ctx, pid)
	if haveSeen {
		chain = mergeChain(chain, seen.chain)
		if !f.AgentEnv && seen.markerOK {
			f.AgentEnv, f.EnvSession = true, seen.marker
		}
	}
	chain = belowDaemon(chain, l.daemonPID)
	var roots map[int]string
	if l.agentRoots != nil {
		roots = l.agentRoots()
	}
	for _, p := range chain {
		if run, ok := roots[p]; ok {
			f.AgentAncestor = true
			if l.sessionFor != nil {
				f.AncestorSession, _ = l.sessionFor(run)
			}
			return f
		}
		if l.liveSession != nil {
			if sess, ok := l.liveSession(ctx, p); ok {
				f.AgentAncestor, f.AncestorSession = true, sess
				return f
			}
		}
	}
	// No ancestor is a live agent: the caller (or an ancestor, whose
	// environment a child cannot change) may still carry an agent
	// session's marker, which the daemon reads itself (fixes-2, H-A).
	if !f.AgentEnv && l.envMarker != nil {
		if v, ok := l.envMarker(chain); ok {
			f.AgentEnv, f.EnvSession = true, v
		}
	}
	return f
}

// mergeChain appends to now the pids of then it lacks, in then's order.
func mergeChain(now, then []int) []int {
	have := make(map[int]bool, len(now))
	for _, p := range now {
		have[p] = true
	}
	for _, p := range then {
		if !have[p] {
			have[p] = true
			now = append(now, p)
		}
	}
	return now
}

// origin is the recorded origin of one launch.
func (l launchInitiator) origin(ctx context.Context, front agentlaunch.Front, pid int, envAgent bool, envSession string) termrun.Origin {
	return agentlaunch.Attribute(l.facts(ctx, front, pid, envAgent, envSession)).Origin
}

// attachCaller judges the attach endpoint's caller in ctx (lane cli-2
// fixes-3, audit M1): its origin, or the line saying it is gone. The pid
// the endpoint recorded names the process that connected; a request sent
// after that process exited (by a child it handed the connection to) or
// after its pid was reused must not be judged by whatever the pid reads
// as now, so the caller is checked against the start read at accept
// before its facts are read and again after (a process that exits while
// they are read leaves them half read). An unidentified caller is judged
// as before (agentlaunch row I3-unidentified).
func (l launchInitiator) attachCaller(ctx context.Context, envAgent bool, envSession string) (o termrun.Origin, gone string) {
	pid, _ := attachsock.CallerPID(ctx)
	if pid <= 0 {
		return l.origin(ctx, agentlaunch.FrontCLI, 0, envAgent, envSession), ""
	}
	if why := l.callerGone(ctx, pid); why != "" {
		return termrun.Origin{}, why
	}
	o = l.origin(ctx, agentlaunch.FrontCLI, pid, envAgent, envSession)
	if why := l.callerGone(ctx, pid); why != "" {
		return termrun.Origin{}, why
	}
	return o, ""
}

// callerGone is CallerPresent's line for pid against the start read at
// accept, "" when the caller is still the process that connected.
func (l launchInitiator) callerGone(ctx context.Context, pid int) string {
	at, _ := attachsock.CallerStart(ctx)
	now := ""
	if l.startOf != nil {
		now, _ = l.startOf(pid)
	}
	if ok, why, _ := agentlaunch.CallerPresent(agentlaunch.CallerIdentity{AtConnect: at, Now: now}); !ok {
		return why
	}
	return ""
}

// dashboardOrigin is the origin of a dashboard launch or confirm: the
// connection's holder (peerproc.Find) is the caller, judged by its ancestry
// and by the session marker in its or an ancestor's environment. A caller
// that cannot be identified (a browser carried by another uid's relay, a
// platform with no lookup) is recorded unknown (agentlaunch row
// I3-unidentified).
func (l launchInitiator) dashboardOrigin(ctx context.Context, client, server netip.AddrPort) (initiator, parentSession string) {
	pid := 0
	if client.IsValid() {
		if peer, err := peerproc.Find(ctx, client, server, nil); err == nil && !peer.Outside {
			pid = peer.PID
		}
	}
	o := l.origin(ctx, agentlaunch.FrontDashboard, pid, false, "")
	return string(o.Initiator), o.ParentSessionID
}

// agentSessionEnv reads the agent session marker from an environment: the
// first allowlisted session-id variable (procmodel.SessionTokenEnvKeys, its
// one owner) with a value. Only that value is read; nothing else of the
// environment is.
func agentSessionEnv(getenv func(string) string) (found bool, sessionID string) {
	for _, k := range procmodel.SessionTokenEnvKeys {
		if v := getenv(k); v != "" {
			return true, v
		}
	}
	return false, ""
}

// liveSessionFor is the session bridge read over db, nil without one.
func liveSessionFor(db *sql.DB) func(ctx context.Context, pid int) (string, bool) {
	if db == nil {
		return nil
	}
	bridge := pidbridge.New(db)
	return func(ctx context.Context, pid int) (string, bool) {
		e, ok, err := bridge.LiveSession(ctx, pid)
		if err != nil || !ok {
			return "", false
		}
		return e.SessionID, true
	}
}

// launchInitiator builds the resolver over the shared terminal stack: the
// daemon's, which judges a caller's chain up to itself (daemonPID).
func (s *terminalStack) launchInitiator() launchInitiator {
	a := s.launchManager()
	return withProcessReaders(launchInitiator{
		daemonPID:   os.Getpid(),
		agentRoots:  func() map[int]string { return agentRootsOf(a.Snapshot(), s.mgr.PIDForHandle) },
		sessionFor:  s.svc.SessionForRun,
		liveSession: s.liveSession,
	})
}

// agentRootsOf maps the child pid of each live daemon terminal that runs an
// agent to its run id. A run is an agent's when its tool is a registry row:
// the plain-shell and SSH pseudo-tools are not, so a human typing `observer
// launch` in a dashboard shell stays a human.
func agentRootsOf(snap []dashapi.LaunchInfo, pidFor func(handle string) (int, bool)) map[int]string {
	roots := map[int]string{}
	for _, t := range snap {
		if t.Exited || t.Setup || t.RunID == "" {
			continue
		}
		if _, ok := integration.For(t.Tool); !ok {
			continue
		}
		if pid, ok := pidFor(t.ID); ok && pid > 0 {
			roots[pid] = t.RunID
		}
	}
	return roots
}

// selfLaunchOrigin is the origin of a launch this CLI process makes in the
// foreground (the sandboxed CLI path): this process is the caller, judged
// by its ancestry against the session bridge and by its own environment.
func selfLaunchOrigin(ctx context.Context, db *sql.DB) termrun.Origin {
	envAgent, envSession := agentSessionEnv(os.Getenv)
	l := withProcessReaders(launchInitiator{liveSession: liveSessionFor(db)})
	return l.origin(ctx, agentlaunch.FrontCLI, os.Getpid(), envAgent, envSession)
}

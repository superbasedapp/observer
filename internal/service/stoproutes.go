package service

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// stoproutes.go is operator ruling L-168 ("Both", 2026-11-24) for the
// daemon's OWN end of a run. The daemon IS the proxy, so a stop leaves every
// AI tool routed through it pointed at a port nobody serves. A deliberate
// stop therefore takes off the persistent routes that reach this proxy
// (journaled in the route hold, internal/proxyroute) and the next daemon
// puts back exactly those once its proxy serves; a restart keeps the port
// answering instead (its listening socket passes to the new process image),
// so nothing comes off.
//
// The `observer service` verbs decide for themselves (DecideRestart) and
// hold the route hold lock while they act; this table is what the daemon
// decides when its run ends however it was ended: a service manager's
// SIGTERM, Ctrl-C in its terminal, a console close on Windows, `kill`, the
// dashboard's Restart now, an update hand-over, or a failure. Which routes
// come off is the route hold's own table (proxyroute.holdRules: only routes
// that reach this proxy, never an organization's or a provider lane's, only
// those that can be put back exactly). The cmd layer gathers the inputs and
// performs the plan.

// StopEvent is how the daemon's run is ending. A closed vocabulary.
type StopEvent string

// The stop events.
const (
	// StopEventStop: a stop was asked for (SIGTERM from a service manager or
	// `kill`, Ctrl-C, a console close or logoff on Windows) and no restart
	// follows in this process.
	StopEventStop StopEvent = "stop"
	// StopEventRestartHandover: an in-place restart (the dashboard's Restart
	// now, `observer service restart`) whose proxy listening socket passes
	// to the new process image.
	StopEventRestartHandover StopEvent = "restart_handover"
	// StopEventRestart: an in-place restart that cannot hand the socket over
	// (no proxy listener to hand, or the socket could not be duplicated).
	StopEventRestart StopEvent = "restart"
	// StopEventUpdateHandover: an in-place update released the listeners
	// for its successor, which serves the port.
	StopEventUpdateHandover StopEvent = "update_handover"
	// StopEventFailure: a part of the daemon failed and took the run down;
	// nobody asked for a stop.
	StopEventFailure StopEvent = "failure"
)

// RouteOwner is who decides about this machine's proxy routes, as the
// daemon reads it at the end of its run.
type RouteOwner string

// The route owners.
const (
	// RouteOwnerNode: an individual node, or a managed one whose
	// organization does not maintain the routes (route posture not
	// "maintain"; the organization's own routes stay on by the hold table).
	RouteOwnerNode RouteOwner = "node"
	// RouteOwnerOrg: the organization maintains the routes (route posture
	// "maintain", govern.Effective.RoutePosture).
	RouteOwnerOrg RouteOwner = "org"
	// RouteOwnerUnknown: whether the organization maintains them could not
	// be read.
	RouteOwnerUnknown RouteOwner = "unknown"
)

// StopRoutesInputs is what the daemon knows when its run ends.
type StopRoutesInputs struct {
	Event StopEvent
	// ProxyServed: THIS process's proxy bound its port and served it. A
	// daemon whose bind failed (another daemon owns the port) never takes
	// that daemon's routes off.
	ProxyServed bool
	Owner       RouteOwner
	// VerbHolds: another Observer process holds the route hold lock (an
	// `observer service stop` or `restart` took the routes itself, or chose
	// --keep-routes, and puts them back itself).
	VerbHolds bool
}

// StopRoutesAction is what the daemon does about its routes.
type StopRoutesAction string

// The actions.
const (
	// StopRoutesLeave: the routes stay as they are.
	StopRoutesLeave StopRoutesAction = "leave"
	// StopRoutesTakeOff: take off the routes that reach this proxy and can
	// be put back exactly, journaled for the next daemon to put back once
	// its proxy serves.
	StopRoutesTakeOff StopRoutesAction = "take_off"
)

// StopRoutesPlan is the table's answer.
type StopRoutesPlan struct {
	Action StopRoutesAction
	// Rule names the row that decided; Reason says why in plain words.
	Rule   string
	Reason string
}

type stopRoutesRule struct {
	name   string
	match  func(in StopRoutesInputs) bool
	action StopRoutesAction
	reason string
}

// stopRoutesRules is the ordered decision table (CLAUDE.md rule 5); the
// first match wins. One test case per row (stoproutes_test.go).
var stopRoutesRules = []stopRoutesRule{
	{
		name:   "update hands the port over",
		match:  func(in StopRoutesInputs) bool { return in.Event == StopEventUpdateHandover },
		action: StopRoutesLeave,
		reason: "an update handed the proxy port to the new binary, which serves it",
	},
	{
		name:   "restart hands the port over",
		match:  func(in StopRoutesInputs) bool { return in.Event == StopEventRestartHandover },
		action: StopRoutesLeave,
		reason: "the proxy's listening socket passes to the restarted daemon, so the port keeps answering",
	},
	{
		name:   "a part of the daemon failed",
		match:  func(in StopRoutesInputs) bool { return in.Event == StopEventFailure },
		action: StopRoutesLeave,
		reason: "the daemon is ending because a part of it failed, not because a stop was asked for; a service manager starts it again",
	},
	{
		name:   "this proxy never served",
		match:  func(in StopRoutesInputs) bool { return !in.ProxyServed },
		action: StopRoutesLeave,
		reason: "this daemon's proxy never served its port, so the routes to that port are not its to take off",
	},
	{
		name:   "a service verb holds the routes",
		match:  func(in StopRoutesInputs) bool { return in.VerbHolds },
		action: StopRoutesLeave,
		reason: "an `observer service` stop or restart holds the routes for this stop and puts them back itself",
	},
	{
		name:   "organization maintains routes",
		match:  func(in StopRoutesInputs) bool { return in.Owner == RouteOwnerOrg },
		action: StopRoutesLeave,
		reason: "your organization maintains this machine's proxy routes, so a stop leaves them on (fail-closed)",
	},
	{
		name:   "organization route posture unreadable",
		match:  func(in StopRoutesInputs) bool { return in.Owner != RouteOwnerNode },
		action: StopRoutesLeave,
		reason: "whether your organization maintains this machine's proxy routes could not be read, so a stop leaves them on",
	},
	{
		name:   "deliberate stop",
		match:  func(in StopRoutesInputs) bool { return in.Event == StopEventStop },
		action: StopRoutesTakeOff,
		reason: "the daemon is stopping, so the routes to its proxy come off; the next daemon puts them back once its proxy answers",
	},
	{
		name:   "restart without a hand-over",
		match:  func(in StopRoutesInputs) bool { return in.Event == StopEventRestart },
		action: StopRoutesTakeOff,
		reason: "the restart cannot hand the proxy port over, so the routes come off until the restarted daemon's proxy answers",
	},
	{
		name:   "unknown event",
		match:  func(StopRoutesInputs) bool { return true },
		action: StopRoutesLeave,
		reason: "the daemon could not tell how its run is ending, so the routes stay on",
	},
}

// DecideStopRoutes walks stopRoutesRules top-down and returns the first
// match.
func DecideStopRoutes(in StopRoutesInputs) StopRoutesPlan {
	for _, r := range stopRoutesRules {
		if r.match(in) {
			return StopRoutesPlan{Action: r.action, Rule: r.name, Reason: r.reason}
		}
	}
	return StopRoutesPlan{Action: StopRoutesLeave, Rule: "none"}
}

// StartArgs returns the arguments after the `start` verb of a daemon's argv
// (argv[0] is the executable), the shape SplitExecStart returns for a unit.
// ok is false when argv does not run `<exe> start`.
func StartArgs(argv []string) ([]string, bool) {
	if len(argv) < 2 || argv[1] != "start" {
		return nil, false
	}
	return append([]string{}, argv[2:]...), true
}

// InvocationDigest identifies the command a daemon runs: its executable
// (resolved by the caller) and the arguments after `start`. The running
// daemon reports its own and `observer service restart` computes the
// installed unit's or agent's; an in-place restart re-executes the running
// command, so it stands in for the manager's restart only while the two
// match. It is a digest so the dashboard never reports the arguments
// themselves. "" (unknown) when exe is empty, and "" never matches.
func InvocationDigest(exe string, args []string) string {
	if strings.TrimSpace(exe) == "" {
		return ""
	}
	h := sha256.New()
	h.Write([]byte("sbo-invocation-v1\x00" + exe))
	for _, a := range args {
		h.Write([]byte("\x00" + a))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// InvocationsMatch reports whether two invocation digests name the same
// command; an unknown one never matches.
func InvocationsMatch(a, b string) bool {
	return a != "" && a == b
}

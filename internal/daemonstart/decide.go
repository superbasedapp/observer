package daemonstart

// ProxyState is what a probe of the launcher's proxy URL found. A closed
// vocabulary.
type ProxyState string

// The proxy states.
const (
	// ProxyDown: nothing accepted a connection on the proxy's address.
	ProxyDown ProxyState = "down"
	// ProxyServing: the Observer proxy answered its liveness probe, or a
	// listener accepted the connection without proving it is something else
	// (the TCP check every launcher made before this table existed).
	ProxyServing ProxyState = "serving"
	// ProxyForeign: a listener on this node's own proxy port answered HTTP,
	// and the answer is not the Observer proxy's liveness answer.
	ProxyForeign ProxyState = "foreign"
)

// OptOut is why auto-start is off for this launch, "" when it is on.
type OptOut string

// The opt-outs.
const (
	// OptOutNone: auto-start is on.
	OptOutNone OptOut = ""
	// OptOutFlag: the launcher was given --no-start.
	OptOutFlag OptOut = "flag"
	// OptOutConfig: [launch].start_daemon = false.
	OptOutConfig OptOut = "config"
	// OptOutTestBinary: a test binary that installed no stand-in starter;
	// a test never starts a real daemon.
	OptOutTestBinary OptOut = "test_binary"
)

// Facts is everything Decide reads, resolved by the caller.
type Facts struct {
	// Wanted: the launch needs the daemon: a launch routed through the proxy,
	// or an attach to a daemon-owned terminal. A --no-proxy-route launch does
	// not.
	Wanted bool
	// Proxy is what the probe of the launcher's proxy URL found.
	Proxy ProxyState
	// NotServed is "" when the daemon this config starts serves the API
	// proxy, else the reason it does not (a build without capture.proxy,
	// the component inactive, [proxy].enabled = false). With no proxy to
	// wait for, there is nothing for a launcher to start.
	NotServed string
	// OwnListener: the proxy URL is this node's own loopback listener at its
	// configured port (not a --proxy override pointing elsewhere).
	OwnListener bool
	// DaemonChild: this launcher runs in a terminal the daemon spawned; the
	// daemon is its parent.
	DaemonChild bool
	// InSandbox: this launcher runs inside an Observer sandbox, which reaches
	// the daemon only through its relay.
	InSandbox bool
	// OptOut is why auto-start is off, OptOutNone when it is on.
	OptOut OptOut
	// Other is the other OS context this machine's daemon belongs to (zero:
	// this one).
	Other OtherContext
	// DaemonRunning: a live daemon holds this database's start lock (its
	// proxy is still coming up, or is slow to answer).
	DaemonRunning bool
	// StartBusy: another launcher holds the launcher start lock: it is
	// starting the daemon right now.
	StartBusy bool
	// PortHeld reports whether the proxy port cannot be bound although
	// nothing answers on it (held or reserved by another program). It is
	// consulted only on the start row, so no other row pays for it; nil
	// reads as false.
	PortHeld func() bool
}

// Action is what the launcher does before its proxy-down fallback.
type Action string

// The actions.
const (
	// ActionProceed: the proxy serves; launch routed as always.
	ActionProceed Action = "proceed"
	// ActionFallback: nothing to start here; the proxy-down fallback rows
	// decide, exactly as before L-169, and nothing extra is printed.
	ActionFallback Action = "fallback"
	// ActionRefuse: do not start a daemon; print why (Decision.Rule), then
	// the proxy-down fallback rows decide.
	ActionRefuse Action = "refuse"
	// ActionWait: a daemon is already starting; wait for its proxy, bounded.
	ActionWait Action = "wait"
	// ActionStart: start the daemon this install owns, then wait for its
	// proxy, bounded.
	ActionStart Action = "start"
)

// Decision is Decide's answer.
type Decision struct {
	Action Action
	// Rule names the row that decided.
	Rule string
}

// The rule names (one per row; the tests key on them).
const (
	RuleNotWanted     = "the launch does not need the daemon"
	RuleServing       = "the proxy serves"
	RuleForeignPort   = "the port answers as something else"
	RuleNotServed     = "this daemon serves no proxy"
	RuleNotOwn        = "not this node's proxy"
	RuleDaemonChild   = "inside a daemon-owned terminal"
	RuleInSandbox     = "inside a sandbox"
	RuleOptedOut      = "auto-start is off"
	RuleOtherContext  = "the daemon belongs to another OS context"
	RuleAlreadyStarts = "a daemon is already starting"
	RulePortHeld      = "the port is held"
	RuleStart         = "start the daemon"
)

type decideRule struct {
	name   string
	match  func(f Facts) bool
	action Action
}

// decideRules is the ordered table (CLAUDE.md rule 5): the first match
// wins, one test case per row (decide_test.go).
var decideRules = []decideRule{
	// A --no-proxy-route launch: the daemon is not what it is asking for.
	{RuleNotWanted, func(f Facts) bool { return !f.Wanted }, ActionFallback},
	// The happy path, unchanged.
	{RuleServing, func(f Facts) bool { return f.Proxy == ProxyServing }, ActionProceed},
	// Something that is not Observer answers on this node's proxy port: a
	// daemon started now could not bind it, and routing into it would send
	// the tool's requests (and its key) to that program.
	{RuleForeignPort, func(f Facts) bool { return f.Proxy == ProxyForeign }, ActionRefuse},
	// A build without capture.proxy (D-514), the component inactive, or
	// [proxy].enabled = false: no proxy would come up to route through.
	{RuleNotServed, func(f Facts) bool { return f.NotServed != "" }, ActionFallback},
	// A --proxy override pointing at another host or port: not this node's
	// daemon to start.
	{RuleNotOwn, func(f Facts) bool { return !f.OwnListener }, ActionFallback},
	// The daemon spawned this terminal: it is running (its [proxy] block is
	// what to check), and a second one must never be started from inside it.
	{RuleDaemonChild, func(f Facts) bool { return f.DaemonChild }, ActionFallback},
	// A sandbox reaches the daemon through its relay; a daemon started in the
	// box would be the box's, not the machine's.
	{RuleInSandbox, func(f Facts) bool { return f.InSandbox }, ActionFallback},
	// --no-start or [launch].start_daemon = false: the pre-L-169 behaviour.
	{RuleOptedOut, func(f Facts) bool { return f.OptOut != OptOutNone }, ActionFallback},
	// The daemon lives in another OS context (a WSL daemon seen from a
	// Windows observer.exe): starting one here opens a second database, the
	// split-brain class CLAUDE.md's Don'ts name. Say where to start it.
	{RuleOtherContext, func(f Facts) bool { return f.Other.Where != "" }, ActionRefuse},
	// A daemon is already starting (its start lock is live, or another
	// launcher holds the launcher start lock): wait for it, never start a
	// second.
	{RuleAlreadyStarts, func(f Facts) bool { return f.DaemonRunning || f.StartBusy }, ActionWait},
	// Nothing answers, but the port cannot be bound: a daemon started now
	// would fail to bind it.
	{RulePortHeld, func(f Facts) bool { return f.PortHeld != nil && f.PortHeld() }, ActionRefuse},
	{RuleStart, func(Facts) bool { return true }, ActionStart},
}

// Decide walks decideRules top-down and returns the first match.
func Decide(f Facts) Decision {
	for _, r := range decideRules {
		if r.match(f) {
			return Decision{Action: r.action, Rule: r.name}
		}
	}
	return Decision{Action: ActionFallback, Rule: "none"}
}

// Rules lists the row names in table order (for the coverage test).
func Rules() []string {
	out := make([]string, 0, len(decideRules))
	for _, r := range decideRules {
		out = append(out, r.name)
	}
	return out
}

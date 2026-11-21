package agentlaunch

import "github.com/marmutapp/superbased-observer/internal/termrun"

// initiator.go is the pure attribution of who started a launch (lane cli-2,
// tracker PT-61): the ordered rows below turn what the boundary resolved
// about the launching process into the run's recorded origin
// (termrun.Origin: initiator plus, for an agent, its parent session). The
// boundary (cmd/observer launch_initiator.go) does the I/O: it identifies
// the caller (the attach endpoint's peer credentials, or the dashboard
// connection's holder), walks its ancestry once (peerproc.Ancestors) and
// asks the session pid bridge and the daemon's own live agent terminals
// whether an ancestor is a live agent session.

// Front is where a launch request entered the daemon.
type Front string

// The closed Front vocabulary.
const (
	// FrontDashboard: a dashboard launch route.
	FrontDashboard Front = "dashboard"
	// FrontCLI: the attach endpoint (`observer launch`, an attach launch)
	// or a CLI process launching in the foreground.
	FrontCLI Front = "cli"
)

// CallerFacts is what the boundary resolved about one launching process.
type CallerFacts struct {
	// Front is where the request entered.
	Front Front
	// Identified: the launching process was found (its pid is known). An
	// unidentified caller is recorded unknown, never as a human (audit M2
	// (b)), unless an agent marker says otherwise.
	Identified bool
	// AgentAncestor: a strict ancestor of the caller is a live agent
	// session's process (a pid the session bridge holds a live row for,
	// or the child of a live daemon terminal running an agent tool).
	AgentAncestor bool
	// AncestorSession is that agent's session id, "" when not known yet
	// (a daemon terminal whose run has no correlated session).
	AncestorSession string
	// AgentEnv: the caller reported an agent session's environment marker
	// (procmodel.SessionTokenEnvKeys). It can only make a launch an
	// agent's, never a human's: a caller that strips its environment is
	// still judged by its ancestry.
	AgentEnv bool
	// EnvSession is the session id the marker named.
	EnvSession string
}

// Attribution is the decision and the row that made it.
type Attribution struct {
	Origin termrun.Origin
	Rule   string
}

// attributionRow is one ordered row of the attribution table: it decides
// (true) or passes.
type attributionRow struct {
	id     string
	decide func(f CallerFacts, o *termrun.Origin) bool
}

// attributionRows are walked top-down; the first deciding row wins
// (TestAttributeRows, one case per row).
var attributionRows = []attributionRow{
	{"I1-agent-ancestor", func(f CallerFacts, o *termrun.Origin) bool {
		if !f.AgentAncestor {
			return false
		}
		o.Initiator, o.ParentSessionID = termrun.InitiatorAgent, f.AncestorSession
		if o.ParentSessionID == "" {
			o.ParentSessionID = f.EnvSession
		}
		return true
	}},
	{"I2-agent-env-marker", func(f CallerFacts, o *termrun.Origin) bool {
		if !f.AgentEnv {
			return false
		}
		o.Initiator, o.ParentSessionID = termrun.InitiatorAgent, f.EnvSession
		return true
	}},
	{"I3-unidentified", func(f CallerFacts, o *termrun.Origin) bool {
		if f.Identified {
			return false
		}
		o.Initiator = termrun.InitiatorUnknown
		return true
	}},
	{"I4-dashboard", func(f CallerFacts, o *termrun.Origin) bool {
		if f.Front != FrontDashboard {
			return false
		}
		o.Initiator = termrun.InitiatorHumanDashboard
		return true
	}},
	{"I5-cli", func(_ CallerFacts, o *termrun.Origin) bool {
		o.Initiator = termrun.InitiatorHumanCLI
		return true
	}},
}

// CodeCallerGone: an attach-endpoint launch whose caller is no longer the
// process that connected (CallerPresent); nothing was started or held.
const CodeCallerGone = "caller_gone"

// CallerIdentity is an identified attach-endpoint caller's start, as the
// endpoint read it when it accepted the connection and as the caller's pid
// reads when the request is judged (lane cli-2 fixes-3, audit M1). The
// endpoint records the connecting process's pid, but the request may be
// sent by another process that inherited the connection: a process that
// carries an agent's marker connects, starts a child, exits, and the child
// sends the request. The exited process's ancestry and environment can no
// longer be read, so without this check it would read as a human.
type CallerIdentity struct {
	// AtConnect is the start token read at accept ("" not read).
	AtConnect string
	// Now is the start token the pid holds now ("" the process is gone,
	// or its start cannot be read).
	Now string
}

// presenceRow is one ordered row of the caller presence decision: it
// decides the caller gone (true) or passes.
type presenceRow struct {
	id   string
	why  string
	gone func(c CallerIdentity) bool
}

// presenceRows are walked top-down; a caller no row finds gone is present
// (TestCallerPresentRows, one case per row).
var presenceRows = []presenceRow{
	{
		"G1-start-unread-at-connect", "its start was not readable when it connected, so it cannot be told from a later process with its pid",
		func(c CallerIdentity) bool { return c.AtConnect == "" },
	},
	{
		"G2-exited", "it has exited, so its ancestry and environment can no longer be read",
		func(c CallerIdentity) bool { return c.Now == "" },
	},
	{
		"G3-pid-reused", "its pid now names another process",
		func(c CallerIdentity) bool { return c.Now != c.AtConnect },
	},
}

// CallerPresent reports whether an identified caller is still the process
// that connected, the line saying why not, and the deciding row
// ("G4-present" when it is).
func CallerPresent(c CallerIdentity) (present bool, why, rule string) {
	for _, r := range presenceRows {
		if r.gone(c) {
			return false, r.why, r.id
		}
	}
	return true, "", "G4-present"
}

// CallerGoneError is the refusal of a launch whose caller is gone: why is
// CallerPresent's line.
func CallerGoneError(why string) error {
	return refuse(CodeCallerGone, "caller",
		"the process that asked for this launch is gone (%s), so the daemon cannot tell whether an agent started it; nothing was started (launch from a process that waits for the reply)", why)
}

// Attribute walks the attribution rows and returns the normalized origin
// and the deciding row.
func Attribute(f CallerFacts) Attribution {
	for _, r := range attributionRows {
		var o termrun.Origin
		if r.decide(f, &o) {
			return Attribution{Origin: o.Normalized(), Rule: r.id}
		}
	}
	return Attribution{}
}

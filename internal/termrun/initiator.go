package termrun

// initiator.go is the vocabulary of who started a terminal run (lane cli-2,
// tracker PT-61): terminal_run.initiator and terminal_run.parent_session_id
// (node migration 220). The store is the one writer of both columns; this
// package owns the closed set, so the daemon, the CLI, the dashboard and
// their tests share it.

// Initiator is who started a run. The zero value is "not recorded": a row
// from before migration 220, or a launch kind that records none.
type Initiator string

// The closed Initiator vocabulary.
const (
	// InitiatorHumanDashboard: a dashboard launch route whose caller was
	// not traced to an agent session (the owner's browser, as far as the
	// daemon can tell).
	InitiatorHumanDashboard Initiator = "human_dashboard"
	// InitiatorHumanCLI: `observer launch`, an attach launch or a
	// sandboxed CLI launch whose process was not traced to an agent
	// session.
	InitiatorHumanCLI Initiator = "human_cli"
	// InitiatorAgent: the launching process descends from a live agent
	// session, or carried an agent session's environment marker.
	InitiatorAgent Initiator = "agent"
	// InitiatorUnknown: the launching process could not be identified (a
	// browser carried by another uid's relay, a platform with no lookup),
	// so the daemon does not claim a human started it (lane cli-2 fixes-1).
	InitiatorUnknown Initiator = "unknown"
)

// Valid reports whether i is in the closed set (the zero value is not).
func (i Initiator) Valid() bool {
	switch i {
	case InitiatorHumanDashboard, InitiatorHumanCLI, InitiatorAgent, InitiatorUnknown:
		return true
	}
	return false
}

// Origin is who started a run and, for an agent, the session it was traced
// to (ParentSessionID, "" when not known). The zero value records nothing.
type Origin struct {
	Initiator       Initiator
	ParentSessionID string
}

// maxParentSessionID bounds a recorded parent session id; a longer value is
// not a session id and is dropped.
const maxParentSessionID = 256

// Normalized returns o with an unknown initiator dropped (to the zero
// value) and a parent session kept only for an agent-started run and only
// when it is a plain, bounded id: a value outside the closed set is never
// recorded.
func (o Origin) Normalized() Origin {
	if !o.Initiator.Valid() {
		return Origin{}
	}
	if o.Initiator != InitiatorAgent || !plainID(o.ParentSessionID) {
		o.ParentSessionID = ""
	}
	return o
}

// plainID reports whether s is a non-empty, bounded id with no control
// character or space.
func plainID(s string) bool {
	if s == "" || len(s) > maxParentSessionID {
		return false
	}
	for _, r := range s {
		if r <= ' ' || r == 0x7f {
			return false
		}
	}
	return true
}

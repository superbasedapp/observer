package reserve

// Prior is what a ledger already holds under a request key.
type Prior struct {
	// Exists is true when a hold was written under the key.
	Exists bool
	// Final is true when that hold is already settled (or otherwise closed).
	Final bool
	// Forwarded is true when the work behind the open hold already started
	// (the gateway's forwarded_at stamp: the upstream was dialed).
	Forwarded bool
}

// Replay is the verdict on a request key.
type Replay string

// The replay verdicts.
const (
	// ReplayFresh is a key never seen: decide the hold with Admit.
	ReplayFresh Replay = "fresh"
	// ReplayRejoin is a retry before its work started: admit on the SAME
	// open hold, never a second one (a pre-forward crash retry).
	ReplayRejoin Replay = "rejoin"
	// ReplayRefuseFinal is a replay of finished work: its cost is booked and
	// a second run would be unbudgeted. Refuse.
	ReplayRefuseFinal Replay = "replayed"
	// ReplayRefuseInFlight is a duplicate of work already running: a second
	// run would cost twice and book once. Refuse.
	ReplayRefuseInFlight Replay = "in_flight"
)

// replayRule is one row of replayRules.
type replayRule struct {
	verdict Replay
	match   func(Prior) bool
}

// replayRules decide a key, top-down, first match wins; the last row always
// matches.
func replayRules() []replayRule {
	return []replayRule{
		{verdict: ReplayFresh, match: func(p Prior) bool { return !p.Exists }},
		{verdict: ReplayRefuseFinal, match: func(p Prior) bool { return p.Final }},
		{verdict: ReplayRefuseInFlight, match: func(p Prior) bool { return p.Forwarded }},
		{verdict: ReplayRejoin, match: func(Prior) bool { return true }},
	}
}

// ReplayFor decides what a request key that may have been seen before is.
func ReplayFor(p Prior) Replay {
	for _, r := range replayRules() {
		if r.match(p) {
			return r.verdict
		}
	}
	return ReplayRejoin
}

package openshellorg

import "time"

// reopen.go is the reopen of a drained organization (FX3 item 11, live
// finding F-L4P5-5): after a drain reached drained, enabling the feature
// again left every login refused org_openshell_draining (T1), and nothing
// moved the record back to active. The reopen is an explicit, audited admin
// act, allowed only by this table.

// ReopenFacts are what the reopen is judged on.
type ReopenFacts struct {
	// Enabled: the feature's switch is on in the server config.
	Enabled bool
	// Drain is the recorded drain state.
	Drain DrainState
	// Sync is the gateway sync's last row (mint rule T8's input).
	Sync SyncFacts
	Now  time.Time
}

// reopenRule is one row: when refuses holds, the reopen is refused reason.
type reopenRule struct {
	name    string
	refuses func(ReopenFacts) bool
	reason  Reason
}

// reopenRules are walked top-down; the first that refuses wins.
var reopenRules = []reopenRule{
	{"the feature is off", func(f ReopenFacts) bool { return !f.Enabled }, ReasonOff},
	// Only a finished drain reopens: an active record has nothing to
	// reopen, and a drain still walking (draining, drain_blocked) is
	// finished (or forced) first, never abandoned half way.
	{"not drained", func(f ReopenFacts) bool { return f.Drain != DrainDrained }, ReasonIllegalTransition},
	// The gateway as T8 judges it at mint: a reopen onto a gateway no sync
	// has read recently, or one that is unsound, would reopen to refusals.
	{"no fresh sync", func(f ReopenFacts) bool {
		return !f.Sync.Present || f.Sync.Interval <= 0 || f.Now.Sub(f.Sync.CheckedAt) > 3*f.Sync.Interval
	}, ReasonGatewayStateStale},
	{"gateway unsound", func(f ReopenFacts) bool { return !f.Sync.Sound }, ReasonGatewayUnsound},
}

// DecideReopen answers ReasonNone when a drained organization may go back
// to active, else the first refusing row's reason.
func DecideReopen(f ReopenFacts) Reason {
	for _, r := range reopenRules {
		if r.refuses(f) {
			return r.reason
		}
	}
	return ReasonNone
}

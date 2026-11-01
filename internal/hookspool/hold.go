package hookspool

import (
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// HOLDING A RECORD UNTIL ITS SESSION EXISTS (T-320).
//
// A hook can fire before the watcher has ingested the session it belongs to:
// a compaction at the start of a long-resumed conversation, a session end for
// a session whose transcript the watcher has not reached, a sub-agent event
// that carries no cwd. Written straight away, a compaction capture failed the
// sessions foreign key, a session end for an unknown session was skipped by
// Ingest (it must not conjure a phantom session), and a row with no project
// root was skipped too. Each was lost.
//
// The drainer now asks Decide about every record: one that needs an existing
// session and does not have one is HELD, re-appended to the live spool with
// Attempts+1, and retried on the next pass. The hold is bounded twice - by
// age (MaxHoldAge from the record's own timestamp) and by passes
// (MaxHoldAttempts) - and the drainer additionally caps how many records it
// holds in one pass (MaxHeldPerPass), so the spool can never grow without
// bound behind a session that never arrives.

// MaxHoldAge is how long a record may wait for its session, measured from the
// record's own timestamp (the hook's time).
const MaxHoldAge = time.Hour

// MaxHoldAttempts is how many drain passes may hold one record. At the
// daemon's 5 s drain interval it is the same hour as MaxHoldAge; it bounds a
// record whose timestamp is wrong (a host clock in the future).
const MaxHoldAttempts = 720

// MaxHeldPerPass caps the records one drain pass may hold. A record past it
// expires instead, so a flood of hooks for sessions that never arrive costs
// one bounded spool, not an unbounded one.
const MaxHeldPerPass = 1024

// Disposition is what a drain pass does with one record.
type Disposition int

const (
	// Apply lands the record now.
	Apply Disposition = iota
	// Hold re-appends the record for a later pass.
	Hold
	// Expire drops the record: it waited past a bound.
	Expire
)

// String names a disposition for logs.
func (d Disposition) String() string {
	switch d {
	case Apply:
		return "apply"
	case Hold:
		return "hold"
	case Expire:
		return "expire"
	default:
		return "unknown"
	}
}

// NeedsSession reports whether the record can only land on a session row
// that already exists: a compaction (its tables reference sessions), a
// session end (Ingest will not bootstrap a session from its terminal marker)
// and a row with no project root (Ingest cannot create a session without
// one; the drainer fills the root from the existing session). An activity
// row never does.
func (r Record) NeedsSession() bool {
	if r.Kind == KindActivity {
		// Liveness is counted per (tool, event, session id) whether or not
		// the session was captured: an activity row is never held.
		return false
	}
	return r.Kind != "" || r.ActionType == models.ActionSessionEnd || r.ProjectRoot == ""
}

// holdRule is one row of the disposition table, walked top-down.
type holdRule struct {
	name  string
	match func(r Record, sessionKnown bool, now time.Time) bool
	out   Disposition
}

var holdRules = []holdRule{
	{"lands without an existing session", func(r Record, _ bool, _ time.Time) bool { return !r.NeedsSession() }, Apply},
	{"its session exists", func(_ Record, known bool, _ time.Time) bool { return known }, Apply},
	{"waited past the age cap", func(r Record, _ bool, now time.Time) bool { return now.Sub(r.Timestamp) > MaxHoldAge }, Expire},
	{"held past the attempt cap", func(r Record, _ bool, _ time.Time) bool { return r.Attempts >= MaxHoldAttempts }, Expire},
	{"wait for the session", func(Record, bool, time.Time) bool { return true }, Hold},
}

// Decide returns what a drain pass does with r. sessionKnown is whether r's
// session row exists now (the caller need not look it up when
// r.NeedsSession() is false).
func Decide(r Record, sessionKnown bool, now time.Time) Disposition {
	for _, rule := range holdRules {
		if rule.match(r, sessionKnown, now) {
			return rule.out
		}
	}
	return Hold
}

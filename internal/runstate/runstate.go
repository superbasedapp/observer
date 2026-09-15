package runstate

import "time"

// Kind names an in-flight record family. A Rule and a Signal always carry one,
// so a single rule table can serve every surface without any rule ever
// matching a record of a different family.
type Kind string

const (
	// KindArenaRun is one models.ArenaRun row (pending/running/judging ->
	// complete/failed).
	KindArenaRun Kind = "arena_run"
	// KindArenaCandidate is one models.ArenaCandidate row (pending/running ->
	// done/failed/timeout/judged/kept/discarded).
	KindArenaCandidate Kind = "arena_candidate"
	// KindTerminalRun is one terminal_run row, synthesized as status "running"
	// while ended_at IS NULL and "ended" once stamped.
	KindTerminalRun Kind = "terminal_run"
)

// Reconciled statuses this package moves a stranded record to.
const (
	// StatusFailed is the terminal status for a stranded Arena run/candidate:
	// the work can no longer complete, so honesty demands "failed" over a
	// perpetual "running".
	StatusFailed = "failed"
	// StatusAbandoned is the terminal display status for a stranded terminal
	// run: the PTY is gone but ended_at is deliberately left NULL on the row
	// (resilient-attach re-adoption keys off that), so the reconciliation is a
	// read-time display, never a stored mutation.
	StatusAbandoned = "abandoned"
)

// Reconciliation thresholds. They are generous multiples of the real worst-case
// so a genuinely-live record can never be reconciled by age alone:
//   - a single Arena candidate is wall-capped at arena.MaxTimeout (2h) and a
//     run adds only its judging tail, so 4h clears any real drive; and
//   - a dashboard terminal PTY cannot survive a daemon restart, so a run still
//     "running" a full day after launch, with no live handle, is orphaned.
const (
	// ArenaStaleAfter bounds a live Arena run/candidate; past it, a still
	// in-flight row whose driver is not live is treated as failed.
	ArenaStaleAfter = 4 * time.Hour
	// TerminalStaleAfter bounds a live terminal run; past it, a still-"running"
	// row with no live handle is displayed as abandoned.
	TerminalStaleAfter = 24 * time.Hour
)

// Signal is the observable evidence about one record at reconcile time. The
// caller resolves it at the boundary (from stored columns + live discovery) and
// hands this package a plain value; the package's types never spread back.
type Signal struct {
	Kind Kind
	// Status is the record's current stored (or synthesized) lifecycle status.
	Status string
	// Age is the elapsed time since the record last made progress (an Arena
	// row's updated_at, a terminal run's launched_at).
	Age time.Duration
	// KnownLive is true when the caller can positively prove the record is
	// live right now (its driver goroutine is in-flight, or its PTY handle is
	// attached). A known-live record is never reconciled, regardless of age.
	KnownLive bool
	// ParentTerminal is true when an owning parent record has itself reached a
	// terminal state (an Arena run that is complete/failed can have no
	// still-running candidate). It lets a child close immediately, without
	// waiting out an age threshold.
	ParentTerminal bool
}

// Rule is one row of the ordered decision table. A Rule fires when every set
// condition holds: the Kind matches, the current Status is in InStatuses (empty
// = any), ParentTerminal is set if RequireParentTerminal, and Age >= MinAge (a
// zero MinAge imposes no age gate). The first firing Rule wins.
type Rule struct {
	Kind                  Kind
	InStatuses            []string
	RequireParentTerminal bool
	MinAge                time.Duration
	To                    string
	Reason                string
}

// Outcome is the reconciliation verdict. Changed is false (and To/Reason empty)
// when no rule fired — the record keeps its current status.
type Outcome struct {
	To      string
	Reason  string
	Changed bool
}

// DefaultRules is the shipped reconciliation table, ordered most-specific
// first. Parent-terminal closure precedes the age gates so a candidate under a
// finished run closes immediately rather than lingering until ArenaStaleAfter.
func DefaultRules() []Rule {
	return []Rule{
		{
			Kind:                  KindArenaCandidate,
			InStatuses:            []string{"pending", "running"},
			RequireParentTerminal: true,
			To:                    StatusFailed,
			Reason:                "parent_run_terminal",
		},
		{
			Kind:       KindArenaCandidate,
			InStatuses: []string{"pending", "running"},
			MinAge:     ArenaStaleAfter,
			To:         StatusFailed,
			Reason:     "stale_no_progress",
		},
		{
			Kind:       KindArenaRun,
			InStatuses: []string{"pending", "running", "judging"},
			MinAge:     ArenaStaleAfter,
			To:         StatusFailed,
			Reason:     "stale_no_progress",
		},
		{
			Kind:       KindTerminalRun,
			InStatuses: []string{"running"},
			MinAge:     TerminalStaleAfter,
			To:         StatusAbandoned,
			Reason:     "stale_no_heartbeat",
		},
	}
}

// Reconcile walks rules top-down and returns the first firing rule's verdict.
// A KnownLive record short-circuits to "no change" before any rule is tested,
// so live work is never reconciled. A record already at its target status does
// not re-fire (the guard keeps Reconcile idempotent).
func Reconcile(rules []Rule, s Signal) Outcome {
	if s.KnownLive {
		return Outcome{}
	}
	for _, r := range rules {
		if r.Kind != s.Kind {
			continue
		}
		if r.RequireParentTerminal && !s.ParentTerminal {
			continue
		}
		if r.MinAge > 0 && s.Age < r.MinAge {
			continue
		}
		if !statusIn(s.Status, r.InStatuses) {
			continue
		}
		if s.Status == r.To {
			return Outcome{}
		}
		return Outcome{To: r.To, Reason: r.Reason, Changed: true}
	}
	return Outcome{}
}

// statusIn reports whether status is in set; an empty set matches any status.
func statusIn(status string, set []string) bool {
	if len(set) == 0 {
		return true
	}
	for _, v := range set {
		if status == v {
			return true
		}
	}
	return false
}

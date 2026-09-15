package taskflow

import (
	"sort"
	"time"
)

// Bucket kinds for AttributeAt's Assignment (§R2.3.2 — "bucket, don't
// split"). Measured on the operator's corpus: attributed_single 52.0%,
// between_tasks 41.4%, shared 6.6%. Splitting the shared bucket evenly
// or picking a "dominant" task would each invent a precision the data
// does not contain; both were rejected by the round-2 review.
const (
	BucketSingle       = "attributed_single"
	BucketBetweenTasks = "between_tasks"
	BucketShared       = "shared"
)

// OpenInterval is one task's in_progress window: [Start, End). HasEnd
// is false for a task still open at the point Summarize/Attribute was
// asked to evaluate (§3.5: "report open, elapsed so far — never
// fabricate a completion time").
type OpenInterval struct {
	Key    string
	Start  time.Time
	End    time.Time
	HasEnd bool
}

// BuildOpenIntervals folds a session's transitions (any key, any order)
// into the in_progress windows the attribution rule sweeps over. ANY
// transition away from in_progress — not just a terminal one
// (completed/cancelled/deleted) — closes the most recently opened
// window for its key: a task paused back to pending or blocked
// (in_progress → pending/blocked, §R2.3's PAUSED case, 9 real
// instances on the grounding corpus) stops accruing elapsed/attribution
// time exactly like a real completion would, even though it is not a
// lifecycle terminus (Summarize, not this function, is where
// "terminal" vs "paused" actually matters). A second in_progress
// transition for a key that is already open is ignored (keeps the
// earliest start — the vendor schemas don't document re-opening, and
// none was observed live); a key reopened AFTER its window closed
// (in_progress → pending → in_progress) legitimately produces a SECOND,
// separate interval.
func BuildOpenIntervals(transitions []Transition) []OpenInterval {
	sorted := sortedByTs(transitions)
	open := make(map[string]*OpenInterval)
	var result []OpenInterval
	for _, tr := range sorted {
		switch {
		case tr.ToStatus == StatusInProgress:
			if _, already := open[tr.Key]; already {
				continue
			}
			iv := &OpenInterval{Key: tr.Key, Start: tr.Ts}
			open[tr.Key] = iv
		default:
			if iv, ok := open[tr.Key]; ok {
				iv.End = tr.Ts
				iv.HasEnd = true
				result = append(result, *iv)
				delete(open, tr.Key)
			}
		}
	}
	// Whatever is left open at the end of the transition stream is
	// still running — HasEnd stays false.
	for _, iv := range open {
		result = append(result, *iv)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Start.Before(result[j].Start) })
	return result
}

// Assignment is where one timestamped row (a token_usage or actions
// row) lands under the §R2.3.2 rule.
type Assignment struct {
	Bucket string // BucketSingle | BucketBetweenTasks | BucketShared
	Key    string // populated only for BucketSingle
}

// ConcurrentAttribution values ([tasks].concurrent_attribution). See
// Options.ConcurrentAttribution.
const (
	ConcurrentAttributionShared = "shared"
	ConcurrentAttributionNone   = "none"
)

// Options bundles the [tasks] behavior knobs a pure-package Phase-2
// consumer (the store/dashboard cost+metrics layer) needs — passed in
// explicitly by that caller rather than branched on inside
// internal/store (CLAUDE.md #3/#6: a capability/config value threaded
// through, never a store-layer if/else on it).
type Options struct {
	// MatchMode mirrors ActionInput.MatchMode / contentKeyForMode —
	// carried here too so a report builder can label which mode
	// produced the keys it is summarizing without re-reading config.
	// Consumed at decode time (Decode/applyMatchMode), not by
	// Attributor itself.
	MatchMode string
	// ConcurrentAttribution selects Attributor.At's behavior when two
	// or more tasks are open at once. "" / ConcurrentAttributionShared
	// (default) reports BucketShared. ConcurrentAttributionNone
	// instead reports BucketBetweenTasks — "drop the row from every
	// task's total instead of a dedicated shared bucket" (§R2.3.2).
	ConcurrentAttribution string
	// IncludeSidechains mirrors [tasks].include_sidechains. Consumed by
	// the store seam's LoadTaskTokenRows/LoadTaskActionTimestamps
	// includeSidechains parameter — carried here so a Phase-2 report
	// builder reads one Options value instead of re-deriving it from
	// config at two call sites.
	IncludeSidechains bool
}

// Attributor answers "which task, if any, was open at ts" for a whole
// session's worth of rows without re-scanning transitions per row.
type Attributor struct {
	intervals             []OpenInterval // sorted by Start
	concurrentAttribution string
}

// NewAttributor builds an Attributor from a session's open intervals,
// defaulting to ConcurrentAttributionShared (the pre-Options
// behavior — existing callers, incl. this package's own tests, are
// unaffected). Call SetConcurrentAttribution to opt into "none".
func NewAttributor(intervals []OpenInterval) *Attributor {
	sorted := make([]OpenInterval, len(intervals))
	copy(sorted, intervals)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Start.Before(sorted[j].Start) })
	return &Attributor{intervals: sorted}
}

// SetConcurrentAttribution applies [tasks].concurrent_attribution to an
// already-built Attributor (additive — see NewAttributor's doc
// comment) and returns the receiver for chaining. "" and
// ConcurrentAttributionShared are both the default; anything else
// falls back to the default rather than silently misbehaving.
func (a *Attributor) SetConcurrentAttribution(mode string) *Attributor {
	a.concurrentAttribution = mode
	return a
}

// At implements the exact rule: count intervals open at ts. Exactly one
// → BucketSingle for that task. Zero → BucketBetweenTasks. Two or more
// → BucketShared, unless SetConcurrentAttribution(ConcurrentAttributionNone)
// was applied, in which case two-or-more instead reports
// BucketBetweenTasks (count intentionally not carried on Assignment —
// the caller can recompute it if a UI ever wants to show "N tasks
// open" for a specific shared row, but Phase 1 has no such surface).
func (a *Attributor) At(ts time.Time) Assignment {
	var matches []string
	for _, iv := range a.intervals {
		if iv.Start.After(ts) {
			// intervals are sorted by Start — every later one starts
			// even further after ts, safe to stop.
			break
		}
		if !iv.HasEnd || ts.Before(iv.End) {
			matches = append(matches, iv.Key)
		}
	}
	switch len(matches) {
	case 0:
		return Assignment{Bucket: BucketBetweenTasks}
	case 1:
		return Assignment{Bucket: BucketSingle, Key: matches[0]}
	default:
		if a.concurrentAttribution == ConcurrentAttributionNone {
			return Assignment{Bucket: BucketBetweenTasks}
		}
		return Assignment{Bucket: BucketShared}
	}
}

// TaskSummary is one task's lifecycle facts (§R2.3.3) — independent of
// token/action attribution, which the caller layers on top per task Key
// using Attributor.
type TaskSummary struct {
	Key             string
	FirstInProgress *time.Time
	TerminalAt      *time.Time
	TerminalStatus  string
	// NeverActivated: closed without ever passing through in_progress
	// (§R2.3.3: 15% of closures on the grounding corpus). No elapsed
	// time, no token window — report as "completed, never activated",
	// never backfill a synthetic start.
	NeverActivated bool
	// StillOpen: in_progress with no terminal transition yet. Elapsed
	// is "so far", not a completion (§3.5).
	StillOpen bool
	// Elapsed is zero when neither FirstInProgress nor a completed
	// window exists to measure.
	//
	// KNOWN ASYMMETRY vs BuildOpenIntervals/Attributor: Elapsed is
	// FirstInProgress → TerminalAt (or asOf for StillOpen) — the FIRST
	// activation to the terminal transition, a single span that
	// INCLUDES any pause (in_progress → pending/blocked → in_progress)
	// in between. BuildOpenIntervals, by contrast, closes a window on
	// ANY transition away from in_progress and opens a fresh one on
	// re-activation, so a paused task's token/action ATTRIBUTION
	// windows EXCLUDE the paused gap (that usage lands in
	// between_tasks/shared instead). A task that paused and resumed
	// therefore reports a "wall clock" Elapsed longer than the sum of
	// its own attributed usage windows — expected, not a bug: Elapsed
	// answers "how long was this task open, start to finish", the
	// attribution windows answer "when was THIS task the one thing
	// active". Both are real questions with different valid answers;
	// no plan exists to unify them (a "paused-adjusted elapsed" would
	// need to re-derive the same interval set BuildOpenIntervals
	// already computes, at which point it should sum THAT instead of
	// duplicating the logic here).
	Elapsed time.Duration
}

// Summarize builds one TaskSummary per key from a session's
// transitions. asOf is used as the "still open" elapsed-so-far
// reference point (pass the session's own last-known activity
// timestamp, never wall-clock "now" — the session may be long since
// abandoned).
func Summarize(transitions []Transition, asOf time.Time) []TaskSummary {
	sorted := sortedByTs(transitions)
	type acc struct {
		firstInProgress *time.Time
		terminalAt      *time.Time
		terminalStatus  string
	}
	byKey := make(map[string]*acc)
	var order []string
	for _, tr := range sorted {
		a, ok := byKey[tr.Key]
		if !ok {
			a = &acc{}
			byKey[tr.Key] = a
			order = append(order, tr.Key)
		}
		ts := tr.Ts
		switch {
		case tr.ToStatus == StatusInProgress && a.firstInProgress == nil:
			t := ts
			a.firstInProgress = &t
		case IsTerminal(tr.ToStatus):
			t := ts
			a.terminalAt = &t
			a.terminalStatus = tr.ToStatus
		}
	}
	summaries := make([]TaskSummary, 0, len(order))
	for _, key := range order {
		a := byKey[key]
		s := TaskSummary{Key: key, FirstInProgress: a.firstInProgress, TerminalAt: a.terminalAt, TerminalStatus: a.terminalStatus}
		switch {
		case a.terminalAt != nil && a.firstInProgress == nil:
			s.NeverActivated = true
		case a.firstInProgress != nil && a.terminalAt == nil:
			s.StillOpen = true
			if asOf.After(*a.firstInProgress) {
				s.Elapsed = asOf.Sub(*a.firstInProgress)
			}
		case a.firstInProgress != nil && a.terminalAt != nil:
			s.Elapsed = a.terminalAt.Sub(*a.firstInProgress)
		}
		summaries = append(summaries, s)
	}
	return summaries
}

func sortedByTs(transitions []Transition) []Transition {
	sorted := make([]Transition, len(transitions))
	copy(sorted, transitions)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Ts.Before(sorted[j].Ts) })
	return sorted
}

package reprice

import "math"

// Change is one row a run changed, as the run's change log recorded it.
type Change struct {
	Table string
	ID    int64
	// Old is the cost before the run (nil = captured unpriced); New the cost
	// the run wrote.
	Old *float64
	New *float64
	// PrevRun is the row's re-price marker before the run (0 = the row had
	// never been re-priced, so Old is its originally captured cost).
	PrevRun int64
}

// Current is a changed row's state now.
type Current struct {
	// Found is false when the row no longer exists (retention, a delete).
	Found bool
	// Cost is the row's current stored cost (nil = NULL).
	Cost *float64
	// Run is the row's current re-price marker (0 = none).
	Run int64
}

// RevertDecision is the verdict on restoring one changed row.
type RevertDecision struct {
	Table string
	ID    int64
	// Restore is the cost to write back (nil = NULL) on a restore.
	Restore *float64
	// Run is the re-price marker to write back (0 = clear it).
	Run    int64
	Action Action
	Reason Reason
}

// Revert reasons, the names of [revertRules] in order, plus the restore.
const (
	ReasonRestored     Reason = "restored"
	ReasonRowGone      Reason = "row_gone"
	ReasonLaterRun     Reason = "superseded_by_later_run"
	ReasonChangedSince Reason = "changed_since"
)

type revertRule struct {
	reason Reason
	when   func(c Change, cur Current, run int64) bool
}

// revertRules is the ordered revert table. A revert restores a row only when
// the row still holds exactly what the run wrote: a later re-price run (which
// must be reverted first - the stores refuse the whole revert while a later
// non-reverted run holds any row), or a capture path that rewrote the cost
// since (a proxy/transcript merge, a node re-send on the org, which also
// clears the row's marker), both win over the revert - reverting must never
// destroy a newer figure. A marker that is neither this run nor a later one
// (cleared by a re-send, say) is a change since, not a later run.
var revertRules = []revertRule{
	{reason: ReasonRowGone, when: func(_ Change, cur Current, _ int64) bool { return !cur.Found }},
	{reason: ReasonLaterRun, when: func(_ Change, cur Current, run int64) bool { return cur.Run > run }},
	{reason: ReasonChangedSince, when: func(c Change, cur Current, run int64) bool {
		return cur.Run != run || !sameCost(c.New, cur.Cost)
	}},
}

func sameCost(a, b *float64) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return math.Abs(*a-*b) <= Epsilon
}

// EvaluateRevert decides whether one changed row of run can be restored.
func EvaluateRevert(c Change, cur Current, run int64) RevertDecision {
	d := RevertDecision{Table: c.Table, ID: c.ID, Action: ActionSkip}
	for _, rule := range revertRules {
		if rule.when(c, cur, run) {
			d.Reason = rule.reason
			return d
		}
	}
	d.Action = ActionUpdate
	d.Reason = ReasonRestored
	d.Restore = copyPtr(c.Old)
	d.Run = c.PrevRun
	return d
}

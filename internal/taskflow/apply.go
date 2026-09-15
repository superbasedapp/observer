package taskflow

import "time"

func unixNanoToTime(ns int64) time.Time {
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns).UTC()
}

// ApplyResult is what Apply computes for one item: the new persisted
// state and, if the item's status actually changed, the transition to
// append.
type ApplyResult struct {
	NewState   ItemState
	Transition *Transition
	// IsNew reports whether existing was nil — the store seam uses this
	// to decide INSERT vs UPDATE without re-deriving it.
	IsNew bool
}

// Apply is the pure per-item fold: given an item's previously persisted
// state (nil if never seen) and one TaskItem from a decoded TaskEvent,
// compute the new state and the transition to record, if any.
//
// Merge rule for content fields: a field only overwrites the stored
// value when the incoming item actually carries it (non-empty) — a
// status-only Delta call (`{"status":"completed","taskId":"8"}`) must
// never blank a task's subject/description (§R2.2 finding 1's
// content-only-edit sibling: the merge must be symmetric — neither
// direction may silently erase what the other is not talking about).
//
// A Failed event must never reach Apply at all — the store seam checks
// TaskEvent.Failed before calling this per-item (§R2.6 item 5).
func Apply(existing *ItemState, item TaskItem, ts time.Time) ApplyResult {
	if existing == nil {
		state := ItemState{
			Content:     item.Content,
			ActiveForm:  item.ActiveForm,
			Owner:       item.Owner,
			FirstSeenAt: ts,
			Order:       item.Order,
		}
		var transition *Transition
		if item.StatusKnown {
			state.RawStatus = item.RawStatus
			state.Status = item.Status
			transition = &Transition{
				Key:        item.Key,
				FromStatus: "",
				ToStatus:   item.Status,
				Ts:         ts,
			}
		}
		return ApplyResult{NewState: state, Transition: transition, IsNew: true}
	}

	next := *existing
	next.Order = item.Order
	if item.Content != "" {
		next.Content = item.Content
	}
	if item.ActiveForm != "" {
		next.ActiveForm = item.ActiveForm
	}
	if item.Owner != "" {
		next.Owner = item.Owner
	}

	var transition *Transition
	if item.StatusKnown && item.Status != existing.Status {
		transition = &Transition{
			Key:        item.Key,
			FromStatus: existing.Status,
			ToStatus:   item.Status,
			Ts:         ts,
		}
		next.RawStatus = item.RawStatus
		next.Status = item.Status
	} else if item.StatusKnown {
		// Same status re-sent (a Snapshot rewrite echoing an unchanged
		// item) — keep RawStatus current in case the vendor dialect
		// spelling itself changed without a normalized-status change.
		next.RawStatus = item.RawStatus
	}
	return ApplyResult{NewState: next, Transition: transition, IsNew: false}
}

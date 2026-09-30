package sessionmsg

import (
	"sort"

	"github.com/marmutapp/superbased-observer/internal/ratelimitstate"
)

// Status actions (2026-09-30). Some action kinds are not a step the agent
// took but a STATUS READING the host reported alongside a turn - the
// rate_limit snapshot Codex repeats on every token_count, the one Cowork
// re-polls. Rendered as ordinary actions they became a standalone
// "Rate limit" message row between every turn (the action's own
// message_id is a per-line "ratelimit:<file>:L<n>" key, so it never
// joined a turn bucket). A status action therefore never becomes, or
// counts as, a tool call: Derive folds it onto the message it follows
// (Row.StatusActions) and marks which readings CHANGED, so a surface can
// show a small marker only where the state actually moved.
//
// statusKinds is the one table of such kinds, keyed by action_type (an
// action KIND, never a tool name). snapshot returns the reading the
// change predicate compares.
type statusKind struct {
	snapshot func(a ActionRow) (snap ratelimitstate.Snapshot, detailed bool)
}

var statusKinds = map[string]statusKind{
	"rate_limit": {snapshot: rateLimitSnapshot},
}

// IsStatusAction reports whether actionType is a status kind Derive folds
// onto the preceding message instead of rendering it as a tool call.
func IsStatusAction(actionType string) bool {
	_, ok := statusKinds[actionType]
	return ok
}

// StatusActionTypes lists the status kinds, sorted - for a caller that
// loads the snapshot body (ActionRow.StatusRaw) only for these rows.
func StatusActionTypes() []string {
	out := make([]string, 0, len(statusKinds))
	for k := range statusKinds {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// statusLimited is the Status a body-less reading gets when its action
// was recorded unsuccessful (a rate-limit hit).
const statusLimited = "limited"

// rateLimitSnapshot reads a rate_limit action. With the stored envelope
// (ActionRow.StatusRaw - the node loads it) the full reading is compared:
// used_percent, windows, plan, status, a reset move beyond jitter. Without
// it (the org's content-free load) only the content-free outcome is known,
// so the reading is just "limited or not" from Success - the org marks the
// first reading and every limit hit / clear, never a used_percent tick it
// cannot see.
func rateLimitSnapshot(a ActionRow) (ratelimitstate.Snapshot, bool) {
	if a.StatusRaw != "" {
		if s, ok := ratelimitstate.Parse(a.StatusRaw); ok {
			return s, true
		}
	}
	var s ratelimitstate.Snapshot
	if a.Success != nil && !*a.Success {
		s.Status = statusLimited
	}
	return s, false
}

// StatusAction is one status reading folded onto a Row.
type StatusAction struct {
	ActionRow
	// Changed is true for the session's first reading of this kind (per
	// limit family, ratelimitstate.StreamKey) and for every reading that
	// differs meaningfully (ratelimitstate.Change) from the last CHANGED
	// one of its family - comparing against the last marked baseline, not
	// the previous row, so seconds of resets_at jitter cannot accumulate
	// into a false change, and a session alternating between two limit
	// families is not a change on every line.
	Changed bool
	// Reason is ratelimitstate's reason ("first", "used_percent", ...),
	// empty when unchanged.
	Reason string
	// Summary is the human reading ("7d 9% · plan prolite"), empty when
	// the caller supplied no body.
	Summary string
	// Limited reports a reading whose status is a limit hit.
	Limited bool
}

// markStatusChanges walks the (chronological) status actions and marks
// the changed readings per kind.
func markStatusChanges(actions []ActionRow) []StatusAction {
	out := make([]StatusAction, len(actions))
	baseline := map[string]ratelimitstate.Snapshot{}
	for i, a := range actions {
		snap, detailed := statusKinds[a.ActionType].snapshot(a)
		sa := StatusAction{ActionRow: a}
		if detailed {
			sa.Summary = ratelimitstate.Summary(snap)
		}
		switch snap.Status {
		case "", "ok", "allowed":
		default:
			sa.Limited = true
		}
		stream := ratelimitstate.StreamKey(a.ActionType, snap)
		prev, seen := baseline[stream]
		switch {
		case !seen:
			sa.Changed, sa.Reason = true, ratelimitstate.ReasonFirst
		default:
			if r := ratelimitstate.Change(prev, snap); r != "" {
				sa.Changed, sa.Reason = true, r
			}
		}
		if sa.Changed {
			baseline[stream] = snap
		}
		out[i] = sa
	}
	return out
}

// attachStatusActions is Derive's stage 7b: each status action lands on
// the last row (in final order) whose timestamp is at or before its own -
// the turn the reading was reported after - or on the first row when it
// precedes them all. A session with no other row at all keeps the old
// shape (one synthesized row per reading) so a probe-only session is not
// rendered empty.
func attachStatusActions(state *deriveState, actions []ActionRow, defaultModel string) {
	if len(actions) == 0 {
		return
	}
	if len(state.out) == 0 {
		for _, a := range actions {
			foldOneAction(state, a, defaultModel)
		}
		return
	}
	ordered := append([]*Row(nil), state.out...)
	sort.SliceStable(ordered, func(i, j int) bool { return Less(ordered[i], ordered[j]) })
	for _, sa := range markStatusChanges(actions) {
		idx := sort.Search(len(ordered), func(i int) bool { return ordered[i].Timestamp > sa.Timestamp }) - 1
		if idx < 0 {
			idx = 0
		}
		ordered[idx].StatusActions = append(ordered[idx].StatusActions, sa)
	}
}

// StatusWire is the per-row status-reading projection BOTH drawers embed
// (the TimingWire precedent), so the field names and the "only changed
// readings travel" rule cannot drift between node and org.
type StatusWire struct {
	// StatusEvents are the row's CHANGED status readings, chronological.
	StatusEvents []StatusEventWire `json:"status_events,omitempty"`
	// StatusEventCount is every status reading folded onto the row,
	// changed or not.
	StatusEventCount int `json:"status_event_count,omitempty"`
}

// StatusEventWire is one changed status reading on the wire.
type StatusEventWire struct {
	ActionType string `json:"action_type"`
	Timestamp  string `json:"ts"`
	Reason     string `json:"reason,omitempty"`
	Summary    string `json:"summary,omitempty"`
	Limited    bool   `json:"limited,omitempty"`
}

// Status returns this row's StatusWire.
func (r *Row) Status() StatusWire {
	w := StatusWire{StatusEventCount: len(r.StatusActions)}
	for _, sa := range r.StatusActions {
		if !sa.Changed {
			continue
		}
		w.StatusEvents = append(w.StatusEvents, StatusEventWire{
			ActionType: sa.ActionType, Timestamp: sa.Timestamp,
			Reason: sa.Reason, Summary: sa.Summary, Limited: sa.Limited,
		})
	}
	return w
}

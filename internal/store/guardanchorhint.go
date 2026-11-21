package store

// guardAnchorHint is one place a candidate's search starts: the action id
// and the hint rule that produced it.
type guardAnchorHint struct {
	rule string
	id   int64
}

// guardAnchorHints tracks, in id order, the anchors a repair has seen (rows
// that still carry one and rows it proved), so each candidate's search
// starts where its action id most likely is.
type guardAnchorHints struct {
	// content is the latest proven anchor per candidate content
	// (guardAnchorPreimage.key: every hashed column but chain_prev and the
	// action slot).
	content map[[32]byte]int64
	// session is the latest anchor of each session.
	session map[string]int64
	// last is the latest anchor in id order (0 before any).
	last int64
	// missed is, per candidate content, the radius-bounded windows a row
	// with that content came up empty in.
	missed map[[32]byte]map[guardAnchorWindow]struct{}
}

func newGuardAnchorHints() *guardAnchorHints {
	return &guardAnchorHints{
		content: map[[32]byte]int64{}, session: map[string]int64{},
		missed: map[[32]byte]map[guardAnchorWindow]struct{}{},
	}
}

// observe records that r (passed in id order) is anchored to id.
func (h *guardAnchorHints) observe(r *GuardEventRow, id int64) {
	h.last = id
	h.session[r.SessionID] = id
}

// observeProven records a proven candidate: observe plus its content.
func (h *guardAnchorHints) observeProven(r *GuardEventRow, key [32]byte, id int64) {
	h.observe(r, id)
	h.content[key] = id
}

// guardAnchorHintInput is what a hint rule sees for one candidate.
type guardAnchorHintInput struct {
	row *GuardEventRow
	key [32]byte
	// next is the anchor of the first row after the candidate (in id order)
	// that still carries one; 0 when none does.
	next int64
}

// Hint rule names (the repair report's per-hint distance table).
const (
	GuardAnchorHintContent  = "same content"
	GuardAnchorHintSession  = "same session"
	GuardAnchorHintPrevious = "previous anchored row"
	GuardAnchorHintNext     = "next anchored row"
	GuardAnchorHintFirst    = "first action id"
)

// guardAnchorHintRules is the ordered hint table; a candidate is searched
// around each distinct hint the rules yield, in this order, until one window
// proves it. Grounded on the operator's node (2026-11-02, lane anchorperf):
// 82,090 of its 82,899 candidates are one copilot session's two flags
// repeated by transcript re-parses (the 2026-10-21 dedup shape), every
// repeat hashed with the same action id as the first, so "same content"
// proves each repeat at distance 0. The other rules seed the first row of a
// content: action ids are issued in insert order and a guard row is written
// with the action it flags, so the session's and the neighbouring rows'
// anchors lie nearby.
var guardAnchorHintRules = []struct {
	name string
	hint func(h *guardAnchorHints, in guardAnchorHintInput) (int64, bool)
}{
	{GuardAnchorHintContent, func(h *guardAnchorHints, in guardAnchorHintInput) (int64, bool) {
		id, ok := h.content[in.key]
		return id, ok
	}},
	{GuardAnchorHintSession, func(h *guardAnchorHints, in guardAnchorHintInput) (int64, bool) {
		id, ok := h.session[in.row.SessionID]
		return id, ok
	}},
	{GuardAnchorHintPrevious, func(h *guardAnchorHints, _ guardAnchorHintInput) (int64, bool) {
		return h.last, h.last > 0
	}},
	{GuardAnchorHintNext, func(_ *guardAnchorHints, in guardAnchorHintInput) (int64, bool) {
		return in.next, in.next > 0
	}},
}

// hintsFor is the candidate's distinct hints in rule order; the first action
// id when no rule yields one.
func (h *guardAnchorHints) hintsFor(in guardAnchorHintInput) []guardAnchorHint {
	var out []guardAnchorHint
	for _, rule := range guardAnchorHintRules {
		id, ok := rule.hint(h, in)
		if !ok || containsGuardAnchorHint(out, id) {
			continue
		}
		out = append(out, guardAnchorHint{rule: rule.name, id: id})
	}
	if len(out) == 0 {
		out = append(out, guardAnchorHint{rule: GuardAnchorHintFirst, id: 1})
	}
	return out
}

func containsGuardAnchorHint(hints []guardAnchorHint, id int64) bool {
	for _, h := range hints {
		if h.id == id {
			return true
		}
	}
	return false
}

// missedBefore reports whether an earlier row with content key came up
// empty in exactly w.
func (h *guardAnchorHints) missedBefore(key [32]byte, w guardAnchorWalk) bool {
	_, ok := h.missed[key][w.window()]
	return ok
}

// markMissed records that a row with content key came up empty in w.
func (h *guardAnchorHints) markMissed(key [32]byte, w guardAnchorWalk) {
	if h.missed[key] == nil {
		h.missed[key] = map[guardAnchorWindow]struct{}{}
	}
	h.missed[key][w.window()] = struct{}{}
}

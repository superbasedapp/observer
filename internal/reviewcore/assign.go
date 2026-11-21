package reviewcore

import (
	"fmt"
	"sort"
	"strings"
)

// Mode is how a queue's items reach reviewers.
type Mode string

// The assignment modes.
const (
	// ModeOpen: any reviewer takes the next item (the W3-6 single-reviewer
	// flow); a review claims the item implicitly.
	ModeOpen Mode = "open"
	// ModeRoundRobin: each new item is assigned to the next reviewers of the
	// pool in turn.
	ModeRoundRobin Mode = "round_robin"
	// ModeClaim: a reviewer claims an item before reviewing it and may
	// release it again.
	ModeClaim Mode = "claim"
)

// PoolKind names who a queue's reviewers are.
type PoolKind string

// The pool kinds.
const (
	PoolNone   PoolKind = ""       // anyone the route gate admits
	PoolMember PoolKind = "member" // one member
	PoolTeam   PoolKind = "team"   // the members of one team
)

// modeRow is one row of the mode table.
type modeRow struct {
	Mode Mode
	// NeedsAssignment: a reviewer must hold an assignment (assigned or
	// claimed) on an item before submitting.
	NeedsAssignment bool
	// AutoAssign: new items are assigned when they are added.
	AutoAssign bool
}

var modeTable = []modeRow{
	{ModeOpen, false, false},
	{ModeRoundRobin, true, true},
	{ModeClaim, true, false},
}

func modeOf(m Mode) (modeRow, bool) {
	for _, r := range modeTable {
		if r.Mode == m {
			return r, true
		}
	}
	return modeRow{}, false
}

// ValidMode reports whether m is a known mode.
func ValidMode(m Mode) bool { _, ok := modeOf(m); return ok }

// NeedsAssignment reports whether a review in mode m needs an assignment.
func NeedsAssignment(m Mode) bool { r, _ := modeOf(m); return r.NeedsAssignment }

// AutoAssign reports whether mode m assigns items as they are added.
func AutoAssign(m Mode) bool { r, _ := modeOf(m); return r.AutoAssign }

// Modes lists the modes in table order.
func Modes() []Mode {
	out := make([]Mode, 0, len(modeTable))
	for _, r := range modeTable {
		out = append(out, r.Mode)
	}
	return out
}

// ValidPoolKind reports whether k is a known pool kind.
func ValidPoolKind(k PoolKind) bool {
	return k == PoolNone || k == PoolMember || k == PoolTeam
}

// Bounds.
const (
	MaxRequiredReviews = 5
	MaxTolerance       = 1e6
)

// Settings is a queue's team settings.
type Settings struct {
	RequiredReviews  int
	Mode             Mode
	PoolKind         PoolKind
	PoolID           string
	Adjudicator      string
	NumericTolerance float64
}

// Validate checks team settings: 1-5 required reviews, a known mode and
// pool kind, a pool id exactly when a pool kind is set, round-robin only
// with a pool, a non-negative tolerance.
func (s Settings) Validate() error {
	if s.RequiredReviews < 1 || s.RequiredReviews > MaxRequiredReviews {
		return fmt.Errorf("required_reviews is 1-%d", MaxRequiredReviews)
	}
	if !ValidMode(s.Mode) {
		return fmt.Errorf("assign_mode must be open, round_robin or claim")
	}
	if !ValidPoolKind(s.PoolKind) {
		return fmt.Errorf("pool_kind must be member, team or empty")
	}
	if (s.PoolKind == PoolNone) != (strings.TrimSpace(s.PoolID) == "") {
		return fmt.Errorf("pool_id is required with a pool_kind and refused without one")
	}
	if s.Mode == ModeRoundRobin && s.PoolKind == PoolNone {
		return fmt.Errorf("round_robin needs a pool (a member or a team)")
	}
	if s.NumericTolerance < 0 || s.NumericTolerance > MaxTolerance {
		return fmt.Errorf("numeric_tolerance is 0-%g", float64(MaxTolerance))
	}
	if s.PoolKind == PoolMember && s.Adjudicator != "" && s.Adjudicator == s.PoolID {
		return fmt.Errorf("the adjudicator cannot be the queue's only reviewer")
	}
	return nil
}

// RoundRobin picks up to n reviewers from pool starting at cursor, skipping
// excluded ones, and returns them with the next cursor. The pool is sorted
// first so every caller walks one order. An empty pool picks nobody.
func RoundRobin(pool []string, cursor, n int, exclude map[string]bool) ([]string, int) {
	if len(pool) == 0 || n <= 0 {
		return nil, cursor
	}
	p := append([]string(nil), pool...)
	sort.Strings(p)
	if cursor < 0 {
		cursor = 0
	}
	start := cursor % len(p)
	var out []string
	next := cursor
	for step := 0; step < len(p) && len(out) < n; step++ {
		i := (start + step) % len(p)
		next = cursor + step + 1
		if exclude[p[i]] {
			continue
		}
		out = append(out, p[i])
	}
	return out, next % len(p)
}

// Item statuses (the org and machine owners store these strings).
const (
	StatusPending      = "pending"
	StatusAdjudication = "adjudication"
	StatusDone         = "done"
	StatusSkipped      = "skipped"
)

// statusRow is one row of the completion table, walked top-down.
type statusRow struct {
	When   func(required, done int, conflicts int) bool
	Status string
}

var statusTable = []statusRow{
	{func(req, done, _ int) bool { return done < req }, StatusPending},
	{func(_, _, c int) bool { return c > 0 }, StatusAdjudication},
	{func(_, _, _ int) bool { return true }, StatusDone},
}

// NextStatus is an item's status after a review: pending until it has the
// required reviews, then adjudication when they conflict, else done.
func NextStatus(required, done, conflicts int) string {
	for _, r := range statusTable {
		if r.When(required, done, conflicts) {
			return r.Status
		}
	}
	return StatusPending
}

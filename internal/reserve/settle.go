package reserve

import (
	"errors"
	"fmt"
)

// HoldState is where a hold stands.
type HoldState string

// The hold states.
const (
	// HoldOpen is a hold that still counts at its estimate.
	HoldOpen HoldState = "open"
	// HoldFinal is a hold already settled, released, expired or reconciled.
	HoldFinal HoldState = "final"
)

// Outcome is how a hold closes.
type Outcome string

// The outcomes.
const (
	// OutcomeSettle books what the work actually cost.
	OutcomeSettle Outcome = "settle"
	// OutcomeRelease refunds the whole hold: the work never ran or produced
	// nothing billable.
	OutcomeRelease Outcome = "release"
	// OutcomeExpire is a release the system made because the hold outlived
	// its work.
	OutcomeExpire Outcome = "expire"
	// OutcomeReconcile closes a hold whose outcome was lost (a crash) at its
	// estimate, so a lost settle can never under-count.
	OutcomeReconcile Outcome = "reconcile"
)

// Hold is a hold as its ledger stored it.
type Hold struct {
	// State is where the hold stands.
	State HoldState
	// Estimate is what the hold counted while open, in its cap's unit.
	Estimate float64
}

// Close is a request to close a hold.
type Close struct {
	// Outcome is how the hold closes.
	Outcome Outcome
	// Actual is what the work cost, read only by OutcomeSettle.
	Actual float64
}

// Settlement is what closing a hold books.
type Settlement struct {
	// Noop is true when the hold was already final: the close changes
	// nothing (idempotency by the hold's key).
	Noop bool
	// Booked is what stays counted against the hold's windows.
	Booked float64
	// Refund is what the windows give back: Estimate minus Booked when the
	// hold was over-estimated, else zero.
	Refund float64
	// Overrun is what the windows count beyond the estimate: Booked minus
	// Estimate when the work cost more than the hold, else zero. It is
	// recorded, never clamped: the next admission sees the real spend.
	Overrun float64
	// FreesSlot is true when the hold's in-flight slot (a concurrency cap)
	// is freed.
	FreesSlot bool
	// Rule is the settle rule that decided.
	Rule string
}

// The settle rule names.
const (
	RuleAlreadyFinal   = "already_final"
	RuleUnknownActual  = "settle_actual_unknown"
	RuleSettleOverrun  = "settle_overrun"
	RuleSettleWithin   = "settle_within_estimate"
	RuleReleaseRefunds = "release_refunds"
	RuleReconcileHolds = "reconcile_books_estimate"
)

// ErrUnknownOutcome is returned for a Close whose Outcome is not one of the
// outcomes.
var ErrUnknownOutcome = errors.New("reserve: unknown outcome")

// settleRule is one row of settleRules.
type settleRule struct {
	name  string
	match func(Hold, Close) bool
	// booked is what the hold books under this rule.
	booked func(Hold, Close) float64
}

// settleRules decide how a hold closes, top-down, first match wins.
func settleRules() []settleRule {
	return []settleRule{
		// An already-final hold is untouched: a retried stream end, a second
		// worker, or a sweep racing a settle closes it once.
		{name: RuleAlreadyFinal, match: func(h Hold, _ Close) bool { return h.State != HoldOpen }},
		// A settle that cannot say what it cost keeps the worst case
		// counted (the reconcile direction: never under-count).
		{
			name: RuleUnknownActual,
			match: func(_ Hold, c Close) bool {
				return c.Outcome == OutcomeSettle && (!finite(c.Actual) || c.Actual < 0)
			},
			booked: func(h Hold, _ Close) float64 { return h.Estimate },
		},
		{
			name:   RuleSettleOverrun,
			match:  func(h Hold, c Close) bool { return c.Outcome == OutcomeSettle && c.Actual > h.Estimate },
			booked: func(_ Hold, c Close) float64 { return c.Actual },
		},
		{
			name:   RuleSettleWithin,
			match:  func(_ Hold, c Close) bool { return c.Outcome == OutcomeSettle },
			booked: func(_ Hold, c Close) float64 { return c.Actual },
		},
		{
			name:   RuleReleaseRefunds,
			match:  func(_ Hold, c Close) bool { return c.Outcome == OutcomeRelease || c.Outcome == OutcomeExpire },
			booked: func(Hold, Close) float64 { return 0 },
		},
		{
			name:   RuleReconcileHolds,
			match:  func(_ Hold, c Close) bool { return c.Outcome == OutcomeReconcile },
			booked: func(h Hold, _ Close) float64 { return h.Estimate },
		},
	}
}

// Settle decides how a hold closes. It returns ErrUnknownOutcome (wrapped)
// for an Outcome outside the vocabulary, before looking at the hold, so a
// caller's typo never reads as an idempotent no-op.
func Settle(h Hold, c Close) (Settlement, error) {
	switch c.Outcome {
	case OutcomeSettle, OutcomeRelease, OutcomeExpire, OutcomeReconcile:
	default:
		return Settlement{}, fmt.Errorf("reserve.Settle: %w: %q", ErrUnknownOutcome, c.Outcome)
	}
	for _, r := range settleRules() {
		if !r.match(h, c) {
			continue
		}
		if r.booked == nil {
			return Settlement{Noop: true, Rule: r.name}, nil
		}
		booked := r.booked(h, c)
		s := Settlement{Booked: booked, FreesSlot: true, Rule: r.name}
		if booked < h.Estimate {
			s.Refund = h.Estimate - booked
		} else {
			s.Overrun = booked - h.Estimate
		}
		return s, nil
	}
	return Settlement{}, fmt.Errorf("reserve.Settle: %w: %q", ErrUnknownOutcome, c.Outcome)
}

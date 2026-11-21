package reserve

import (
	"math"
	"slices"
)

// Unit is what a cap counts.
type Unit string

// The units.
const (
	// UnitCount counts whole reservations (the cloud service's allowances,
	// its concurrency slots and its budget pools).
	UnitCount Unit = "count"
	// UnitUSD counts US dollars.
	UnitUSD Unit = "usd"
	// UnitTokens counts model tokens.
	UnitTokens Unit = "tokens"
)

// Boundary says when a cap is breached.
type Boundary string

// The boundaries.
const (
	// OverCap refuses when committed plus this hold's estimate would exceed
	// the cap. Landing exactly on the cap is admitted. It is the boundary of
	// every cap whose hold size is known before the call: a count cap (the
	// estimate is the hold's units) and the gateway's USD and token caps
	// (the estimate is the worst case).
	OverCap Boundary = "over_cap"
	// AtCap refuses once committed has reached the cap, whatever the hold
	// will cost. It is the boundary of a ceiling checked before a call whose
	// cost is only known after it (the cloud service's pool spend ceilings):
	// the window is closed the moment the spend reaches the ceiling.
	AtCap Boundary = "at_cap"
)

// Limit is one cap as a reservation sees it, in one unit. Every field is a
// value the caller read under its own locks.
//
// A Limit that is present is a cap. A caller whose storage uses a zero or
// negative cap to mean "no cap" leaves that Limit out; the core never reads a
// sentinel, so a present cap of zero refuses every hold (the cloud service's
// zero-allowance plan).
type Limit struct {
	// Group names the cap this Limit belongs to. Limits sharing a Group are
	// one cap expressed in several units (the gateway's USD and token caps on
	// one cap row) and are decided together; an empty Group is the Limit's
	// own group.
	Group string
	// Name says which cap this is, for the caller's error vocabulary (the
	// cloud service's "daily", "monthly", "concurrency", "pool",
	// "ceiling_daily", ...).
	Name string
	// Unit is what Cap, Committed and Estimate count.
	Unit Unit
	// Cap is the cap.
	Cap float64
	// Committed is everything already counted in the cap's window: settled
	// holds at what they booked plus open holds at their estimate.
	Committed float64
	// Estimate is this hold's worst case in Unit (zero under AtCap when the
	// cost is not known before the call).
	Estimate float64
	// Boundary says when the cap is breached; the zero value is OverCap.
	Boundary Boundary
	// Soft makes a breach of this cap's Group admit with a warning instead of
	// refusing. It is a property of the Group: the leading Limit's value
	// decides.
	Soft bool
}

// Breach is one cap a hold would exhaust.
type Breach struct {
	// Group, Name, Unit, Cap, Committed and Estimate are the breached Limit's.
	Group     string
	Name      string
	Unit      Unit
	Cap       float64
	Committed float64
	Estimate  float64
	// Remaining is Cap minus Committed: the headroom left before this hold
	// (negative when an earlier overrun already passed the cap).
	Remaining float64
	// Ratio is (Committed + Estimate) / Cap, the share of the cap the hold
	// would reach; +Inf for a cap at or below zero. Within a Group the Limit
	// with the largest Ratio leads: it is the unit that exhausts first.
	Ratio float64
	// Soft is the Group's enforcement: true when the breach only warns.
	Soft bool
	// Rule is the rule that decided the breach.
	Rule string
}

// The rule names a Breach or a Decision carries.
const (
	RuleInvalid          = "invalid_input"
	RuleAtCap            = "at_cap"
	RuleOverCap          = "over_cap"
	RuleUnknownCapped    = "unknown_estimate_capped"
	RuleUnknownUncapped  = "unknown_estimate_uncapped"
	RuleWithinCaps       = "within_caps"
	RuleHardBreach       = "hard_breach"
	RuleSoftBreachWarned = "soft_breach_warned"
)

// limitRule is one row of limitRules.
type limitRule struct {
	name  string
	match func(Limit) bool
}

// limitRules decide whether one Limit is breached, top-down, first match
// wins; no match means the hold fits under it. A function, not a package
// variable, so the table is never shared mutable state.
func limitRules() []limitRule {
	return []limitRule{
		// A value the arithmetic cannot order (NaN, an infinity, a negative
		// estimate or committed) fails closed: a cap must never be passed
		// because its input was garbage.
		{name: RuleInvalid, match: func(l Limit) bool {
			return !finite(l.Cap) || !finite(l.Committed) || !finite(l.Estimate) || l.Estimate < 0 || l.Committed < 0
		}},
		{name: RuleAtCap, match: func(l Limit) bool { return l.Boundary == AtCap && l.Committed >= l.Cap }},
		{name: RuleOverCap, match: func(l Limit) bool { return l.Boundary != AtCap && l.Committed+l.Estimate > l.Cap }},
	}
}

func finite(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }

// Check decides one Limit: the Breach and true when the hold would exhaust
// it, false when the hold fits.
func Check(l Limit) (Breach, bool) {
	for _, r := range limitRules() {
		if r.match(l) {
			return breachOf(l, r.name), true
		}
	}
	return Breach{}, false
}

func breachOf(l Limit, rule string) Breach {
	ratio := math.Inf(1)
	if rule != RuleInvalid && l.Cap > 0 {
		ratio = (l.Committed + l.Estimate) / l.Cap
	}
	return Breach{
		Group:     l.Group,
		Name:      l.Name,
		Unit:      l.Unit,
		Cap:       l.Cap,
		Committed: l.Committed,
		Estimate:  l.Estimate,
		Remaining: l.Cap - l.Committed,
		Ratio:     ratio,
		Soft:      l.Soft,
		Rule:      rule,
	}
}

// Request is one hold to decide against every cap in scope.
type Request struct {
	// Limits are the caps in scope, in the caller's canonical order: the
	// first hard-breached Group in this order is the one a refusal names.
	Limits []Limit
	// Unknown are the units in which this hold's cost cannot be computed
	// (the gateway's unpriced model: its USD worst case is unknown). A cap in
	// an unknown unit cannot bound the hold, so the hold is refused.
	Unknown []Unit
	// RefuseUnknownUncapped refuses a hold with an Unknown unit when no cap
	// is in scope at all: nothing would bound it in any unit (the gateway's
	// G4 posture).
	RefuseUnknownUncapped bool
}

// Decision is the verdict on a Request.
type Decision struct {
	// Admitted is true when the hold may be written.
	Admitted bool
	// Refused is the breach that refused the hold (nil when admitted, and
	// nil for an unknown-estimate refusal, which names no cap).
	Refused *Breach
	// UnknownUnit is the unit whose unknown estimate refused the hold.
	UnknownUnit Unit
	// Warnings are the soft breaches met before the decision, in order.
	Warnings []Breach
	// Rule is the request rule that decided.
	Rule string
}

// requestRule is one row of requestRules: it returns a decision (carrying
// the rule's name) and true when it decides the request.
type requestRule func(Request) (Decision, bool)

// requestRules decide a Request, top-down, first decision wins. The last
// row always decides.
func requestRules() []requestRule {
	return []requestRule{
		decideUnknownCapped,   // RuleUnknownCapped
		decideUnknownUncapped, // RuleUnknownUncapped
		decideGroups,          // RuleHardBreach, RuleSoftBreachWarned, RuleWithinCaps
	}
}

func decideUnknownCapped(r Request) (Decision, bool) {
	for _, l := range r.Limits {
		if slices.Contains(r.Unknown, l.Unit) {
			return Decision{Rule: RuleUnknownCapped, UnknownUnit: l.Unit}, true
		}
	}
	return Decision{}, false
}

func decideUnknownUncapped(r Request) (Decision, bool) {
	if len(r.Unknown) > 0 && len(r.Limits) == 0 && r.RefuseUnknownUncapped {
		return Decision{Rule: RuleUnknownUncapped, UnknownUnit: r.Unknown[0]}, true
	}
	return Decision{}, false
}

// decideGroups walks the cap Groups in order of first appearance. A
// breached hard Group refuses; a breached soft Group warns and the walk
// goes on; a walk that ends admits.
func decideGroups(r Request) (Decision, bool) {
	var warnings []Breach
	for _, g := range groups(r.Limits) {
		lead, breached := leading(g)
		if !breached {
			continue
		}
		if lead.Soft {
			lead.Rule = RuleSoftBreachWarned
			warnings = append(warnings, lead)
			continue
		}
		return Decision{Refused: &lead, Warnings: warnings, Rule: RuleHardBreach}, true
	}
	rule := RuleWithinCaps
	if len(warnings) > 0 {
		rule = RuleSoftBreachWarned
	}
	return Decision{Admitted: true, Warnings: warnings, Rule: rule}, true
}

// groups splits limits into their Groups, in order of each Group's first
// appearance; an empty Group is a Limit's own group.
func groups(limits []Limit) [][]Limit {
	var out [][]Limit
	index := map[string]int{}
	for _, l := range limits {
		if l.Group == "" {
			out = append(out, []Limit{l})
			continue
		}
		if i, ok := index[l.Group]; ok {
			out[i] = append(out[i], l)
			continue
		}
		index[l.Group] = len(out)
		out = append(out, []Limit{l})
	}
	return out
}

// leading returns the breach of a Group's Limit with the largest Ratio (the
// unit that exhausts first; the earlier Limit wins a tie), and whether any
// Limit of the Group is breached.
func leading(g []Limit) (Breach, bool) {
	var lead Breach
	found := false
	for _, l := range g {
		b, breached := Check(l)
		if !breached {
			continue
		}
		if !found || b.Ratio > lead.Ratio {
			lead, found = b, true
		}
	}
	return lead, found
}

// Admit decides a Request by walking requestRules.
func Admit(r Request) Decision {
	for _, rule := range requestRules() {
		if d, ok := rule(r); ok {
			return d
		}
	}
	return Decision{Admitted: true, Rule: RuleWithinCaps}
}

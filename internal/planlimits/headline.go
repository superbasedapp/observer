package planlimits

import (
	"time"
)

// headline.go picks the one number a card leads with. The rule (D-681): the
// headline is what is LEFT wherever the vendor says so, with what was used as
// the secondary number; a card whose vendor reports only usage says so
// honestly instead of passing usage off as a balance.

// Headline kinds.
const (
	HeadlineLeft        = "left"         // an amount left (money, credits, requests ...)
	HeadlinePercentLeft = "percent_left" // a fraction of a window left
	HeadlineUsedOnly    = "used_only"    // the vendor reports usage but not what is left
	HeadlineNone        = "none"         // no reading yet
)

// Headline is the card's lead number.
type Headline struct {
	Kind string `json:"kind"`
	Unit Unit   `json:"unit,omitempty"`
	// Value is the amount left (left), the fraction left 0..1 (percent_left)
	// or the amount used (used_only).
	Value *float64 `json:"value,omitempty"`
	// Of is the limit, or the amount bought, when the vendor says.
	Of *float64 `json:"of,omitempty"`
	// Used is the amount used, shown second, when known.
	Used *float64 `json:"used,omitempty"`
	// Basis names the input: balance:<kind> | window:<key> | spend:<period>.
	Basis      string     `json:"basis,omitempty"`
	ResetsAt   *time.Time `json:"resets_at,omitempty"`
	Confidence Confidence `json:"confidence,omitempty"`
	// Also lists the same balance in every OTHER currency the account holds
	// (a non-zero amount), one entry per currency. Currencies are never
	// converted or summed; Of and Used always describe the primary Unit.
	Also []HeadlineAmount `json:"also,omitempty"`
}

// HeadlineAmount is one more currency of a balance headline.
type HeadlineAmount struct {
	Unit  Unit    `json:"unit"`
	Value float64 `json:"value"`
}

// leftBalanceKinds are the balance kinds that mean "money or credits you
// still have", in preference order. "purchased", "granted", "topup",
// "voucher", "cash" and "included_used" are breakdowns, never the headline.
var leftBalanceKinds = []string{"prepaid", "available", "total", "wallet", "credits", "points", "posted"}

// boughtBalanceKinds name the "out of" amount for a left balance.
var boughtBalanceKinds = []string{"purchased", "granted_total", "allowance"}

// headlineRule is one row of the ordered headline table.
type headlineRule struct {
	name string
	pick func(m Merged, now time.Time) (Headline, bool)
}

// headlineOrder: which rules a provider group tries, in order. A balance
// leads with the balance; a plan or a usage account with its tightest window.
var headlineOrder = map[string][]headlineRule{
	GroupBalance: {ruleBalanceLeft, ruleWindowLeft, ruleUsedOnly},
	GroupPlans:   {ruleWindowLeft, ruleBalanceLeft, ruleUsedOnly},
	GroupUsage:   {ruleWindowLeft, ruleBalanceLeft, ruleUsedOnly},
}

// HeadlineOf picks a card's headline from a merged reading.
func HeadlineOf(group string, m Merged, now time.Time) Headline {
	rules, ok := headlineOrder[group]
	if !ok {
		rules = headlineOrder[GroupPlans]
	}
	for _, r := range rules {
		if h, ok := r.pick(m, now); ok {
			return h
		}
	}
	return Headline{Kind: HeadlineNone}
}

var ruleBalanceLeft = headlineRule{"balance_left", func(m Merged, _ time.Time) (Headline, bool) {
	for _, kind := range leftBalanceKinds {
		b, others, ok := heldBalance(m, kind)
		if !ok {
			continue
		}
		v := float64(b.Amount)
		h := Headline{Kind: HeadlineLeft, Unit: b.Unit, Value: &v, Basis: "balance:" + kind}
		for _, o := range others {
			h.Also = append(h.Also, HeadlineAmount{Unit: o.Unit, Value: float64(o.Amount)})
		}
		h.Confidence = m.BalanceProv[b.Kind+"|"+string(b.Unit)].Confidence
		for _, bk := range boughtBalanceKinds {
			if t, ok := pickBalance(m, bk, b.Unit); ok && t.Amount > 0 {
				of, used := float64(t.Amount), float64(t.Amount-b.Amount)
				h.Of, h.Used = &of, &used
				break
			}
		}
		if h.Used == nil {
			if sp, ok := pickSpend(m, b.Unit); ok {
				u := float64(sp.Amount)
				h.Used = &u
			}
		}
		return h, true
	}
	return Headline{}, false
}}

var ruleWindowLeft = headlineRule{"window_left", func(m Merged, now time.Time) (Headline, bool) {
	var best *Window
	bestFrac := -1.0
	for i := range m.Windows {
		w := m.Windows[i]
		if Expired(w, now) {
			continue
		}
		f, ok := usedFrac(w)
		if !ok {
			continue
		}
		if f > bestFrac {
			best, bestFrac = &m.Windows[i], f
		}
	}
	if best == nil {
		return Headline{}, false
	}
	w := *best
	h := Headline{Basis: "window:" + w.Key, ResetsAt: w.ResetsAt, Confidence: m.WindowProv[w.Key].Confidence}
	if w.Unit != UnitPercent && w.Limit != nil && *w.Limit > 0 {
		left := *w.Limit - *w.Limit*bestFrac
		if w.Remaining != nil {
			left = *w.Remaining
		}
		used := *w.Limit - left
		if w.Used != nil {
			used = *w.Used
		}
		left = max(left, 0)
		h.Kind, h.Unit, h.Value, h.Of, h.Used = HeadlineLeft, w.Unit, &left, w.Limit, &used
		return h, true
	}
	left := max(1-bestFrac, 0)
	h.Kind, h.Unit, h.Value = HeadlinePercentLeft, UnitPercent, &left
	return h, true
}}

var ruleUsedOnly = headlineRule{"used_only", func(m Merged, _ time.Time) (Headline, bool) {
	if sp, ok := pickSpend(m, ""); ok {
		v := float64(sp.Amount)
		return Headline{Kind: HeadlineUsedOnly, Unit: sp.Unit, Value: &v, Basis: "spend:" + sp.Period, Confidence: m.Confidence}, true
	}
	for _, w := range m.Windows {
		if w.Used != nil {
			return Headline{Kind: HeadlineUsedOnly, Unit: w.Unit, Value: w.Used, Basis: "window:" + w.Key, ResetsAt: w.ResetsAt, Confidence: m.WindowProv[w.Key].Confidence}, true
		}
	}
	return Headline{}, false
}}

// heldBalance picks the primary currency of a balance kind: the one the
// account actually holds. Rule order: US dollars when non-zero, else the
// first non-zero currency, else US dollars, else the first. Every other
// currency with a non-zero amount is returned as an extra line, never
// converted and never added to the primary.
func heldBalance(m Merged, kind string) (Balance, []Balance, bool) {
	var found []Balance
	for _, b := range m.Balances {
		if b.Kind == kind {
			found = append(found, b)
		}
	}
	if len(found) == 0 {
		return Balance{}, nil, false
	}
	primary := -1
	for _, pick := range []func(Balance) bool{
		func(b Balance) bool { return b.Unit == UnitUSDMicros && b.Amount != 0 },
		func(b Balance) bool { return b.Amount != 0 },
		func(b Balance) bool { return b.Unit == UnitUSDMicros },
		func(Balance) bool { return true },
	} {
		for i, b := range found {
			if pick(b) {
				primary = i
				break
			}
		}
		if primary >= 0 {
			break
		}
	}
	var others []Balance
	for i, b := range found {
		if i != primary && b.Amount != 0 {
			others = append(others, b)
		}
	}
	return found[primary], others, true
}

// pickBalance returns the balance of kind (in unit, when unit is set). With
// several currencies it prefers US dollars, then the first.
func pickBalance(m Merged, kind string, unit Unit) (Balance, bool) {
	var found []Balance
	for _, b := range m.Balances {
		if b.Kind == kind && (unit == "" || b.Unit == unit) {
			found = append(found, b)
		}
	}
	if len(found) == 0 {
		return Balance{}, false
	}
	for _, b := range found {
		if b.Unit == UnitUSDMicros {
			return b, true
		}
	}
	return found[0], true
}

// spendPeriodOrder is the preference for a "used" figure.
var spendPeriodOrder = []string{"cycle", "month", "30d", "week", "day", "all_time"}

// pickSpend returns the most useful spend figure (in unit, when set).
func pickSpend(m Merged, unit Unit) (Spend, bool) {
	for _, p := range spendPeriodOrder {
		for _, sp := range m.Spend {
			if sp.Period == p && (unit == "" || sp.Unit == unit) {
				return sp, true
			}
		}
	}
	for _, sp := range m.Spend {
		if unit == "" || sp.Unit == unit {
			return sp, true
		}
	}
	return Spend{}, false
}

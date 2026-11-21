package main

import (
	"sync"

	"github.com/marmutapp/superbased-observer/internal/budgetwarn"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/orgbudget"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// Per-tool / per-model budget warnings (Sol A5-04, D-011 + D-016).
//
// The org's subject caps are ENFORCED by the guard against the accounting
// owner's ByTool / ByModel totals, but the warning service only ever saw the
// whole-caller Origins, so a $10/day cap on one tool could deny at $10 with no
// warning at $7.50 or $9. The warning ladder now walks every subject cap too,
// measured against the SAME accounting the guard enforces with.
//
// ONE ACCOUNTING OWNER. The guard does not expose its per-subject totals, and
// a second spend query would be a second truth that could disagree with the
// enforcement number. So guardwire registers the exact accounting lookup it
// installs on the guard (registerProcessBudgetAccounting), and the warning
// service reads ByTool / ByModel through that same function, with the same
// calendars the composed engine uses, keyed by the same resolved subject id
// (orgbudget.SubjectCap.ID is folded through the guard's subject resolver at
// composition).

// processBudgetAccounting holds, per DB path, the accounting lookup guardwire
// installed on the process guard.
var processBudgetAccounting sync.Map // dbPath -> guard.BudgetAccountingLookup

// registerProcessBudgetAccounting records the accounting lookup the guard for
// dbPath was composed with. Called by guardwire next to
// SetBudgetAccountingLookup; the last registration wins (one guard per
// process and DB).
func registerProcessBudgetAccounting(dbPath string, fn guard.BudgetAccountingLookup) {
	if fn == nil {
		processBudgetAccounting.Delete(dbPath)
		return
	}
	processBudgetAccounting.Store(dbPath, fn)
}

// processBudgetSubjectSpend returns the per-subject spend reader over the
// registered accounting lookup: node-wide (no session), the composed engine's
// calendars, the same non-managed accounting the guard's own warning reader
// (BudgetWindowSpendNow) uses. ok=false when nothing is registered yet or the
// read failed.
func processBudgetSubjectSpend(dbPath string) func(guard.BudgetCalendars) (guard.BudgetSnapshot, bool) {
	return func(cal guard.BudgetCalendars) (guard.BudgetSnapshot, bool) {
		v, ok := processBudgetAccounting.Load(dbPath)
		if !ok {
			return guard.BudgetSnapshot{}, false
		}
		fn, _ := v.(guard.BudgetAccountingLookup)
		if fn == nil {
			return guard.BudgetSnapshot{}, false
		}
		return fn("", guard.BudgetAccountingContext{Calendars: cal})
	}
}

// budgetWarnCalendars is the composed calendar pair as the guard engine holds
// it (an empty zone is UTC).
func budgetWarnCalendars(daily, monthly string) guard.BudgetCalendars {
	if daily == "" {
		daily = "UTC"
	}
	if monthly == "" {
		monthly = "UTC"
	}
	return guard.BudgetCalendars{DailyTimezone: daily, MonthlyTimezone: monthly}
}

// budgetWarnSubjectWindows turns each adopted subject cap into one warning
// window per authored unit, measured as the subject's local total from the
// accounting snapshot plus its cross-machine baseline (the same composition
// the guard's rows compare). A subject with no rows on this node has spent
// nothing here: it reads zero, never a guess.
func budgetWarnSubjectWindows(subjects []orgbudget.SubjectCap, snap guard.BudgetSnapshot) []budgetwarn.Window {
	var out []budgetwarn.Window
	for _, sc := range subjects {
		totals := snap.ByTool
		if sc.Kind == orgcontract.BudgetSubjectModel {
			totals = snap.ByModel
		}
		amounts := totals[sc.ID]
		subject := sc.Kind + ":" + sc.ID
		if sc.CapUSD > 0 {
			if spent, ok := subjectWindowUSD(amounts, sc.Window); ok {
				out = append(out, budgetwarn.Window{
					Window: sc.Window, Unit: "usd", Cap: sc.CapUSD, Spent: spent + sc.BaselineUSD,
					Scope: sc.ScopeUSD, Enforcement: sc.Enforcement, Thresholds: sc.Thresholds,
					Timezone: sc.Timezone, Subject: subject,
					DeniesOnLocal: sc.BaselineFlagOnly && sc.Hard, LocalSpent: spent,
				})
			}
		}
		if sc.CapTokens > 0 {
			if spent, ok := subjectWindowTokens(amounts, sc.Window); ok {
				out = append(out, budgetwarn.Window{
					Window: sc.Window, Unit: "tokens", Cap: float64(sc.CapTokens), Spent: float64(spent + sc.BaselineTokens),
					Scope: sc.ScopeTokens, Enforcement: sc.Enforcement, Thresholds: sc.Thresholds,
					Timezone: sc.Timezone, Subject: subject,
					DeniesOnLocal: sc.BaselineFlagOnly && sc.Hard, LocalSpent: float64(spent),
				})
			}
		}
	}
	return out
}

// subjectWindowUSD / subjectWindowTokens read one window's amount; only the
// calendar windows the warning ladder has periods for are warned.
func subjectWindowUSD(a policy.BudgetWindowAmounts, window string) (float64, bool) {
	switch window {
	case "daily":
		return a.DailyUSD, true
	case "monthly":
		return a.MonthlyUSD, true
	}
	return 0, false
}

func subjectWindowTokens(a policy.BudgetWindowAmounts, window string) (int64, bool) {
	switch window {
	case "daily":
		return a.DailyTokens, true
	case "monthly":
		return a.MonthlyTokens, true
	}
	return 0, false
}

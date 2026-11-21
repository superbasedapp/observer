package guard

import (
	"strings"

	"github.com/marmutapp/superbased-observer/internal/budgetwarn"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// BudgetOrigin labels one budget rule's ceiling as ORGANIZATION-authored
// (2026-10-02 budget-latency arc, finding A5). The demo-estate incident showed
// a soft org cap rendered as "daily cost (all sessions) exceeded
// [guard.budget].daily_usd … hard=true blocks further proxy requests" - a local
// key the developer never set and an enforcement the org never chose. The
// composition boundary (cmd/observer/orgbudget_wire.go) knows which windows the
// org authored; it hands the guard this table so a verdict on one of those
// windows is rendered in the org's terms.
type BudgetOrigin struct {
	// Window is "daily" or "monthly"; Unit is "usd" or "tokens".
	Window, Unit string
	// Scope is the org scope that supplied the number ("member:<id>",
	// "team:<id>", "org").
	Scope string
	// Enforcement is the org mode: report | soft | hard.
	Enforcement string
}

// budgetOriginRuleIDs maps (window, unit) onto the rule row that compares it.
// One table, one owner (CLAUDE.md #5); orgBudgetSoftRules in orgbudget.go
// names the same rows for the same windows.
var budgetOriginRuleIDs = map[[2]string]string{
	{"daily", "usd"}:      "B-602",
	{"daily", "tokens"}:   "B-622",
	{"monthly", "usd"}:    "B-603",
	{"monthly", "tokens"}: "B-623",
}

// BudgetOriginRuleID returns the rule row a (window, unit) origin governs.
func BudgetOriginRuleID(window, unit string) (string, bool) {
	id, ok := budgetOriginRuleIDs[[2]string{window, unit}]
	return id, ok
}

// SetBudgetOrigins publishes the org-authored window table. It is a LABEL
// table only: it never changes a number or a decision, so it needs no engine
// rebuild and is safe to swap at any time. nil clears it (purely local
// budgets render exactly as before).
func (g *Guard) SetBudgetOrigins(origins []BudgetOrigin) {
	if g == nil {
		return
	}
	if len(origins) == 0 {
		g.budgetOrigins.Store(nil)
		return
	}
	m := make(map[string]BudgetOrigin, len(origins))
	for _, o := range origins {
		if id, ok := BudgetOriginRuleID(o.Window, o.Unit); ok {
			m[id] = o
		}
	}
	g.budgetOrigins.Store(&m)
}

// hasOrgBudgetOrigin reports whether a rule's ceiling is org-authored. A
// FLAG on such a window is announced by the budget-warning service (the org's
// own warn ladder, once per period, on every developer surface), so the
// guard's own desktop alert for it is suppressed rather than doubled.
func (g *Guard) hasOrgBudgetOrigin(ruleID string) bool {
	if g == nil {
		return false
	}
	p := g.budgetOrigins.Load()
	if p == nil {
		return false
	}
	_, ok := (*p)[ruleID]
	return ok
}

// BudgetWindowSpend is the node's current spend in the two windows the org's
// period vocabulary reaches, as the guard's OWN accounting measures it (the
// same lookup enforcement compares against), plus the organization's
// cross-machine baseline in force. One definition: a warning and a verdict
// can never disagree about how much was spent.
type BudgetWindowSpend struct {
	DailyUSD, MonthlyUSD       float64
	DailyTokens, MonthlyTokens int64
	// The Local* fields are this machine's own spend, without the org's
	// cross-machine baseline: what a blocking cap is compared against when
	// BaselineFlagOnly holds (policy baselineWithheld). The warning surfaces
	// read them so they never call a reading "blocked" that the guard will not
	// refuse (budget-enforcement honesty, 2026-11-18).
	LocalDailyUSD, LocalMonthlyUSD       float64
	LocalDailyTokens, LocalMonthlyTokens int64
	// BaselineFlagOnly says the baseline in the totals may warn and may not
	// deny (orgcontract.BudgetBaselineAppliedFlagOnly).
	BaselineFlagOnly bool
}

// BudgetWindowSpendNow measures BudgetWindowSpend now, uncached. ok=false when
// no accounting lookup is wired (the hook process, a test) or it failed.
func (g *Guard) BudgetWindowSpendNow() (BudgetWindowSpend, bool) {
	if g == nil || g.budgetLookup == nil {
		return BudgetWindowSpend{}, false
	}
	es := g.set.Load()
	if es == nil {
		return BudgetWindowSpend{}, false
	}
	snap, ok := g.budgetLookup("", es.accountingContext(false))
	if !ok {
		return BudgetWindowSpend{}, false
	}
	b := g.budgetBaseline()
	return BudgetWindowSpend{
		DailyUSD: snap.DailyUSD + b.DailyUSD, MonthlyUSD: snap.MonthlyUSD + b.MonthlyUSD,
		DailyTokens: snap.DailyTokens + b.DailyTokens, MonthlyTokens: snap.MonthlyTokens + b.MonthlyTokens,
		LocalDailyUSD: snap.DailyUSD, LocalMonthlyUSD: snap.MonthlyUSD,
		LocalDailyTokens: snap.DailyTokens, LocalMonthlyTokens: snap.MonthlyTokens,
		BaselineFlagOnly: g.budgetBaselineFlagOnly(),
	}, true
}

// SetCostDisplay installs the developer cost-display resolver (operator
// ruling 2026-10-02: the org chooses whether developers see dollar costs or
// only token usage; the node resolves it once, store.ResolveDeveloperCostDisplay).
// When it answers "tokens", a dollar budget verdict's reason renders the share
// of the budget used instead of the amounts (policy.BudgetReasonWithoutDollars).
// It is consulted only when a budget verdict is rendered. nil restores dollars.
// Like SetBudgetOrigins it changes text only, never a number or a decision.
func (g *Guard) SetCostDisplay(resolve func() string) {
	if g == nil {
		return
	}
	if resolve == nil {
		g.costDisplay.Store(nil)
		return
	}
	g.costDisplay.Store(&resolve)
}

// costDisplayTokens reports whether the developer cost display is tokens.
func (g *Guard) costDisplayTokens() bool {
	p := g.costDisplay.Load()
	return p != nil && (*p)() == "tokens"
}

// labelOrgBudgetVerdict rewrites the reason and advice of a budget verdict
// whose window the org authored, and renders a dollar budget reason without
// dollars when the developer cost display is tokens. Anything else (a
// non-budget rule, a guard error) is returned unchanged.
func (g *Guard) labelOrgBudgetVerdict(v policy.Verdict) policy.Verdict {
	if g == nil || !isBudgetRuleID(v.RuleID) {
		return v
	}
	if p := g.budgetOrigins.Load(); p != nil {
		if o, ok := (*p)[v.RuleID]; ok {
			v = OrgBudgetVerdictText(v, o)
		}
	}
	return g.displayBudgetVerdict(v)
}

// displayBudgetVerdict applies only the developer cost display to a budget
// verdict, with no organization label. It is the whole of the rendering for a
// verdict the node's own local-only engine produced (REVIEW-4 P4-02), whose
// cap no organization authored.
func (g *Guard) displayBudgetVerdict(v policy.Verdict) policy.Verdict {
	if g == nil || !isBudgetRuleID(v.RuleID) {
		return v
	}
	if g.costDisplayTokens() {
		if r, ok := policy.BudgetReasonWithoutDollars(v.Reason); ok {
			v.Reason = r
		}
	}
	return v
}

// OrgBudgetVerdictText is the pure renderer behind labelOrgBudgetVerdict,
// exported for the budget-warning surfaces so a warning and a verdict read the
// same way.
func OrgBudgetVerdictText(v policy.Verdict, o BudgetOrigin) policy.Verdict {
	detail := v.Reason
	if i := strings.Index(detail, ": "); i >= 0 {
		detail = detail[i+2:]
	}
	// The labels are budgetwarn's (one owner), so a verdict and a warning on
	// the same window read the same way.
	//
	// A hard window's verdict that only FLAGS was taken by a guard that is
	// not refusing it (observe mode): it reads as a warning on this machine,
	// never as "blocking" (budget-enforcement honesty, 2026-11-18). A deny,
	// or a reason rendered for a hook stop (no decision), keeps "blocking".
	flagsOnly := o.Enforcement == "hard" && v.Decision == policy.DecisionFlag
	label := budgetwarn.EnforcementLabel(o.Enforcement)
	if flagsOnly {
		label = budgetwarn.EffectiveLabel(o.Enforcement, budgetwarn.EffectObserve)
	}
	v.Reason = "organization " + o.Window + " budget (" + budgetwarn.ScopeLabel(o.Scope) + ", " +
		label + ") reached: " + detail
	switch {
	case flagsOnly:
		v.Advice = "Your organization set this budget to block, but this machine's guard is not in enforce mode, so requests are not blocked. Ask an admin if you need more headroom."
	case o.Enforcement == "hard":
		v.Advice = "Your organization's budget blocks further proxied requests, and the next prompt or tool call in tools with a pre-send hook, until the period resets or an admin raises the cap."
	default:
		v.Advice = "This is a warning from your organization's budget; requests are not blocked. Ask an admin if you need more headroom."
	}
	return v
}

// displayVerdict renders a verdict's reason under the developer cost display:
// a user policy rule's session-spend condition reads as a share of the rule's
// limit, never dollars, when the org chose token usage (T-204). Text only;
// the decision and rule id are unchanged. Budget rules take their own
// rendering through labelOrgBudgetVerdict.
func (g *Guard) displayVerdict(v policy.Verdict) policy.Verdict {
	if g == nil || !g.costDisplayTokens() {
		return v
	}
	if r, ok := policy.CostConditionReasonWithoutDollars(v.Reason); ok {
		v.Reason = r
	}
	return v
}

package policy

import "strconv"

// Budget rules B-601/B-602 (spec §5.7, §12.1) — cost-threshold
// breaches. Managed hard budgets also match at the ceiling: an exhausted
// allowance must not admit another request. Local/individual budgets retain
// their existing strictly-over comparison. The rows compare stamped values
// (SessionCostUSD / DailyCostUSD, computed at the owner: the guard
// layer's TTL-cached budget lookup over proxy turns + token_usage)
// against the [guard.budget] thresholds carried on Config. An explicitly
// unavailable window matches its configured row without inventing spend. Otherwise both sides
// must be non-zero: an unconfigured threshold disables the row, and
// an unstamped event (hook path, lookup not wired) never matches.
//
// Decisions: flag/flag by default — a budget breach alerts, it does
// not block (D2). [guard.budget].hard upgrades the ENFORCE-mode
// decision to deny at engine construction (Config.BudgetHard): the
// §12.1 "deny-on-proxy" — the proxy is the only stamped channel that
// can block (synthetic 4xx), watcher surfaces record the §6.2
// degradation, hook events are never stamped. Severity high so the
// default [guard.alerts] min_severity surfaces the breach.
//
// Record volume is bounded at the guard layer: flag-class budget
// verdicts dedup once per (session, rule) — cost only grows within a
// session, so re-recording every subsequent action is noise; denies
// always record (each blocked request is its own audit event).

// matchCostOver builds a matcher comparing a stamped cost value
// against a configured threshold, both injected as accessors so the
// two budget rows share one implementation (and one test shape).
func matchCostOver(value func(*Event) float64, limit func(*Config) float64, unavailable func(*Event) bool, scope string) MatchFn {
	return func(ctx *MatchContext) (bool, string) {
		lim := limit(ctx.Cfg)
		got := value(ctx.Event)
		if lim <= 0 {
			return false, ""
		}
		if unavailable(ctx.Event) {
			return true, scope + " spend accounting is unavailable; cannot verify the configured budget"
		}
		atLimitBlocks := ctx.Cfg.BudgetHard && ctx.Cfg.BudgetProtection.protectsUSD(scope)
		if got < lim || (got == lim && !atLimitBlocks) {
			return false, ""
		}
		comparison := " exceeds the $"
		if got == lim {
			comparison = " has reached the $"
		}
		return true, scope + " spend $" + strconv.FormatFloat(got, 'f', 2, 64) +
			comparison + strconv.FormatFloat(lim, 'f', 2, 64) + " budget"
	}
}

// matchCountOver is the INTEGER sibling of matchCostOver: it compares a
// stamped token count against a configured token ceiling, with the identical
// both-sides-non-zero rule (an unconfigured ceiling disables the row; an
// unstamped event never matches). It exists because a budget can be authored in
// EITHER unit — an org token cap needs no rate card, which is why the org rail
// carries one (org-budget plan §3.3c / R3) — and the two units must be two rows
// over one shape, never one row that branches on where its number came from
// (CLAUDE.md #3).
func matchCountOver(value func(*Event) int64, limit func(*Config) int64, unavailable func(*Event) bool, scope string) MatchFn {
	return func(ctx *MatchContext) (bool, string) {
		lim := limit(ctx.Cfg)
		got := value(ctx.Event)
		if lim <= 0 {
			return false, ""
		}
		if unavailable(ctx.Event) {
			return true, scope + " token usage accounting is unavailable; cannot verify the configured budget"
		}
		atLimitBlocks := ctx.Cfg.BudgetHard && ctx.Cfg.BudgetProtection.protectsTokens(scope)
		if got < lim || (got == lim && !atLimitBlocks) {
			return false, ""
		}
		comparison := " tokens exceeds the "
		if got == lim {
			comparison = " tokens has reached the "
		}
		return true, scope + " usage " + strconv.FormatInt(got, 10) +
			comparison + strconv.FormatInt(lim, 10) + "-token budget"
	}
}

// matchUtilOver builds a matcher comparing a stamped utilization
// (0..1, the provider's own usage-window fraction) against a
// configured threshold. AT-OR-OVER matches (got >= lim) so a window
// exactly at the threshold trips; both sides must be non-zero (an
// unconfigured threshold disables the row, an unstamped event —
// no window observed — never matches). Reason is rendered as a
// percentage, the operator-facing unit.
func matchUtilOver(value func(*Event) float64, limit func(*Config) float64, window, action string) MatchFn {
	return func(ctx *MatchContext) (bool, string) {
		lim := limit(ctx.Cfg)
		got := value(ctx.Event)
		if lim <= 0 || got <= 0 || got < lim {
			return false, ""
		}
		return true, window + " usage window at " +
			strconv.FormatFloat(got*100, 'f', 0, 64) + "% (≥ " +
			strconv.FormatFloat(lim*100, 'f', 0, 64) + "% " + action + " threshold)"
	}
}

// budgetEventKinds are the kinds the guard layer stamps spend onto:
// every classified watcher kind plus the proxy's api_request.
func budgetEventKinds() []EventKind {
	return []EventKind{
		KindAPIRequest, KindShellExec, KindFileAccess,
		KindMCPCall, KindConfigChange, KindToolCall,
	}
}

// budgetRules assembles the §5.7 budget rows.
func budgetRules() []Rule {
	kinds := budgetEventKinds()
	return []Rule{
		{
			ID: "B-601", Category: CategoryBudget, Severity: SeverityHigh,
			AppliesTo: kinds,
			Match: matchCostOver(
				func(ev *Event) float64 { return ev.SessionCostUSD },
				func(cfg *Config) float64 { return cfg.BudgetSessionUSD },
				func(ev *Event) bool { return ev.USDUnavailable.Session },
				"session",
			),
			Observe: DecisionFlag, Enforce: DecisionFlag,
			Doc:    "session cost exceeded [guard.budget].session_usd",
			Advice: "Review what the session is burning tokens on; raise [guard.budget].session_usd, approve B-601 for this session, or stop the run. hard=true blocks further proxy requests in enforce mode.",
		},
		{
			ID: "B-602", Category: CategoryBudget, Severity: SeverityHigh,
			AppliesTo: kinds,
			Match: matchCostOver(
				func(ev *Event) float64 { return ev.DailyCostUSD },
				func(cfg *Config) float64 { return cfg.BudgetDailyUSD },
				func(ev *Event) bool { return ev.USDUnavailable.Daily },
				"daily",
			),
			Observe: DecisionFlag, Enforce: DecisionFlag,
			Doc:    "daily cost (all sessions) exceeded [guard.budget].daily_usd",
			Advice: "Today's total spend across sessions crossed the configured ceiling; raise [guard.budget].daily_usd or pause agent work. hard=true blocks further proxy requests in enforce mode.",
		},
		{
			ID: "B-603", Category: CategoryBudget, Severity: SeverityHigh,
			AppliesTo: kinds,
			Match: matchCostOver(
				func(ev *Event) float64 { return ev.MonthlyCostUSD },
				func(cfg *Config) float64 { return cfg.BudgetMonthlyUSD },
				func(ev *Event) bool { return ev.USDUnavailable.Monthly },
				"monthly",
			),
			Observe: DecisionFlag, Enforce: DecisionFlag,
			Doc:    "calendar-month cost (all sessions) exceeded [guard.budget].monthly_usd",
			Advice: "Month-to-date spend crossed the configured ceiling; raise [guard.budget].monthly_usd or pause agent work. hard=true blocks further proxy requests in enforce mode.",
		},
		{
			ID: "B-604", Category: CategoryBudget, Severity: SeverityHigh,
			AppliesTo: kinds,
			Match: matchCostOver(
				func(ev *Event) float64 { return ev.WeeklyCostUSD },
				func(cfg *Config) float64 { return cfg.BudgetWeeklyUSD },
				func(ev *Event) bool { return ev.USDUnavailable.Weekly },
				"weekly",
			),
			Observe: DecisionFlag, Enforce: DecisionFlag,
			Doc:    "rolling-7-day cost (all sessions) exceeded [guard.budget].weekly_usd",
			Advice: "Last-7-days spend crossed the configured ceiling; raise [guard.budget].weekly_usd or pause agent work. hard=true blocks further proxy requests in enforce mode.",
		},
	}
}

// tokenBudgetRules assembles the TOKEN-denominated budget rows B-621..B-624 —
// the four $ rows above, one for one, in the other unit (org-budget plan
// §3.3c).
//
// They are CategoryBudget like their $ siblings, so the single
// Config.BudgetHard switch in engine.go upgrades all eight rows' enforce-mode
// decision together: there is one budget posture on a node, not one per unit.
// Severity high for the same reason (the default [guard.alerts] min_severity
// surfaces a breach), and the same session-scoped flag dedup applies because
// isBudgetRuleID matches the whole "B-6" prefix.
//
// The thresholds may be the node's own [guard.budget].*_tokens or an
// ORGANIZATION cap composed onto them (internal/orgbudget). The rows cannot
// tell the difference and must not: composition is resolved at the boundary and
// arrives here as a number, exactly like every other configured ceiling.
func tokenBudgetRules() []Rule {
	kinds := budgetEventKinds()
	return []Rule{
		{
			ID: "B-621", Category: CategoryBudget, Severity: SeverityHigh,
			AppliesTo: kinds,
			Match: matchCountOver(
				func(ev *Event) int64 { return ev.SessionTokens },
				func(cfg *Config) int64 { return cfg.BudgetSessionTokens },
				func(ev *Event) bool { return ev.TokensUnavailable.Session },
				"session",
			),
			Observe: DecisionFlag, Enforce: DecisionFlag,
			Doc:    "session token usage exceeded [guard.budget].session_tokens",
			Advice: "Review what the session is burning tokens on; raise [guard.budget].session_tokens, approve B-621 for this session, or stop the run. hard=true blocks further proxy requests in enforce mode. An organization budget can lower this ceiling but never raise it.",
		},
		{
			ID: "B-622", Category: CategoryBudget, Severity: SeverityHigh,
			AppliesTo: kinds,
			Match: matchCountOver(
				func(ev *Event) int64 { return ev.DailyTokens },
				func(cfg *Config) int64 { return cfg.BudgetDailyTokens },
				func(ev *Event) bool { return ev.TokensUnavailable.Daily },
				"daily",
			),
			Observe: DecisionFlag, Enforce: DecisionFlag,
			Doc:    "daily token usage (all sessions) exceeded [guard.budget].daily_tokens",
			Advice: "Today's total token usage across sessions crossed the configured ceiling; raise [guard.budget].daily_tokens or pause agent work. hard=true blocks further proxy requests in enforce mode.",
		},
		{
			ID: "B-623", Category: CategoryBudget, Severity: SeverityHigh,
			AppliesTo: kinds,
			Match: matchCountOver(
				func(ev *Event) int64 { return ev.MonthlyTokens },
				func(cfg *Config) int64 { return cfg.BudgetMonthlyTokens },
				func(ev *Event) bool { return ev.TokensUnavailable.Monthly },
				"monthly",
			),
			Observe: DecisionFlag, Enforce: DecisionFlag,
			Doc:    "calendar-month token usage (all sessions) exceeded [guard.budget].monthly_tokens",
			Advice: "Month-to-date token usage crossed the configured ceiling; raise [guard.budget].monthly_tokens or pause agent work. hard=true blocks further proxy requests in enforce mode.",
		},
		{
			ID: "B-624", Category: CategoryBudget, Severity: SeverityHigh,
			AppliesTo: kinds,
			Match: matchCountOver(
				func(ev *Event) int64 { return ev.WeeklyTokens },
				func(cfg *Config) int64 { return cfg.BudgetWeeklyTokens },
				func(ev *Event) bool { return ev.TokensUnavailable.Weekly },
				"weekly",
			),
			Observe: DecisionFlag, Enforce: DecisionFlag,
			Doc:    "rolling-7-day token usage (all sessions) exceeded [guard.budget].weekly_tokens",
			Advice: "Last-7-days token usage crossed the configured ceiling; raise [guard.budget].weekly_tokens or pause agent work. hard=true blocks further proxy requests in enforce mode.",
		},
	}
}

// BudgetRequired reports whether this engine was built with the fail-closed
// org-budget posture armed. It is the read side of Config.BudgetRequired for
// the ONE caller that needs it outside Evaluate: the guard's proxy budget
// check, which returns early when an event carries no stamped spend at all
// and would otherwise never reach B-625 (internal/guard/budget.go::scanBudget).
//
// An accessor rather than a second copy of the flag on the guard's own hot
// path, so the engine that is actually evaluating and the early-return that
// decides whether to evaluate can never disagree.
func (e *Engine) BudgetRequired() bool {
	if e == nil {
		return false
	}
	return e.cfg.BudgetRequired
}

// requiredBudgetRules assembles B-625, the fail-closed row (org-budget ruling
// R2): a MANAGED node whose organization holds enforce.budget, with no
// verified org budget body ever applied, refuses proxied requests.
//
// It is the odd row in this file and deliberately so:
//
//   - It compares NO number. Every other budget row needs both a stamped
//     value and a configured ceiling, which is exactly why an absent budget
//     could never block: there was nothing to exceed. The state this row
//     names is "there is no ceiling and there was supposed to be one".
//   - AppliesTo is KindAPIRequest ALONE. The proxy request path is the only
//     channel that can actually refuse anything (§12.1 deny-on-proxy);
//     matching the watcher and hook kinds would record a verdict on every
//     captured action for a condition none of them can act on.
//   - Enforce is deny outright rather than relying on Config.BudgetHard. The
//     hard flag is the developer's own posture about THEIR ceilings; this row
//     is the organization's requirement, and a node that could turn it back
//     into a flag by clearing one local key would not be failing closed.
//     Observe still flags: D2 holds — nothing blocks until enforce.
func requiredBudgetRules() []Rule {
	return []Rule{
		{
			ID: "B-625", Category: CategoryBudget, Severity: SeverityHigh,
			AppliesTo: []EventKind{KindAPIRequest},
			Match: func(ctx *MatchContext) (bool, string) {
				if !ctx.Cfg.BudgetRequired {
					return false, ""
				}
				return true, "this node is managed and its organization requires a budget; " +
					"no verified organization budget has been applied here"
			},
			Observe: DecisionFlag, Enforce: DecisionDeny,
			Doc: "the organization requires a budget on this managed node and none has been verified",
			Advice: "The node is enrolled with an organization that holds enforce.budget, and its signed budget " +
				"document has never verified here. Check `observer org status` and the daemon log for the budget " +
				"rail's fetch state; the organization must publish a budget covering this member, and the node " +
				"must be able to verify its signature.",
		},
	}
}

// limitRules assembles the §12.1 provider-usage-window rows (B-610..
// B-613). Unlike the $ budget rows these compare a UTILIZATION
// fraction (0..1) read from limit_snapshots against explicit warn/deny
// thresholds — CategoryLimit, so [guard.budget].hard never rewrites
// them (the deny threshold is the block trigger, no hard flag needed).
// Each window is TWO rows (warn flag, deny block); a util at-or-over
// the deny threshold matches both and the engine's stricter-wins
// resolution picks the deny.
func limitRules() []Rule {
	kinds := budgetEventKinds()
	return []Rule{
		{
			ID: "B-610", Category: CategoryLimit, Severity: SeverityWarn,
			AppliesTo: kinds,
			Match: matchUtilOver(
				func(ev *Event) float64 { return ev.Window5hUtil },
				func(cfg *Config) float64 { return cfg.LimitUtil5hWarn },
				"5h", "warn",
			),
			Observe: DecisionFlag, Enforce: DecisionFlag,
			Doc:    "5h usage window utilization reached [guard.budget.window].util_5h_warn",
			Advice: "Nearing the provider's 5-hour quota; pace requests or switch to a lighter model. Raise util_5h_warn to quiet this.",
		},
		{
			ID: "B-611", Category: CategoryLimit, Severity: SeverityHigh,
			AppliesTo: kinds,
			Match: matchUtilOver(
				func(ev *Event) float64 { return ev.Window5hUtil },
				func(cfg *Config) float64 { return cfg.LimitUtil5hDeny },
				"5h", "deny",
			),
			Observe: DecisionFlag, Enforce: DecisionDeny,
			Doc:    "5h usage window utilization reached [guard.budget.window].util_5h_deny",
			Advice: "At the provider's 5-hour quota ceiling; further proxy requests are blocked in enforce mode until the window resets. Raise util_5h_deny to relax.",
		},
		{
			ID: "B-612", Category: CategoryLimit, Severity: SeverityWarn,
			AppliesTo: kinds,
			Match: matchUtilOver(
				func(ev *Event) float64 { return ev.Window7dUtil },
				func(cfg *Config) float64 { return cfg.LimitUtilWeeklyWarn },
				"weekly", "warn",
			),
			Observe: DecisionFlag, Enforce: DecisionFlag,
			Doc:    "weekly usage window utilization reached [guard.budget.window].util_weekly_warn",
			Advice: "Nearing the provider's weekly quota; pace requests or switch to a lighter model. Raise util_weekly_warn to quiet this.",
		},
		{
			ID: "B-613", Category: CategoryLimit, Severity: SeverityHigh,
			AppliesTo: kinds,
			Match: matchUtilOver(
				func(ev *Event) float64 { return ev.Window7dUtil },
				func(cfg *Config) float64 { return cfg.LimitUtilWeeklyDeny },
				"weekly", "deny",
			),
			Observe: DecisionFlag, Enforce: DecisionDeny,
			Doc:    "weekly usage window utilization reached [guard.budget.window].util_weekly_deny",
			Advice: "At the provider's weekly quota ceiling; further proxy requests are blocked in enforce mode until the window resets. Raise util_weekly_deny to relax.",
		},
	}
}

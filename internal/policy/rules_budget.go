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
		// THE CROSS-MACHINE BASELINE (bundle BUD-N / P1-9). The value a cap is
		// compared against is the organization's measurement of this caller's
		// spend on its OTHER machines plus this machine's own. One developer
		// with a laptop and a devbox burns one org budget from two nodes, and a
		// node comparing only its own rows enforces a ceiling the org already
		// considers crossed.
		//
		// It is a plain addend and nothing more: zero on every individual node,
		// zero whenever the baseline was stale, absent or uncomposable (the
		// composition boundary decides — internal/orgbudget), and in that case
		// this comparison is byte-for-byte the one that shipped before.
		base, _ := ctx.Event.OrgBaseline.USD(scope)
		if baselineWithheld(ctx) {
			base = 0
		}
		got := value(ctx.Event) + base
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
			comparison + strconv.FormatFloat(lim, 'f', 2, 64) + " budget" + baselineNote(base > 0)
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
		// The same cross-machine baseline as matchCostOver, in the other unit.
		base, _ := ctx.Event.OrgBaseline.Tokens(scope)
		if baselineWithheld(ctx) {
			base = 0
		}
		got := value(ctx.Event) + base
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
			comparison + strconv.FormatInt(lim, 10) + "-token budget" + baselineNote(base > 0)
	}
}

// baselineWithheld reports whether the cross-machine baseline must be left OUT
// of a NODE-WIDE comparison because the row it feeds can deny.
//
// It is the arithmetic half of orgcontract.BudgetBaselineAppliedFlagOnly
// (adversarial review of BUD-N, P1-2): when the org's measurement counted rows
// it could not attribute to any machine, the number may double-count this
// node's own spend, and a request refused — or, through the process-control
// pass, a running process stopped — on such a number is exactly the failure
// class this rail cannot afford. So it warns and never blocks.
//
// "Can deny" for the node-wide rows IS [guard.budget].hard, because that single
// flag is what engine.New upgrades all eight of them with; there is no soft
// sibling row to fall back to, so on a hard node the baseline simply stops
// contributing. A node that flags keeps composing it, which is the whole point:
// the developer still sees "you are over the fleet budget", they are just not
// stopped by a number that may have counted their own turns twice.
//
// The SUBJECT rows do not use this: their hardness is per cap, and
// subjectCapBreach reads BudgetSubjectCap.BaselineFlagOnly against that cap's
// own Hard flag instead.
func baselineWithheld(ctx *MatchContext) bool {
	return ctx.Event.OrgBaselineFlagOnly && ctx.Cfg.BudgetHard
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

// SUBJECT budget rows B-626..B-629 (bundle BUD-N): the organization's
// PER-TOOL and PER-MODEL caps.
//
//	B-626  tool cap, dollars      B-627  tool cap, tokens
//	B-628  model cap, dollars     B-629  model cap, tokens
//
// They are the same comparison the node-wide rows make — a stamped total
// against a configured ceiling, both sides non-zero, plus the cross-machine
// baseline — with two differences that are entirely data:
//
//   - the ceiling comes from Config.BudgetSubjectCaps, a TABLE the org
//     authored, rather than from a scalar field; and
//   - the stamped total is the event's own Tool/Model slice of spend
//     (Event.ToolUsage / Event.ModelUsage) rather than the node-wide one.
//
// Each ID ships TWO rows (approved deviation 3, the same mechanism the §5
// catalog uses when decision splits by sub-shape): a DENY row that matches only
// caps the org authored hard, and a FLAG row that matches only soft ones. That
// is why subjectBudgetRuleID exempts them from the [guard.budget].hard blanket
// upgrade in engine.go — their hardness is per cap and already resolved, and
// folding a node-wide posture over it would deny a nudge.
//
// WHY NOT ONE ROW PER SUBJECT: the org chooses how many subjects it caps, and a
// rule ID is a documented, stable catalog entry. Twenty tools would otherwise
// mean twenty IDs nobody can document, and an ID that appeared and vanished
// with an admin's edit. One row per kind+unit, walking the table, keeps the
// catalog closed while the caps stay the org's business.

// subjectBudgetRuleIDs is the closed set of subject rows, in catalog order.
// Kind and unit are DATA on the row so the assembler below is a table walk and
// engine.go's exemption check is a set lookup.
var subjectBudgetRuleIDs = []struct {
	id     string
	kind   string
	tokens bool
}{
	{id: "B-626", kind: BudgetSubjectKindTool},
	{id: "B-627", kind: BudgetSubjectKindTool, tokens: true},
	{id: "B-628", kind: BudgetSubjectKindModel},
	{id: "B-629", kind: BudgetSubjectKindModel, tokens: true},
}

// Subject KIND vocabulary as this package spells it. It mirrors
// orgcontract.BudgetSubjectTool / BudgetSubjectModel, re-declared because this
// package imports zero observer packages; the boundary normalizes onto these
// two strings and internal/orgbudget's table pins the pairing.
const (
	BudgetSubjectKindTool  = "tool"
	BudgetSubjectKindModel = "model"
)

// subjectBudgetRuleID reports whether id is one of the four subject rows.
func subjectBudgetRuleID(id string) bool {
	for _, row := range subjectBudgetRuleIDs {
		if row.id == id {
			return true
		}
	}
	return false
}

// subjectOf returns the event's identifier for one subject kind and the spend
// slice that goes with it. ok=false means the event carries no such subject —
// every hook-path event for a model, for instance — and the row then cannot
// match, which is the honest answer rather than a node-wide fallback.
//
// The RESOLVED id wins when the guard stamped one: a cap and an event must be
// compared on the identity the price table folds them both onto, or a dated
// model name never equals its own family and an authored cap governs nothing
// (adversarial review of BUD-N, P1-3). The plain normalisation remains the
// fallback for every path that carries no resolver.
func subjectOf(ev *Event, kind string) (id string, usage BudgetWindowAmounts, ok bool) {
	switch kind {
	case BudgetSubjectKindTool:
		id = subjectIdentity(ev.ToolSubjectID, ev.Tool)
		usage = ev.ToolUsage
	case BudgetSubjectKindModel:
		id = subjectIdentity(ev.ModelSubjectID, ev.Model)
		usage = ev.ModelUsage
	default:
		return "", BudgetWindowAmounts{}, false
	}
	return id, usage, id != ""
}

// subjectIdentity prefers the resolved subject id and falls back to normalizing
// the raw one. Both are normalized here rather than trusted, so a stamp that
// arrived in some other spelling still meets the cap on one rule.
func subjectIdentity(resolved, raw string) string {
	if out := normalizeSubjectID(resolved); out != "" {
		return out
	}
	return normalizeSubjectID(raw)
}

// normalizeSubjectID folds a captured tool/model id onto the same spelling the
// boundary normalized the org's cap onto: trimmed, ASCII-lowered. One rule, two
// sources.
func normalizeSubjectID(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			if len(out) == 0 {
				continue
			}
		}
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out = append(out, c)
	}
	for len(out) > 0 {
		switch out[len(out)-1] {
		case ' ', '\t', '\n', '\r':
			out = out[:len(out)-1]
			continue
		}
		break
	}
	return string(out)
}

// matchSubjectOver is the ONE matcher behind all four subject rows. hard
// selects which half of the table this row owns, so the deny row and the flag
// row never both fire on the same cap.
//
// The comparison is the node-wide rows' comparison, subject-scoped:
//
//	baseline (the org's other machines) + this machine's usage  >=  cap
//
// with the same at-the-limit rule (a managed hard ceiling matches AT the
// limit — an exhausted allowance must not admit another request — and a soft or
// local one needs a strict crossing), and the same treatment of unavailable
// accounting: a window whose accounting could not be established matches a
// configured cap rather than admitting on a fabricated zero.
func matchSubjectOver(kind string, tokens, hard bool) MatchFn {
	return func(ctx *MatchContext) (bool, string) {
		if len(ctx.Cfg.BudgetSubjectCaps) == 0 {
			return false, ""
		}
		id, usage, haveSubject := subjectOf(ctx.Event, kind)
		for i := range ctx.Cfg.BudgetSubjectCaps {
			sc := ctx.Cfg.BudgetSubjectCaps[i]
			if sc.Kind != kind || sc.Hard != hard {
				continue
			}
			// AN EVENT THAT NAMES NO SUBJECT cannot be shown to be OUTSIDE a
			// cap when the accounting for that cap's window could not be
			// established at all. It matches, for exactly the reason the
			// node-wide rows match an unavailable window: a configured ceiling
			// must not admit on a fabricated zero. With accounting AVAILABLE it
			// does not match — an unattributed event is not evidence against
			// somebody else's cap — and this is also what makes a snapshot's
			// "can this policy deny?" probe (Engine.ManagedBudgetRequired,
			// which evaluates an all-unavailable event carrying no subject)
			// answer honestly for a subject cap.
			if !haveSubject {
				if hit, detail := subjectCapUnverifiable(ctx.Event, sc, tokens); hit {
					return true, detail
				}
				continue
			}
			if sc.ID != id {
				continue
			}
			if hit, detail := subjectCapBreach(ctx.Event, sc, usage, tokens); hit {
				return true, detail
			}
		}
		return false, ""
	}
}

// subjectCapUnverifiable reports the unavailable-accounting match for a cap
// whose subject the event did not name. It is split from subjectCapBreach
// because it compares NOTHING: there is no usage to compare, only a configured
// ceiling and a window nobody could measure.
func subjectCapUnverifiable(ev *Event, sc BudgetSubjectCap, tokens bool) (bool, string) {
	if tokens {
		if sc.CapTokens <= 0 || !ev.TokensUnavailable.Unavailable(sc.Window) {
			return false, ""
		}
		return true, subjectLabel(sc) + " token usage accounting is unavailable; cannot verify the configured budget"
	}
	if sc.CapUSD <= 0 || !ev.USDUnavailable.Unavailable(sc.Window) {
		return false, ""
	}
	return true, subjectLabel(sc) + " spend accounting is unavailable; cannot verify the configured budget"
}

// subjectCapBreach compares ONE cap in ONE unit. Split out so the walk above
// reads as a walk and this reads as the comparison — and so a test can drive
// the comparison one row at a time.
func subjectCapBreach(ev *Event, sc BudgetSubjectCap, usage BudgetWindowAmounts, tokens bool) (bool, string) {
	if tokens {
		lim := sc.CapTokens
		if lim <= 0 {
			return false, ""
		}
		if ev.TokensUnavailable.Unavailable(sc.Window) {
			return true, subjectLabel(sc) + " token usage accounting is unavailable; cannot verify the configured budget"
		}
		got, known := usage.Tokens(sc.Window)
		if !known {
			return false, ""
		}
		got += subjectBaselineTokens(sc)
		if got < lim || (got == lim && !sc.Hard) {
			return false, ""
		}
		comparison := " tokens exceeds the "
		if got == lim {
			comparison = " tokens has reached the "
		}
		return true, subjectLabel(sc) + " usage " + strconv.FormatInt(got, 10) +
			comparison + strconv.FormatInt(lim, 10) + "-token budget" + baselineNote(subjectBaselineTokens(sc) > 0)
	}
	lim := sc.CapUSD
	if lim <= 0 {
		return false, ""
	}
	if ev.USDUnavailable.Unavailable(sc.Window) {
		return true, subjectLabel(sc) + " spend accounting is unavailable; cannot verify the configured budget"
	}
	got, known := usage.USD(sc.Window)
	if !known {
		return false, ""
	}
	got += subjectBaselineUSD(sc)
	if got < lim || (got == lim && !sc.Hard) {
		return false, ""
	}
	comparison := " exceeds the $"
	if got == lim {
		comparison = " has reached the $"
	}
	return true, subjectLabel(sc) + " spend $" + strconv.FormatFloat(got, 'f', 2, 64) +
		comparison + strconv.FormatFloat(lim, 'f', 2, 64) + " budget" + baselineNote(subjectBaselineUSD(sc) > 0)
}

// subjectBaselineUSD / subjectBaselineTokens are this cap's cross-machine
// baseline AS THIS ROW MAY USE IT.
//
// A cap the org authored HARD can stop a request and, through the
// process-control pass, a running process. A baseline the server flagged as
// including unattributed rows may already contain this node's own spend, so a
// hard cap compares local usage alone (orgcontract.
// BudgetBaselineAppliedFlagOnly). A SOFT cap keeps composing the two: a warning
// raised on a possibly-overlapping number costs nothing, and suppressing it
// would hide the very fact the fleet-wide cap exists to surface.
//
// The reason text reads the same helpers, so a verdict never claims it counted
// other machines' spend in a comparison that did not.
func subjectBaselineUSD(sc BudgetSubjectCap) float64 {
	if sc.BaselineFlagOnly && sc.Hard {
		return 0
	}
	return sc.BaselineUSD
}

func subjectBaselineTokens(sc BudgetSubjectCap) int64 {
	if sc.BaselineFlagOnly && sc.Hard {
		return 0
	}
	return sc.BaselineTokens
}

// subjectLabel renders the cap's scope for the verdict reason, e.g.
// `daily claude-code`. The subject id is the org's own cap and the node's own
// captured tool/model name — both already travel on the push wire — so naming
// it is the difference between an operator knowing which cap bit them and
// reading "budget exceeded".
func subjectLabel(sc BudgetSubjectCap) string { return sc.Window + " " + sc.ID }

// baselineNote appends the one fact an operator cannot otherwise infer: the
// number that crossed includes spend from their OTHER machines.
func baselineNote(applied bool) string {
	if !applied {
		return ""
	}
	return " (including organization spend on this developer's other machines)"
}

// subjectBudgetRules assembles the eight rows behind the four subject IDs.
func subjectBudgetRules() []Rule {
	kinds := budgetEventKinds()
	var out []Rule
	for _, row := range subjectBudgetRuleIDs {
		unit, ceiling := "spend", "cap"
		if row.tokens {
			unit = "token usage"
		}
		for _, hard := range []bool{true, false} {
			enforce := DecisionFlag
			if hard {
				enforce = DecisionDeny
			}
			out = append(out, Rule{
				ID: row.id, Category: CategoryBudget, Severity: SeverityHigh,
				AppliesTo: kinds,
				Match:     matchSubjectOver(row.kind, row.tokens, hard),
				Observe:   DecisionFlag, Enforce: enforce,
				Doc: "per-" + row.kind + " " + unit + " exceeded the organization's " + row.kind + " budget " + ceiling,
				Advice: "The organization authored a budget for this " + row.kind + " and this period's usage has reached it. " +
					"The ceiling counts spend across every machine this developer is enrolled with, so another machine may have " +
					"consumed it. Ask the organization to raise or retire the " + row.kind + " cap, or switch to one it has not capped.",
			})
		}
	}
	return out
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

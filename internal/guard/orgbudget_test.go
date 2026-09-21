package guard

import (
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// budgetEvent is an api_request event carrying a monthly token stamp, the
// shape the proxy budget check produces.
func budgetEvent(monthlyTokens int64) policy.Event {
	return policy.Event{
		Kind:          policy.KindAPIRequest,
		Target:        "api.anthropic.com",
		SessionID:     "s1",
		MonthlyTokens: monthlyTokens,
		Now:           time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC),
	}
}

// TestApplyOrgBudgetTakesEffectOnTheLiveEngine: the composed numbers must bite
// WITHOUT a daemon restart — the whole point of applying them on the push
// cycle.
func TestApplyOrgBudgetTakesEffectOnTheLiveEngine(t *testing.T) {
	t.Parallel()

	cfg := guardCfg()
	cfg.Mode = "enforce"
	g := newTestGuard(t, cfg, nil)

	if v, gerr := g.Evaluate(budgetEvent(2_000_001)); gerr != nil || v.Decision >= policy.DecisionFlag {
		t.Fatalf("before ApplyOrgBudget: %s fired with no configured ceiling (err %v)", v.RuleID, gerr)
	}

	eff := cfg.Budget
	eff.MonthlyTokens = 2_000_000
	eff.Hard = true
	if err := g.ApplyOrgBudget(eff, nil, false, policy.BudgetProtection{}, ""); err != nil {
		t.Fatalf("ApplyOrgBudget: %v", err)
	}
	v, gerr := g.Evaluate(budgetEvent(2_000_001))
	if gerr != nil {
		t.Fatalf("Evaluate: %v", gerr)
	}
	if v.Decision != policy.DecisionDeny || v.RuleID != "B-623" {
		t.Fatalf("after ApplyOrgBudget: decision=%v rule=%q, want deny/B-623", v.Decision, v.RuleID)
	}
	if got := g.EffectiveBudget().MonthlyTokens; got != 2_000_000 {
		t.Errorf("EffectiveBudget().MonthlyTokens = %d, want 2000000", got)
	}
}

// TestEngineSetRebuildKeepsTheOrgThresholds is the plan's failing-first case
// for the SECOND build site. buildEngine is the one funnel every rebuild goes
// through, so a fix that stashed the numbers only into the base engine would
// pass the test above and fail here: the project-layer engine is built LAZILY,
// on the first event for that root, LONG after ApplyOrgBudget ran.
func TestEngineSetRebuildKeepsTheOrgThresholds(t *testing.T) {
	t.Parallel()

	cfg := guardCfg()
	cfg.Mode = "enforce"
	// A project policy layer, so evaluating an event scoped to that root
	// forces a project-engine rebuild through buildEngine.
	g := newTestGuard(t, cfg, map[string]string{
		"/home/u/proj/.observer/guard-policy.toml": "[[override]]\nrule = \"R-111\"\ndecision = \"deny\"\n",
	})

	eff := cfg.Budget
	eff.MonthlyTokens = 2_000_000
	eff.Hard = true
	if err := g.ApplyOrgBudget(eff, nil, false, policy.BudgetProtection{}, ""); err != nil {
		t.Fatalf("ApplyOrgBudget: %v", err)
	}

	ev := budgetEvent(2_000_001)
	ev.ProjectRoot = "/home/u/proj"
	v, gerr := g.Evaluate(ev)
	if gerr != nil {
		t.Fatalf("Evaluate: %v", gerr)
	}
	if v.Decision != policy.DecisionDeny || v.RuleID != "B-623" {
		t.Fatalf("project-scoped rebuild: decision=%v rule=%q, want deny/B-623 — the rebuilt engine reverted to the node's own thresholds",
			v.Decision, v.RuleID)
	}
	// The assertion above is only meaningful if a project engine was actually
	// BUILT. Without this, a project layer that silently failed to load would
	// fall back to the base engine and make the test vacuous.
	built := false
	for _, st := range g.PolicyStates() {
		if st.Layer == layerProject {
			built = true
		}
	}
	if !built {
		t.Fatal("no project policy layer loaded — this test never exercised the second build site")
	}
}

// TestApplyOrgBudgetIsIdempotent: the push cycle calls this every time, so an
// unchanged budget must not churn the engine snapshot (and with it the warm
// project cache).
func TestApplyOrgBudgetIsIdempotent(t *testing.T) {
	t.Parallel()

	cfg := guardCfg()
	g := newTestGuard(t, cfg, nil)

	eff := cfg.Budget
	eff.DailyTokens = 5000
	if err := g.ApplyOrgBudget(eff, nil, false, policy.BudgetProtection{}, ""); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	before := g.set.Load()
	if err := g.ApplyOrgBudget(eff, nil, false, policy.BudgetProtection{}, ""); err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if g.set.Load() != before {
		t.Error("an unchanged budget swapped the engine set — every push cycle would discard the warm project cache")
	}
}

// TestUnappliedGuardUsesItsConstructedBudget pins the default: with nothing
// applied, budgetConfig() is exactly the config the Guard was built with, so a
// build with no org rail behaves byte-identically.
func TestUnappliedGuardUsesItsConstructedBudget(t *testing.T) {
	t.Parallel()

	cfg := guardCfg()
	cfg.Budget.MonthlyUSD = 42
	cfg.Budget.MonthlyTokens = 99
	g := newTestGuard(t, cfg, nil)

	got := g.EffectiveBudget()
	if got != cfg.Budget {
		t.Errorf("EffectiveBudget() = %+v, want the constructed %+v", got, cfg.Budget)
	}
}

// TestStampBudgetFillsBothUnits: one lookup, both units — a token budget and a
// dollar budget must never disagree about which turns they counted.
func TestStampBudgetFillsBothUnits(t *testing.T) {
	t.Parallel()

	g := newTestGuard(t, guardCfg(), nil)
	g.SetBudgetLookup(func(string) (BudgetSnapshot, bool) {
		return BudgetSnapshot{
			SessionUSD: 1, DailyUSD: 2, WeeklyUSD: 3, MonthlyUSD: 4,
			SessionTokens: 10, DailyTokens: 20, WeeklyTokens: 30, MonthlyTokens: 40,
		}, true
	})
	ev := policy.Event{Kind: policy.KindAPIRequest, SessionID: "s1", Now: time.Now().UTC()}
	g.stampBudget(&ev)
	if ev.SessionTokens != 10 || ev.DailyTokens != 20 || ev.WeeklyTokens != 30 || ev.MonthlyTokens != 40 {
		t.Errorf("token stamps = %d/%d/%d/%d, want 10/20/30/40",
			ev.SessionTokens, ev.DailyTokens, ev.WeeklyTokens, ev.MonthlyTokens)
	}
	if ev.MonthlyCostUSD != 4 {
		t.Errorf("the $ stamps regressed: MonthlyCostUSD = %v, want 4", ev.MonthlyCostUSD)
	}
}

// TestProxyBudgetScanDeniesOnATokenOnlyBreach walks the real proxy seam: a
// session with NO dollar spend recorded but a token breach must still be
// refused. Before the token arms existed, scanBudget's all-zero early return
// swallowed exactly this case.
func TestProxyBudgetScanDeniesOnATokenOnlyBreach(t *testing.T) {
	t.Parallel()

	cfg := guardCfg()
	cfg.Mode = "enforce"
	cfg.Budget.MonthlyTokens = 1000
	cfg.Budget.Hard = true
	g := newTestGuard(t, cfg, nil)
	g.SetBudgetLookup(func(string) (BudgetSnapshot, bool) {
		return BudgetSnapshot{MonthlyTokens: 1001}, true
	})

	var res ProxyRequestResult
	g.scanBudget(g.set.Load(), &res, "s1", "api.anthropic.com", time.Now().UTC())
	if !res.Deny {
		t.Fatal("a token-only breach was admitted — scanBudget's zero-check must consider the token stamps too")
	}
	if res.DenyRuleID != "B-623" {
		t.Errorf("deny rule = %q, want B-623", res.DenyRuleID)
	}
}

// TestApplyOrgBudgetOnANilGuardIsANoOp: the wiring may hold a nil guard (guard
// off, or construction failed) and must never panic on the push cycle.
func TestApplyOrgBudgetOnANilGuardIsANoOp(t *testing.T) {
	t.Parallel()

	var g *Guard
	if err := g.ApplyOrgBudget(config.GuardBudgetConfig{DailyTokens: 1}, nil, false, policy.BudgetProtection{}, ""); err != nil {
		t.Fatalf("nil guard: %v", err)
	}
	if got := g.EffectiveBudget(); got != (config.GuardBudgetConfig{}) {
		t.Errorf("nil guard EffectiveBudget() = %+v, want the zero value", got)
	}
}

// dailyTokenEvent is budgetEvent's DAILY sibling: an api_request carrying a
// daily token stamp, the window a `soft` org cap governs.
func dailyTokenEvent(dailyTokens int64) policy.Event {
	ev := budgetEvent(0)
	ev.DailyTokens = dailyTokens
	return ev
}

// TestSoftWindowsHoldTheirRowsAtFlagWhileAnotherWindowDenies is MEDIUM-3's
// guard half (review fix round 2).
//
// One authored org budget: a `soft` daily cap and a `hard` monthly one. The
// gateway warns on the daily breach and denies on the monthly one, per cap.
// The node must do the same — but [guard.budget].hard is ONE switch that
// upgrades every CategoryBudget row, so the soft windows arrive as an explicit
// set and are held back at flag by an override.
//
// Without budgetSoftOverrides the daily breach denies here.
func TestSoftWindowsHoldTheirRowsAtFlagWhileAnotherWindowDenies(t *testing.T) {
	t.Parallel()

	cfg := guardCfg()
	cfg.Mode = "enforce"
	g := newTestGuard(t, cfg, nil)

	eff := cfg.Budget
	eff.DailyTokens = 1_000_000
	eff.MonthlyTokens = 30_000_000
	eff.Hard = true
	if err := g.ApplyOrgBudget(eff, []string{"session", "daily", "weekly"}, false,
		policy.BudgetProtection{MonthlyTokens: true}, ""); err != nil {
		t.Fatalf("ApplyOrgBudget: %v", err)
	}

	// The soft window: over its cap, and it must FLAG, not deny.
	v, gerr := g.Evaluate(dailyTokenEvent(1_000_001))
	if gerr != nil {
		t.Fatalf("Evaluate(daily): %v", gerr)
	}
	if v.RuleID != "B-622" {
		t.Fatalf("daily breach fired %q, want B-622", v.RuleID)
	}
	if v.Decision != policy.DecisionFlag {
		t.Errorf("daily breach decision = %v, want flag — the org authored this window as soft, "+
			"and the gateway admits-and-warns on it; a node that denies is a second answer to one budget",
			v.Decision)
	}

	// The hard window still denies: the override is per window, not a global
	// downgrade.
	v, gerr = g.Evaluate(budgetEvent(30_000_001))
	if gerr != nil {
		t.Fatalf("Evaluate(monthly): %v", gerr)
	}
	if v.Decision != policy.DecisionDeny || v.RuleID != "B-623" {
		t.Errorf("monthly breach = %v/%q, want deny/B-623", v.Decision, v.RuleID)
	}
}

// TestSoftWindowsSurviveAnEngineRebuild pins the same property at the SECOND
// build site: the project-layer engine is built lazily, long after
// ApplyOrgBudget ran, and a fix that appended the overrides only to the base
// engine would silently deny the soft window on the first project-scoped
// event.
func TestSoftWindowsSurviveAnEngineRebuild(t *testing.T) {
	t.Parallel()

	cfg := guardCfg()
	cfg.Mode = "enforce"
	g := newTestGuard(t, cfg, nil)

	eff := cfg.Budget
	eff.DailyTokens = 1_000_000
	eff.MonthlyTokens = 30_000_000
	eff.Hard = true
	if err := g.ApplyOrgBudget(eff, []string{"daily"}, false,
		policy.BudgetProtection{MonthlyTokens: true}, ""); err != nil {
		t.Fatalf("ApplyOrgBudget: %v", err)
	}
	// Force a rebuild through the one funnel every later build uses.
	cur := g.set.Load()
	base, err := g.buildEngine(cur.base.Mode(), cur.orgLayer, cur.userLayer, nil, nil)
	if err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	v := base.Evaluate(dailyTokenEvent(1_000_001))
	if v.Decision != policy.DecisionFlag {
		t.Errorf("after a rebuild the daily (soft) window decision = %v, want flag", v.Decision)
	}
}

// TestSoftWindowsChangeIsNotANoOp: the idempotence short-circuit must consider
// the soft-window set too, or a budget whose NUMBERS are unchanged but whose
// enforcement moved from soft to hard would never take effect.
func TestSoftWindowsChangeIsNotANoOp(t *testing.T) {
	t.Parallel()

	cfg := guardCfg()
	cfg.Mode = "enforce"
	g := newTestGuard(t, cfg, nil)

	eff := cfg.Budget
	eff.DailyTokens = 1_000_000
	eff.MonthlyTokens = 30_000_000
	eff.Hard = true
	if err := g.ApplyOrgBudget(eff, []string{"daily"}, false,
		policy.BudgetProtection{MonthlyTokens: true}, ""); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	if err := g.ApplyOrgBudget(eff, nil, false,
		policy.BudgetProtection{DailyTokens: true, MonthlyTokens: true}, ""); err != nil {
		t.Fatalf("second apply: %v", err)
	}
	v, gerr := g.Evaluate(dailyTokenEvent(1_000_001))
	if gerr != nil {
		t.Fatalf("Evaluate: %v", gerr)
	}
	if v.Decision != policy.DecisionDeny {
		t.Errorf("after the org hardened the daily window the decision = %v, want deny — "+
			"the no-op check ignored the soft-window set", v.Decision)
	}
}

// TestDisabledSoftOrgRowDoesNotAcquireHardProtection pins the distinction
// between managed provenance and native-intervention authority. The monthly
// hard row survives local policy; the daily soft row stays advisory and does
// not acquire protection merely because both came from one organization body.
func TestDisabledSoftOrgRowDoesNotAcquireHardProtection(t *testing.T) {
	t.Parallel()

	cfg := guardCfg()
	cfg.Mode = "enforce"
	cfg.Rules.Disable = []string{"B-622"}
	g := newTestGuard(t, cfg, nil)

	eff := cfg.Budget
	eff.DailyTokens = 1_000_000
	eff.MonthlyTokens = 30_000_000
	eff.Hard = true
	if err := g.ApplyOrgBudget(eff, []string{"daily"}, false,
		policy.BudgetProtection{MonthlyTokens: true}, ""); err != nil {
		t.Fatalf("ApplyOrgBudget with a disabled budget row: %v", err)
	}
	if got := g.EffectiveBudget().MonthlyTokens; got != 30_000_000 {
		t.Errorf("EffectiveBudget().MonthlyTokens = %d, want 30000000 — the apply was rolled back", got)
	}
	v, gerr := g.Evaluate(dailyTokenEvent(1_000_001))
	if gerr != nil {
		t.Fatalf("Evaluate: %v", gerr)
	}
	if v.RuleID != "" || v.Decision != policy.DecisionAllow {
		t.Errorf("disabled organization soft row = %s/%s, want allow", v.RuleID, v.Decision)
	}
	v, gerr = g.Evaluate(budgetEvent(30_000_001))
	if gerr != nil {
		t.Fatalf("Evaluate(monthly): %v", gerr)
	}
	if v.RuleID != "B-623" || v.Decision != policy.DecisionDeny {
		t.Errorf("protected monthly row = %s/%s, want B-623/deny", v.RuleID, v.Decision)
	}
}

// TestBudgetRequiredDeniesAnUNSTAMPEDProxyRequest is the guard half of ruling
// R2, and it is deliberately written against the state that USED to be the
// safest-looking one: a session with no recorded spend at all.
//
// scanBudget's all-zero early return is the shortcut B-625 has to survive —
// the row fires BECAUSE no organization budget was ever verified, so the
// common case is a request carrying nothing to compare. Without the
// BudgetRequired gate on that early return, this request is admitted.
func TestBudgetRequiredDeniesAnUNSTAMPEDProxyRequest(t *testing.T) {
	t.Parallel()

	cfg := guardCfg()
	cfg.Mode = "enforce"
	g := newTestGuard(t, cfg, nil)
	// No lookup wired at all: every stamp is zero, which is exactly the shape
	// a fresh managed node presents on its first proxied request.
	if err := g.ApplyOrgBudget(cfg.Budget, nil, true, policy.BudgetProtection{}, ""); err != nil {
		t.Fatalf("ApplyOrgBudget: %v", err)
	}

	var res ProxyRequestResult
	g.scanBudget(g.set.Load(), &res, "s1", "api.anthropic.com", time.Now().UTC())
	if !res.Deny {
		t.Fatal("an unstamped request was admitted on a node that requires the org's budget")
	}
	if res.DenyRuleID != "B-625" {
		t.Errorf("deny rule = %q, want B-625", res.DenyRuleID)
	}
}

// TestBudgetRequiredOnlyFlagsInObserveMode: D2 holds even for the fail-closed
// row. Nothing blocks until the operator (or the org's pin) flips enforce.
func TestBudgetRequiredOnlyFlagsInObserveMode(t *testing.T) {
	t.Parallel()

	cfg := guardCfg()
	cfg.Mode = "observe"
	g := newTestGuard(t, cfg, nil)
	if err := g.ApplyOrgBudget(cfg.Budget, nil, true, policy.BudgetProtection{}, ""); err != nil {
		t.Fatalf("ApplyOrgBudget: %v", err)
	}

	var res ProxyRequestResult
	g.scanBudget(g.set.Load(), &res, "s1", "api.anthropic.com", time.Now().UTC())
	if res.Deny {
		t.Fatal("observe mode denied — D2 says nothing blocks until enforce")
	}
	if len(res.Verdicts) != 1 || res.Verdicts[0].Verdict.RuleID != "B-625" {
		t.Fatalf("verdicts = %+v, want one flagged B-625", res.Verdicts)
	}
}

// TestBudgetNotRequiredIsByteIdenticalOnAnUnstampedRequest is the other half:
// with the posture OFF (every individual node), an unstamped request is still
// admitted with no verdict at all, exactly as before ruling R2.
func TestBudgetNotRequiredIsByteIdenticalOnAnUnstampedRequest(t *testing.T) {
	t.Parallel()

	cfg := guardCfg()
	cfg.Mode = "enforce"
	g := newTestGuard(t, cfg, nil)
	if err := g.ApplyOrgBudget(cfg.Budget, nil, false, policy.BudgetProtection{}, ""); err != nil {
		t.Fatalf("ApplyOrgBudget: %v", err)
	}

	var res ProxyRequestResult
	g.scanBudget(g.set.Load(), &res, "s1", "api.anthropic.com", time.Now().UTC())
	if res.Deny || len(res.Verdicts) != 0 {
		t.Fatalf("res = %+v, want an untouched result", res)
	}
}

// TestApplyOrgBudgetRepublishesWhenOnlyTheRequiredFlagChanges: the no-op
// shortcut compares the numbers and the soft set; a fail-closed posture that
// arrived with unchanged numbers must still rebuild the engine, or the block
// never arms.
func TestApplyOrgBudgetRepublishesWhenOnlyTheRequiredFlagChanges(t *testing.T) {
	t.Parallel()

	cfg := guardCfg()
	cfg.Mode = "enforce"
	g := newTestGuard(t, cfg, nil)
	if err := g.ApplyOrgBudget(cfg.Budget, nil, false, policy.BudgetProtection{}, ""); err != nil {
		t.Fatalf("ApplyOrgBudget(false): %v", err)
	}
	if err := g.ApplyOrgBudget(cfg.Budget, nil, true, policy.BudgetProtection{}, ""); err != nil {
		t.Fatalf("ApplyOrgBudget(true): %v", err)
	}
	if !g.set.Load().base.BudgetRequired() {
		t.Fatal("the rebuilt engine does not carry the fail-closed posture")
	}
}

func TestApplyOrgBudgetRepublishesWhenOnlyProtectionChanges(t *testing.T) {
	t.Parallel()
	cfg := guardCfg()
	cfg.Mode = "enforce"
	cfg.Budget.DailyTokens = 100
	cfg.Budget.Hard = true
	g := newTestGuard(t, cfg, nil)
	if err := g.ApplyOrgBudget(cfg.Budget, nil, false, policy.BudgetProtection{}, ""); err != nil {
		t.Fatalf("local apply: %v", err)
	}
	before := g.set.Load()
	if err := g.ApplyOrgBudget(cfg.Budget, nil, false, policy.BudgetProtection{DailyTokens: true}, ""); err != nil {
		t.Fatalf("protected apply: %v", err)
	}
	if g.set.Load() == before {
		t.Fatal("protection-only change did not rebuild the engine")
	}
	if !g.set.Load().base.BudgetRuleProtected("B-622") {
		t.Fatal("rebuilt engine does not carry organization budget protection")
	}
}

func TestProtectedBudgetRowsIgnoreLocalPolicyAndApprovals(t *testing.T) {
	t.Parallel()

	t.Run("B-625 survives disable and approval", func(t *testing.T) {
		t.Parallel()
		cfg := guardCfg()
		cfg.Mode = "enforce"
		cfg.Rules.Disable = []string{"B-625"}
		g := newTestGuard(t, cfg, nil)
		approvalCalls := 0
		g.SetApprovalLookup(func(string, string, string) bool {
			approvalCalls++
			return true
		})
		if err := g.ApplyOrgBudget(cfg.Budget, nil, true, policy.BudgetProtection{}, ""); err != nil {
			t.Fatalf("ApplyOrgBudget: %v", err)
		}

		var res ProxyRequestResult
		g.scanBudget(g.set.Load(), &res, "s1", "api.anthropic.com", time.Now().UTC())
		if !res.Deny || res.DenyRuleID != "B-625" {
			t.Fatalf("result = %+v, want protected B-625 denial", res)
		}
		if approvalCalls != 0 {
			t.Errorf("approval lookup called %d times for protected B-625", approvalCalls)
		}
	})

	t.Run("hard dollar disable and token override cannot weaken org rows", func(t *testing.T) {
		t.Parallel()
		cfg := guardCfg()
		cfg.Mode = "enforce"
		cfg.Rules.Disable = []string{"B-602"}
		g := newTestGuard(t, cfg, map[string]string{
			"/home/u/.observer/guard-policy.toml": "[[override]]\nrule = \"B-622\"\ndecision = \"flag\"\n",
		})
		eff := cfg.Budget
		eff.DailyUSD = 1
		eff.DailyTokens = 100
		eff.Hard = true
		if err := g.ApplyOrgBudget(eff, nil, false,
			policy.BudgetProtection{DailyUSD: true, DailyTokens: true}, ""); err != nil {
			t.Fatalf("ApplyOrgBudget: %v", err)
		}

		for _, tc := range []struct {
			name string
			snap BudgetSnapshot
			id   string
		}{
			{name: "disabled dollar row", snap: BudgetSnapshot{DailyUSD: 2}, id: "B-602"},
			{name: "weakened token row", snap: BudgetSnapshot{DailyTokens: 101}, id: "B-622"},
		} {
			g.budgetMu.Lock()
			g.budgetCache = nil
			g.budgetMu.Unlock()
			g.SetBudgetLookup(func(string) (BudgetSnapshot, bool) { return tc.snap, true })
			approvalCalls := 0
			g.SetApprovalLookup(func(string, string, string) bool {
				approvalCalls++
				return true
			})
			var res ProxyRequestResult
			g.scanBudget(g.set.Load(), &res, "s-"+tc.name, "api.anthropic.com", time.Now().UTC())
			if !res.Deny || res.DenyRuleID != tc.id {
				t.Errorf("%s result = %+v, want protected %s denial", tc.name, res, tc.id)
			}
			if approvalCalls != 0 {
				t.Errorf("%s consulted approvals %d times", tc.name, approvalCalls)
			}
		}
	})
}

func TestLocalHardBudgetApprovalStillDowngrades(t *testing.T) {
	t.Parallel()
	cfg := guardCfg()
	cfg.Mode = "enforce"
	cfg.Budget.DailyTokens = 100
	cfg.Budget.Hard = true
	g := newTestGuard(t, cfg, nil)
	g.SetBudgetLookup(func(string) (BudgetSnapshot, bool) {
		return BudgetSnapshot{DailyTokens: 101}, true
	})
	approvalCalls := 0
	g.SetApprovalLookup(func(ruleID, _, _ string) bool {
		approvalCalls++
		return ruleID == "B-622"
	})

	var res ProxyRequestResult
	g.scanBudget(g.set.Load(), &res, "s1", "api.anthropic.com", time.Now().UTC())
	if res.Deny {
		t.Fatalf("local approved budget denied: %+v", res)
	}
	if len(res.Verdicts) != 1 || res.Verdicts[0].Verdict.RuleID != "B-622" ||
		res.Verdicts[0].DegradedFrom != "approved" {
		t.Fatalf("verdicts = %+v, want approved B-622 flag", res.Verdicts)
	}
	if approvalCalls != 1 {
		t.Errorf("approval lookup calls = %d, want 1", approvalCalls)
	}
}

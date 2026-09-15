package guard

import (
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// budgetCfg returns a guard config with a $5 session budget.
func budgetCfg(mode string, hard bool) config.GuardConfig {
	cfg := guardCfg()
	cfg.Mode = mode
	cfg.Budget = config.GuardBudgetConfig{SessionUSD: 5, Hard: hard}
	return cfg
}

// budgetIn builds one benign shell action input.
func budgetIn(session, target string, ts time.Time) ActionInput {
	return ActionInput{
		ActionID: 1, SessionID: session, ProjectRoot: "/home/u/proj",
		Tool: "claude-code", ActionType: "run_command", Target: target,
		Timestamp: ts,
	}
}

// TestBudgetWatcherFlagAndDedup covers the §12.1 watcher half: a
// breached session flags B-601 exactly once per session (cost only
// grows — later actions are silent), a second session records its
// own, lookup failure and nil lookup stay silent.
func TestBudgetWatcherFlagAndDedup(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)

	g := newTestGuard(t, budgetCfg("observe", false), nil)
	g.SetBudgetLookup(func(string) (BudgetSnapshot, bool) { return BudgetSnapshot{SessionUSD: 6.0}, true })

	out := g.EvaluateActions([]ActionInput{budgetIn("s1", "echo one", now)})
	if len(out) != 1 || out[0].Verdict.RuleID != "B-601" || out[0].Verdict.Decision != policy.DecisionFlag {
		t.Fatalf("first breach = %+v", out)
	}
	if !strings.Contains(out[0].Verdict.Reason, "$6.00") {
		t.Errorf("reason %q lacks spend", out[0].Verdict.Reason)
	}
	out = g.EvaluateActions([]ActionInput{budgetIn("s1", "echo two", now.Add(time.Second))})
	if len(out) != 0 {
		t.Fatalf("second action re-recorded the breach: %+v", out)
	}
	out = g.EvaluateActions([]ActionInput{budgetIn("s2", "echo other", now)})
	if len(out) != 1 || out[0].Verdict.RuleID != "B-601" {
		t.Fatalf("second session = %+v", out)
	}

	// Lookup failure → zero stamps → silence (fail toward quiet).
	g2 := newTestGuard(t, budgetCfg("observe", false), nil)
	g2.SetBudgetLookup(func(string) (BudgetSnapshot, bool) { return BudgetSnapshot{}, false })
	if out := g2.EvaluateActions([]ActionInput{budgetIn("s1", "echo", now)}); len(out) != 0 {
		t.Fatalf("failed lookup produced %+v", out)
	}

	// No lookup wired (hook posture) → silence.
	g3 := newTestGuard(t, budgetCfg("observe", false), nil)
	if out := g3.EvaluateActions([]ActionInput{budgetIn("s1", "echo", now)}); len(out) != 0 {
		t.Fatalf("nil lookup produced %+v", out)
	}
}

// TestBudgetLookupTTLCache pins the cache contract: one underlying
// lookup per session per TTL window, refreshed after expiry.
func TestBudgetLookupTTLCache(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)
	g := newTestGuard(t, budgetCfg("observe", false), nil)
	calls := 0
	g.SetBudgetLookup(func(string) (BudgetSnapshot, bool) { calls++; return BudgetSnapshot{SessionUSD: 1.0}, true })

	g.EvaluateActions([]ActionInput{
		budgetIn("s1", "echo a", now),
		budgetIn("s1", "echo b", now.Add(2*time.Second)),
	})
	if calls != 1 {
		t.Fatalf("calls within TTL = %d, want 1", calls)
	}
	g.EvaluateActions([]ActionInput{budgetIn("s1", "echo c", now.Add(budgetCacheTTL+time.Second))})
	if calls != 2 {
		t.Fatalf("calls after TTL = %d, want 2", calls)
	}
	g.EvaluateActions([]ActionInput{budgetIn("s9", "echo d", now)})
	if calls != 3 {
		t.Fatalf("calls for a second session = %d, want 3", calls)
	}
}

func TestHardProxyAdmissionBypassesBudgetCache(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)
	cfg := guardCfg()
	cfg.Mode = "enforce"
	g := newTestGuard(t, cfg, nil)
	eff := cfg.Budget
	eff.DailyUSD = 10
	eff.Hard = true
	if err := g.ApplyOrgBudget(eff, nil, false, policy.BudgetProtection{DailyUSD: true}, ""); err != nil {
		t.Fatalf("ApplyOrgBudget: %v", err)
	}

	// The second value represents spend committed by another session after
	// this session's first admission lookup. A node-wide daily cap must see it
	// on the very next request, even though this session's cache is still warm.
	daily := 9.0
	calls := 0
	g.SetBudgetLookup(func(string) (BudgetSnapshot, bool) {
		calls++
		return BudgetSnapshot{DailyUSD: daily}, true
	})
	var first ProxyRequestResult
	g.scanBudget(g.set.Load(), &first, "s1", "api.anthropic.com", now)
	if first.Deny {
		t.Fatalf("first request unexpectedly denied: %+v", first)
	}
	// Exactly exhausted is already unavailable for another managed request;
	// the controller must not wait for one more request to exceed the cap.
	daily = 10
	var second ProxyRequestResult
	g.scanBudget(g.set.Load(), &second, "s1", "api.anthropic.com", now.Add(time.Second))
	if !second.Deny || second.DenyRuleID != "B-602" {
		t.Fatalf("fresh daily total was not enforced: %+v", second)
	}
	if calls != 2 {
		t.Errorf("hard admission lookup calls = %d, want 2", calls)
	}
}

func TestUnprotectedProxyAdmissionKeepsBudgetCache(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)
	g := newTestGuard(t, budgetCfg("enforce", true), nil)
	calls := 0
	g.SetBudgetLookup(func(string) (BudgetSnapshot, bool) {
		calls++
		return BudgetSnapshot{SessionUSD: 1}, true
	})
	for i := 0; i < 2; i++ {
		var res ProxyRequestResult
		g.scanBudget(g.set.Load(), &res, "s1", "api.anthropic.com", now.Add(time.Duration(i)*time.Second))
	}
	if calls != 1 {
		t.Errorf("unprotected admission lookup calls = %d, want cached 1", calls)
	}
}

func TestBudgetOnlyEvaluationCannotBeMaskedByCustomAPIRequestRule(t *testing.T) {
	t.Parallel()
	userPolicy := `
[[rule]]
id = "U-API-CRITICAL"
category = "destructive"
severity = "critical"
decision = "deny"
applies_to = ["api_request"]
match.session_cost_usd_gt = 0.5
`
	cfg := budgetCfg("enforce", true)
	g := newTestGuard(t, cfg, map[string]string{
		"/home/u/.observer/guard-policy.toml": userPolicy,
	})
	g.SetBudgetLookup(func(string) (BudgetSnapshot, bool) {
		return BudgetSnapshot{SessionUSD: 6}, true
	})

	// The general engine still evaluates the complete table, where the
	// critical custom row wins the normal severity tie-break.
	ordinary, err := g.Evaluate(policy.Event{Kind: policy.KindAPIRequest, SessionCostUSD: 6})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if ordinary.RuleID != "U-API-CRITICAL" {
		t.Fatalf("ordinary evaluation = %s, want custom rule", ordinary.RuleID)
	}

	var res ProxyRequestResult
	g.scanBudget(g.set.Load(), &res, "s1", "api.anthropic.com", time.Now().UTC())
	if !res.Deny || res.DenyRuleID != "B-601" {
		t.Fatalf("budget admission was masked by custom rule: %+v", res)
	}
}

// TestScanBudget_ProxyHardDeny covers the §12.1 proxy half: hard mode
// denies the request in enforce (synthetic-4xx plumbing takes
// DenyRuleID/Reason), records the enforced verdict every time, and in
// observe mode degrades to a single recorded flag (D2).
func TestScanBudget_ProxyHardDeny(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)
	body := []byte(`{"model":"claude-x","messages":[]}`)

	g := newTestGuard(t, budgetCfg("enforce", true), nil)
	g.SetBudgetLookup(func(string) (BudgetSnapshot, bool) { return BudgetSnapshot{SessionUSD: 9.0}, true })
	res := g.ScanProxyRequest("anthropic", body, "s1", now)
	if !res.Deny || res.DenyRuleID != "B-601" || !strings.Contains(res.DenyReason, "budget") {
		t.Fatalf("hard enforce = %+v", res)
	}
	if len(res.Verdicts) != 1 || !res.Verdicts[0].Enforced {
		t.Fatalf("deny verdict = %+v", res.Verdicts)
	}
	// Denies are not deduped — every blocked request is audited.
	res = g.ScanProxyRequest("anthropic", body, "s1", now.Add(time.Second))
	if !res.Deny || len(res.Verdicts) != 1 {
		t.Fatalf("second deny = %+v", res)
	}

	// Observe mode: D2 — no blocking, one flag record per session.
	g2 := newTestGuard(t, budgetCfg("observe", true), nil)
	g2.SetBudgetLookup(func(string) (BudgetSnapshot, bool) { return BudgetSnapshot{SessionUSD: 9.0}, true })
	res = g2.ScanProxyRequest("anthropic", body, "s1", now)
	if res.Deny || len(res.Verdicts) != 1 || res.Verdicts[0].Verdict.Decision != policy.DecisionFlag {
		t.Fatalf("observe hard = %+v", res)
	}
	res = g2.ScanProxyRequest("anthropic", body, "s1", now.Add(time.Second))
	if res.Deny || len(res.Verdicts) != 0 {
		t.Fatalf("observe re-record = %+v", res)
	}

	// Soft (hard=false) enforce: flag once, never deny.
	g3 := newTestGuard(t, budgetCfg("enforce", false), nil)
	g3.SetBudgetLookup(func(string) (BudgetSnapshot, bool) { return BudgetSnapshot{SessionUSD: 9.0}, true })
	res = g3.ScanProxyRequest("anthropic", body, "s1", now)
	if res.Deny || len(res.Verdicts) != 1 {
		t.Fatalf("soft enforce = %+v", res)
	}
}

// TestScanBudget_UtilLimitDeny covers the §12.1 provider-usage-window
// half through the proxy scan: a 5h utilization at/over util_5h_deny
// blocks the request (B-611) in enforce, while a warn-only breach
// flags once (B-610) and never denies. Exercises the util stamps
// flowing through the BudgetSnapshot lookup into scanBudget.
func TestScanBudget_UtilLimitDeny(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)
	body := []byte(`{"model":"claude-x","messages":[]}`)

	cfg := guardCfg()
	cfg.Mode = "enforce"
	cfg.Budget = config.GuardBudgetConfig{
		Window: config.GuardBudgetWindowConfig{Util5hWarn: 0.8, Util5hDeny: 0.95},
	}

	g := newTestGuard(t, cfg, nil)
	g.SetBudgetLookup(func(string) (BudgetSnapshot, bool) { return BudgetSnapshot{Util5h: 0.97}, true })
	res := g.ScanProxyRequest("anthropic", body, "s1", now)
	if !res.Deny || res.DenyRuleID != "B-611" {
		t.Fatalf("util deny = %+v", res)
	}

	g2 := newTestGuard(t, cfg, nil)
	g2.SetBudgetLookup(func(string) (BudgetSnapshot, bool) { return BudgetSnapshot{Util5h: 0.85}, true })
	res = g2.ScanProxyRequest("anthropic", body, "s1", now)
	if res.Deny || len(res.Verdicts) != 1 || res.Verdicts[0].Verdict.RuleID != "B-610" {
		t.Fatalf("util warn = %+v", res)
	}
}

// TestRepeatTracker_A610 covers the stuck-loop tracker end-to-end on
// the ingest path: the crossing event fires exactly one A-610, deeper
// repeats stay silent, a different action resets the run, and
// sessions are isolated.
func TestRepeatTracker_A610(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)
	g := newTestGuard(t, mcpCfg("observe"), nil)

	run := func(session, target string, n int) []ActionVerdict {
		var all []ActionVerdict
		for i := 0; i < n; i++ {
			all = append(all, g.EvaluateActions([]ActionInput{
				budgetIn(session, target, now.Add(time.Duration(i)*time.Second)),
			})...)
		}
		return all
	}

	a610 := func(vs []ActionVerdict) int {
		n := 0
		for _, v := range vs {
			if v.Verdict.RuleID == "A-610" {
				n++
			}
		}
		return n
	}

	// 12 identical actions: exactly one A-610 (at the 9th).
	if got := a610(run("loop", "go test ./pkg", 12)); got != 1 {
		t.Fatalf("A-610 count over 12 repeats = %d, want 1", got)
	}
	// A different action resets; 9 more identical fire again.
	run("loop", "echo break", 1)
	if got := a610(run("loop", "go test ./pkg", 9)); got != 1 {
		t.Fatalf("A-610 after reset = %d, want 1", got)
	}
	// Sessions are isolated: 5+5 across two sessions never fires.
	if got := a610(append(run("sA", "make build", 5), run("sB", "make build", 5)...)); got != 0 {
		t.Fatalf("A-610 across sessions = %d, want 0", got)
	}
}

// TestUserCostMatcher pins the unlocked §4.4 vocabulary end-to-end: a
// user rule AND-ing session_cost_usd_gt with a command matcher fires
// only when both halves hold.
func TestUserCostMatcher(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)
	cfg := guardCfg()
	cfg.Rules.UserPolicy = "/home/u/.observer/guard-policy.toml"
	files := map[string]string{
		"/home/u/.observer/guard-policy.toml": "[[rule]]\n" +
			"id = 'U-700'\ncategory = 'budget'\ndecision = 'flag'\n" +
			"severity = 'high'\napplies_to = ['shell_exec']\n" +
			"match.session_cost_usd_gt = 2.5\n",
	}
	g := newTestGuard(t, cfg, files)
	if issues := g.LoadIssues(); len(issues) != 0 {
		t.Fatalf("load issues: %v", issues)
	}

	g.SetBudgetLookup(func(string) (BudgetSnapshot, bool) { return BudgetSnapshot{SessionUSD: 3.0}, true })
	out := g.EvaluateActions([]ActionInput{budgetIn("s1", "echo hi", now)})
	if len(out) != 1 || out[0].Verdict.RuleID != "U-700" {
		t.Fatalf("user cost rule = %+v", out)
	}

	g2 := newTestGuard(t, cfg, files)
	g2.SetBudgetLookup(func(string) (BudgetSnapshot, bool) { return BudgetSnapshot{SessionUSD: 2.0}, true })
	if out := g2.EvaluateActions([]ActionInput{budgetIn("s1", "echo hi", now)}); len(out) != 0 {
		t.Fatalf("under-threshold user rule fired: %+v", out)
	}
}

package guard

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestOrgBudgetVerdictText pins finding A5 of the 2026-10-02 demo-estate
// incident: a breach of an ORG-authored window must read in the org's terms
// and must never cite a local [guard.budget] key or claim hard=true blocks
// when the org chose a soft cap.
func TestOrgBudgetVerdictText(t *testing.T) {
	base := policy.Verdict{
		RuleID: "B-602", Decision: policy.DecisionFlag,
		Reason: "daily cost (all sessions) exceeded [guard.budget].daily_usd: daily spend $1.26 exceeds the $0.75 budget",
		Advice: "Today's total spend across sessions crossed the configured ceiling; raise [guard.budget].daily_usd or pause agent work. hard=true blocks further proxy requests in enforce mode.",
	}
	cases := []struct {
		name       string
		origin     BudgetOrigin
		wantReason string
		wantAdvice string
	}{
		{
			name:       "member soft cap",
			origin:     BudgetOrigin{Window: "daily", Unit: "usd", Scope: "member:abc", Enforcement: "soft"},
			wantReason: "organization daily budget (you, warning only) reached: daily spend $1.26 exceeds the $0.75 budget",
			wantAdvice: "requests are not blocked",
		},
		{
			// A hard cap whose verdict only FLAGS was taken by a guard that is
			// not enforcing (observe mode): never "blocking" (2026-11-18).
			name:       "team hard cap, guard not enforcing",
			origin:     BudgetOrigin{Window: "daily", Unit: "usd", Scope: "team:t1", Enforcement: "hard"},
			wantReason: "organization daily budget (your team, warning only on this machine) reached:",
			wantAdvice: "requests are not blocked",
		},
		{
			name:       "org report cap",
			origin:     BudgetOrigin{Window: "monthly", Unit: "usd", Scope: "org", Enforcement: "report"},
			wantReason: "organization monthly budget (your organization, report only) reached:",
			wantAdvice: "requests are not blocked",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := OrgBudgetVerdictText(base, tc.origin)
			if !strings.HasPrefix(got.Reason, tc.wantReason) {
				t.Fatalf("reason = %q, want prefix %q", got.Reason, tc.wantReason)
			}
			if !strings.Contains(got.Advice, tc.wantAdvice) {
				t.Fatalf("advice = %q, want %q", got.Advice, tc.wantAdvice)
			}
			for _, banned := range []string{"[guard.budget]", "hard=true"} {
				if strings.Contains(got.Reason+got.Advice, banned) {
					t.Fatalf("org verdict still cites %q: %q / %q", banned, got.Reason, got.Advice)
				}
			}
			if got.Decision != base.Decision || got.RuleID != base.RuleID {
				t.Fatal("labelling must never change the decision or the rule")
			}
		})
	}
}

// TestOrgBudgetVerdictTextHardDeny: a hard cap the guard DENIES reads as
// blocking, and so does a hook-stop reason rendered with no decision.
func TestOrgBudgetVerdictTextHardDeny(t *testing.T) {
	o := BudgetOrigin{Window: "daily", Unit: "usd", Scope: "team:t1", Enforcement: "hard"}
	for _, d := range []policy.Decision{policy.DecisionDeny, policy.DecisionAllow} {
		got := OrgBudgetVerdictText(policy.Verdict{RuleID: "B-602", Decision: d, Reason: "x: daily spend $1.26 exceeds the $0.75 budget"}, o)
		if !strings.HasPrefix(got.Reason, "organization daily budget (your team, blocking) reached:") {
			t.Errorf("decision %v: reason = %q", d, got.Reason)
		}
		if !strings.Contains(got.Advice, "blocks further proxied requests") {
			t.Errorf("decision %v: advice = %q", d, got.Advice)
		}
	}
}

// TestLabelBudgetVerdictByCostDisplay pins the developer cost display on the
// guard's budget verdict text (operator ruling 2026-10-02): in token mode a
// dollar reason renders the share of the budget used and never an amount;
// dollar mode, token budgets and non-budget rules are unchanged.
func TestLabelBudgetVerdictByCostDisplay(t *testing.T) {
	usd := policy.Verdict{
		RuleID: "B-602", Decision: policy.DecisionFlag,
		Reason: "daily cost (all sessions) exceeded [guard.budget].daily_usd: daily spend $0.90 exceeds the $0.75 budget",
	}
	tok := policy.Verdict{
		RuleID: "B-622", Decision: policy.DecisionFlag,
		Reason: "daily token usage exceeded [guard.budget].daily_tokens: daily usage 960000 tokens exceeds the 900000-token budget",
	}
	other := policy.Verdict{RuleID: "S-101", Reason: "spend $5.00 exceeds the $1.00 budget"}
	soft := []BudgetOrigin{{Window: "daily", Unit: "usd", Scope: "member:abc", Enforcement: "soft"}}
	cases := []struct {
		name    string
		display string
		origins []BudgetOrigin
		in      policy.Verdict
		want    string
	}{
		{"usd display, local cap", "usd", nil, usd, usd.Reason},
		{
			"tokens display, local cap", "tokens", nil, usd,
			"daily cost (all sessions) exceeded [guard.budget].daily_usd: daily spend is at 120% of the budget",
		},
		{
			"usd display, org cap", "usd", soft, usd,
			"organization daily budget (you, warning only) reached: daily spend $0.90 exceeds the $0.75 budget",
		},
		{
			"tokens display, org cap", "tokens", soft, usd,
			"organization daily budget (you, warning only) reached: daily spend is at 120% of the budget",
		},
		{"tokens display, token cap kept", "tokens", nil, tok, tok.Reason},
		{"tokens display, non-budget rule kept", "tokens", nil, other, other.Reason},
		{"no resolver is dollars", "", nil, usd, usd.Reason},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := &Guard{}
			g.SetBudgetOrigins(tc.origins)
			if tc.display != "" {
				d := tc.display
				g.SetCostDisplay(func() string { return d })
			}
			got := g.labelOrgBudgetVerdict(tc.in)
			if got.Reason != tc.want {
				t.Fatalf("reason = %q\nwant     %q", got.Reason, tc.want)
			}
			if got.Decision != tc.in.Decision || got.RuleID != tc.in.RuleID {
				t.Fatal("the cost display must never change the decision or the rule")
			}
		})
	}
}

// TestLabelOrgBudgetVerdictOnlyTouchesOrgWindows pins that a purely local
// ceiling, an unmapped rule and a cleared table all render unchanged.
func TestLabelOrgBudgetVerdictOnlyTouchesOrgWindows(t *testing.T) {
	g := &Guard{}
	local := policy.Verdict{RuleID: "B-602", Reason: "daily cost (all sessions) exceeded [guard.budget].daily_usd: x"}
	if got := g.labelOrgBudgetVerdict(local); got.Reason != local.Reason {
		t.Fatalf("no origins: reason changed to %q", got.Reason)
	}
	g.SetBudgetOrigins([]BudgetOrigin{{Window: "monthly", Unit: "tokens", Scope: "team:t", Enforcement: "soft"}})
	if got := g.labelOrgBudgetVerdict(local); got.Reason != local.Reason {
		t.Fatalf("B-602 is local while only B-623 is org: reason changed to %q", got.Reason)
	}
	tok := policy.Verdict{RuleID: "B-623", Reason: "calendar-month token usage exceeded [guard.budget].monthly_tokens: n"}
	if got := g.labelOrgBudgetVerdict(tok); !strings.HasPrefix(got.Reason, "organization monthly budget (your team") {
		t.Fatalf("B-623 org reason = %q", got.Reason)
	}
	g.SetBudgetOrigins(nil)
	if got := g.labelOrgBudgetVerdict(tok); got.Reason != tok.Reason {
		t.Fatal("cleared table must restore local rendering")
	}
	for _, c := range []struct{ w, u, id string }{{"daily", "usd", "B-602"}, {"daily", "tokens", "B-622"}, {"monthly", "usd", "B-603"}, {"monthly", "tokens", "B-623"}} {
		if id, ok := BudgetOriginRuleID(c.w, c.u); !ok || id != c.id {
			t.Errorf("BudgetOriginRuleID(%s,%s) = %q,%v want %q", c.w, c.u, id, ok, c.id)
		}
	}
}

// TestUserCostRuleReasonFollowsCostDisplay pins T-204: a user policy rule's
// session-spend condition reads in dollars by default and as a share of the
// rule's limit under the token-usage developer cost display, with the
// decision and rule id unchanged.
func TestUserCostRuleReasonFollowsCostDisplay(t *testing.T) {
	t.Parallel()
	userPolicy := `
[[rule]]
id = "U-COST"
category = "budget"
severity = "high"
decision = "flag"
applies_to = ["api_request"]
match.session_cost_usd_gt = 0.5
`
	rows := []struct {
		display string
		want    string
	}{
		{"usd", "session spend $0.65 > $0.50"},
		{"tokens", "session spend is at 130% of the rule's limit"},
	}
	for _, r := range rows {
		g := newTestGuard(t, budgetCfg("enforce", false), map[string]string{
			"/home/u/.observer/guard-policy.toml": userPolicy,
		})
		d := r.display
		g.SetCostDisplay(func() string { return d })
		v, err := g.Evaluate(policy.Event{Kind: policy.KindAPIRequest, SessionCostUSD: 0.65})
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if v.RuleID != "U-COST" || !strings.Contains(v.Reason, r.want) {
			t.Errorf("%s: verdict %s %q, want rule U-COST with %q", r.display, v.RuleID, v.Reason, r.want)
		}
		if r.display == "tokens" && strings.Contains(v.Reason, "$") {
			t.Errorf("tokens: reason kept a dollar figure: %q", v.Reason)
		}
	}
}

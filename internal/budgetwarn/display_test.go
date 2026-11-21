package budgetwarn

import (
	"strings"
	"testing"
	"time"
)

// TestRenderMessageByDisplay pins the developer-facing sentence in both cost
// displays (operator ruling 2026-10-02: the org chooses whether developers see
// dollar costs or only token usage). One row per (unit, display, enforcement)
// shape.
func TestRenderMessageByDisplay(t *testing.T) {
	usdSoft := Notice{Window: "daily", Unit: "usd", Scope: "member:dana", Enforcement: "soft", Threshold: 1, Ratio: 1.2, Spent: 0.9, Cap: 0.75}
	usdHard := Notice{Window: "monthly", Unit: "usd", Scope: "team:web", Enforcement: "hard", Threshold: 1, Ratio: 1.05, Spent: 21, Cap: 20, Effect: EffectBlocks, Blocked: true}
	usdHardWarn := Notice{Window: "daily", Unit: "usd", Scope: "org", Enforcement: "hard", Threshold: 0.75, Ratio: 0.8, Spent: 8, Cap: 10, Effect: EffectBlocks}
	// The 2026-11-18 production shapes: the org asked for a block, this
	// machine cannot (or only partly can) make one.
	hardObserve := Notice{Window: "monthly", Unit: "usd", Scope: "member:dana", Enforcement: "hard", Threshold: 1, Ratio: 42, Spent: 0.42, Cap: 0.01, Effect: EffectObserve}
	hardObserveBelow := Notice{Window: "monthly", Unit: "usd", Scope: "member:dana", Enforcement: "hard", Threshold: 0.75, Ratio: 0.8, Spent: 8, Cap: 10, Effect: EffectObserve}
	hardGuardOff := Notice{Window: "daily", Unit: "usd", Scope: "member:dana", Enforcement: "hard", Threshold: 1, Ratio: 1.5, Spent: 1.5, Cap: 1, Effect: EffectGuardOff}
	hardNoEffect := Notice{Window: "daily", Unit: "usd", Scope: "member:dana", Enforcement: "hard", Threshold: 1, Ratio: 1.5, Spent: 1.5, Cap: 1}
	hardProxied := Notice{Window: "daily", Unit: "usd", Scope: "member:dana", Enforcement: "hard", Threshold: 1, Ratio: 1.5, Spent: 1.5, Cap: 1, Effect: EffectBlocksProxied, Blocked: true}
	hardProxiedBelow := Notice{Window: "daily", Unit: "usd", Scope: "member:dana", Enforcement: "hard", Threshold: 0.9, Ratio: 0.9, Spent: 0.9, Cap: 1, Effect: EffectBlocksProxied}
	hardLocalUnder := Notice{Window: "daily", Unit: "usd", Scope: "member:dana", Enforcement: "hard", Threshold: 1, Ratio: 1.5, Spent: 1.5, Cap: 1, Effect: EffectBlocks, DeniesOnLocal: true}
	hardLocalBelow := Notice{Window: "daily", Unit: "usd", Scope: "member:dana", Enforcement: "hard", Threshold: 0.75, Ratio: 0.8, Spent: 0.8, Cap: 1, Effect: EffectBlocks, DeniesOnLocal: true}
	tokSoft := Notice{Window: "daily", Unit: "tokens", Scope: "member:dana", Enforcement: "report", Threshold: 0.75, Ratio: 0.8, Spent: 960000, Cap: 1200000}
	cases := []struct {
		name    string
		n       Notice
		display string
		want    string
	}{
		{
			"usd cap, dollar display", usdSoft, DisplayUSD,
			"Org daily budget (you, warning only): 120% used - $0.90 of $0.75. Requests are not blocked.",
		},
		{
			"usd cap, token display", usdSoft, DisplayTokens,
			"Org daily budget (you, warning only): 120% used of the budget. Requests are not blocked.",
		},
		{
			"usd hard exhausted, token display", usdHard, DisplayTokens,
			"Org monthly budget (your team, blocking): 105% used of the budget. Further proxied requests, and the next prompt or tool call in tools with a pre-send hook, are blocked until the period resets or an admin raises the cap.",
		},
		{
			"usd hard below 100, token display", usdHardWarn, DisplayTokens,
			"Org daily budget (your organization, blocking): 80% used of the budget. Requests will be blocked at 100%.",
		},
		{
			"hard cap, observe mode (the incident)", hardObserve, DisplayUSD,
			"Org monthly budget (you, warning only on this machine): 4200% used - $0.42 of $0.01. This machine is in observe mode, so requests are not blocked.",
		},
		{
			"hard cap below 100, observe mode", hardObserveBelow, DisplayUSD,
			"Org monthly budget (you, warning only on this machine): 80% used - $8.00 of $10.00. This machine is in observe mode, so requests will not be blocked at 100%.",
		},
		{
			"hard cap, guard off", hardGuardOff, DisplayUSD,
			"Org daily budget (you, warning only on this machine): 150% used - $1.50 of $1.00. The guard is off on this machine, so requests are not blocked.",
		},
		{
			"hard cap, no machine facts: never claims blocking", hardNoEffect, DisplayUSD,
			"Org daily budget (you, warning only on this machine): 150% used - $1.50 of $1.00. The guard is off on this machine, so requests are not blocked.",
		},
		{
			"hard cap, proxied requests only", hardProxied, DisplayUSD,
			"Org daily budget (you, blocking): 150% used - $1.50 of $1.00. Further proxied requests are blocked until the period resets or an admin raises the cap. Tools that do not go through the proxy are not blocked.",
		},
		{
			"hard cap below 100, proxied requests only", hardProxiedBelow, DisplayUSD,
			"Org daily budget (you, blocking): 90% used - $0.90 of $1.00. Proxied requests will be blocked at 100%.",
		},
		{
			"hard cap over only with other machines' spend", hardLocalUnder, DisplayUSD,
			"Org daily budget (you, blocking): 150% used - $1.50 of $1.00. Requests are not blocked yet: this machine blocks when its own spend reaches the cap, and spend from your other machines only warns.",
		},
		{
			"hard cap below 100, own spend decides", hardLocalBelow, DisplayUSD,
			"Org daily budget (you, blocking): 80% used - $0.80 of $1.00. Requests will be blocked when this machine's own spend reaches the cap.",
		},
		{
			"token cap, dollar display", tokSoft, DisplayUSD,
			"Org daily budget (you, report only): 80% used - 960,000 tokens of 1,200,000 tokens. Requests are not blocked.",
		},
		{
			"token cap, token display", tokSoft, DisplayTokens,
			"Org daily budget (you, report only): 80% used - 960,000 tokens of 1,200,000 tokens. Requests are not blocked.",
		},
		{
			"unknown display falls back to dollars", usdSoft, "",
			"Org daily budget (you, warning only): 120% used - $0.90 of $0.75. Requests are not blocked.",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := RenderMessage(tc.n, tc.display)
			if got != tc.want {
				t.Fatalf("RenderMessage = %q\nwant            %q", got, tc.want)
			}
			if tc.display == DisplayTokens && strings.Contains(got, "$") {
				t.Fatalf("token display rendered a dollar figure: %q", got)
			}
		})
	}
}

// TestNoticeForRendersDollars keeps the evaluator's own message (the
// pre-display baseline every surface re-renders from) in dollars.
func TestNoticeForRendersDollars(t *testing.T) {
	w := Window{Window: "daily", Unit: "usd", Cap: 0.75, Spent: 0.72, Scope: "member:x", Enforcement: "soft"}
	n := noticeFor(w, "2026-10-02", 0.9, 0.96, time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC))
	if want := RenderMessage(n, DisplayUSD); n.Message != want {
		t.Fatalf("noticeFor message %q, want %q", n.Message, want)
	}
}

// TestStatusLabelByDisplay pins the statusline's short budget form.
func TestStatusLabelByDisplay(t *testing.T) {
	cases := []struct {
		name string
		w    WindowStatus
		disp string
		want string
	}{
		{"usd daily, dollars", WindowStatus{Window: "daily", Unit: "usd", Enforcement: "soft", Cap: 0.75, Ratio: 1.68, Crossed: 1, Effect: EffectNone}, DisplayUSD, "budget 168% of $0.75/day"},
		{"usd daily, tokens", WindowStatus{Window: "daily", Unit: "usd", Enforcement: "soft", Cap: 0.75, Ratio: 1.68, Crossed: 1, Effect: EffectNone}, DisplayTokens, "budget 168%"},
		{"usd monthly hard blocked, tokens", WindowStatus{Window: "monthly", Unit: "usd", Enforcement: "hard", Cap: 20, Ratio: 1.05, Crossed: 1, Effect: EffectBlocks, Blocked: true}, DisplayTokens, "budget 105% (blocked)"},
		{"usd monthly hard blocked, dollars", WindowStatus{Window: "monthly", Unit: "usd", Enforcement: "hard", Cap: 20, Ratio: 1.05, Crossed: 1, Effect: EffectBlocks, Blocked: true}, DisplayUSD, "budget 105% of $20.00/mo (blocked)"},
		{"usd monthly hard, observe mode", WindowStatus{Window: "monthly", Unit: "usd", Enforcement: "hard", Cap: 20, Ratio: 1.05, Crossed: 1, Effect: EffectObserve}, DisplayUSD, "budget 105% of $20.00/mo (not blocked)"},
		{"usd monthly hard, legacy file without an effect", WindowStatus{Window: "monthly", Unit: "usd", Enforcement: "hard", Cap: 20, Ratio: 1.05, Crossed: 1}, DisplayUSD, "budget 105% of $20.00/mo"},
		{"token cap, tokens", WindowStatus{Window: "daily", Unit: "tokens", Enforcement: "report", Cap: 1200000, Ratio: 0.8, Crossed: 0.75, Effect: EffectNone}, DisplayTokens, "budget 80% of 1,200,000 tokens/day"},
		{"token cap, dollars", WindowStatus{Window: "daily", Unit: "tokens", Enforcement: "report", Cap: 1200000, Ratio: 0.8, Crossed: 0.75, Effect: EffectNone}, DisplayUSD, "budget 80% of 1,200,000 tokens/day"},
		{"hard below 100 is not blocked", WindowStatus{Window: "daily", Unit: "usd", Enforcement: "hard", Cap: 10, Ratio: 0.9, Crossed: 0.9, Effect: EffectBlocks}, DisplayUSD, "budget 90% of $10.00/day"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := StatusLabel(tc.w, tc.disp); got != tc.want {
				t.Fatalf("StatusLabel = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestEffectOf walks the effect table one row per rule (CLAUDE.md #5).
func TestEffectOf(t *testing.T) {
	cases := []struct {
		name string
		in   EffectInput
		want string
	}{
		{"report never blocks", EffectInput{Enforcement: "report", GuardMode: "enforce", OrgAuthoritative: true}, EffectNone},
		{"soft never blocks", EffectInput{Enforcement: "soft", GuardMode: "enforce", OrgAuthoritative: true}, EffectNone},
		{"hard, observe mode", EffectInput{Enforcement: "hard", GuardMode: "observe", OrgAuthoritative: true}, EffectObserve},
		{"hard, guard off", EffectInput{Enforcement: "hard", GuardMode: "off", OrgAuthoritative: true}, EffectGuardOff},
		{"hard, guard mode unknown", EffectInput{Enforcement: "hard"}, EffectGuardOff},
		{"hard, per-model cap", EffectInput{Enforcement: "hard", GuardMode: "enforce", OrgAuthoritative: true, Subject: "model:gpt-5"}, EffectBlocksProxied},
		{"hard, per-tool cap, authoritative", EffectInput{Enforcement: "hard", GuardMode: "enforce", OrgAuthoritative: true, Subject: "tool:codex"}, EffectBlocks},
		{"hard, authoritative", EffectInput{Enforcement: "hard", GuardMode: "enforce", OrgAuthoritative: true}, EffectBlocks},
		{"hard, lowering only", EffectInput{Enforcement: "hard", GuardMode: "enforce"}, EffectBlocksProxied},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := EffectOf(tc.in); got != tc.want {
				t.Fatalf("EffectOf(%+v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestEvaluateBlockedFollowsTheGuardsComparison: Blocked is the guard's own
// comparison (local spend when the baseline only warns), never the reading.
func TestEvaluateBlockedFollowsTheGuardsComparison(t *testing.T) {
	now := time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)
	base := Window{Window: "daily", Unit: "usd", Cap: 1, Spent: 1.5, Enforcement: "hard", GuardMode: "enforce", OrgAuthoritative: true}
	cases := []struct {
		name string
		w    func(Window) Window
		want bool
	}{
		{"enforcing, over", func(w Window) Window { return w }, true},
		{"observe, over", func(w Window) Window { w.GuardMode = "observe"; return w }, false},
		{"flag-only baseline, local under", func(w Window) Window { w.DeniesOnLocal, w.LocalSpent = true, 0.4; return w }, false},
		{"flag-only baseline, local over", func(w Window) Window { w.DeniesOnLocal, w.LocalSpent = true, 1.0; return w }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st, _ := Evaluate([]Window{tc.w(base)}, State{}, now)
			if len(st.Windows) != 1 || len(st.Active) != 1 {
				t.Fatalf("status = %+v", st)
			}
			if st.Windows[0].Blocked != tc.want || st.Active[0].Blocked != tc.want {
				t.Fatalf("blocked = window %v / notice %v, want %v", st.Windows[0].Blocked, st.Active[0].Blocked, tc.want)
			}
			if !tc.want && strings.Contains(st.Active[0].Message, "are blocked until") {
				t.Fatalf("an unblocked reading claims blocking: %q", st.Active[0].Message)
			}
		})
	}
}

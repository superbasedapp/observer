package policy

import (
	"strings"
	"testing"
	"time"
)

// TestTokenBudgetRulesFireOnlyWhenBothSidesAreSet mirrors the $ rows' contract
// one for one: an unconfigured ceiling disables the row, an unstamped event
// never matches, and only a value STRICTLY over the ceiling trips.
func TestTokenBudgetRulesFireOnlyWhenBothSidesAreSet(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		cfg     Config
		ev      Event
		wantHit string
	}{
		{
			name: "session tokens over the ceiling",
			cfg:  Config{Mode: ModeObserve, BudgetSessionTokens: 1000},
			ev:   Event{Kind: KindAPIRequest, SessionTokens: 1001},
			// B-621
			wantHit: "B-621",
		},
		{
			name: "session tokens exactly at the ceiling do not trip",
			cfg:  Config{Mode: ModeObserve, BudgetSessionTokens: 1000},
			ev:   Event{Kind: KindAPIRequest, SessionTokens: 1000},
		},
		{
			name: "an unconfigured ceiling disables the row",
			cfg:  Config{Mode: ModeObserve},
			ev:   Event{Kind: KindAPIRequest, SessionTokens: 1_000_000_000},
		},
		{
			name: "an unstamped event never matches",
			cfg:  Config{Mode: ModeObserve, BudgetSessionTokens: 1},
			ev:   Event{Kind: KindAPIRequest},
		},
		{
			name:    "daily tokens",
			cfg:     Config{Mode: ModeObserve, BudgetDailyTokens: 10},
			ev:      Event{Kind: KindAPIRequest, DailyTokens: 11},
			wantHit: "B-622",
		},
		{
			name:    "monthly tokens",
			cfg:     Config{Mode: ModeObserve, BudgetMonthlyTokens: 10},
			ev:      Event{Kind: KindAPIRequest, MonthlyTokens: 11},
			wantHit: "B-623",
		},
		{
			name:    "weekly tokens",
			cfg:     Config{Mode: ModeObserve, BudgetWeeklyTokens: 10},
			ev:      Event{Kind: KindAPIRequest, WeeklyTokens: 11},
			wantHit: "B-624",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			eng, err := New(tc.cfg)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			ev := tc.ev
			ev.Now = time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
			v := eng.Evaluate(ev)
			switch {
			case tc.wantHit == "" && v.Decision >= DecisionFlag:
				t.Fatalf("expected no budget hit, got %s (%s)", v.RuleID, v.Reason)
			case tc.wantHit == "":
				return
			case v.RuleID != tc.wantHit:
				t.Fatalf("rule = %q, want %q (reason %q)", v.RuleID, tc.wantHit, v.Reason)
			}
			if !strings.Contains(v.Reason, "tokens") {
				t.Errorf("reason %q does not name the unit — a token breach rendered in dollars is unreadable", v.Reason)
			}
		})
	}
}

// TestTokenBudgetRulesDenyOnProxyWhenHard is the plan's failing-first case for
// the enforcement ladder: the token rows must ride the SAME
// [guard.budget].hard switch as the $ rows — one budget posture per node, not
// one per unit.
func TestTokenBudgetRulesDenyOnProxyWhenHard(t *testing.T) {
	t.Parallel()

	ev := Event{
		Kind: KindAPIRequest, MonthlyTokens: 2_000_001,
		Now: time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC),
	}

	observe, err := New(Config{Mode: ModeObserve, BudgetMonthlyTokens: 2_000_000, BudgetHard: true})
	if err != nil {
		t.Fatalf("New(observe): %v", err)
	}
	if v := observe.Evaluate(ev); v.Decision != DecisionFlag {
		t.Errorf("observe mode: decision = %v, want flag — nothing blocks until the operator flips enforce (D2)", v.Decision)
	}

	soft, err := New(Config{Mode: ModeEnforce, BudgetMonthlyTokens: 2_000_000})
	if err != nil {
		t.Fatalf("New(enforce, hard=false): %v", err)
	}
	if v := soft.Evaluate(ev); v.Decision != DecisionFlag {
		t.Errorf("enforce + hard=false: decision = %v, want flag", v.Decision)
	}

	hard, err := New(Config{Mode: ModeEnforce, BudgetMonthlyTokens: 2_000_000, BudgetHard: true})
	if err != nil {
		t.Fatalf("New(enforce, hard=true): %v", err)
	}
	v := hard.Evaluate(ev)
	if v.Decision != DecisionDeny {
		t.Fatalf("enforce + hard=true: decision = %v (rule %s), want deny — the token rows must be CategoryBudget so the one BudgetHard switch upgrades them",
			v.Decision, v.RuleID)
	}
	if v.RuleID != "B-623" {
		t.Errorf("rule = %q, want B-623", v.RuleID)
	}
}

// TestTokenBudgetRowsAreCategoryBudget pins the category that makes the
// previous test work, so a regression names the cause and not the symptom.
func TestTokenBudgetRowsAreCategoryBudget(t *testing.T) {
	t.Parallel()

	want := map[string]bool{"B-621": true, "B-622": true, "B-623": true, "B-624": true}
	seen := map[string]bool{}
	for _, info := range Catalog() {
		if !want[info.ID] {
			continue
		}
		seen[info.ID] = true
		if info.Category != CategoryBudget {
			t.Errorf("%s category = %q, want %q — [guard.budget].hard only upgrades CategoryBudget rows",
				info.ID, info.Category, CategoryBudget)
		}
	}
	for id := range want {
		if !seen[id] {
			t.Errorf("%s is not in the built-in catalog", id)
		}
	}
}

// TestRequiredBudgetRowB625 pins the fail-closed row's whole contract: it
// compares no number, it applies ONLY to the proxy request path, and its
// enforce decision is deny without any help from BudgetHard.
func TestRequiredBudgetRowB625(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		cfg  Config
		ev   Event
		// wantRule is "" when nothing should fire.
		wantRule string
		wantDec  Decision
	}{
		{
			name: "off by default: an unset flag fires nothing",
			cfg:  Config{Mode: ModeEnforce},
			ev:   Event{Kind: KindAPIRequest, Target: "api.anthropic.com"},
		},
		{
			name:     "armed + enforce: an UNSTAMPED api_request denies",
			cfg:      Config{Mode: ModeEnforce, BudgetRequired: true},
			ev:       Event{Kind: KindAPIRequest, Target: "api.anthropic.com"},
			wantRule: "B-625", wantDec: DecisionDeny,
		},
		{
			name:     "armed + observe: flags only (D2)",
			cfg:      Config{Mode: ModeObserve, BudgetRequired: true},
			ev:       Event{Kind: KindAPIRequest, Target: "api.anthropic.com"},
			wantRule: "B-625", wantDec: DecisionFlag,
		},
		{
			// A shell exec is not a channel that can refuse anything, and
			// recording a verdict on every captured action for a condition
			// none of them can act on would be noise, not coverage.
			name: "armed but a non-proxy kind: no row applies",
			cfg:  Config{Mode: ModeEnforce, BudgetRequired: true},
			ev:   Event{Kind: KindShellExec, Target: "ls"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			eng, err := New(tc.cfg)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			v := eng.Evaluate(tc.ev)
			if tc.wantRule == "" {
				if v.RuleID == "B-625" {
					t.Fatalf("B-625 fired on %+v", tc.ev)
				}
				return
			}
			if v.RuleID != tc.wantRule {
				t.Fatalf("rule = %q, want %q", v.RuleID, tc.wantRule)
			}
			if v.Decision != tc.wantDec {
				t.Errorf("decision = %v, want %v", v.Decision, tc.wantDec)
			}
		})
	}
}

// TestEngineBudgetRequiredAccessor pins the read side the guard's proxy
// early-return consults, including the nil receiver it may be called on.
func TestEngineBudgetRequiredAccessor(t *testing.T) {
	t.Parallel()
	var nilEngine *Engine
	if nilEngine.BudgetRequired() {
		t.Error("a nil engine must not report the fail-closed posture")
	}
	on, err := New(Config{Mode: ModeEnforce, BudgetRequired: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !on.BudgetRequired() {
		t.Error("BudgetRequired() = false on an engine built with it")
	}
}

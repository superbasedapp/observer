package policy

import (
	"strings"
	"testing"
	"time"
)

// TestBudgetRules is the §5.7 budget conformance table: per row a
// breach hit, the at-threshold near-miss, the unconfigured-threshold
// off-switch, and the unstamped-event off-switch — flag in both modes
// without hard.
func TestBudgetRules(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		cfg      Config
		ev       Event
		wantRule string
	}{
		{
			name:     "B-601 hit: session over budget",
			cfg:      Config{BudgetSessionUSD: 5},
			ev:       Event{SessionCostUSD: 5.01},
			wantRule: "B-601",
		},
		{
			name: "B-601 near-miss: exactly at threshold",
			cfg:  Config{BudgetSessionUSD: 5},
			ev:   Event{SessionCostUSD: 5},
		},
		{
			name: "B-601 off: threshold unconfigured",
			cfg:  Config{},
			ev:   Event{SessionCostUSD: 99},
		},
		{
			name: "B-601 off: event unstamped",
			cfg:  Config{BudgetSessionUSD: 5},
			ev:   Event{},
		},
		{
			name:     "B-602 hit: daily over budget",
			cfg:      Config{BudgetDailyUSD: 20},
			ev:       Event{DailyCostUSD: 25},
			wantRule: "B-602",
		},
		{
			name: "B-602 near-miss: at threshold",
			cfg:  Config{BudgetDailyUSD: 20},
			ev:   Event{DailyCostUSD: 20},
		},
		{
			name:     "B-601 wins over B-602 by table order when both breach",
			cfg:      Config{BudgetSessionUSD: 5, BudgetDailyUSD: 20},
			ev:       Event{SessionCostUSD: 6, DailyCostUSD: 25},
			wantRule: "B-601",
		},
		{
			name:     "B-603 hit: monthly over budget",
			cfg:      Config{BudgetMonthlyUSD: 100},
			ev:       Event{MonthlyCostUSD: 100.01},
			wantRule: "B-603",
		},
		{
			name: "B-603 near-miss: at threshold",
			cfg:  Config{BudgetMonthlyUSD: 100},
			ev:   Event{MonthlyCostUSD: 100},
		},
		{
			name:     "B-604 hit: weekly over budget",
			cfg:      Config{BudgetWeeklyUSD: 40},
			ev:       Event{WeeklyCostUSD: 40.5},
			wantRule: "B-604",
		},
		{
			name: "B-604 off: threshold unconfigured",
			cfg:  Config{},
			ev:   Event{WeeklyCostUSD: 99},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ev := tc.ev
			ev.Kind = KindAPIRequest
			ev.Target = "anthropic:claude-x"
			ev.Now = time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)
			for _, mode := range []Mode{ModeObserve, ModeEnforce} {
				cfg := tc.cfg
				cfg.Mode = mode
				eng, err := New(cfg)
				if err != nil {
					t.Fatalf("New %s: %v", mode, err)
				}
				v := eng.Evaluate(ev)
				if tc.wantRule == "" {
					if v.RuleID != "" {
						t.Fatalf("%s: want no hit, got %+v", mode, v)
					}
					continue
				}
				if v.RuleID != tc.wantRule || v.Decision != DecisionFlag || v.Severity != SeverityHigh {
					t.Errorf("%s = %s/%s/%s, want %s/flag/high", mode, v.RuleID, v.Decision, v.Severity, tc.wantRule)
				}
				if v.RuleID == tc.wantRule && !strings.Contains(v.Reason, "$") {
					t.Errorf("reason %q lacks the spend detail", v.Reason)
				}
			}
		})
	}
}

// TestLimitRules is the §12.1 provider-usage-window conformance table
// (B-610..B-613): warn flags and deny blocks per window, at-or-over
// matches (unlike the strictly-over $ rows), a util at the deny level
// resolves to deny (stricter-wins over the co-matching warn), and the
// [guard.budget].hard $-deny upgrade never touches CategoryLimit.
func TestLimitRules(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name         string
		cfg          Config
		ev           Event
		wantRule     string
		wantObserve  Decision
		wantEnforce  Decision
		wantSeverity Severity
	}{
		{
			name:         "B-610 5h warn at threshold (>=)",
			cfg:          Config{LimitUtil5hWarn: 0.8},
			ev:           Event{Window5hUtil: 0.8},
			wantRule:     "B-610",
			wantObserve:  DecisionFlag,
			wantEnforce:  DecisionFlag,
			wantSeverity: SeverityWarn,
		},
		{
			name: "B-610 off: below threshold",
			cfg:  Config{LimitUtil5hWarn: 0.8},
			ev:   Event{Window5hUtil: 0.79},
		},
		{
			name: "5h off: threshold unconfigured",
			cfg:  Config{},
			ev:   Event{Window5hUtil: 0.99},
		},
		{
			name:         "B-611 5h deny at threshold, stricter-wins over warn",
			cfg:          Config{LimitUtil5hWarn: 0.8, LimitUtil5hDeny: 0.95},
			ev:           Event{Window5hUtil: 0.96},
			wantRule:     "B-611",
			wantObserve:  DecisionFlag,
			wantEnforce:  DecisionDeny,
			wantSeverity: SeverityHigh,
		},
		{
			name:         "B-612 weekly warn",
			cfg:          Config{LimitUtilWeeklyWarn: 0.5},
			ev:           Event{Window7dUtil: 0.6},
			wantRule:     "B-612",
			wantObserve:  DecisionFlag,
			wantEnforce:  DecisionFlag,
			wantSeverity: SeverityWarn,
		},
		{
			name:         "B-613 weekly deny",
			cfg:          Config{LimitUtilWeeklyDeny: 0.9},
			ev:           Event{Window7dUtil: 1.0},
			wantRule:     "B-613",
			wantObserve:  DecisionFlag,
			wantEnforce:  DecisionDeny,
			wantSeverity: SeverityHigh,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ev := tc.ev
			ev.Kind = KindAPIRequest
			ev.Target = "anthropic:claude-x"
			ev.Now = time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)
			for _, mode := range []Mode{ModeObserve, ModeEnforce} {
				cfg := tc.cfg
				cfg.Mode = mode
				eng, err := New(cfg)
				if err != nil {
					t.Fatalf("New %s: %v", mode, err)
				}
				v := eng.Evaluate(ev)
				if tc.wantRule == "" {
					if v.RuleID != "" {
						t.Fatalf("%s: want no hit, got %+v", mode, v)
					}
					continue
				}
				want := tc.wantObserve
				if mode == ModeEnforce {
					want = tc.wantEnforce
				}
				if v.RuleID != tc.wantRule || v.Decision != want || v.Severity != tc.wantSeverity {
					t.Errorf("%s = %s/%s/%s, want %s/%s/%s", mode, v.RuleID, v.Decision, v.Severity,
						tc.wantRule, want, tc.wantSeverity)
				}
				if !strings.Contains(v.Reason, "%") {
					t.Errorf("reason %q lacks the utilization percentage", v.Reason)
				}
			}
		})
	}

	// [guard.budget].hard must NOT rewrite CategoryLimit rows: a warn
	// window stays flag in enforce even under hard (its own deny
	// threshold is the block trigger).
	eng, err := New(Config{Mode: ModeEnforce, LimitUtil5hWarn: 0.8, BudgetHard: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if v := eng.Evaluate(Event{
		Kind: KindAPIRequest, Target: "anthropic:claude-x",
		Window5hUtil: 0.85, Now: time.Now(),
	}); v.RuleID != "B-610" || v.Decision != DecisionFlag {
		t.Errorf("hard mode clobbered a CategoryLimit warn: %s/%s, want B-610/flag", v.RuleID, v.Decision)
	}
}

// TestBudgetRules_HardMode pins the §12.1 hard upgrade: enforce-mode
// decision becomes deny while observe stays flag (D2 — nothing blocks
// until the operator flips enforce), and the upgrade shows in the
// effective table.
func TestBudgetRules_HardMode(t *testing.T) {
	t.Parallel()
	ev := Event{
		Kind: KindAPIRequest, Target: "anthropic:claude-x",
		SessionCostUSD: 6, Now: time.Now(),
	}
	for _, tc := range []struct {
		mode Mode
		want Decision
	}{
		{ModeObserve, DecisionFlag},
		{ModeEnforce, DecisionDeny},
	} {
		eng, err := New(Config{Mode: tc.mode, BudgetSessionUSD: 5, BudgetHard: true})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if v := eng.Evaluate(ev); v.RuleID != "B-601" || v.Decision != tc.want {
			t.Errorf("%s = %s/%s, want B-601/%s", tc.mode, v.RuleID, v.Decision, tc.want)
		}
	}
	eng, _ := New(Config{Mode: ModeEnforce, BudgetSessionUSD: 5, BudgetHard: true})
	for _, info := range eng.RuleInfos() {
		if subjectBudgetRuleID(info.ID) {
			// SUBJECT rows are exempt from the node-wide hard upgrade, by
			// design (bundle BUD-N). [guard.budget].hard is the node's posture
			// about the node's OWN ceilings; a per-tool / per-model cap carries
			// the ORGANIZATION's per-cap enforcement, which each subject id's
			// row PAIR already encodes — a deny row matching only hard caps and
			// a flag row matching only soft ones. Sweeping them up here would
			// deny a cap the admin authored as a nudge, which is the
			// cross-period fold MEDIUM-3 removed for windows.
			continue
		}
		if info.Category == CategoryBudget && info.Enforce != DecisionDeny {
			t.Errorf("hard mode: %s effective enforce = %s, want deny", info.ID, info.Enforce)
		}
		if info.Category == CategoryBudget && info.Observe != DecisionFlag {
			t.Errorf("hard mode: %s effective observe = %s, want flag (D2)", info.ID, info.Observe)
		}
	}
}

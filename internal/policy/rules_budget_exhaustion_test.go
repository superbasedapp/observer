package policy

import (
	"math"
	"testing"
	"time"
)

func TestManagedBudgetExhaustion(t *testing.T) {
	t.Parallel()
	rows := []struct {
		rule string
		cfg  Config
		set  func(*Event, float64)
		usd  bool
	}{
		{"B-601", Config{BudgetSessionUSD: 0.35}, func(e *Event, n float64) { e.SessionCostUSD = n }, true},
		{"B-602", Config{BudgetDailyUSD: 0.35}, func(e *Event, n float64) { e.DailyCostUSD = n }, true},
		{"B-603", Config{BudgetMonthlyUSD: 0.35}, func(e *Event, n float64) { e.MonthlyCostUSD = n }, true},
		{"B-604", Config{BudgetWeeklyUSD: 0.35}, func(e *Event, n float64) { e.WeeklyCostUSD = n }, true},
		{"B-621", Config{BudgetSessionTokens: 35}, func(e *Event, n float64) { e.SessionTokens = int64(n) }, false},
		{"B-622", Config{BudgetDailyTokens: 35}, func(e *Event, n float64) { e.DailyTokens = int64(n) }, false},
		{"B-623", Config{BudgetMonthlyTokens: 35}, func(e *Event, n float64) { e.MonthlyTokens = int64(n) }, false},
		{"B-624", Config{BudgetWeeklyTokens: 35}, func(e *Event, n float64) { e.WeeklyTokens = int64(n) }, false},
	}
	for _, row := range rows {
		t.Run(row.rule, func(t *testing.T) {
			t.Parallel()
			limit, below, above := 35.0, 34.0, 36.0
			if row.usd {
				limit, below, above = 0.35, math.Nextafter(0.35, 0), math.Nextafter(0.35, 1)
			}
			for _, tc := range []struct {
				name      string
				usage     float64
				mode      Mode
				protected bool
				hard      bool
				want      Decision
			}{
				{"managed below", below, ModeEnforce, true, true, DecisionAllow},
				{"managed exhausted", limit, ModeEnforce, true, true, DecisionDeny},
				{"managed over", above, ModeEnforce, true, true, DecisionDeny},
				{"managed observe", limit, ModeObserve, true, true, DecisionFlag},
				{"managed soft preserved", limit, ModeEnforce, false, false, DecisionAllow},
				{"individual hard preserved", limit, ModeEnforce, false, true, DecisionAllow},
				{"individual above preserved", above, ModeEnforce, false, true, DecisionDeny},
			} {
				t.Run(tc.name, func(t *testing.T) {
					cfg := row.cfg
					cfg.Mode, cfg.BudgetHard = tc.mode, tc.hard
					if tc.protected {
						cfg.BudgetProtection = budgetProtectionFor(row.rule)
					}
					engine, err := New(cfg)
					if err != nil {
						t.Fatal(err)
					}
					event := Event{Kind: KindAPIRequest, Now: time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)}
					row.set(&event, tc.usage)
					got := engine.EvaluateBudget(event)
					if got.Decision != tc.want {
						t.Fatalf("decision = %v (%s), want %v", got.Decision, got.Reason, tc.want)
					}
					if tc.want != DecisionAllow && got.RuleID != row.rule {
						t.Fatalf("rule = %q, want %q", got.RuleID, row.rule)
					}
				})
			}
		})
	}
}

func TestManagedBudgetRequired(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		cfg  Config
		want bool
	}{
		{"no configured cap", Config{BudgetProtection: budgetProtectionFor("B-602"), BudgetHard: true}, false},
		{"individual", Config{BudgetDailyUSD: 0.35, BudgetHard: true}, false},
		{"soft", Config{BudgetDailyUSD: 0.35, BudgetProtection: budgetProtectionFor("B-602")}, false},
		{"hard dollars", Config{BudgetDailyUSD: 0.35, BudgetProtection: budgetProtectionFor("B-602"), BudgetHard: true}, true},
		{"hard tokens", Config{BudgetWeeklyTokens: 35, BudgetProtection: budgetProtectionFor("B-624"), BudgetHard: true}, true},
		{"missing org document", Config{BudgetRequired: true}, true},
	} {
		for _, mode := range []Mode{ModeOff, ModeObserve, ModeEnforce} {
			t.Run(tc.name+"/"+string(mode), func(t *testing.T) {
				cfg := tc.cfg
				cfg.Mode = mode
				e, err := New(cfg)
				if err != nil {
					t.Fatal(err)
				}
				if got := e.ManagedBudgetRequired(); got != tc.want {
					t.Fatalf("required=%v want %v", got, tc.want)
				}
			})
		}
	}
}

func TestEvaluateManagedBudgetFiltersBeforeVerdictOrdering(t *testing.T) {
	t.Parallel()
	engine, err := New(Config{
		Mode:                ModeEnforce,
		BudgetHard:          true,
		BudgetSessionUSD:    0.35,
		BudgetMonthlyTokens: 100,
		BudgetProtection:    BudgetProtection{MonthlyTokens: true},
	})
	if err != nil {
		t.Fatal(err)
	}

	event := Event{
		Kind: KindAPIRequest, SessionCostUSD: 0.36, MonthlyTokens: 101,
		Now: time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC),
	}
	if got := engine.EvaluateBudget(event); got.RuleID != "B-601" || got.Decision != DecisionDeny {
		t.Fatalf("ordinary budget verdict = %s/%s, want local B-601/deny", got.RuleID, got.Decision)
	}
	if got := engine.EvaluateManagedBudget(event); got.RuleID != "B-623" || got.Decision != DecisionDeny {
		t.Fatalf("managed budget verdict = %s/%s, want organization B-623/deny", got.RuleID, got.Decision)
	}

	event.MonthlyTokens = 99
	if got := engine.EvaluateManagedBudget(event); got.RuleID != "" || got.Decision != DecisionAllow {
		t.Fatalf("local-only exhaustion authorized intervention: %+v", got)
	}
}

func TestEvaluateManagedBudgetDoesNotAuthorizeUnitSibling(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		protection BudgetProtection
		event      Event
	}{
		{
			name:       "USD authority does not authorize tokens",
			protection: BudgetProtection{DailyUSD: true},
			event:      Event{Kind: KindAPIRequest, DailyCostUSD: 0.34, DailyTokens: 101},
		},
		{
			name:       "token authority does not authorize USD",
			protection: BudgetProtection{DailyTokens: true},
			event:      Event{Kind: KindAPIRequest, DailyCostUSD: 0.36, DailyTokens: 99},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			engine, err := New(Config{
				Mode: ModeEnforce, BudgetHard: true,
				BudgetDailyUSD: 0.35, BudgetDailyTokens: 100,
				BudgetProtection: tc.protection,
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := engine.EvaluateBudget(tc.event); got.Decision != DecisionDeny {
				t.Fatalf("ordinary budget verdict = %+v, want deny", got)
			}
			if got := engine.EvaluateManagedBudget(tc.event); got.RuleID != "" || got.Decision != DecisionAllow {
				t.Fatalf("sibling unit authorized intervention: %+v", got)
			}
		})
	}
}

func budgetProtectionFor(ruleID string) BudgetProtection {
	var protection BudgetProtection
	switch ruleID {
	case "B-601":
		protection.SessionUSD = true
	case "B-602":
		protection.DailyUSD = true
	case "B-603":
		protection.MonthlyUSD = true
	case "B-604":
		protection.WeeklyUSD = true
	case "B-621":
		protection.SessionTokens = true
	case "B-622":
		protection.DailyTokens = true
	case "B-623":
		protection.MonthlyTokens = true
	case "B-624":
		protection.WeeklyTokens = true
	}
	return protection
}

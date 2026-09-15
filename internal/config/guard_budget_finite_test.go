package config

import (
	"math"
	"testing"
)

func TestGuardBudgetRejectsNonfiniteValues(t *testing.T) {
	t.Parallel()
	for _, field := range []struct {
		name string
		set  func(*GuardBudgetConfig, float64)
	}{
		{"session_usd", func(b *GuardBudgetConfig, v float64) { b.SessionUSD = v }},
		{"daily_usd", func(b *GuardBudgetConfig, v float64) { b.DailyUSD = v }},
		{"weekly_usd", func(b *GuardBudgetConfig, v float64) { b.WeeklyUSD = v }},
		{"monthly_usd", func(b *GuardBudgetConfig, v float64) { b.MonthlyUSD = v }},
		{"util_5h_warn", func(b *GuardBudgetConfig, v float64) { b.Window.Util5hWarn = v }},
		{"util_5h_deny", func(b *GuardBudgetConfig, v float64) { b.Window.Util5hDeny = v }},
		{"util_weekly_warn", func(b *GuardBudgetConfig, v float64) { b.Window.UtilWeeklyWarn = v }},
		{"util_weekly_deny", func(b *GuardBudgetConfig, v float64) { b.Window.UtilWeeklyDeny = v }},
	} {
		t.Run(field.name, func(t *testing.T) {
			for _, value := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
				g := Default().Guard
				g.Enabled = true
				field.set(&g.Budget, value)
				if err := validateGuard(g); err == nil {
					t.Fatalf("accepted nonfinite %s", field.name)
				}
			}
		})
	}
}

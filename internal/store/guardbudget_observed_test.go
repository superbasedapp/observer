package store

import (
	"context"
	"testing"
	"time"
)

// TestGuardBudgetObservedStatsPriced pins demo bug #6's substrate: rows with
// no recorded cost are priced into the per-session and per-day totals, rows
// nothing prices are counted as unpriced, and empty windows stay excluded.
func TestGuardBudgetObservedStatsPriced(t *testing.T) {
	s, db := newTestStore(t)
	guardBudgetTestSession(t, s, "a")
	guardBudgetTestSession(t, s, "b")
	now := time.Now().UTC().Truncate(time.Hour)
	day1, day2 := now.Add(-50*time.Hour), now.Add(-2*time.Hour)
	insertGuardBudgetUsage(t, db, "a", "known-model", "a1", day1, 100, 10, 0) // no recorded cost: priced
	insertGuardBudgetUsage(t, db, "a", "known-model", "a2", day2, 100, 10, 0)
	insertGuardBudgetUsage(t, db, "b", "known-model", "b1", day2, 100, 10, 3) // recorded cost kept
	insertGuardBudgetUsage(t, db, "b", "mystery", "b2", day2, 100, 10, 0)     // nothing prices it
	pricer := func(model string, _ time.Time, _ PushTokenSplit) (float64, string, bool) {
		if model == "known-model" {
			return 1, "exact", true
		}
		return 0, "miss", false
	}
	got, err := s.GuardBudgetObservedStatsPriced(context.Background(), now.Add(-30*24*time.Hour), pricer)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name      string
		got, want float64
	}{
		{"sessions", float64(got.Sessions), 2},
		{"days", float64(got.Days), 2},
		{"session max (b: 3 recorded)", got.SessionMaxUSD, 3},
		{"daily max (day2: 1 + 3)", got.DailyMaxUSD, 4},
		{"unpriced rows", float64(got.UnpricedRows), 1},
	}
	for _, c := range cases {
		assertGuardBudgetNear(t, c.name, c.got, c.want)
	}
	if _, err := s.GuardBudgetObservedStatsPriced(context.Background(), now, nil); err == nil {
		t.Fatal("a nil pricer must be refused")
	}
}

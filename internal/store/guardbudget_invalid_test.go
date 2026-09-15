package store

import (
	"context"
	"math"
	"testing"
	"time"
)

func TestGuardBudgetNegativeTokensAreUnavailableInTheirWindows(t *testing.T) {
	for _, source := range []string{"proxy", "native"} {
		t.Run(source, func(t *testing.T) {
			s, db := newTestStore(t)
			guardBudgetTestSession(t, s, "bad-session")
			day, week, month := guardBudgetTestWindows()
			at := day.Add(-time.Hour)
			if source == "proxy" {
				insertGuardBudgetAPI(t, db, "bad-session", "fixture", at, -1, 0, 0)
			} else {
				insertGuardBudgetUsage(t, db, "bad-session", "fixture", "bad", at, -1, 0, 0)
			}
			got, err := s.GuardBudgetTokens(context.Background(), "bad-session", day, week, month)
			if err != nil {
				t.Fatal(err)
			}
			want := GuardBudgetUnavailableWindows{Session: true, Weekly: true, Monthly: true}
			if got.Unavailable != want {
				t.Fatalf("token availability=%+v want %+v", got.Unavailable, want)
			}
			usd, err := s.GuardBudgetSpendPriced(context.Background(), "bad-session", day, week, month, func(string, time.Time, PushTokenSplit) (float64, string, bool) {
				t.Fatal("invalid negative usage sent to pricer")
				return 0, "", false
			})
			if err != nil {
				t.Fatal(err)
			}
			if usd.UnpricedWindows != want {
				t.Fatalf("USD availability=%+v want %+v", usd.UnpricedWindows, want)
			}
		})
	}
}

func TestGuardBudgetInvalidStoredCostCannotReduceSpend(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value float64
	}{
		{"negative", -1}, {"positive infinity", math.Inf(1)}, {"negative infinity", math.Inf(-1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, db := newTestStore(t)
			guardBudgetTestSession(t, s, "native")
			at := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
			insertGuardBudgetUsage(t, db, "native", "fixture", "good", at, 10, 10, 0.35)
			// Invalid dollars remain unavailable even when the bad row has no
			// token counts. It must not act as a credit against other usage.
			insertGuardBudgetUsage(t, db, "native", "fixture", "bad", at, 0, 0, tc.value)
			day, week, month := guardBudgetTestWindows()
			got, err := s.GuardBudgetSpendPriced(context.Background(), "native", day, week, month, func(string, time.Time, PushTokenSplit) (float64, string, bool) {
				t.Fatal("corrupt stored cost was silently repriced")
				return 0, "", false
			})
			if err != nil {
				t.Fatal(err)
			}
			if got.SessionUSD != 0.35 || got.DailyUSD != 0.35 || got.UnpricedRows != 1 || got.UnpricedWindows != (GuardBudgetUnavailableWindows{Session: true, Daily: true, Weekly: true, Monthly: true}) {
				t.Fatalf("spend=%+v", got)
			}
		})
	}
}

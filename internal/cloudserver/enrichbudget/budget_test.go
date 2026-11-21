package enrichbudget

import (
	"errors"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/reserve"
)

func freeTier() Tier {
	return Tier{
		Name: "free", Version: 1, RouteID: "session_enrichment.gpt-oss-20b.v1",
		EvidenceTokens: 4000, SessionTokens: 60000, DailyTokens: 200000, MonthlyTokens: 2000000,
	}
}

func readyRoute() RouteFacts {
	return RouteFacts{
		Found: true, Feature: "session_enrichment", Production: true, Active: true,
		Bound: true, Priced: true, Attested: true, MaxOutputTokens: 4096,
	}
}

func TestTierValidateRules(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Tier)
		want   string // "" = valid
	}{
		{"valid", func(*Tier) {}, ""},
		{"bad name", func(x *Tier) { x.Name = "Free!" }, "tier name"},
		{"empty name", func(x *Tier) { x.Name = "" }, "tier name"},
		{"no route", func(x *Tier) { x.RouteID = "" }, "route id"},
		{"evidence too small", func(x *Tier) { x.EvidenceTokens = MinEvidenceTokens - 1 }, "evidence budget"},
		{"evidence too large", func(x *Tier) { x.EvidenceTokens = MaxEvidenceTokens + 1 }, "evidence budget"},
		{"zero session", func(x *Tier) { x.SessionTokens = 0 }, "token budgets"},
		{"negative daily", func(x *Tier) { x.DailyTokens = -1 }, "token budgets"},
		{"monthly typo", func(x *Tier) { x.MonthlyTokens = MaxAccountTokens + 1 }, "token budgets"},
		{"month below day", func(x *Tier) { x.MonthlyTokens = x.DailyTokens - 1 }, "monthly budget"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tier := freeTier()
			tc.mutate(&tier)
			err := tier.Validate()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("want valid, got %v", err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidTier) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q refusal, got %v", tc.want, err)
			}
		})
	}
}

// TestCheckTierRefusesUnreadyRoutes is one row per route rule: a tier can
// only name a route that exists, serves the feature, is production, active,
// bound, priced and attested, and whose worst-case call fits the budgets.
func TestCheckTierRefusesUnreadyRoutes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*RouteFacts, *Tier)
		want   string
	}{
		{"ready", func(*RouteFacts, *Tier) {}, ""},
		{"missing", func(r *RouteFacts, _ *Tier) { r.Found = false }, "does not exist"},
		{"other feature", func(r *RouteFacts, _ *Tier) { r.Feature = "project_digest" }, "serves"},
		{"non-production", func(r *RouteFacts, _ *Tier) { r.Production = false }, "not a production route"},
		{"inactive", func(r *RouteFacts, _ *Tier) { r.Active = false }, "not active"},
		{"unbound", func(r *RouteFacts, _ *Tier) { r.Bound = false }, "not bound"},
		{"unpriced", func(r *RouteFacts, _ *Tier) { r.Priced = false }, "price snapshot"},
		{"unattested", func(r *RouteFacts, _ *Tier) { r.Attested = false; r.AttestReason = "no disclosure" }, "not attested: no disclosure"},
		{"session below one call", func(_ *RouteFacts, x *Tier) { x.SessionTokens = 1000 }, "session budget"},
		{"day below one call", func(_ *RouteFacts, x *Tier) { x.DailyTokens = 1000; x.MonthlyTokens = 1000 }, "daily budget"},
		{"invalid tier first", func(r *RouteFacts, x *Tier) { x.EvidenceTokens = 1; r.Found = false }, "evidence budget"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tier, route := freeTier(), readyRoute()
			tc.mutate(&route, &tier)
			err := CheckTier(tier, "session_enrichment", route)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("want ok, got %v", err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidTier) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q refusal, got %v", tc.want, err)
			}
		})
	}
}

func TestWorstCaseTokens(t *testing.T) {
	for _, tc := range []struct {
		name      string
		bytes     int64
		maxOutput int
		want      int64
	}{
		{"empty", 0, 4096, PromptOverheadTokens + 4096},
		{"negative bytes", -10, 4096, PromptOverheadTokens + 4096},
		{"ceil", 1, 1024, 1 + PromptOverheadTokens + 1024},
		{"12k bytes", 12000, 4096, 6000 + PromptOverheadTokens + 4096},
		{"no route cap", 2000, 0, 1000 + PromptOverheadTokens + DefaultMaxOutputTokens},
	} {
		if got := WorstCaseTokens(tc.bytes, tc.maxOutput); got != tc.want {
			t.Errorf("%s: WorstCaseTokens = %d, want %d", tc.name, got, tc.want)
		}
	}
	// The free default (4,000 evidence tokens on a 4,096-output route): an
	// envelope that just fits is 12,383 bytes, so its hold is 6,192 + 3,072 +
	// 4,096.
	if got := MaxEvidenceBytes(4000); got != 12383 {
		t.Fatalf("MaxEvidenceBytes(4000) = %d", got)
	}
	if got := WorstCaseForEvidenceBudget(4000, 4096); got != 6192+PromptOverheadTokens+4096 {
		t.Fatalf("WorstCaseForEvidenceBudget = %d", got)
	}
}

// TestAdmitRules is one row per refusal the store maps to a sentinel, plus
// the boundary that lands exactly on a cap.
func TestAdmitRules(t *testing.T) {
	caps := Caps{Daily: 100000, Monthly: 1000000, Session: 40000, Concurrency: 2}
	for _, tc := range []struct {
		name    string
		used    Committed
		hold    int64
		refused string // "" = admitted
	}{
		{"fits", Committed{}, 13000, ""},
		{"lands exactly on the daily cap", Committed{Daily: 87000}, 13000, ""},
		{"daily", Committed{Daily: 87001}, 13000, LimitDaily},
		{"monthly", Committed{Monthly: 990000}, 13000, LimitMonthly},
		{"concurrency", Committed{InFlight: 2}, 13000, LimitConcurrency},
		{"session spent", Committed{Session: 30000}, 13000, LimitSession},
		{"daily named before session", Committed{Daily: 99000, Session: 39000}, 13000, LimitDaily},
		{"zero hold is invalid", Committed{}, 0, LimitDaily},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := Admit(caps, tc.used, tc.hold)
			if tc.refused == "" {
				if !d.Admitted {
					t.Fatalf("want admitted, got %+v", d.Refused)
				}
				return
			}
			if d.Admitted || d.Refused == nil || d.Refused.Name != tc.refused {
				t.Fatalf("want refused by %s, got %+v", tc.refused, d)
			}
		})
	}
}

func TestActualTokensMissingMeterBooksTheHold(t *testing.T) {
	for _, tc := range []struct {
		in, out int64
		want    float64
	}{
		{4000, 1400, 5400},
		{4000, 0, 4000},
		{0, 1400, -1},
		{-1, 10, -1},
		{4000, -1, -1},
	} {
		got := ActualTokens(tc.in, tc.out)
		if got != tc.want {
			t.Errorf("ActualTokens(%d,%d) = %v, want %v", tc.in, tc.out, got, tc.want)
		}
		s, err := reserve.Settle(reserve.Hold{State: reserve.HoldOpen, Estimate: 9000}, reserve.Close{Outcome: reserve.OutcomeSettle, Actual: got})
		if err != nil {
			t.Fatal(err)
		}
		if got < 0 && s.Booked != 9000 {
			t.Errorf("a missing meter booked %v, want the hold", s.Booked)
		}
	}
}

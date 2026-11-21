package main

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/enrichbudget"
)

func TestPlanTierSet(t *testing.T) {
	cur := enrichbudget.Tier{
		Name: "free", Version: 3, RouteID: "session_enrichment.gpt-oss-20b.v1",
		EvidenceTokens: 4000, SessionTokens: 60000, DailyTokens: 250000, MonthlyTokens: 3000000,
	}
	str := func(s string) *string { return &s }
	i := func(v int) *int { return &v }
	i64 := func(v int64) *int64 { return &v }
	for _, tc := range []struct {
		name    string
		current enrichbudget.Tier
		req     tierRequest
		want    enrichbudget.Tier
		errWant string
	}{
		{
			name: "change only the route", current: cur,
			req: tierRequest{Name: "free", RouteID: str("session_enrichment.gpt-oss-120b.v1"), CurrentExists: true},
			want: enrichbudget.Tier{
				Name: "free", RouteID: "session_enrichment.gpt-oss-120b.v1", EvidenceTokens: 4000,
				SessionTokens: 60000, DailyTokens: 250000, MonthlyTokens: 3000000,
			},
		},
		{
			name: "change the budgets", current: cur,
			req: tierRequest{Name: "free", Evidence: i(5000), Daily: i64(300000), CurrentExists: true},
			want: enrichbudget.Tier{
				Name: "free", RouteID: cur.RouteID, EvidenceTokens: 5000,
				SessionTokens: 60000, DailyTokens: 300000, MonthlyTokens: 3000000,
			},
		},
		{
			name:    "a new tier needs every field",
			req:     tierRequest{Name: "team", RouteID: str("r"), Evidence: i(4000)},
			errWant: "missing --session-tokens, --daily-tokens, --monthly-tokens",
		},
		{
			name: "a new tier with every field",
			req:  tierRequest{Name: "team", RouteID: str("r"), Evidence: i(4000), Session: i64(1), Daily: i64(2), Monthly: i64(3)},
			want: enrichbudget.Tier{Name: "team", RouteID: "r", EvidenceTokens: 4000, SessionTokens: 1, DailyTokens: 2, MonthlyTokens: 3},
		},
		{name: "no tier name", req: tierRequest{}, errWant: "--tier is required"},
		{
			name: "nothing changes", current: cur,
			req:     tierRequest{Name: "free", Evidence: i(4000), CurrentExists: true},
			errWant: "nothing to change",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := planTierSet(tc.current, tc.req)
			if tc.errWant != "" {
				if err == nil || !strings.Contains(err.Error(), tc.errWant) {
					t.Fatalf("want error %q, got %v", tc.errWant, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("planTierSet: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

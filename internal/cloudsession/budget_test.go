package cloudsession

import (
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestSoftBudgetStop: one case per row of the skip table and the over/under
// outcomes, including a figure from an earlier period that is ignored.
func TestSoftBudgetStop(t *testing.T) {
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	month := func(c orgcontract.BudgetPolicyCap) orgcontract.BudgetPolicyCap {
		if c.Period == "" {
			c.Period = orgcontract.BudgetPolicyPeriodCalendarMonth
		}
		if c.Enforcement == "" {
			c.Enforcement = orgcontract.BudgetPolicyEnforcementHard
		}
		if c.SpentAsOf == "" {
			c.SpentAsOf = "2026-11-14T09:00:00Z"
		}
		return c
	}
	body := func(caps ...orgcontract.BudgetPolicyCap) *orgcontract.BudgetPolicyBody {
		b := &orgcontract.BudgetPolicyBody{Version: 1, Period: caps[0].Period, Caps: caps}
		return b
	}
	cases := []struct {
		name    string
		body    *orgcontract.BudgetPolicyBody
		want    BudgetOutcome
		skipped string
	}{
		{"no document", nil, BudgetNone, ""},
		{"signed explicit none", &orgcontract.BudgetPolicyBody{Version: 1}, BudgetNone, ""},
		{"dollars over", body(month(orgcontract.BudgetPolicyCap{CapUSD: 50, SpentUSD: 51})), BudgetOver, ""},
		{"dollars exactly at the cap", body(month(orgcontract.BudgetPolicyCap{CapUSD: 50, SpentUSD: 50})), BudgetOver, ""},
		{"tokens over", body(month(orgcontract.BudgetPolicyCap{CapTokens: 1000, SpentTokens: 2000})), BudgetOver, ""},
		{"under", body(month(orgcontract.BudgetPolicyCap{CapUSD: 50, SpentUSD: 10})), BudgetUnder, ""},
		{"report-only cap", body(month(orgcontract.BudgetPolicyCap{CapUSD: 50, SpentUSD: 99, Enforcement: "report"})), BudgetStale, "report-only"},
		{"subject cap", body(month(orgcontract.BudgetPolicyCap{CapUSD: 50, SpentUSD: 99, Subject: &orgcontract.BudgetSubject{Kind: "tool", ID: "claude-code"}})), BudgetStale, "narrowed"},
		{"no cap value", body(month(orgcontract.BudgetPolicyCap{SpentUSD: 99})), BudgetStale, "no cap"},
		{"undated figure", body(orgcontract.BudgetPolicyCap{Period: "calendar_month", Enforcement: "hard", CapUSD: 50, SpentUSD: 99, SpentAsOf: "yesterday"}), BudgetStale, "no dated spend figure"},
		{"last month's figure", body(month(orgcontract.BudgetPolicyCap{CapUSD: 50, SpentUSD: 99, SpentAsOf: "2026-10-31T23:00:00Z"})), BudgetStale, "earlier period"},
		{"yesterday's daily figure", body(orgcontract.BudgetPolicyCap{Period: "calendar_day", Enforcement: "soft", CapUSD: 5, SpentUSD: 9, SpentAsOf: "2026-11-14T23:00:00Z"}), BudgetStale, "earlier period"},
		{"today's daily figure", body(orgcontract.BudgetPolicyCap{Period: "calendar_day", Enforcement: "soft", CapUSD: 5, SpentUSD: 9, SpentAsOf: "2026-11-15T08:00:00Z"}), BudgetOver, ""},
		{"rolling figure inside the snapshot life", body(orgcontract.BudgetPolicyCap{Period: "rolling_30d", Enforcement: "soft", CapUSD: 5, SpentUSD: 9, SpentAsOf: "2026-11-10T00:00:00Z"}), BudgetOver, ""},
		{"rolling figure past the snapshot life", body(orgcontract.BudgetPolicyCap{Period: "rolling_30d", Enforcement: "soft", CapUSD: 5, SpentUSD: 9, SpentAsOf: "2026-11-01T00:00:00Z"}), BudgetStale, "earlier period"},
		{"unknown timezone", body(month(orgcontract.BudgetPolicyCap{CapUSD: 5, SpentUSD: 9, Timezone: "Nowhere/Land"})), BudgetStale, "earlier period"},
		{"expired grant reverts to the base cap", body(month(orgcontract.BudgetPolicyCap{CapUSD: 100, SpentUSD: 60, GrantID: 1, BaseCapUSD: 50, GrantExpiresAtNs: now.Add(-time.Hour).UnixNano()})), BudgetOver, ""},
		{"leading cap only (no Caps list)", &orgcontract.BudgetPolicyBody{Version: 1, Period: "calendar_month", Enforcement: "soft", CapUSD: 5}, BudgetStale, "no dated spend figure"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := SoftBudgetStop(tc.body, now, time.LoadLocation)
			if d.Outcome != tc.want {
				t.Fatalf("outcome = %s (%+v), want %s", d.Outcome, d, tc.want)
			}
			if d.Stop() != (tc.want == BudgetOver) {
				t.Fatal("Stop disagrees with the outcome")
			}
			if tc.want == BudgetOver && !strings.Contains(d.Reason, "soft stop") {
				t.Errorf("reason does not say it is a soft stop: %s", d.Reason)
			}
			// The developer-facing reason never shows a dollar amount (T-204):
			// a dollar cap reads as the share of the cap used.
			if strings.Contains(d.Reason, "$") {
				t.Errorf("reason shows dollars: %s", d.Reason)
			}
			if tc.skipped != "" && !strings.Contains(strings.Join(d.Skipped, ";"), tc.skipped) {
				t.Errorf("skipped = %v, want it to mention %q", d.Skipped, tc.skipped)
			}
		})
	}
}

// TestSoftBudgetStopReasonShare: a dollar cap names the share used, a token
// cap its tokens.
func TestSoftBudgetStopReasonShare(t *testing.T) {
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		cap  orgcontract.BudgetPolicyCap
		want string
	}{
		{"over a dollar cap", orgcontract.BudgetPolicyCap{CapUSD: 50, SpentUSD: 52}, "used up: 104% of the budget as of"},
		{"at a dollar cap", orgcontract.BudgetPolicyCap{CapUSD: 50, SpentUSD: 50}, "used up: 100% of the budget as of"},
		{"over a token cap", orgcontract.BudgetPolicyCap{CapTokens: 1000, SpentTokens: 2000}, "used up: 2000 of 1000 tokens as of"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.cap
			c.Period, c.Enforcement, c.SpentAsOf = orgcontract.BudgetPolicyPeriodCalendarMonth, orgcontract.BudgetPolicyEnforcementHard, "2026-11-14T09:00:00Z"
			d := SoftBudgetStop(&orgcontract.BudgetPolicyBody{Version: 1, Period: c.Period, Caps: []orgcontract.BudgetPolicyCap{c}}, now, time.LoadLocation)
			if !d.Stop() || !strings.Contains(d.Reason, tc.want) {
				t.Errorf("reason = %q, want it to contain %q", d.Reason, tc.want)
			}
		})
	}
}

// TestBudgetWindowsCoverEveryPeriod: every period the contract names has a
// validity row.
func TestBudgetWindowsCoverEveryPeriod(t *testing.T) {
	for _, p := range []string{orgcontract.BudgetPolicyPeriodRolling30d, orgcontract.BudgetPolicyPeriodCalendarDay, orgcontract.BudgetPolicyPeriodCalendarMonth} {
		if _, ok := windowEnd(orgcontract.BudgetPolicyCap{Period: p}, time.Now(), nil); !ok {
			t.Errorf("no window for period %q", p)
		}
	}
}

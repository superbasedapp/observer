package store

import (
	"errors"
	"testing"
	"time"
)

// TestUnitHoldRefusals pins how this ledger's count caps map onto the
// reserve core (no database needed): `used` reaching the cap refuses with
// the cap's own sentinel, the hold that lands exactly on the cap is
// admitted, and a zero cap refuses every hold.
func TestUnitHoldRefusals(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		kind       string
		capUnits   int64
		used       int64
		wantRefuse error
	}{
		{name: "daily: the 100th hold lands on the cap", kind: "daily", capUnits: 100, used: 99},
		{name: "daily: the 101st is refused", kind: "daily", capUnits: 100, used: 100, wantRefuse: ErrDailyLimit},
		{name: "monthly: over the cap", kind: "monthly", capUnits: 3000, used: 3000, wantRefuse: ErrMonthlyLimit},
		{name: "concurrency: both slots held", kind: "concurrency", capUnits: 2, used: 2, wantRefuse: ErrConcurrency},
		{name: "pool: exhausted", kind: "pool", capUnits: 50, used: 50, wantRefuse: ErrGlobalBudget},
		{name: "pool: one left", kind: "pool", capUnits: 50, used: 49},
		{name: "zero cap refuses", kind: "daily", capUnits: 0, used: 0, wantRefuse: ErrDailyLimit},
		{name: "a stale counter past the cap still refuses", kind: "monthly", capUnits: 10, used: 12, wantRefuse: ErrMonthlyLimit},
		{name: "an unnamed kind falls back to concurrency", kind: "other", capUnits: 1, used: 1, wantRefuse: ErrConcurrency},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if err := refusal(unitHold(c.kind, c.capUnits, c.used)); !errors.Is(err, c.wantRefuse) || (c.wantRefuse == nil) != (err == nil) {
				t.Fatalf("refusal = %v, want %v", err, c.wantRefuse)
			}
		})
	}
}

// TestCeilingLimitsAtCap pins the spend ceilings' AtCap boundary through the
// core: a window whose spend has reached its ceiling refuses (no estimate is
// known before the call), and a zero ceiling is no ceiling.
func TestCeilingLimitsAtCap(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		c       SpendCeiling
		spent   map[string]float64
		reached bool
	}{
		{name: "nothing spent", c: SpendCeiling{DailyUSD: 5, MonthlyUSD: 50}, spent: map[string]float64{}},
		{name: "daily just below", c: SpendCeiling{DailyUSD: 5, MonthlyUSD: 50}, spent: map[string]float64{"daily": 4.99}},
		{name: "daily exactly at the ceiling", c: SpendCeiling{DailyUSD: 5, MonthlyUSD: 50}, spent: map[string]float64{"daily": 5}, reached: true},
		{name: "monthly past the ceiling", c: SpendCeiling{DailyUSD: 5, MonthlyUSD: 50}, spent: map[string]float64{"daily": 1, "monthly": 50.5}, reached: true},
		{name: "zero ceilings are no ceilings", c: SpendCeiling{}, spent: map[string]float64{"daily": 1e6, "monthly": 1e6}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := ceilingReached(c.c, c.spent); got != c.reached {
				t.Fatalf("ceilingReached = %v, want %v (limits %+v)", got, c.reached, ceilingLimits(c.c, c.spent))
			}
		})
	}
}

// TestCloseOutcomes pins the terminal states each finalize caller passes,
// and refuses a pair no caller passes.
func TestCloseOutcomes(t *testing.T) {
	t.Parallel()
	for _, r := range closeOutcomes() {
		if got, err := closeOutcomeFor(r.state, r.refund); err != nil || got != r.outcome {
			t.Fatalf("closeOutcomeFor(%q, %t) = (%q, %v), want %q", r.state, r.refund, got, err, r.outcome)
		}
	}
	for _, bad := range []struct {
		state  string
		refund bool
	}{{"settled", true}, {"released", false}, {"reserved", false}, {"", true}} {
		if _, err := closeOutcomeFor(bad.state, bad.refund); err == nil {
			t.Fatalf("closeOutcomeFor(%q, %t) = nil error, want a refusal", bad.state, bad.refund)
		}
	}
}

// TestWindowKeysAreUTC pins the UTC calendar of the two cycle windows.
func TestWindowKeysAreUTC(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 11, 1, 3, 30, 0, 0, time.FixedZone("UTC-8", -8*3600)) // 11:30 UTC
	if got := DailyWindowKey(at); got != "2026-11-01" {
		t.Fatalf("DailyWindowKey = %q", got)
	}
	if got := MonthlyWindowKey(at.Add(-12 * time.Hour)); got != "2026-10" {
		t.Fatalf("MonthlyWindowKey = %q", got)
	}
	if concurrencyWindowKey != "live" {
		t.Fatalf("concurrencyWindowKey = %q", concurrencyWindowKey)
	}
}

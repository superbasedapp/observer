package orgclient

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestBenignRailFetchState pins which org policy-distribution fetch-states are
// EXPECTED steady states (logged at Debug in the push loop) versus genuine
// problems (kept at WARN). The budget/pricing/intel rails share their
// fetch-state string values, so one predicate classifies all three — this test
// walks the union of their vocabularies, one row per state string.
//
// The regression this guards: flipping [guard.budget].from_org on by default
// (d67768ce5) made every enrolled node poll rails a legitimately-unconfigured
// org answers 409 channel_off on, and that logged a WARN per rail per cycle
// forever. channel_off / not_supported / disabled / no_budget / no_pricing (and
// not_enrolled) are benign; unverified (a signature FAILURE) / auth_failed /
// unreachable are not.
func TestBenignRailFetchState(t *testing.T) {
	tests := []struct {
		name  string
		state string
		want  bool
	}{
		// Benign — the org deliberately isn't distributing, or the node isn't asking.
		{"channel_off (budget)", orgcontract.BudgetFetchChannelOff, true},
		{"channel_off (pricing)", orgcontract.PricingFetchChannelOff, true},
		{"channel_off (intel)", IntelFetchChannelOff, true},
		{"not_supported (pricing)", orgcontract.PricingFetchNotSupported, true},
		{"not_supported (intel)", IntelFetchNotSupported, true},
		{"disabled (budget)", orgcontract.BudgetFetchDisabled, true},
		{"disabled (pricing)", orgcontract.PricingFetchDisabled, true},
		{"disabled (intel)", IntelFetchDisabled, true},
		{"no_budget (budget)", orgcontract.BudgetFetchNoBudget, true},
		{"no_pricing (pricing)", orgcontract.PricingFetchNoPricing, true},
		{"not_enrolled (budget)", orgcontract.BudgetFetchNotEnrolled, true},
		{"not_enrolled (intel)", IntelFetchNotEnrolled, true},

		// Genuine problems — must stay at WARN.
		{"unverified (budget) — signature failure, security-relevant", orgcontract.BudgetFetchUnverified, false},
		{"unverified (pricing) — signature failure, security-relevant", orgcontract.PricingFetchUnverified, false},
		{"auth_failed (budget)", orgcontract.BudgetFetchAuthFailed, false},
		{"auth_failed (pricing)", orgcontract.PricingFetchAuthFailed, false},
		{"auth_failed (intel)", IntelFetchAuthFailed, false},
		{"unreachable (budget) — transient, but persistent-unreachable is worth surfacing", orgcontract.BudgetFetchUnreachable, false},
		{"unreachable (pricing)", orgcontract.PricingFetchUnreachable, false},
		{"unreachable (intel)", IntelFetchUnreachable, false},
		{"malformed (intel) — a 200 that didn't decode is a real bug", IntelFetchMalformed, false},
		{"ok (budget) — success is not an error path at all", orgcontract.BudgetFetchOK, false},
		{"verified (pricing) — success", orgcontract.PricingFetchVerified, false},
		{"ok (intel) — success", IntelFetchOK, false},
		{"unknown/empty state defaults to non-benign", "", false},
		{"garbage state defaults to non-benign", "totally-made-up", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := benignRailFetchState(tt.state); got != tt.want {
				t.Errorf("benignRailFetchState(%q) = %v, want %v", tt.state, got, tt.want)
			}
		})
	}
}

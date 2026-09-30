package pricewire

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

func rate(v float64) *float64 { return &v }
func thr(v int64) *int64      { return &v }

// TestPresenceRules is one case per presence rule the projection carries: a
// nil rate is not quoted, a set 0 is quoted free, and the two rails read an
// absent threshold / peak in opposite ways.
func TestPresenceRules(t *testing.T) {
	unquotedThreshold := orgcontract.PricingPolicyRow{Model: "m"}
	unquotedThreshold.SetOrgThreshold(nil)
	cases := []struct {
		name         string
		row          orgcontract.PricingPolicyRow
		org          bool
		inputSet     bool
		input        float64
		outputSet    bool
		thresholdSet bool
		threshold    int64
		peakSet      bool
	}{
		{"org: nil rate is not quoted, absent threshold and peak are quoted flat", orgcontract.PricingPolicyRow{Model: "m"}, true, false, 0, false, true, 0, true},
		{"org: a set zero is a negotiated free rate", orgcontract.PricingPolicyRow{Model: "m", InputPerMTok: rate(0)}, true, true, 0, false, true, 0, true},
		{"org: the unquoted marker keeps the seed's threshold", unquotedThreshold, true, false, 0, false, false, 0, true},
		{"org: a stated threshold is quoted", orgcontract.PricingPolicyRow{Model: "m", OutputPerMTok: rate(5), LongContextThreshold: thr(200000)}, true, false, 0, true, true, 200000, true},
		{"feed: absent threshold and peak are not quoted", orgcontract.PricingPolicyRow{Model: "m", InputPerMTok: rate(3)}, false, true, 3, false, false, 0, false},
		{"feed: a stated zero threshold is quoted", orgcontract.PricingPolicyRow{Model: "m", LongContextThreshold: thr(0)}, false, false, 0, false, true, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			project := FeedPriceRows
			if tc.org {
				project = OrgPriceRows
			}
			out := project([]orgcontract.PricingPolicyRow{tc.row})
			if len(out) != 1 {
				t.Fatalf("rows = %d", len(out))
			}
			p := out[0]
			if p.Set.Input != tc.inputSet || p.Input != tc.input {
				t.Errorf("input = %v set=%v, want %v set=%v", p.Input, p.Set.Input, tc.input, tc.inputSet)
			}
			if p.Set.Output != tc.outputSet {
				t.Errorf("output set=%v, want %v", p.Set.Output, tc.outputSet)
			}
			if p.Set.LongContextThreshold != tc.thresholdSet || p.LongContextThreshold != tc.threshold {
				t.Errorf("threshold = %d set=%v, want %d set=%v", p.LongContextThreshold, p.Set.LongContextThreshold, tc.threshold, tc.thresholdSet)
			}
			if p.Set.Peak != tc.peakSet {
				t.Errorf("peak set=%v, want %v", p.Set.Peak, tc.peakSet)
			}
		})
	}
}

// TestOrgHistoryProjected: a model with a dated history carries every period,
// each through the same rule; a single-row history is not a timeline.
func TestOrgHistoryProjected(t *testing.T) {
	row := orgcontract.PricingPolicyRow{
		Model: "m", InputPerMTok: rate(3), EffectiveFrom: "2026-09-16",
		History: []orgcontract.PricingPolicyRow{
			{Model: "m", InputPerMTok: rate(1)},
			{Model: "m", InputPerMTok: rate(3), EffectiveFrom: "2026-09-16"},
		},
	}
	out := OrgPriceRows([]orgcontract.PricingPolicyRow{row})
	if len(out[0].History) != 2 || out[0].History[0].Input != 1 || out[0].History[1].EffectiveFrom != "2026-09-16" {
		t.Fatalf("history = %+v", out[0].History)
	}
	row.History = row.History[:1]
	if got := OrgPriceRows([]orgcontract.PricingPolicyRow{row}); got[0].History != nil {
		t.Fatalf("a one-period history must not project a timeline: %+v", got[0].History)
	}
}

func TestPeakRatesToCostNil(t *testing.T) {
	if PeakRatesToCost(nil) != nil {
		t.Fatal("nil in must be nil out")
	}
}

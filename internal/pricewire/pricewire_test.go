package pricewire

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
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

// TestExtendedRatesProjected: both rails carry the extended dimensions and the
// fast multiplier with the plain presence rule, rounded to the 1e-10 grid, so
// an enrolled node takes its fast premium from the org rail.
func TestExtendedRatesProjected(t *testing.T) {
	row := orgcontract.PricingPolicyRow{
		Model: "m", InputPerMTok: rate(1), OutputPerMTok: rate(2),
		ReasoningPerMTok: rate(0.1 + 0.2), RequestFeeUSD: rate(0), FastMultiplier: rate(2.5),
		ImageOutputPerImage: rate(0.04),
	}
	for name, project := range map[string]func([]orgcontract.PricingPolicyRow) []cost.OrgPrice{
		"org": OrgPriceRows, "feed": FeedPriceRows,
	} {
		p := project([]orgcontract.PricingPolicyRow{row})[0]
		switch {
		case !p.Set.Reasoning || p.Reasoning != 0.3:
			t.Errorf("%s: reasoning = %v set=%v, want rounded 0.3", name, p.Reasoning, p.Set.Reasoning)
		case !p.Set.RequestFee || p.RequestFee != 0:
			t.Errorf("%s: a quoted-free request fee lost its presence", name)
		case !p.Set.FastMultiplier || p.FastMultiplier != 2.5:
			t.Errorf("%s: fast multiplier = %v set=%v, want 2.5", name, p.FastMultiplier, p.Set.FastMultiplier)
		case !p.Set.ImageOutputPerImage || p.ImageOutputPerImage != 0.04:
			t.Errorf("%s: image output = %v", name, p.ImageOutputPerImage)
		case p.Set.AudioInput || p.Set.CacheCreationOther:
			t.Errorf("%s: an unquoted dimension was marked quoted", name)
		}
	}
}

// TestOrgRailFastMultiplierReachesTheEngine: an enrolled node's fast premium
// comes from the org rail's fast_multiplier, overriding the seed's, through
// the real engine rebuild (the 2026-09-30 operator ruling).
func TestOrgRailFastMultiplierReachesTheEngine(t *testing.T) {
	e := cost.NewEngine(config.IntelligenceConfig{})
	const model = "zz-chain-fast"
	e.SetOrgRows(OrgPriceRows([]orgcontract.PricingPolicyRow{{
		Model: model, InputPerMTok: rate(1), OutputPerMTok: rate(2), FastMultiplier: rate(3),
	}}), 1, true, "binding")
	p, ok := e.Lookup(model)
	if !ok || p.FastMultiplier != 3 {
		t.Fatalf("lookup = %+v ok=%v, want the org rail's fast multiplier 3", p, ok)
	}
	b, _ := e.ComputeBreakdown(model, cost.TokenBundle{Input: 1_000_000, Fast: true})
	if b.InputCost != 3 {
		t.Fatalf("fast input cost = %v, want 1 x 3", b.InputCost)
	}
}

package cost

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// Synthetic ids + rates so the test never depends on (or restates) a real
// vendor price; every real rate comes from the Tokenomics-fed table.
const (
	synthTierBase    = "synth-tiered-model"
	synthTierPriced  = "synth-tiered-model-ultrafast"
	synthTierNoSKU   = "synth-untiered-model"
	synthTierDatedID = "synth-tiered-model-20260930"
)

func synthTierEngine() *Engine {
	return NewEngine(config.IntelligenceConfig{Pricing: config.PricingConfig{Models: map[string]config.ModelPricing{
		synthTierBase:   {Input: 1, Output: 2, CacheRead: 0.1, FastMultiplier: 2},
		synthTierPriced: {Input: 6, Output: 12, CacheRead: 0.6},
		synthTierNoSKU:  {Input: 1, Output: 2, CacheRead: 0.1, FastMultiplier: 2},
	}}})
}

func TestServiceTierModel(t *testing.T) {
	has := func(k string) bool { return k == synthTierPriced }
	cases := []struct {
		name, model, tier string
		wantID            string
		wantRes           TierResolution
	}{
		{"empty tier", synthTierBase, "", synthTierBase, TierNone},
		{"default tier", synthTierBase, "default", synthTierBase, TierNone},
		{"priority is Fast, not a SKU", synthTierBase, "priority", synthTierBase, TierNone},
		{"unknown tier", synthTierBase, "hyperdrive", synthTierBase, TierNone},
		{"ultrafast priced", synthTierBase, "ultrafast", synthTierPriced, TierOwnSKU},
		{"ultrafast case-insensitive", synthTierBase, "UltraFast", synthTierPriced, TierOwnSKU},
		{"ultrafast dated served id", synthTierDatedID, "ultrafast", synthTierPriced, TierOwnSKU},
		{"ultrafast unpriced", synthTierNoSKU, "ultrafast", synthTierNoSKU, TierUnpriced},
		{"already the SKU", synthTierPriced, "ultrafast", synthTierPriced, TierNone},
		{"empty model", "", "ultrafast", "", TierNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, res := ServiceTierModel(tc.model, tc.tier, has)
			if id != tc.wantID || res != tc.wantRes {
				t.Fatalf("ServiceTierModel(%q,%q) = (%q,%d), want (%q,%d)", tc.model, tc.tier, id, res, tc.wantID, tc.wantRes)
			}
		})
	}
}

// TestEngineResolveServiceTier_Pricing pins the end-to-end billing rule the
// proxy's cost adapter applies: priority keeps the FastMultiplier, an
// Ultrafast turn with a priced SKU bills that SKU's absolute rates (and never
// the multiplier on top), an unpriced Ultrafast turn falls back to the
// standard rate WITH a warning, and an unknown tier is standard.
func TestEngineResolveServiceTier_Pricing(t *testing.T) {
	tokens := TokenBundle{Input: 1_000_000, Output: 1_000_000}
	cases := []struct {
		name, model, tier string
		fast              bool
		wantUSD           float64
		wantWarn          bool
	}{
		{"priority -> fast multiplier", synthTierBase, "priority", true, 6, false},
		{"ultrafast priced -> own SKU", synthTierBase, "ultrafast", false, 18, false},
		{"ultrafast unpriced -> standard + warning", synthTierNoSKU, "ultrafast", false, 3, true},
		{"unknown tier -> standard", synthTierBase, "hyperdrive", false, 3, false},
		{"no tier -> standard", synthTierBase, "", false, 3, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := synthTierEngine()
			model, _ := e.ResolveServiceTier(tc.model, tc.tier)
			b := tokens
			b.Fast = tc.fast
			usd, ok := e.Compute(model, b)
			if !ok {
				t.Fatalf("Compute(%q) not ok", model)
			}
			if usd != tc.wantUSD {
				t.Fatalf("cost = %v, want %v (priced as %q)", usd, tc.wantUSD, model)
			}
			var warned bool
			for _, w := range e.PricingWarnings() {
				if strings.Contains(w, tc.model) && strings.Contains(w, "ultrafast") {
					warned = true
				}
			}
			if warned != tc.wantWarn {
				t.Fatalf("warning present = %v, want %v (warnings %q)", warned, tc.wantWarn, e.PricingWarnings())
			}
		})
	}
}

// TestEngineResolveServiceTier_NoFamilyFallback pins that the SKU check is
// exact: `<model>-ultrafast` family-matches `<model>` on the lookup ladder,
// which would pass the standard rate off as the tier's.
func TestEngineResolveServiceTier_NoFamilyFallback(t *testing.T) {
	e := synthTierEngine()
	if _, ok := e.Lookup(synthTierNoSKU + "-ultrafast"); !ok {
		t.Skip("family ladder no longer matches the suffixed id; the guard is moot")
	}
	if _, res := e.ResolveServiceTier(synthTierNoSKU, "ultrafast"); res != TierUnpriced {
		t.Fatalf("res = %d, want TierUnpriced", res)
	}
}

func TestTierGapSetBounded(t *testing.T) {
	var g tierGapSet
	for i := 0; i < maxTierGaps+10; i++ {
		g.note(strings.Repeat("m", i+1), "ultrafast")
	}
	g.note("m", "ultrafast") // duplicate
	if n := len(g.warnings()); n != maxTierGaps {
		t.Fatalf("warnings = %d, want %d", n, maxTierGaps)
	}
}

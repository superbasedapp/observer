package main

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/proxy"
)

// TestCostEngineAdapter_ServiceTier pins the proxy's cost seam: an
// Ultrafast-served turn is priced under `<model>-ultrafast` when the table
// has it, and at the model's own standard rate (never the Fast 2x) when it
// does not. Synthetic ids/rates: real prices come from Tokenomics.
func TestCostEngineAdapter_ServiceTier(t *testing.T) {
	e := cost.NewEngine(config.IntelligenceConfig{Pricing: config.PricingConfig{Models: map[string]config.ModelPricing{
		"synth-adapter-model":           {Input: 1, Output: 2, FastMultiplier: 2},
		"synth-adapter-model-ultrafast": {Input: 6, Output: 12},
		"synth-adapter-plain":           {Input: 1, Output: 2, FastMultiplier: 2},
	}}})
	a := costEngineAdapter{e: e}
	for _, tc := range []struct {
		name, model, tier string
		fast              bool
		want              float64
	}{
		{"priority fast", "synth-adapter-model", "priority", true, 6},
		{"ultrafast priced", "synth-adapter-model", "ultrafast", false, 18},
		{"ultrafast unpriced falls back to standard", "synth-adapter-plain", "ultrafast", false, 3},
		{"unknown tier standard", "synth-adapter-model", "hyperdrive", false, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := a.Compute(tc.model, proxy.CostTokens{Input: 1_000_000, Output: 1_000_000, Fast: tc.fast, ServiceTier: tc.tier})
			if !ok || got != tc.want {
				t.Fatalf("Compute = (%v, %v), want (%v, true)", got, ok, tc.want)
			}
		})
	}
}

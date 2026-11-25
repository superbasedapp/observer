package cost

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/routingcore"
)

// TestRoutingPriceFn pins the routing adapter to Compute: every PromptUsage
// field lands on the same TokenBundle field, and a nil engine yields a nil
// PriceFn so callers keep their default pricing.
func TestRoutingPriceFn(t *testing.T) {
	var nilEngine *Engine
	if nilEngine.RoutingPriceFn() != nil {
		t.Fatal("nil engine: RoutingPriceFn() != nil")
	}

	e := NewEngine(config.IntelligenceConfig{})
	price := e.RoutingPriceFn()
	if price == nil {
		t.Fatal("RoutingPriceFn() = nil for a live engine")
	}
	u := routingcore.PromptUsage{
		Input: 1000, Output: 2000, CacheRead: 3000, CacheCreation: 4000,
		CacheCreation1h: 5000, Reasoning: 600, WebSearchRequests: 2, Fast: true,
	}
	b := TokenBundle{
		Input: 1000, Output: 2000, CacheRead: 3000, CacheCreation: 4000,
		CacheCreation1h: 5000, Reasoning: 600, WebSearchRequests: 2, Fast: true,
	}
	for _, model := range []string{"claude-opus-4-8", "gpt-5.6-sol", "no-such-model-xyz"} {
		gotUSD, gotOK := price(model, u)
		wantUSD, wantOK := e.Compute(model, b)
		if gotUSD != wantUSD || gotOK != wantOK {
			t.Errorf("%s: RoutingPriceFn = (%v, %v), Compute = (%v, %v)", model, gotUSD, gotOK, wantUSD, wantOK)
		}
	}
}

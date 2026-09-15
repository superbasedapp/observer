package cost

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
)

func TestNewEngine_MergesConfigOverrides(t *testing.T) {
	cfg := config.IntelligenceConfig{
		Pricing: config.PricingConfig{Models: map[string]config.ModelPricing{
			"claude-sonnet-4-20250514": {Input: 100, Output: 200, CacheRead: 10, CacheCreation: 50},
			"my-local-llm":             {Input: 0, Output: 0},
		}},
	}
	e := NewEngine(cfg)

	// Override takes effect.
	p, ok := e.Lookup("claude-sonnet-4-20250514")
	if !ok || p.Input != 100 || p.Output != 200 {
		t.Errorf("override not applied: %+v ok=%v", p, ok)
	}

	// Baked-in entries that weren't overridden remain.
	if _, ok := e.Lookup("claude-opus-4-20250514"); !ok {
		t.Errorf("baked-in opus missing after merge")
	}

	// Zero-only entry is present but Compute returns (0, true) — the model
	// was registered, just at zero cost (some users run local models free
	// of charge).
	cost, ok := e.Compute("my-local-llm", TokenBundle{Input: 1000, Output: 1000})
	if !ok {
		t.Errorf("my-local-llm lookup should succeed")
	}
	if cost != 0 {
		t.Errorf("expected zero cost, got %v", cost)
	}
}

func TestEngine_Compute_UnknownModel(t *testing.T) {
	e := NewEngine(config.IntelligenceConfig{})
	if _, ok := e.Compute("definitely-fake-model-99", TokenBundle{Input: 1000}); ok {
		t.Errorf("unknown model should return ok=false")
	}
}

// TestEngine_CursorGrokAliasCost pins the live Cursor hook model shape
// (cursor-grok-4.6-medium). The alias must produce a known, non-zero cost
// from representative token counts, retain Cursor's standard cache card
// without direct-xAI long-context pricing, and still obey ordinary exact-
// override precedence for that captured id.
func TestEngine_CursorGrokAliasCost(t *testing.T) {
	e := NewEngine(config.IntelligenceConfig{})
	b := TokenBundle{Input: 12_000, Output: 400, CacheRead: 50_000}
	cost, ok := e.Compute("cursor-grok-4.6-medium", b)
	if !ok {
		t.Fatal("cursor-grok-4.6-medium should be priced")
	}
	const want = 0.0514 // 12000*2 + 400*6 + 50000*0.5, per 1M tokens
	if diff := cost - want; diff > 1e-12 || diff < -1e-12 {
		t.Fatalf("cost=%0.9f want %0.9f", cost, want)
	}

	p, src, ok := e.LookupWithSource("cursor-grok-4.6-medium")
	if !ok || src != PricingSourceExact {
		t.Fatalf("lookup = (%+v, %q, %v), want exact hit", p, src, ok)
	}
	if p.CacheRead != 0.50 || p.LongContextThreshold != 0 {
		t.Fatalf("Cursor standard Grok card lost through alias: %+v", p)
	}
	longCost, ok := e.Compute("cursor-grok-4.6-medium", TokenBundle{Input: 200_001})
	if !ok {
		t.Fatalf("long-context lookup ok=%v want true", ok)
	}
	if diff := longCost - 0.400002; diff > 1e-12 || diff < -1e-12 {
		t.Fatalf("long-context cost=%0.9f ok=%v want 0.400002", longCost, ok)
	}

	override := config.IntelligenceConfig{
		Pricing: config.PricingConfig{Models: map[string]config.ModelPricing{
			"cursor-grok-4.6-medium": {Input: 9, Output: 10, CacheRead: 1},
		}},
	}
	oe := NewEngine(override)
	op, osrc, ook := oe.LookupWithSource("cursor-grok-4.6-medium")
	// A node-config override is provenance PricingSourceLocal ("a developer
	// typed this"), distinct from a shipped PricingSourceExact table hit —
	// see sourceFor / orgprice_test.go.
	if !ook || osrc != PricingSourceLocal || op.Input != 9 || op.Output != 10 || op.CacheRead != 1 {
		t.Fatalf("Cursor override = (%+v, %q, %v), want 9/10/1 local", op, osrc, ook)
	}
}

func TestTokenBundle_Add(t *testing.T) {
	a := TokenBundle{Input: 1, Output: 2, CacheRead: 3, CacheCreation: 4, CacheCreation1h: 1}
	b := TokenBundle{Input: 10, Output: 20, CacheRead: 30, CacheCreation: 40, CacheCreation1h: 5}
	a.Add(b)
	if a.Input != 11 || a.Output != 22 || a.CacheRead != 33 || a.CacheCreation != 44 || a.CacheCreation1h != 6 {
		t.Errorf("Add wrong: %+v", a)
	}
}

// TestCompute_CacheCreationTierSplit verifies that the 1h ephemeral
// subset of cache_creation is billed at the 1h rate and the remainder at
// the 5m rate. Anthropic prices 1h-tier at 2× the 5m rate; the engine
// must apply both bands and never charge the 1h portion at the cheaper
// 5m rate.
func TestCompute_CacheCreationTierSplit(t *testing.T) {
	p := Pricing{
		Input:           3,
		Output:          15,
		CacheRead:       0.30,
		CacheCreation:   3.75,
		CacheCreation1h: 7.50, // 2 × 5m rate, mirroring Anthropic public pricing
	}
	// 1M total cache_creation tokens; 400k of them landed in 1h tier.
	// 5m portion = 600k × 3.75 / 1M = 2.25
	// 1h portion = 400k × 7.50 / 1M = 3.00
	// Expected total = 5.25
	got := Compute(p, TokenBundle{
		CacheCreation:   1_000_000,
		CacheCreation1h: 400_000,
	})
	want := 5.25
	if diff := got - want; diff > 1e-9 || diff < -1e-9 {
		t.Errorf("Compute tier split: got %v want %v", got, want)
	}

	// Pre-tier-aware data has CacheCreation1h=0 → entirely 5m rate.
	got = Compute(p, TokenBundle{CacheCreation: 1_000_000})
	want = 3.75
	if diff := got - want; diff > 1e-9 || diff < -1e-9 {
		t.Errorf("Compute pre-tier (no 1h): got %v want %v", got, want)
	}
}

// TestCompute_CacheCreation1hClamps guards against malformed input where
// the 1h portion exceeds the total — the engine clamps rather than
// double-counting.
func TestCompute_CacheCreation1hClamps(t *testing.T) {
	p := Pricing{Input: 3, Output: 15, CacheCreation: 3.75, CacheCreation1h: 7.50}
	// 1h > total: clamp 1h down to the total, 5m portion becomes 0.
	got := Compute(p, TokenBundle{CacheCreation: 100_000, CacheCreation1h: 500_000})
	// Expected: 100k × 7.50 / 1M = 0.75 (entire bundle billed at 1h rate).
	want := 0.75
	if diff := got - want; diff > 1e-9 || diff < -1e-9 {
		t.Errorf("Compute clamp: got %v want %v", got, want)
	}

	// Negative 1h: treat as zero (defensive).
	got = Compute(p, TokenBundle{CacheCreation: 100_000, CacheCreation1h: -50_000})
	want = 0.375 // entire bundle at 5m rate
	if diff := got - want; diff > 1e-9 || diff < -1e-9 {
		t.Errorf("Compute negative 1h: got %v want %v", got, want)
	}
}

// TestCompute_WebSearchPerRequest pins the per-request server-tool fee:
// Anthropic bills $10/1000 web_search invocations on top of token costs.
// The engine must multiply web_search_requests by Pricing.WebSearchPerRequest
// directly (no /1M-tokens scaling — these are flat per-call fees), and the
// charge must NOT be affected by long-context tier dispatch (LC repricing
// only applies to token rates).
func TestCompute_WebSearchPerRequest(t *testing.T) {
	p := Pricing{
		Input:               3,
		Output:              15,
		CacheRead:           0.30,
		CacheCreation:       3.75,
		WebSearchPerRequest: 0.01, // $10 / 1000 = $0.01 per call
	}
	// 5 web searches with zero tokens: cost = 5 × $0.01 = $0.05
	got := Compute(p, TokenBundle{WebSearchRequests: 5})
	want := 0.05
	if diff := got - want; diff > 1e-9 || diff < -1e-9 {
		t.Errorf("Compute web_search only: got %v want %v", got, want)
	}
	// Combined with token costs.
	got = Compute(p, TokenBundle{
		Input:             100,
		Output:            200,
		WebSearchRequests: 3,
	})
	// 100×3/1M + 200×15/1M + 3×0.01 = 0.0003 + 0.003 + 0.03 = 0.0333
	want = 0.0333
	if diff := got - want; diff > 1e-9 || diff < -1e-9 {
		t.Errorf("Compute web_search + tokens: got %v want %v", got, want)
	}
	// Zero rate (non-Anthropic / pre-field entry): web searches contribute
	// nothing, leaving token costs intact.
	p2 := Pricing{Input: 3, Output: 15}
	got = Compute(p2, TokenBundle{Input: 100, WebSearchRequests: 5})
	want = 0.0003
	if diff := got - want; diff > 1e-9 || diff < -1e-9 {
		t.Errorf("Compute zero web_search rate: got %v want %v", got, want)
	}
}

// TestComputeBreakdown_SplitsAIvsTool pins the v1.4.53 cost-split
// contract: ComputeBreakdown returns AICost (input/output/cache/
// reasoning) and ToolCost (web_search and future per-call fees)
// separately. Total = AICost + ToolCost. Dashboard surfaces all
// three so users can see how much of their spend is API tokens vs
// tool invocations — different optimization levers.
func TestComputeBreakdown_SplitsAIvsTool(t *testing.T) {
	p := Pricing{Input: 5, Output: 30, CacheRead: 0.50, WebSearchPerRequest: 0.01}
	// Session 019e2bb0 shape.
	b := TokenBundle{
		Input: 71135, Output: 2738, CacheRead: 14720,
		Reasoning: 1496, WebSearchRequests: 9,
	}
	got := ComputeBreakdown(p, b)
	wantAI := 71135*5/1e6 + 2738*30/1e6 + 14720*0.50/1e6 + 1496*30/1e6
	wantTool := 9 * 0.01
	if diff := got.AICost - wantAI; diff > 1e-9 || diff < -1e-9 {
		t.Errorf("AICost: got %v want %v", got.AICost, wantAI)
	}
	if diff := got.ToolCost - wantTool; diff > 1e-9 || diff < -1e-9 {
		t.Errorf("ToolCost: got %v want %v", got.ToolCost, wantTool)
	}
	if diff := got.Total - (wantAI + wantTool); diff > 1e-9 || diff < -1e-9 {
		t.Errorf("Total: got %v want %v", got.Total, wantAI+wantTool)
	}
	// Compute() returns the same Total (the wrapper invariant).
	if diff := Compute(p, b) - got.Total; diff > 1e-9 || diff < -1e-9 {
		t.Errorf("Compute(p,b)=%v != ComputeBreakdown.Total=%v", Compute(p, b), got.Total)
	}
	// Pure-token bundle: ToolCost is exactly zero, AICost == Total.
	tokenOnly := TokenBundle{Input: 1000, Output: 100}
	gotTO := ComputeBreakdown(p, tokenOnly)
	if gotTO.ToolCost != 0 {
		t.Errorf("token-only ToolCost: got %v want 0", gotTO.ToolCost)
	}
	if gotTO.AICost != gotTO.Total {
		t.Errorf("token-only AICost != Total: %v vs %v", gotTO.AICost, gotTO.Total)
	}
	// Pure-tool bundle: AICost is exactly zero, ToolCost == Total.
	toolOnly := TokenBundle{WebSearchRequests: 9}
	gotXTool := ComputeBreakdown(p, toolOnly)
	if gotXTool.AICost != 0 {
		t.Errorf("tool-only AICost: got %v want 0", gotXTool.AICost)
	}
	if diff := gotXTool.ToolCost - 0.09; diff > 1e-9 || diff < -1e-9 {
		t.Errorf("tool-only ToolCost: got %v want 0.09", gotXTool.ToolCost)
	}
}

// TestComputeBreakdown_PerBucketComponentsSumToAICost pins the v1.6.13
// per-bucket component contract: InputCost + OutputCost + CacheReadCost
// + CacheCreationCost == AICost on every reachable shape. Reasoning
// tokens are billed at the output rate and folded into OutputCost (not
// emitted as a separate ReasoningCost field) so the four buckets
// always cover the full AI bill.
func TestComputeBreakdown_PerBucketComponentsSumToAICost(t *testing.T) {
	cases := []struct {
		name string
		p    Pricing
		b    TokenBundle
	}{
		{
			name: "anthropic-shape with cache",
			p:    Pricing{Input: 5, Output: 30, CacheRead: 0.50, CacheCreation: 6.25, WebSearchPerRequest: 0.01},
			b:    TokenBundle{Input: 1000, Output: 200, CacheRead: 5000, CacheCreation: 1500, WebSearchRequests: 3},
		},
		{
			name: "openai-shape with reasoning",
			p:    Pricing{Input: 1.25, Output: 10, CacheRead: 0.125},
			b:    TokenBundle{Input: 10_000, Output: 500, CacheRead: 2_000, Reasoning: 800},
		},
		{
			name: "with 1h cache split",
			p:    Pricing{Input: 5, Output: 30, CacheRead: 0.50, CacheCreation: 6.25, CacheCreation1h: 12.50},
			b:    TokenBundle{Input: 100, Output: 50, CacheCreation: 2000, CacheCreation1h: 800},
		},
		{
			name: "zero bundle",
			p:    Pricing{Input: 5, Output: 30, CacheRead: 0.50, CacheCreation: 6.25},
			b:    TokenBundle{},
		},
		{
			name: "tool-only bundle",
			p:    Pricing{Input: 5, Output: 30, WebSearchPerRequest: 0.01},
			b:    TokenBundle{WebSearchRequests: 7},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ComputeBreakdown(tc.p, tc.b)
			sum := got.InputCost + got.OutputCost + got.CacheReadCost + got.CacheCreationCost
			if diff := sum - got.AICost; diff > 1e-9 || diff < -1e-9 {
				t.Errorf("bucket components sum %v != AICost %v (diff=%v)\n  in=%v out=%v cr=%v cc=%v",
					sum, got.AICost, diff,
					got.InputCost, got.OutputCost, got.CacheReadCost, got.CacheCreationCost)
			}
			// Each component must be non-negative.
			for _, p := range []struct {
				name string
				v    float64
			}{
				{"InputCost", got.InputCost},
				{"OutputCost", got.OutputCost},
				{"CacheReadCost", got.CacheReadCost},
				{"CacheCreationCost", got.CacheCreationCost},
			} {
				if p.v < 0 {
					t.Errorf("%s = %v, must be >= 0", p.name, p.v)
				}
			}
		})
	}
}

// TestComputeBreakdown_ReasoningFoldsIntoOutputCost pins that
// reasoning_tokens contribute to OutputCost (not a separate component)
// at the output rate. Verifies the four-bucket sum invariant continues
// to hold when a bundle has reasoning tokens, by comparing against
// (b without reasoning) + delta = b.Reasoning * Output rate.
func TestComputeBreakdown_ReasoningFoldsIntoOutputCost(t *testing.T) {
	p := Pricing{Input: 1.25, Output: 10, CacheRead: 0.125}
	base := TokenBundle{Input: 1000, Output: 500, CacheRead: 200}
	withReasoning := base
	withReasoning.Reasoning = 800
	baseB := ComputeBreakdown(p, base)
	withB := ComputeBreakdown(p, withReasoning)
	wantDelta := 800.0 * 10 / 1_000_000
	if diff := (withB.OutputCost - baseB.OutputCost) - wantDelta; diff > 1e-9 || diff < -1e-9 {
		t.Errorf("OutputCost delta from 800 reasoning tokens: got %v want %v",
			withB.OutputCost-baseB.OutputCost, wantDelta)
	}
	if withB.InputCost != baseB.InputCost {
		t.Errorf("reasoning tokens must not affect InputCost")
	}
	if withB.CacheReadCost != baseB.CacheReadCost {
		t.Errorf("reasoning tokens must not affect CacheReadCost")
	}
}

// TestCompute_ReasoningTokensBilledAtOutputRate pins v1.4.53 closure
// of the reasoning-tokens billing gap: OpenAI o-series / gpt-5
// `reasoning_output_tokens` and Anthropic extended-thinking output
// tokens are both billed at the model's output rate. Pre-fix the
// cost engine ignored TokenBundle.Reasoning entirely — every
// reasoning-capable session was under-billed by reasoning_tokens ×
// output_rate. This test pins reasoning × Output / 1M is added to
// the total, that LC-tier dispatch applies to reasoning too
// (reasoning is part of the model's output stream), and that
// non-zero reasoning with zero other tokens still produces cost.
func TestCompute_ReasoningTokensBilledAtOutputRate(t *testing.T) {
	p := Pricing{Input: 5, Output: 30, CacheRead: 0.50}
	// 1496 reasoning, no other tokens: cost = 1496 × $30/1M = $0.04488
	got := Compute(p, TokenBundle{Reasoning: 1496})
	want := 1496.0 * 30 / 1_000_000
	if diff := got - want; diff > 1e-9 || diff < -1e-9 {
		t.Errorf("Compute reasoning only: got %v want %v", got, want)
	}
	// Combined with full bundle (session 019e2bb0 shape).
	got = Compute(p, TokenBundle{
		Input: 71135, Output: 2738, CacheRead: 14720,
		Reasoning: 1496,
	})
	want = 71135*5/1_000_000.0 + 2738*30/1_000_000.0 +
		14720*0.50/1_000_000.0 + 1496*30/1_000_000.0
	if diff := got - want; diff > 1e-9 || diff < -1e-9 {
		t.Errorf("Compute reasoning + tokens: got %v want %v", got, want)
	}
	// LC-tier dispatch: reasoning prices at LongContextOutput when
	// the prompt window exceeds LongContextThreshold (reasoning is
	// output-stream by both providers' billing model).
	pLC := Pricing{
		Input: 5, Output: 30, CacheRead: 0.50,
		LongContextThreshold: 272_000,
		LongContextInput:     10, LongContextOutput: 60, LongContextCacheRead: 1,
	}
	got = Compute(pLC, TokenBundle{
		Input: 300_000, Reasoning: 1000,
	})
	// LC tier active (prompt 300k > 272k): reasoning × $60/1M = $0.06
	wantLC := 300_000*10/1_000_000.0 + 1000*60/1_000_000.0
	if diff := got - wantLC; diff > 1e-9 || diff < -1e-9 {
		t.Errorf("Compute LC-tier reasoning: got %v want %v", got, wantLC)
	}
}

// TestCompute_FastMultiplier_DoublesAITokenCost pins the v1.8.2
// fast-mode pricing premium. Anthropic Opus 4.8 with speed:"fast" on
// the Messages API is the same model id at 2× per-token rates ($10/$50
// vs $5/$25 for 2.5× throughput). The struct models this as a flat
// FastMultiplier on the Pricing entry; Compute multiplies the AI token
// cost when both b.Fast and p.FastMultiplier > 0.
//
// Pins three invariants:
//
//  1. Same tokens, b.Fast=false vs true on a model with FastMultiplier=2
//     → AI cost EXACTLY doubles.
//  2. b.Fast=true on a model with FastMultiplier=0 → unchanged (no
//     accidental scaling for models without a fast tier).
//  3. Web search fees are NOT multiplied (inference premium, not
//     server-tool premium).
//
// Tested against the baked-in claude-opus-4-8 row + a synthetic Pricing
// shape so neither test passes by virtue of the other.
func TestCompute_FastMultiplier_DoublesAITokenCost(t *testing.T) {
	// (1) Same tokens, Fast=true → AI cost doubles.
	tb := NewTable()
	p, ok := tb.Lookup("claude-opus-4-8")
	if !ok {
		t.Fatalf("claude-opus-4-8 missing")
	}
	if p.FastMultiplier != 2 {
		t.Fatalf("claude-opus-4-8 FastMultiplier=%v want 2", p.FastMultiplier)
	}
	bundle := TokenBundle{
		Input:         100_000,
		Output:        20_000,
		CacheRead:     50_000,
		CacheCreation: 10_000,
		Reasoning:     5_000,
	}
	standard := Compute(p, bundle)
	bundle.Fast = true
	fast := Compute(p, bundle)
	if diff := fast - 2*standard; diff > 1e-9 || diff < -1e-9 {
		t.Errorf("Fast cost %v should be exactly 2× standard %v (delta=%v)",
			fast, standard, diff)
	}

	// (2) Model without a fast tier (FastMultiplier=0) — Fast=true must
	// be a no-op. Pick claude-sonnet-4-6 (no fast mode published).
	pSonnet, _ := tb.Lookup("claude-sonnet-4-6")
	if pSonnet.FastMultiplier != 0 {
		t.Errorf("claude-sonnet-4-6 FastMultiplier=%v want 0 (no fast tier)",
			pSonnet.FastMultiplier)
	}
	std := Compute(pSonnet, TokenBundle{Input: 1000, Output: 1000})
	bundleFast := TokenBundle{Input: 1000, Output: 1000, Fast: true}
	fastResult := Compute(pSonnet, bundleFast)
	if std != fastResult {
		t.Errorf("Sonnet 4.6 Fast=true cost %v should equal standard cost %v (no fast tier)",
			fastResult, std)
	}

	// (3) Web search fees are NOT multiplied — Opus 4.8 carries
	// WebSearchPerRequest=0.01 + FastMultiplier=2. A bundle with both
	// tokens and web_search should see AI×2 but ToolCost unchanged.
	bSearch := TokenBundle{
		Input: 10_000, Output: 5_000,
		WebSearchRequests: 4,
		Fast:              true,
	}
	bSearchStd := bSearch
	bSearchStd.Fast = false
	cbStd := ComputeBreakdown(p, bSearchStd)
	cbFast := ComputeBreakdown(p, bSearch)
	// AI doubles.
	if diff := cbFast.AICost - 2*cbStd.AICost; diff > 1e-9 || diff < -1e-9 {
		t.Errorf("AICost fast/std ratio: %v vs %v want 2× (web_search isolation)",
			cbFast.AICost, cbStd.AICost)
	}
	// Tool stays flat.
	if cbFast.ToolCost != cbStd.ToolCost {
		t.Errorf("ToolCost fast=%v std=%v — should NOT scale with FastMultiplier",
			cbFast.ToolCost, cbStd.ToolCost)
	}
	// Per-bucket sum invariant holds in both cases.
	for _, cb := range []Breakdown{cbStd, cbFast} {
		sum := cb.InputCost + cb.OutputCost + cb.CacheReadCost + cb.CacheCreationCost
		if diff := sum - cb.AICost; diff > 1e-9 || diff < -1e-9 {
			t.Errorf("bucket sum %v != AICost %v under FastMultiplier", sum, cb.AICost)
		}
	}
}

// TestCompute_FastMultiplier_OpusFamilyDoesNotInherit pins that
// FastMultiplier lives on the explicit 4-8 entry only — the
// `claude-opus-4` family prefix does NOT carry it. Fast mode is 4.8+
// only and future Opus SKUs (4-9, ...) must opt in explicitly rather
// than silently inheriting the premium tier via family fallback.
func TestCompute_FastMultiplier_OpusFamilyDoesNotInherit(t *testing.T) {
	tb := NewTable()
	// Explicit 4-8 carries FastMultiplier=2.
	p48, _ := tb.Lookup("claude-opus-4-8")
	if p48.FastMultiplier != 2 {
		t.Errorf("4-8: %v want 2", p48.FastMultiplier)
	}
	// Family prefix carries FastMultiplier=0.
	pFam, _ := tb.Lookup("claude-opus-4")
	if pFam.FastMultiplier != 0 {
		t.Errorf("`claude-opus-4` family: FastMultiplier=%v want 0 (no inherit)",
			pFam.FastMultiplier)
	}
	// A hypothetical 4-9 falls through the family prefix → no fast tier
	// until explicitly added.
	pFuture, srcFuture, ok := tb.LookupWithSource("claude-opus-4-9")
	if !ok || srcFuture != PricingSourceFamily {
		t.Fatalf("4-9: ok=%v src=%q want family", ok, srcFuture)
	}
	if pFuture.FastMultiplier != 0 {
		t.Errorf("4-9 via family: FastMultiplier=%v want 0 (must opt in)",
			pFuture.FastMultiplier)
	}
}

// TestCompute_FastMultiplier_LCDispatchIntact verifies the fast
// multiplier composes correctly with the long-context tier dispatch.
// A uniform 2× across input/output/cache_read post-multiplies cleanly:
// 2× × LC = LC × 2 either way. Uses a synthetic Pricing entry with
// both an LC tier and FastMultiplier so the interaction is isolated
// from the live-pricing table.
func TestCompute_FastMultiplier_LCDispatchIntact(t *testing.T) {
	p := Pricing{
		Input: 3, Output: 15, CacheRead: 0.30,
		LongContextThreshold: 200_000,
		LongContextInput:     6, LongContextOutput: 22.50, LongContextCacheRead: 0.60,
		FastMultiplier: 2,
	}
	// Prompt window 250K → LC triggers.
	bundle := TokenBundle{Input: 100_000, Output: 50_000, CacheRead: 150_000}
	std := Compute(p, bundle)
	bundle.Fast = true
	fast := Compute(p, bundle)
	if diff := fast - 2*std; diff > 1e-9 || diff < -1e-9 {
		t.Errorf("LC+Fast: %v vs LC-only %v want exactly 2×", fast, std)
	}
	// Sanity: LC-only number is what we expect (100K*$6 + 50K*$22.50 + 150K*$0.60)
	wantLC := 0.60 + 1.125 + 0.09 // 1.815
	if diff := std - wantLC; diff > 1e-9 || diff < -1e-9 {
		t.Errorf("LC-only sanity: %v want %v", std, wantLC)
	}
}

// TestCompute_LCTier_BelowThreshold verifies that prompt windows under
// LongContextThreshold price at standard rates — the LC fields don't
// kick in until the threshold is exceeded.
func TestCompute_LCTier_BelowThreshold(t *testing.T) {
	p := Pricing{
		Input: 3, Output: 15, CacheRead: 0.30, CacheCreation: 3.75, CacheCreation1h: 6,
		LongContextThreshold:     200_000,
		LongContextInput:         6,
		LongContextOutput:        22.50,
		LongContextCacheRead:     0.60,
		LongContextCacheCreation: 7.50, LongContextCacheCreation1h: 12,
	}
	// 199_999 prompt — exactly at threshold (>=, not >). LC must NOT
	// kick in: standard rate 3 × 199_999 / 1M = 0.599997.
	got := Compute(p, TokenBundle{Input: 199_999})
	want := 199_999 * 3.0 / 1_000_000
	if diff := got - want; diff > 1e-9 || diff < -1e-9 {
		t.Errorf("at-threshold-minus-1: got %v want %v", got, want)
	}
	// Threshold equality: still standard rate (the boundary is strict >).
	got = Compute(p, TokenBundle{Input: 200_000})
	want = 200_000 * 3.0 / 1_000_000
	if diff := got - want; diff > 1e-9 || diff < -1e-9 {
		t.Errorf("at-threshold-exact: got %v want %v", got, want)
	}
}

// TestCompute_LCTier_AboveThreshold pins the dispatch behavior for a
// Sonnet 4 / 4.5 turn that clears the 200K threshold. Every dimension
// reprices at the LC rate, including the 1h cache-creation tier.
func TestCompute_LCTier_AboveThreshold(t *testing.T) {
	p := Pricing{
		Input: 3, Output: 15, CacheRead: 0.30, CacheCreation: 3.75, CacheCreation1h: 6,
		LongContextThreshold:     200_000,
		LongContextInput:         6,
		LongContextOutput:        22.50,
		LongContextCacheRead:     0.60,
		LongContextCacheCreation: 7.50, LongContextCacheCreation1h: 12,
	}
	// Prompt window = 100K + 50K + 100K = 250K → > 200K threshold.
	// LC pricing applies to every dimension:
	//   input        100K × $6     / 1M = 0.60
	//   output        50K × $22.50 / 1M = 1.125
	//   cache_read   200K × $0.60  / 1M = 0.12
	//   cc_5m         50K × $7.50  / 1M = 0.375  (100K total - 50K 1h)
	//   cc_1h         50K × $12    / 1M = 0.60
	// Total = 2.82
	got := Compute(p, TokenBundle{
		Input: 100_000, Output: 50_000,
		CacheRead: 200_000, CacheCreation: 100_000, CacheCreation1h: 50_000,
	})
	want := 2.82
	if diff := got - want; diff > 1e-9 || diff < -1e-9 {
		t.Errorf("LC rates above threshold: got %v want %v", got, want)
	}
}

// TestCompute_LCTier_ZeroFieldFallsBack verifies that when an LC override
// is left at zero on one dimension, that dimension uses the standard rate
// while other dimensions still get the LC override. Lets a Pricing entry
// pin only the rates that change at the LC tier (e.g. Sonnet's output
// goes 1.5× while every other dim goes 2×).
func TestCompute_LCTier_ZeroFieldFallsBack(t *testing.T) {
	// Hypothetical: only LC input overridden; output stays at standard $15.
	p := Pricing{
		Input: 3, Output: 15,
		LongContextThreshold: 200_000,
		LongContextInput:     6, // override input only
		// LongContextOutput intentionally zero → falls back to 15.
	}
	got := Compute(p, TokenBundle{Input: 300_000, Output: 100_000})
	// 300K × $6 + 100K × $15 = 1.80 + 1.50 = 3.30
	want := 3.30
	if diff := got - want; diff > 1e-9 || diff < -1e-9 {
		t.Errorf("LC partial override: got %v want %v", got, want)
	}
}

// TestCompute_LCTier_ThresholdZeroDisables guards that an entry without
// an LC threshold (the default for non-LC providers) never reprices,
// even at huge prompt sizes.
func TestCompute_LCTier_ThresholdZeroDisables(t *testing.T) {
	p := Pricing{Input: 3, Output: 15} // no LC fields set
	got := Compute(p, TokenBundle{Input: 10_000_000, Output: 1_000_000})
	want := 10_000_000*3.0/1_000_000 + 1_000_000*15.0/1_000_000 // 30 + 15 = 45
	if diff := got - want; diff > 1e-9 || diff < -1e-9 {
		t.Errorf("no LC threshold should never reprice: got %v want %v", got, want)
	}
}

// TestCompute_LCTier_PromptIncludesCacheRead verifies the threshold is
// compared against (Input + CacheRead + CacheCreation), not just Input.
// A turn where most of the prompt is cached must still trigger LC if
// the total prompt window crosses the threshold — that's how Anthropic
// and OpenAI bill the LC tier.
func TestCompute_LCTier_PromptIncludesCacheRead(t *testing.T) {
	p := Pricing{
		Input: 3, Output: 15, CacheRead: 0.30,
		LongContextThreshold: 200_000,
		LongContextInput:     6, LongContextOutput: 22.50, LongContextCacheRead: 0.60,
	}
	// Input alone = 50K (under threshold), but prompt window =
	// 50K + 200K cached = 250K → triggers LC.
	got := Compute(p, TokenBundle{Input: 50_000, Output: 10_000, CacheRead: 200_000})
	// LC: 50K × $6 + 10K × $22.50 + 200K × $0.60 / 1M
	//   = 0.30 + 0.225 + 0.12 = 0.645
	want := 0.645
	if diff := got - want; diff > 1e-9 || diff < -1e-9 {
		t.Errorf("LC by cached prompt window: got %v want %v", got, want)
	}
}

// TestTable_LongContextDefaults pins the LC entries baked into
// defaultPricing. When Anthropic / OpenAI / Google publish new LC
// rates or thresholds, update both this test and the matching
// docs/pricing-reference.md section.
func TestTable_LongContextDefaults(t *testing.T) {
	tb := NewTable()
	for _, tc := range []struct {
		model             string
		threshold         int64
		lcIn, lcOut, lcCR float64
		lcCC, lcCC1h      float64 // 0 if not applicable (non-Anthropic)
	}{
		{"claude-sonnet-4-5", 200_000, 6, 22.50, 0.60, 7.50, 12},
		{"claude-sonnet-4-20250514", 200_000, 6, 22.50, 0.60, 7.50, 12},
		{"claude-sonnet-4", 200_000, 6, 22.50, 0.60, 7.50, 12},
		// OpenAI gpt-5.x LC rule is 2× input, 1.5× output above 272K
		// (NOT 2×/2×). Gemini Pro variants likewise: 2× input, 1.5×
		// output above 200K. Pre-2026-05-19 these were 2×/2× across
		// the board, over-billing every LC turn by 33%.
		{"gpt-5.4", 272_000, 5, 22.50, 0.50, 0, 0},
		{"gpt-5.5", 272_000, 10, 45, 1, 0, 0},
		// Gemini's LC cache-write rates are DERIVED, not baked: Google
		// publishes no cache-write line (a write is an ordinary input
		// token), so cacheWriteRules fills LongContextCacheCreation
		// (+1h) from LongContextInput at lookup time. Expecting 0 here
		// would be expecting the pre-2026-09-03 $0 under-bill.
		{"gemini-2.5-pro", 200_000, 2.50, 15, 0.25, 2.50, 2.50},
		{"gemini-3.1-pro-preview", 200_000, 4, 18, 0.40, 4, 4},
	} {
		t.Run(tc.model, func(t *testing.T) {
			p, ok := tb.Lookup(tc.model)
			if !ok {
				t.Fatalf("Lookup(%q) returned ok=false", tc.model)
			}
			if p.LongContextThreshold != tc.threshold {
				t.Errorf("threshold: got %v want %v", p.LongContextThreshold, tc.threshold)
			}
			if p.LongContextInput != tc.lcIn {
				t.Errorf("lc_input: got %v want %v", p.LongContextInput, tc.lcIn)
			}
			if p.LongContextOutput != tc.lcOut {
				t.Errorf("lc_output: got %v want %v", p.LongContextOutput, tc.lcOut)
			}
			if p.LongContextCacheRead != tc.lcCR {
				t.Errorf("lc_cache_read: got %v want %v", p.LongContextCacheRead, tc.lcCR)
			}
			if p.LongContextCacheCreation != tc.lcCC {
				t.Errorf("lc_cache_creation: got %v want %v", p.LongContextCacheCreation, tc.lcCC)
			}
			if p.LongContextCacheCreation1h != tc.lcCC1h {
				t.Errorf("lc_cache_creation_1h: got %v want %v", p.LongContextCacheCreation1h, tc.lcCC1h)
			}
		})
	}

	// Sonnet 4.6 is flat-rate per the 2026-04-29 snapshot — no LC tier.
	p, _ := tb.Lookup("claude-sonnet-4-6")
	if p.LongContextThreshold != 0 {
		t.Errorf("sonnet-4-6 should be flat-rate, got threshold %v", p.LongContextThreshold)
	}
	// gpt-5.4-mini has no public LC numbers — flat-rate for now.
	p, _ = tb.Lookup("gpt-5.4-mini")
	if p.LongContextThreshold != 0 {
		t.Errorf("gpt-5.4-mini should be flat-rate, got threshold %v", p.LongContextThreshold)
	}
}

// TestCompute_LongContextOutputIs1p5xNot2x is a regression guard against
// the 2026-05-19 pricing audit's headline bug: pricing.go had OpenAI
// gpt-5.x and Gemini Pro LongContextOutput set to 2× the standard
// output rate, but the actual published rule is 2× input / **1.5×**
// output above the threshold. The bug over-billed every LC turn by
// 33% on the output side. Pinned end-to-end (table lookup → Compute)
// against real-corpus prompt shapes so a future table edit can't
// silently reintroduce the same 33% inflation.
func TestCompute_LongContextOutputIs1p5xNot2x(t *testing.T) {
	tb := NewTable()
	for _, tc := range []struct {
		model     string
		prompt    int64 // > model.LongContextThreshold
		output    int64
		wantLCOut float64 // the *output* rate that must be in effect (1.5× std)
	}{
		// OpenAI gpt-5.x: std $15/$30 → LC output $22.50/$45 (1.5×).
		{"gpt-5.4", 280_000, 1_000_000, 22.50},
		{"gpt-5.5", 280_000, 1_000_000, 45},
		// Gemini Pro: std $10/$12 → LC output $15/$18 (1.5×).
		{"gemini-2.5-pro", 250_000, 1_000_000, 15},
		{"gemini-3.1-pro-preview", 250_000, 1_000_000, 18},
		{"gemini-3.1-pro-high", 250_000, 1_000_000, 18},
		{"gemini-pro-agent", 250_000, 1_000_000, 18},
	} {
		t.Run(tc.model, func(t *testing.T) {
			p, ok := tb.Lookup(tc.model)
			if !ok {
				t.Fatalf("Lookup(%q) ok=false", tc.model)
			}
			// Sanity: the test inputs must actually cross the LC threshold.
			if tc.prompt <= p.LongContextThreshold {
				t.Fatalf("test prompt %v not above threshold %v",
					tc.prompt, p.LongContextThreshold)
			}
			// Output-only bundle so the assertion isolates the output rate.
			got := Compute(p, TokenBundle{Input: tc.prompt, Output: tc.output})
			wantOutput := float64(tc.output) * tc.wantLCOut / 1_000_000
			wantInput := float64(tc.prompt) * p.LongContextInput / 1_000_000
			want := wantInput + wantOutput
			if diff := got - want; diff > 1e-9 || diff < -1e-9 {
				t.Errorf("Compute(%q) at %dK prompt: got %v want %v (LC output rate should be 1.5× std = %v)",
					tc.model, tc.prompt/1000, got, want, tc.wantLCOut)
			}
		})
	}
}

// TestEngine_ReloadSwapsTable verifies the Settings-page hot-reload
// path: building a new IntelligenceConfig and calling Reload swaps the
// active pricing in place, in-flight callers see consistent rates, and
// previously-cached *Table snapshots stay safe to read.
func TestEngine_ReloadSwapsTable(t *testing.T) {
	e := NewEngine(config.IntelligenceConfig{})
	// Default pricing for sonnet 4.6 is $3 input.
	pBefore, ok := e.Lookup("claude-sonnet-4-6")
	if !ok || pBefore.Input != 3 {
		t.Fatalf("baseline lookup: got %+v ok=%v want input=3", pBefore, ok)
	}
	// Snapshot the pre-reload table — must remain valid for reads after
	// Reload because we use atomic.Pointer (immutable Tables).
	snap := e.Table()

	// Reload with an override.
	e.Reload(config.IntelligenceConfig{
		Pricing: config.PricingConfig{Models: map[string]config.ModelPricing{
			"claude-sonnet-4-6": {Input: 99, Output: 999},
		}},
	})
	pAfter, ok := e.Lookup("claude-sonnet-4-6")
	if !ok || pAfter.Input != 99 || pAfter.Output != 999 {
		t.Errorf("post-reload lookup: got %+v want input=99 output=999", pAfter)
	}
	// Pre-reload snapshot still works — atomic.Pointer guarantees reads
	// against the old *Table never tear, so a goroutine that grabbed
	// the table before Reload finishes its work without panicking.
	pSnap, ok := snap.Lookup("claude-sonnet-4-6")
	if !ok || pSnap.Input != 3 {
		t.Errorf("snapshot stale-read: got %+v ok=%v want input=3", pSnap, ok)
	}
}

// TestEngine_ReloadConcurrentSafe runs many concurrent Lookups against
// a Reload loop. Pure smoke test for the atomic.Pointer wiring; the -race
// flag (make test) is the actual guarantor.
func TestEngine_ReloadConcurrentSafe(t *testing.T) {
	e := NewEngine(config.IntelligenceConfig{})
	done := make(chan struct{})
	// Reader goroutines.
	for i := 0; i < 4; i++ {
		go func() {
			for {
				select {
				case <-done:
					return
				default:
					_, _ = e.Lookup("claude-sonnet-4-6")
					_, _ = e.Compute("claude-sonnet-4-6", TokenBundle{Input: 1000})
				}
			}
		}()
	}
	// Reload loop.
	for i := 0; i < 50; i++ {
		e.Reload(config.IntelligenceConfig{
			Pricing: config.PricingConfig{Models: map[string]config.ModelPricing{
				"claude-sonnet-4-6": {Input: float64(i % 5), Output: float64(i)},
			}},
		})
	}
	close(done)
}

// TestNewEngine_LCFieldsRoundTripFromConfig verifies that user overrides
// via config.toml carry the LC fields through to the engine — so an
// install can pin LC rates for SKUs we haven't baked in yet (or correct
// a baked-in rate that's gone stale).
func TestNewEngine_LCFieldsRoundTripFromConfig(t *testing.T) {
	cfg := config.IntelligenceConfig{
		Pricing: config.PricingConfig{Models: map[string]config.ModelPricing{
			"my-custom-llm": {
				Input: 1, Output: 5,
				LongContextThreshold:       300_000,
				LongContextInput:           2,
				LongContextOutput:          10,
				LongContextCacheRead:       0.20,
				LongContextCacheCreation:   2.50,
				LongContextCacheCreation1h: 4,
			},
		}},
	}
	e := NewEngine(cfg)
	p, ok := e.Lookup("my-custom-llm")
	if !ok {
		t.Fatalf("lookup failed")
	}
	if p.LongContextThreshold != 300_000 {
		t.Errorf("threshold not threaded through: %v", p.LongContextThreshold)
	}
	if p.LongContextInput != 2 || p.LongContextOutput != 10 ||
		p.LongContextCacheRead != 0.20 || p.LongContextCacheCreation != 2.50 ||
		p.LongContextCacheCreation1h != 4 {
		t.Errorf("LC overrides not threaded through: %+v", p)
	}
}

// TestFillDefaults_CacheCreation1h verifies the 2 × Input default for the
// 1h tier when the config leaves it blank — but ONLY when CacheCreation
// is explicit non-zero (signal: this entry is Anthropic-shape). For
// non-Anthropic entries (CacheCreation = 0) we don't speculatively
// derive a 1h rate. Pre-2026-04-29 the default was 2 × CacheCreation
// (= 2.5 × Input) and applied unconditionally to anything with Input >
// 0; that over-billed Anthropic 1h cache writes by 25% AND would have
// inflated non-Anthropic rows if a stray cache_creation_tokens leaked
// in. The fix: gate on CacheCreation > 0, use 2 × Input as the rate.
func TestFillDefaults_CacheCreation1h(t *testing.T) {
	// Anthropic-shape entry: explicit CacheCreation triggers the 1h default.
	p := fillDefaults(Pricing{Input: 3, Output: 15, CacheCreation: 3.75})
	if p.CacheCreation1h != 6 {
		t.Errorf("CacheCreation1h default wrong: got %v want 6 (2 × Input)", p.CacheCreation1h)
	}

	// Explicit override stays.
	p = fillDefaults(Pricing{Input: 3, Output: 15, CacheCreation: 3.75, CacheCreation1h: 1})
	if p.CacheCreation1h != 1 {
		t.Errorf("explicit CacheCreation1h overwritten: got %v", p.CacheCreation1h)
	}

	// Non-Anthropic shape (CacheCreation == 0): no default.
	p = fillDefaults(Pricing{Input: 3, Output: 15})
	if p.CacheCreation1h != 0 {
		t.Errorf("CacheCreation1h should stay 0 for non-Anthropic shape: got %v", p.CacheCreation1h)
	}

	// Without Input set, no default applies (we can't infer from CacheCreation
	// alone — the 1h:input ratio is the invariant, not 1h:cache_creation).
	p = fillDefaults(Pricing{CacheCreation: 3.75})
	if p.CacheCreation1h != 0 {
		t.Errorf("CacheCreation1h should be 0 without Input: got %v", p.CacheCreation1h)
	}
}

// TestComputeBreakdown_OpenAIShape_NoDoubleBill pins the v1.6.29
// audit fix: when an OpenAI-shape adapter (codex JSONL, proxy)
// correctly emits NET non-cached input (= gross_prompt - cached),
// the cost engine bills the cached portion ONLY at the cache_read
// rate, not at both rates simultaneously. Pre-fix, the codex
// adapter stored gross input and the engine double-billed the
// cached portion → ~3.4× overbill on short cached sessions
// (specifically session 019e5adb on 2026-05-24 showed $0.01136
// when correct value was ~$0.00339).
//
// This test pins the CONTRACT: TokenBundle.Input must be NET. If
// a future adapter regresses to storing gross input, the dashboard
// will silently overbill; that adapter's own tests should catch it,
// but this cost-engine test documents why the contract exists.
func TestComputeBreakdown_OpenAIShape_NoDoubleBill(t *testing.T) {
	// gpt-5.4-mini-style pricing (rough): $0.75/M input, $6/M output,
	// $0.075/M cache_read (10% of input). All rates expressed per 1M.
	p := Pricing{Input: 0.75, Output: 6, CacheRead: 0.075}

	// The session 019e5adb shape: 13923 gross prompt tokens, of which
	// 10624 hit cache. NET = 13923 - 10624 = 3299.
	const gross, cached = 13923, 10624
	const net = gross - cached
	bundle := TokenBundle{
		Input:     net, // adapter pre-subtracts cached (the contract!)
		Output:    17,
		CacheRead: cached,
		Reasoning: 10,
	}

	got := ComputeBreakdown(p, bundle)

	// Correct math: net at input rate + cached at cache_read rate +
	// output at output rate + reasoning at output rate.
	wantInput := float64(net) * 0.75 / 1e6     // 3299 * 0.00000075 = 0.00247425
	wantCache := float64(cached) * 0.075 / 1e6 // 10624 * 7.5e-8 = 0.0007968
	wantOutput := float64(17+10) * 6 / 1e6     // (17 output + 10 reasoning) * output rate
	wantTotal := wantInput + wantCache + wantOutput

	if diff := got.Total - wantTotal; diff > 1e-9 || diff < -1e-9 {
		t.Errorf("Total cost: got %v want %v (diff %v)", got.Total, wantTotal, diff)
	}

	// Anti-regression: the pre-fix wrong total would have been
	// gross*input_rate + cached*cache_rate + output stuff:
	wrongInputCost := float64(gross) * 0.75 / 1e6 // billed gross at input rate
	wrongTotal := wrongInputCost + wantCache + wantOutput
	if got.Total >= wrongTotal*0.99 {
		t.Errorf("Total %v is close to the pre-fix WRONG total %v — contract may have regressed", got.Total, wrongTotal)
	}
}

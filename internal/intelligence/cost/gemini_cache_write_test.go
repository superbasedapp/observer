package cost

import (
	"math"
	"testing"
)

const cwEps = 1e-9

// TestCacheWriteRule_TableDriven walks the per-provider cache-write
// fallback across the three shapes that matter:
//
//   - a Gemini row that leaves CacheCreation blank → writes bill at the
//     row's own Input rate (the 2026-09-03 fix; previously $0);
//   - an Anthropic row → untouched, its explicit 1.25 × input write rate
//     still governs;
//   - an OpenAI GPT-5.6 row carrying an explicit write rate → untouched.
//
// The assertion is on cost, not on the rate field, so it fails if either
// the fallback or ComputeBreakdown's cache-creation math regresses.
func TestCacheWriteRule_TableDriven(t *testing.T) {
	t.Parallel()
	tbl := NewTable()

	cases := []struct {
		name  string
		model string
		// wantCreationRate is the USD/1M rate the cache_creation bucket
		// must be billed at.
		wantCreationRate float64
		// wantDerived says whether that rate is expected to come from
		// the provider fallback (true) or from the row itself (false).
		wantDerived bool
	}{
		// Gemini: no CacheCreation on any row → derived from Input.
		{"gemini 3 pro effort SKU (antigravity)", "gemini-3-pro-high", 2, true},
		{"gemini pro agent alias", "gemini-pro-agent", 2, true},
		{"gemini 3.1 pro preview", "gemini-3.1-pro-preview", 2, true},
		{"gemini 3 flash", "gemini-3-flash-agent", 0.50, true},
		{"gemini 2.5 pro", "gemini-2.5-pro", 1.25, true},
		{"gemini 2.5 flash", "gemini-2.5-flash", 0.30, true},
		{"gemini 2.0 flash (deprecated row)", "gemini-2.0-flash", 0.10, true},
		// Family-prefix resolution goes through the same seam.
		{"unknown gemini SKU via family fallback", "gemini-3-pro-experimental", 2, true},
		// Anthropic: explicit write tier on the row, must not move.
		{"anthropic sonnet 4.5", "claude-sonnet-4-5", 0, false},
		// OpenAI 5.6: explicit write tier on the row, must not move.
		{"openai gpt-5.6-sol", "gpt-5.6-sol", 6.25, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, ok := tbl.Lookup(tc.model)
			if !ok {
				t.Fatalf("Lookup(%q) missed", tc.model)
			}
			want := tc.wantCreationRate
			if want == 0 && !tc.wantDerived {
				// Anthropic rows: resolve the expected rate from the row
				// itself rather than hardcoding a published number that
				// a future rate sync would have to chase.
				want = p.CacheCreation
				if want <= 0 {
					t.Fatalf("%s: expected an explicit CacheCreation rate on the row, got %v", tc.model, p.CacheCreation)
				}
				if want == p.Input {
					t.Fatalf("%s: row's write rate equals its input rate — this case can no longer distinguish the fallback", tc.model)
				}
			}
			if tc.wantDerived && p.CacheCreation != p.Input {
				t.Errorf("%s: CacheCreation = %v, want the row's Input rate %v (provider fallback)", tc.model, p.CacheCreation, p.Input)
			}

			// 10k cache-creation tokens, nothing else — isolates the bucket.
			// Kept well under every LongContextThreshold so the standard
			// rates apply.
			const writes = 10_000
			got := ComputeBreakdown(p, TokenBundle{CacheCreation: writes})
			wantCost := writes * want / 1_000_000
			if math.Abs(got.CacheCreationCost-wantCost) > cwEps {
				t.Errorf("%s: CacheCreationCost = %v, want %v (%v per 1M)", tc.model, got.CacheCreationCost, wantCost, want)
			}
			if math.Abs(got.AICost-got.CacheCreationCost) > cwEps {
				t.Errorf("%s: AICost = %v, want it to equal the cache-creation bucket %v", tc.model, got.AICost, got.CacheCreationCost)
			}
		})
	}
}

// TestCacheWriteRule_GeminiWriteWasPreviouslyFree is the regression pin
// for the finding itself: a Gemini turn shaped like a real Antigravity
// generation (small uncached suffix + large newly-written prefix) must
// no longer price the prefix at $0.
//
// Numbers are the grounded 2026-09-03 Antigravity capture: field 1
// (uncached suffix) ~1,071-1,318 tokens per generation, field 2 (cache
// write) 151,337 tokens across 10 generations.
func TestCacheWriteRule_GeminiWriteWasPreviouslyFree(t *testing.T) {
	t.Parallel()
	p, ok := NewTable().Lookup("gemini-3-pro-high")
	if !ok {
		t.Fatal("gemini-3-pro-high not in pricing table")
	}
	b := TokenBundle{Input: 1_318, CacheCreation: 15_134, Output: 900}
	got := ComputeBreakdown(p, b)

	if got.CacheCreationCost <= 0 {
		t.Fatalf("CacheCreationCost = %v, want > 0 — the field-2 prefix is being billed at $0 again", got.CacheCreationCost)
	}
	wantCreation := 15_134 * 2.0 / 1_000_000
	if math.Abs(got.CacheCreationCost-wantCreation) > cwEps {
		t.Errorf("CacheCreationCost = %v, want %v (input rate $2/1M)", got.CacheCreationCost, wantCreation)
	}
	// The written prefix dominates the turn — that is the whole point of
	// the finding, and the reason the $0 bug was material.
	if got.CacheCreationCost <= got.InputCost {
		t.Errorf("CacheCreationCost %v should dominate InputCost %v on a real Antigravity generation", got.CacheCreationCost, got.InputCost)
	}
	sum := got.InputCost + got.OutputCost + got.CacheReadCost + got.CacheCreationCost
	if math.Abs(sum-got.AICost) > cwEps {
		t.Errorf("bucket sum %v != AICost %v", sum, got.AICost)
	}
}

// TestCacheWriteRule_ExplicitRateWins proves the fallback is a fallback:
// a config.toml override that sets a Gemini cache-write rate explicitly
// is not clobbered by the Input-rate derivation.
func TestCacheWriteRule_ExplicitRateWins(t *testing.T) {
	t.Parallel()
	tbl := NewTable()
	tbl.Merge(map[string]Pricing{
		"gemini-2.5-pro": {Input: 1.25, Output: 10, CacheRead: 0.125, CacheCreation: 9.99},
	})
	p, ok := tbl.Lookup("gemini-2.5-pro")
	if !ok {
		t.Fatal("gemini-2.5-pro missing after Merge")
	}
	if p.CacheCreation != 9.99 {
		t.Errorf("CacheCreation = %v, want the explicit override 9.99", p.CacheCreation)
	}
}

// TestCacheWriteRule_GeminiLongContextTier pins the LC half of the rule:
// above the 200K threshold Google reprices the whole request, so the
// write must follow LongContextInput ($4/1M on the Pro line), not the
// standard $2.
func TestCacheWriteRule_GeminiLongContextTier(t *testing.T) {
	t.Parallel()
	p, ok := NewTable().Lookup("gemini-3-pro-high")
	if !ok {
		t.Fatal("gemini-3-pro-high not in pricing table")
	}
	if p.LongContextCacheCreation != p.LongContextInput {
		t.Errorf("LongContextCacheCreation = %v, want LongContextInput %v", p.LongContextCacheCreation, p.LongContextInput)
	}
	// 250K written prefix — crosses the 200K threshold on its own.
	const writes = 250_000
	got := ComputeBreakdown(p, TokenBundle{CacheCreation: writes})
	want := writes * 4.0 / 1_000_000
	if math.Abs(got.CacheCreationCost-want) > cwEps {
		t.Errorf("CacheCreationCost = %v, want %v (LC input rate $4/1M)", got.CacheCreationCost, want)
	}
}

// TestCacheWriteRule_NonGeminiFamiliesUnaffected sweeps the rest of the
// baked table: no row outside the ruled families may gain a
// cache-write rate it did not already carry. This is the blast-radius
// guard — the rule table must stay a Gemini-only change until another
// provider is grounded.
func TestCacheWriteRule_NonGeminiFamiliesUnaffected(t *testing.T) {
	t.Parallel()
	tbl := NewTable()
	for key, raw := range defaultPricing {
		if cacheWritePolicyFor(key) == cacheWriteAtInputRate {
			continue
		}
		got, ok := tbl.Lookup(key)
		if !ok {
			t.Fatalf("Lookup(%q) missed on a baked row", key)
		}
		if want := fillDefaults(raw); got.CacheCreation != want.CacheCreation ||
			got.CacheCreation1h != want.CacheCreation1h ||
			got.LongContextCacheCreation != want.LongContextCacheCreation ||
			got.LongContextCacheCreation1h != want.LongContextCacheCreation1h {
			t.Errorf("%s: cache-write rates changed: got %v/%v/%v/%v, want %v/%v/%v/%v",
				key,
				got.CacheCreation, got.CacheCreation1h, got.LongContextCacheCreation, got.LongContextCacheCreation1h,
				want.CacheCreation, want.CacheCreation1h, want.LongContextCacheCreation, want.LongContextCacheCreation1h)
		}
	}
}

// TestCacheWritePolicyFor pins key resolution, including the
// provider-path-segment form a config.toml override can take.
func TestCacheWritePolicyFor(t *testing.T) {
	t.Parallel()
	cases := []struct {
		key  string
		want cacheWritePolicy
	}{
		{"gemini-3-pro-high", cacheWriteAtInputRate},
		{"gemini-2.5-flash-lite", cacheWriteAtInputRate},
		{"Gemini-3", cacheWriteAtInputRate},
		{"google/gemini-2.5-pro", cacheWriteAtInputRate},
		{"openrouter/google/gemini-3-flash", cacheWriteAtInputRate},
		{"claude-sonnet-4-5", cacheWriteRowPriced},
		{"gpt-5.6-sol", cacheWriteRowPriced},
		{"grok-4.6", cacheWriteRowPriced},
		{"", cacheWriteRowPriced},
	}
	for _, tc := range cases {
		if got := cacheWritePolicyFor(tc.key); got != tc.want {
			t.Errorf("cacheWritePolicyFor(%q) = %v, want %v", tc.key, got, tc.want)
		}
	}
}

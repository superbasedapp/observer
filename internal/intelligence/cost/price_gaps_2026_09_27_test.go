package cost

import "testing"

// TestPriceGaps_2026_09_27 pins the rows added or corrected by the
// 2026-09-27 adapter-sweep pass (tracker item 13, lane R2-PRICING) AND the
// resolution each one gets. As in the 2026-09-23 refresh, every defect here
// was a resolution defect: a Flash-Lite id billed through a Pro or Flash
// family, a MiMo id that MISSed to $0.00, a Moonshot first-party id billed at
// the OpenRouter-era `kimi` family rate. Asserting the source catches a row
// that is shadowed and right only by coincidence.
//
// Sources (all fetched 2026-09-27):
//   - ai.google.dev/gemini-api/docs/pricing (Gemini Flash-Lite)
//   - mimo.mi.com/models/en-US/mimo-v2.6-flash and .../mimo-v2.6-pro
//   - platform.kimi.ai/docs/pricing/chat (Kimi K2.6 / K2.7 Code)
//   - cursor.com/docs/models (Composer 2.5 Fast cache read, Grok 4.7 on Cursor,
//     the claude-opus-5-5-fast id)
//   - platform.claude.com/docs/en/about-claude/pricing (Opus 5.5 fast card)
func TestPriceGaps_2026_09_27(t *testing.T) {
	t.Parallel()
	tb := NewTable()

	for _, tc := range []struct {
		name            string
		model           string
		in, cacheR, out float64
		lcThreshold     int64
		wantSource      PricingSource
	}{
		// Was gemini-3.1 PRO family ($2/$12 + 200K LC tier): ~8x over-bill.
		{"gemini 3.1 flash-lite GA id", "gemini-3.1-flash-lite", 0.25, 0.025, 1.50, 0, PricingSourceExact},
		{"gemini 3.1 flash-lite preview unchanged", "gemini-3.1-flash-lite-preview", 0.25, 0.025, 1.50, 0, PricingSourceExact},
		// Was gemini-3.5-flash family ($1.50/$9): 5x input over-bill.
		{"gemini 3.5 flash-lite", "gemini-3.5-flash-lite", 0.30, 0.03, 2.50, 0, PricingSourceExact},
		{"gemini 3.5 flash unchanged", "gemini-3.5-flash", 1.50, 0.15, 9, 0, PricingSourceExact},

		// Was a MISS. Cache hit is 2% of input - NOT the 10% default.
		{"mimo v2.6 flash", "mimo-v2.6-flash", 0.14, 0.0028, 0.28, 0, PricingSourceExact},
		{"mimo v2.6 pro", "mimo-v2.6-pro", 0.435, 0.0036, 0.87, 0, PricingSourceExact},
		// The OpenRouter-qualified spelling reaches the first-party row through
		// the last-resort provider-prefix strip.
		{"openrouter mimo spelling", "xiaomi/mimo-v2.6-flash", 0.14, 0.0028, 0.28, 0, PricingSourceFamily},

		// Were the `kimi` family ($0.684/$3.42/$0.144).
		{"kimi k2.6 first-party id", "kimi-k2.6", 0.95, 0.16, 4, 0, PricingSourceExact},
		{"kimi k2.7 code", "kimi-k2.7-code", 0.95, 0.19, 4, 0, PricingSourceExact},
		{"kimi k2.7 code highspeed", "kimi-k2.7-code-highspeed", 1.90, 0.38, 8, 0, PricingSourceExact},

		// Cursor's Opus 5.5 fast id: was the standard row by family prefix
		// (2x under-bill). Suffix-selected, so FastMultiplier is 0 (checked
		// below).
		{"cursor opus 5.5 fast id", "claude-opus-5-5-fast", 8, 0.40, 40, 0, PricingSourceExact},
		{"opus 5.5 unchanged", "claude-opus-5-5", 4, 0.20, 20, 0, PricingSourceExact},

		// Composer 2.5 Fast: cache read corrected $0.30 -> $0.50.
		{"composer 2.5 fast", "composer-2.5-fast", 3, 0.50, 15, 0, PricingSourceExact},
		{"composer 2.5 unchanged", "composer-2.5", 0.50, 0.20, 2.50, 0, PricingSourceExact},

		// Grok 4.7 on Cursor: family key only (no observed Cursor 4.7 wire id
		// yet); was a MISS. Carries Cursor's >256k 2x tier.
		{"cursor grok 4.7 effort id", "cursor-grok-4.7-high", 2, 0.50, 6, 256_000, PricingSourceFamily},
		{"cursor grok 4.6 unchanged", "cursor-grok-4.6-high", 2, 0.50, 6, 0, PricingSourceExact},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, src, ok := tb.LookupWithSource(tc.model)
			if !ok {
				t.Fatalf("Lookup(%q) returned ok=false - a MISS prices at $0.00 silently", tc.model)
			}
			if src != tc.wantSource {
				t.Errorf("source: got %q want %q - the rate may be right by coincidence", src, tc.wantSource)
			}
			if p.Input != tc.in || p.Output != tc.out || p.CacheRead != tc.cacheR {
				t.Errorf("rates: got in=%v cr=%v out=%v, want in=%v cr=%v out=%v",
					p.Input, p.CacheRead, p.Output, tc.in, tc.cacheR, tc.out)
			}
			if p.LongContextThreshold != tc.lcThreshold {
				t.Errorf("long_context_threshold: got %d want %d", p.LongContextThreshold, tc.lcThreshold)
			}
		})
	}

	if p, _, _ := tb.LookupWithSource("claude-opus-5-5-fast"); p.FastMultiplier != 0 || p.CacheCreation != 10 || p.CacheCreation1h != 16 {
		t.Errorf("claude-opus-5-5-fast = fast %v write %v/%v, want fast 0 (suffix-selected, never doubled) and writes 10/16",
			p.FastMultiplier, p.CacheCreation, p.CacheCreation1h)
	}
	// Cursor Grok 4.7's >256k tier is exactly 2x every dimension.
	if p, _, _ := tb.LookupWithSource("cursor-grok-4.7"); p.LongContextInput != 4 || p.LongContextOutput != 12 || p.LongContextCacheRead != 1 {
		t.Errorf("cursor-grok-4.7 LC tier = in %v out %v cr %v, want 4/12/1", p.LongContextInput, p.LongContextOutput, p.LongContextCacheRead)
	}
}

// TestPriceGaps_2026_09_27_Unpriced pins the ids this pass deliberately did
// NOT price, so a later edit that adds a guessed number fails loudly:
//   - kimi-for-coding: Kimi Code's subscription id (K2.8 Preview). Moonshot
//     publishes no per-token rate; it keeps resolving through the `kimi`
//     FAMILY (approximate), never an exact row.
//   - gpt-live-1: OpenAI bills GPT-Live per second of a voice session, not
//     per token - a token row would be a fabrication. MISS.
//   - auto: a router sentinel names no model. MISS (the cure is adapter-side).
func TestPriceGaps_2026_09_27_Unpriced(t *testing.T) {
	t.Parallel()
	tb := NewTable()
	if _, src, _ := tb.LookupWithSource("kimi-for-coding"); src != PricingSourceFamily {
		t.Errorf("kimi-for-coding source = %q, want family (no vendor per-token rate exists)", src)
	}
	for _, model := range []string{"gpt-live-1", "gpt-live", "auto"} {
		if p, src, ok := tb.LookupWithSource(model); ok || src != PricingSourceMiss {
			t.Errorf("Lookup(%q) = %+v %q ok=%v, want an explicit MISS", model, p, src, ok)
		}
	}
}

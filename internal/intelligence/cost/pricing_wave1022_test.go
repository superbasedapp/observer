package cost

import "testing"

// TestWave1021RecordedModelsPriced pins how every model string the ten
// 2026-10-21 wave tools recorded on the live node (token_usage, queried
// 2026-10-22) resolves, plus the two CodeBuddy ids that have not been
// recorded yet. A row whose want is PricingSourceMiss must stay unpriced.
func TestWave1021RecordedModelsPriced(t *testing.T) {
	tests := []struct {
		model string
		tool  string
		want  PricingSource
		in    float64
		out   float64
	}{
		{"fantail", "autohand", PricingSourceExact, 0, 0},
		{"minimax/minimax-m3.1-flash:free", "autohand/deepagents/vtcode", PricingSourceExact, 0, 0},
		{"hy3", "codebuddy", PricingSourceExact, 0.132, 0.528},
		{"claude-opus-5-5", "cortex-code", PricingSourceExact, 4, 20},
		{"dots-studio/dots-3-note-preview:free", "dimcode", PricingSourceExact, 0, 0},
		{"poolside/laguna-s-2.1:free", "dimcode", PricingSourceExact, 0, 0},
		{"poolside/laguna-xs-2.1:free", "dimcode", PricingSourceExact, 0, 0},
		{"gpt-5.6-luna", "dirac", PricingSourceExact, 0.2, 1.2},
		{"gpt-6-luna", "dirac", PricingSourceExact, 0.1, 0.5},
		// kimchi stamps "<provider>/<model>"; the provider segment is
		// stripped by the last-resort normalization, so this is an alias of
		// the priced gpt-5.6-luna row, not a second price.
		{"openai-codex/gpt-5.6-luna", "kimchi", PricingSourceFamily, 0.2, 1.2},
		{"hy4-preview", "codebuddy", PricingSourceExact, 0.834, 2.501},
		{"kimchi-dev/gemma-4-31b", "kimchi", PricingSourceExact, 0, 0},
		// No official price for K2.8 (Moonshot and Tencent pages, 2026-10-22):
		// it may only price approximately via the kimi family, never exact.
		{"kimi-k2.8-preview", "codebuddy", PricingSourceFamily, 0.95, 4},
		// A bare gemma-4-31b served elsewhere is not the free kimchi row.
		{"gemma-4-31b", "kimchi", PricingSourceMiss, 0, 0},
		// Tiers with no model string are unpriceable by construction.
		{"", "stakpak/ibm-bob", PricingSourceMiss, 0, 0},
	}
	tbl := NewTable()
	for _, tc := range tests {
		t.Run(tc.tool+"/"+tc.model, func(t *testing.T) {
			p, src, ok := tbl.LookupWithSource(tc.model)
			if src != tc.want {
				t.Fatalf("source = %q, want %q", src, tc.want)
			}
			if ok != (tc.want != PricingSourceMiss) {
				t.Fatalf("ok = %v for source %q", ok, src)
			}
			if p.Input != tc.in || p.Output != tc.out {
				t.Fatalf("rate = %v/%v, want %v/%v", p.Input, p.Output, tc.in, tc.out)
			}
		})
	}
}

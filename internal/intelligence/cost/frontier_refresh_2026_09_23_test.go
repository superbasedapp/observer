package cost

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// TestFrontierRefresh_2026_09_23 pins the models added or corrected by the
// 2026-09-23 vendor-page refresh, and - more importantly - pins the RESOLUTION
// each one gets, because every defect this refresh fixed was a resolution
// defect rather than a typo: a model that resolved through the wrong family
// prefix and billed a plausible wrong number nobody questioned.
//
// wantSource is asserted on purpose. "claude-opus-5-5 costs $4" passing while
// it resolves via PricingSourceFamily would mean the row is being shadowed and
// the number is a coincidence.
func TestFrontierRefresh_2026_09_23(t *testing.T) {
	t.Parallel()
	tb := NewTable()
	const skip = -1.0

	for _, tc := range []struct {
		name            string
		model           string
		in, cacheR, out float64
		lcThreshold     int64
		wantSource      PricingSource
	}{
		// Anthropic. NO long-context tier: 4.6 and later include the full 1M
		// window at standard pricing, so a threshold here would invent a
		// repricing Anthropic does not perform.
		{"opus 5.5", "claude-opus-5-5", 4, 0.20, 20, 0, PricingSourceExact},
		{"opus 5.5 dot alias", "claude-opus-5.5", 4, 0.20, 20, 0, PricingSourceExact},
		// A dated SKU reaches the exact row by the date-strip rung, ahead of
		// the family ladder - so it can never be captured by opus-5.
		{"opus 5.5 dated SKU resolves to its own row, not opus-5", "claude-opus-5-5-20260922", 4, 0.20, 20, 0, PricingSourceDateStripped},
		// The regression this row exists to stop: opus-5-5 must NOT inherit
		// opus-5's $5/$25.
		{"opus 5 unchanged", "claude-opus-5", 5, 0.50, 25, 0, PricingSourceExact},

		// OpenAI GPT-6. Sol and Luna previously inherited Astra's $10/$50
		// through the `gpt-6` family prefix - a 5x and a 100x over-bill.
		{"gpt-6 astra unchanged", "gpt-6-astra", 10, 1, 50, 272_000, PricingSourceExact},
		{"gpt-6 sol", "gpt-6-sol", 2, 0.20, 10, 272_000, PricingSourceExact},
		{"gpt-6 luna", "gpt-6-luna", 0.10, 0.01, 0.50, 272_000, PricingSourceExact},

		// GPT-5.6 Sol repriced to its published promotional rate; the bare
		// family row deliberately keeps the non-promotional $5/$30.
		{"gpt-5.6 sol repriced", "gpt-5.6-sol", 4, 0.40, 20, 272_000, PricingSourceExact},
		{"gpt-5.6 family keeps the non-promotional rate", "gpt-5.6", 5, 0.50, 30, 272_000, PricingSourceExact},

		// xAI. The flagship needed a row for the TIER, not the base rate: the
		// `grok` family prefix already answered $2/$6/$0.50 but must never
		// carry the doubled >=200K tier.
		{"grok 4.7", "grok-4.7", 2, 0.50, 6, 200_000, PricingSourceExact},
		{"grok 4.5 published cache rate", "grok-4.5", 2, 0.30, 6, 200_000, PricingSourceExact},
		{"grok 4.3 published cache rate", "grok-4.3", 1.25, 0.20, 2.50, 200_000, PricingSourceExact},
		{"grok build 0.1 published cache rate", "grok-build-0.1", 1, 0.20, 2, 200_000, PricingSourceExact},
		// The exact Grok 4.20 vendor API ids (research-xai.md) resolve to the
		// `grok-4.20` row, which carries their shared card AND the 200K tier.
		{"grok 4.20 reasoning exact id", "grok-4.20-0309-reasoning", 1.25, 0.20, 2.50, 200_000, PricingSourceFamily},
		{"grok 4.20 non-reasoning exact id", "grok-4.20-0309-non-reasoning", 1.25, 0.20, 2.50, 200_000, PricingSourceFamily},
		{"grok 4.20 multi-agent exact id", "grok-4.20-multi-agent-0309", 1.25, 0.20, 2.50, 200_000, PricingSourceFamily},
		{"grok family carries no long-context tier", "grok", 2, 0.50, 6, 0, PricingSourceExact},
		{"an unknown grok SKU inherits the base tier only", "grok-9.9", 2, 0.50, 6, 0, PricingSourceFamily},

		// Cognition. Every one of these was a MISS - $0.00 silently - before
		// this refresh, because no `swe` prefix existed anywhere in the table.
		{"swe-2 high", "swe-2-high", 0.75, 0.075, 3.75, 0, PricingSourceExact},
		{"swe-2 family", "swe-2", 0.75, 0.075, 3.75, 0, PricingSourceExact},
		{"swe-1.7 lightning", "swe-1-7-lightning", 2.50, 1.00, 12.50, 0, PricingSourceExact},
		{"swe-1.7 max", "swe-1-7", 0.50, 0.20, 2.50, 0, PricingSourceExact},
		// THE LIVE ID. internal/adapter/devin captures `generation_model`
		// values like "swe-1-6-slow" (see that package's doc.go and its
		// fixtures), not the bare catalog id, so the longest-prefix ladder is
		// what actually prices a real Devin turn. If this case ever fails,
		// every Cognition turn on that variant is mispriced.
		{"the live devin variant id resolves to its own generation", "swe-1-6-slow", 0.50, 0.20, 2.50, 0, PricingSourceFamily},
		// SWE-1.7 Medium: the vendor quotes input/output only. CacheRead stays
		// 0 - NOT the universal 10%-of-input default (review finding 5).
		{"swe-1.7 medium cache read is unquoted, not defaulted", "swe-1-7-medium", 0.50, 0, 2.50, 0, PricingSourceExact},
		// grok-code-fast-1 is retired; its CURRENT rate is the replacement's
		// (review finding 6). History is pinned in the dated test below.
		{"retired grok-code-fast-1 bills the replacement today", "grok-code-fast-1", 1, 0.20, 2, 200_000, PricingSourceExact},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, src, ok := tb.LookupWithSource(tc.model)
			if !ok {
				t.Fatalf("Lookup(%q) returned ok=false - a MISS prices at $0.00 silently", tc.model)
			}
			if src != tc.wantSource {
				t.Errorf("source: got %q want %q - the rate may be right by coincidence", src, tc.wantSource)
			}
			if p.Input != tc.in {
				t.Errorf("input: got %v want %v", p.Input, tc.in)
			}
			if p.Output != tc.out {
				t.Errorf("output: got %v want %v", p.Output, tc.out)
			}
			if tc.cacheR != skip && p.CacheRead != tc.cacheR {
				t.Errorf("cache_read: got %v want %v", p.CacheRead, tc.cacheR)
			}
			if p.LongContextThreshold != tc.lcThreshold {
				t.Errorf("long_context_threshold: got %d want %d", p.LongContextThreshold, tc.lcThreshold)
			}
		})
	}
}

// TestFrontierRefresh_UnpricedSWEStayMisses pins review finding 4. SWE-1,
// SWE-1-lite, SWE-1-mini and SWE-1.5 have NO vendor-published per-token rate,
// so they must resolve to an explicit MISS (reliability "unknown") and never
// borrow SWE-1.6/1.7's card through a family floor.
func TestFrontierRefresh_UnpricedSWEStayMisses(t *testing.T) {
	t.Parallel()
	tb := NewTable()
	for _, model := range []string{"swe-1", "swe-1-lite", "swe-1-mini", "swe-1-5", "swe-1.5", "SWE-1-mini"} {
		t.Run(model, func(t *testing.T) {
			if p, src, ok := tb.LookupWithSource(model); ok || src != PricingSourceMiss {
				t.Fatalf("Lookup(%q) = %+v %q ok=%v, want an explicit MISS: no vendor rate is published", model, p, src, ok)
			}
		})
	}
	if _, ok := BakedInDefaults()["swe-1"]; ok {
		t.Fatal(`BakedInDefaults still carries a "swe-1" family row - the fabricated floor is back`)
	}
}

// TestFrontierRefresh_CacheReadNotQuoted pins review finding 5 end to end:
// cached-read tokens on SWE-1.7 Medium contribute $0 (an unpriced dimension)
// instead of an invented 10%-of-input charge, while a sibling SKU with a
// published cache rate still bills it, and an explicit override still wins.
func TestFrontierRefresh_CacheReadNotQuoted(t *testing.T) {
	t.Parallel()
	tb := NewTable()
	bundle := TokenBundle{Input: 1_000_000, CacheRead: 1_000_000}

	medium, ok := tb.Lookup("swe-1-7-medium")
	if !ok {
		t.Fatal("swe-1-7-medium missing")
	}
	if got := Compute(medium, bundle); math.Abs(got-0.50) > 1e-9 {
		t.Errorf("swe-1-7-medium cost = %v, want 0.50 (input only; cache read unquoted)", got)
	}
	// A decorated live id resolving to the key by family prefix is covered.
	if p, src, ok := tb.LookupWithSource("swe-1-7-medium-slow"); !ok || src != PricingSourceFamily || p.CacheRead != 0 {
		t.Errorf("swe-1-7-medium-slow = %+v %q %v, want family resolution with unquoted cache read", p, src, ok)
	}
	maxP, _ := tb.Lookup("swe-1-7")
	if got := Compute(maxP, bundle); math.Abs(got-0.70) > 1e-9 {
		t.Errorf("swe-1-7 cost = %v, want 0.70 (0.50 input + 0.20 published cache read)", got)
	}
	// Only a ZERO field is left alone: an explicit override wins.
	tb.Merge(map[string]Pricing{"swe-1-7-medium": {Input: 0.50, Output: 2.50, CacheRead: 0.10}})
	if p, _ := tb.Lookup("swe-1-7-medium"); p.CacheRead != 0.10 {
		t.Errorf("override cache read = %v, want 0.10", p.CacheRead)
	}
	// Every other key keeps the universal default (the rule is narrow).
	tb.Merge(map[string]Pricing{"some-unlisted-model": {Input: 1, Output: 2}})
	if p, _ := tb.Lookup("some-unlisted-model"); p.CacheRead != 0.10 {
		t.Errorf("unlisted model cache read = %v, want the universal 0.10 default", p.CacheRead)
	}
}

// TestFrontierRefresh_GrokCodeFast1Retirement pins review finding 6 on BOTH
// sides of the 2026-05-15 retirement, for the exact id and the family row.
func TestFrontierRefresh_GrokCodeFast1Retirement(t *testing.T) {
	t.Parallel()
	tb := NewTable()
	// "Effective May 15, 2026 at 12:00 PM PT" (docs.x.ai, fetched 2026-09-27).
	retired := time.Date(2026, 5, 15, 19, 0, 0, 0, time.UTC)
	// xAI's launch post (x.ai/news/grok-code-fast-1): "$0.20 / 1M input
	// tokens, $1.50 / 1M output tokens, and $0.02 / 1M cached input tokens".
	historical := fillDefaults(Pricing{Input: 0.20, Output: 1.50, CacheRead: 0.02})
	replacement, _ := tb.Lookup("grok-build-0.1")

	for _, model := range []string{"grok-code-fast-1", "grok-code"} {
		for _, tc := range []struct {
			name string
			at   time.Time
			want Pricing
		}{
			{"long before retirement", retired.AddDate(0, -6, 0), historical},
			{"one nanosecond before", retired.Add(-time.Nanosecond), historical},
			{"exactly at retirement -> replacement", retired, replacement},
			{"after retirement", retired.AddDate(0, 1, 0), replacement},
			{"zero time -> current (replacement)", time.Time{}, replacement},
		} {
			t.Run(model+"/"+tc.name, func(t *testing.T) {
				got, ok := tb.LookupAt(model, tc.at)
				if !ok || got != tc.want {
					t.Fatalf("LookupAt(%q, %s) = %+v ok=%v, want %+v", model, tc.at, got, ok, tc.want)
				}
			})
		}
	}
	// A decorated id reaches the same timeline through the family ladder.
	if got, _ := tb.LookupAt("grok-code-fast-1-0825", retired.AddDate(0, -1, 0)); got != historical {
		t.Errorf("grok-code-fast-1-0825 before retirement = %+v, want the historical card", got)
	}
}

// TestSummary_UnquotedCacheReadIsAnUnknownSignal pins round-2 review finding
// 4 end to end through Engine.Summary: a proxy turn on a model whose cache-read
// rate is UNQUOTED (swe-1-7-medium) records its cached tokens as UNPRICED volume and the bucket's pricing source
// stops reading "exact", and the compression-savings lower bound does NOT
// reinvent the 10%-of-input cache rate. A sibling with a quoted cache rate
// (swe-1-7) is the control.
func TestSummary_UnquotedCacheReadIsAnUnknownSignal(t *testing.T) {
	now := time.Now().UTC()
	preRetirement := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name          string
		model         string
		at            time.Time
		wantUnpriced  int64
		wantSource    string
		wantCacheTier float64
	}{
		{"unquoted swe-1-7-medium", "swe-1-7-medium", now.Add(-time.Hour), 1_000_000, "mixed", 0},
		// grok-code-fast-1 before its retirement: its cached rate IS quoted
		// ($0.02, x.ai/news/grok-code-fast-1), so it prices.
		{"quoted historical grok-code-fast-1", "grok-code-fast-1", preRetirement, 0, "exact", 0.02},
		{"quoted swe-1-7 control", "swe-1-7", now.Add(-time.Hour), 0, "exact", 0.20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database := openTestDB(t)
			f := seedSession(t, database, t.TempDir(), "unq-"+tc.model, "devin")
			if _, err := database.ExecContext(context.Background(),
				`INSERT INTO api_turns (session_id, project_id, timestamp, provider, model,
					input_tokens, output_tokens, cache_read_tokens,
					compression_original_bytes, compression_compressed_bytes, compression_count)
				 VALUES (?, ?, ?, 'anthropic', ?, 1000, 100, 1000000, 4000000, 0, 1)`,
				f.sessionID, f.projectID, tc.at.Format(time.RFC3339Nano), tc.model); err != nil {
				t.Fatalf("insert api_turn: %v", err)
			}
			e := NewEngine(config.IntelligenceConfig{})
			s, err := e.Summary(context.Background(), database, Options{
				Since: tc.at.Add(-time.Hour), Until: tc.at.Add(time.Hour),
				GroupBy: GroupByModel, Source: SourceProxy,
			})
			if err != nil {
				t.Fatalf("Summary: %v", err)
			}
			if s.UnpricedTokens != tc.wantUnpriced {
				t.Errorf("UnpricedTokens = %d, want %d", s.UnpricedTokens, tc.wantUnpriced)
			}
			if len(s.Rows) != 1 || s.Rows[0].PricingSource != tc.wantSource {
				t.Fatalf("rows = %+v, want one row with pricing source %q", s.Rows, tc.wantSource)
			}
			if got := s.TotalCompression.CostSavedUSDEstCacheReadTier; math.Abs(got-tc.wantCacheTier) > 1e-9 {
				t.Errorf("cache-read-tier savings = %v, want %v (no reinvented 10%% rate)", got, tc.wantCacheTier)
			}
		})
	}
}

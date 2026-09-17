package cost

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
)

func TestTable_LookupExact(t *testing.T) {
	tb := NewTable()
	p, ok := tb.Lookup("claude-sonnet-4-20250514")
	if !ok {
		t.Fatalf("expected sonnet-4 pricing to exist")
	}
	if p.Input != 3 || p.Output != 15 {
		t.Errorf("sonnet-4 input/output wrong: %+v", p)
	}
	if p.CacheRead != 0.30 {
		t.Errorf("sonnet-4 cache_read wrong: %+v", p)
	}
	if p.CacheCreation != 3.75 {
		t.Errorf("sonnet-4 cache_creation wrong: %+v", p)
	}
}

// TestTable_Anthropic2026Q2Pricing pins the post-2026-04-29 pricing
// snapshot (docs/pricing-reference.md). When Anthropic changes
// rates, update both this test and the reference doc.
//
// The interesting cases are the SKUs where pricing diverged WITHIN a
// model family — Opus 4.5+ dropped to 1/3 of Opus 4 / 4.1 rates. Family
// fallback for new SKUs (claude-opus-4-7) must hit the latest tier, not
// the legacy.
func TestTable_Anthropic2026Q2Pricing(t *testing.T) {
	tb := NewTable()

	for _, tc := range []struct {
		name, model    string
		in, out        float64
		cacheR, cacheW float64
		cacheW1h       float64
	}{
		// Current-gen Opus (4.5 / 4.6 / 4.7): 1/3 of legacy Opus pricing.
		{"opus-4-7 explicit", "claude-opus-4-7", 5, 25, 0.50, 6.25, 10},
		{"opus-4-6 explicit", "claude-opus-4-6", 5, 25, 0.50, 6.25, 10},
		{"opus-4-5 explicit", "claude-opus-4-5", 5, 25, 0.50, 6.25, 10},
		// Legacy Opus 4 / 4.1 — full $15/$75 rates.
		{"opus-4-1 explicit", "claude-opus-4-1", 15, 75, 1.5, 18.75, 30},
		{"opus-4-1 dated", "claude-opus-4-1-20250805", 15, 75, 1.5, 18.75, 30},
		// Sonnet 4 family — single rate across versions.
		{"sonnet-4-6", "claude-sonnet-4-6", 3, 15, 0.30, 3.75, 6},
		{"sonnet-3-7 deprecated", "claude-sonnet-3-7", 3, 15, 0.30, 3.75, 6},
		// Haiku 4.5.
		{"haiku-4-5", "claude-haiku-4-5", 1, 5, 0.10, 1.25, 2},
		{"haiku-4-5 dated", "claude-haiku-4-5-20251001", 1, 5, 0.10, 1.25, 2},
		// Opus 4.8 — pinned explicit row (was family fallback prior to
		// 2026-06-07). Same rates as 4.7. The explicit row holds the
		// FastMultiplier premium tier (speed=fast → $10/$50 — 2× across
		// the board).
		{"opus-4-8 explicit", "claude-opus-4-8", 5, 25, 0.50, 6.25, 10},
		// Fable 5 — Anthropic's most capable model, priced from the
		// published first-party card at $10/$50 (2× the Opus-4.8 flagship
		// tier). Cache: read $1, 5m-write $12.50, 1h-write $20. Corrected
		// 2026-07-12 from a stale $5/$25 Opus-anchor placeholder.
		{"fable-5 explicit", "claude-fable-5", 10, 50, 1, 12.50, 20},
		// Fable 5.1 — same base $10/$50/$12.50/$20 card as Fable 5, but a
		// 0.025x (not the universal 0.10x) cache-read multiplier: $0.25,
		// not $1. Verified against platform.claude.com/docs/en/
		// about-claude/pricing, fetched 2026-09-07.
		{"fable-5-1 explicit (0.025x cache read)", "claude-fable-5-1", 10, 50, 0.25, 12.50, 20},
		{"mythos-5-1 explicit (mirrors fable-5-1)", "claude-mythos-5-1", 10, 50, 0.25, 12.50, 20},
		// Dot-form aliases — some surfaces spell the minor version with a
		// dot ("5.1") instead of a dash ("5-1"). Without an explicit alias
		// these fall through to the SHORTER "claude-fable-5" / "claude-
		// mythos-5" family match (dots and dashes never normalize against
		// each other in the lookup ladder), landing on the wrong
		// generation's $1 cache-read instead of $0.25 — same precedent as
		// the "gpt-5-6" / "gpt-5.6" dual keys.
		{"fable-5.1 dot-form alias", "claude-fable-5.1", 10, 50, 0.25, 12.50, 20},
		{"mythos-5.1 dot-form alias", "claude-mythos-5.1", 10, 50, 0.25, 12.50, 20},
		// Dated 5.1 SKUs resolve via the claude-fable-5-1 prefix (longer
		// than claude-fable-5, so it wins the longest-first sort) and keep
		// the $0.25 read rate.
		{"fable-5-1 dated → 5.1 prefix", "claude-fable-5-1-20260901", 10, 50, 0.25, 12.50, 20},
		// Fable 5 legacy SKUs must KEEP the standard $1 read rate — a
		// dated Fable-5 id lands on the claude-fable-5 key, not 5.1.
		{"fable-5 dated keeps $1 reads", "claude-fable-5-20260601", 10, 50, 1, 12.50, 20},
		// claude-fable family prefix stays at the UNIVERSAL 0.10x cache-read
		// ($1), NOT the 0.025x rate — Anthropic's footnote scopes the
		// discount to two NAMED models ("Cache hits and refreshes on Claude
		// Fable 5.1 and Claude Mythos 5.1 are priced at 0.025x the base
		// input price. All other models use the standard 0.1x multiplier.").
		// A family row prices an UNKNOWN future SKU, which is an "other
		// model" per that footnote until it earns its own explicit row, so
		// bumping the family prefix to 0.025x would silently UNDER-bill it
		// 4x the moment it ships. Base input/output/cache-write are
		// unchanged from Fable 5/5.1.
		{"future fable-6 inherits current (universal cache-read, not the named-SKU discount)", "claude-fable-6", 10, 50, 1, 12.50, 20},
		// Sonnet 5 — $2/$10 (cache 0.20/2.50/4), launched as introductory
		// pricing and made PERMANENT: the scheduled 2026-09-01 rise to
		// $3/$15 was canceled per the pricing-page note (re-verified
		// 2026-09-07). NOT $3/$15 — see pricing.go.
		{"sonnet-5 intro", "claude-sonnet-5", 2, 10, 0.20, 2.50, 4},
		// Dated Sonnet-5 SKU resolves via the bare-name family prefix.
		{"sonnet-5 dated → family", "claude-sonnet-5-20260601", 2, 10, 0.20, 2.50, 4},
		// Hypothetical future SKU — must inherit the LATEST family rates,
		// not the legacy. claude-opus-4-9 should be priced like Opus 4.7/4.8,
		// not Opus 4. (Family prefix "claude-opus-4" is set to current
		// rates so this works out of the box.)
		{"future opus-4-9 inherits current", "claude-opus-4-9", 5, 25, 0.50, 6.25, 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, ok := tb.Lookup(tc.model)
			if !ok {
				t.Fatalf("Lookup(%q) returned ok=false", tc.model)
			}
			if p.Input != tc.in {
				t.Errorf("input: got %v want %v", p.Input, tc.in)
			}
			if p.Output != tc.out {
				t.Errorf("output: got %v want %v", p.Output, tc.out)
			}
			if p.CacheRead != tc.cacheR {
				t.Errorf("cache_read: got %v want %v", p.CacheRead, tc.cacheR)
			}
			if p.CacheCreation != tc.cacheW {
				t.Errorf("cache_creation: got %v want %v", p.CacheCreation, tc.cacheW)
			}
			if p.CacheCreation1h != tc.cacheW1h {
				t.Errorf("cache_creation_1h: got %v want %v", p.CacheCreation1h, tc.cacheW1h)
			}
		})
	}
}

// TestTable_OpenAI2026Q2Pricing pins the post-2026-04-29 OpenAI snapshot.
// Cached input maps to CacheRead. For models that publish a cache rate
// (gpt-5, gpt-4.1, gpt-4o, o-series with cache support, etc.) the
// explicit rate must round-trip exactly. For models without a published
// cache tier (gpt-5-pro, o1-pro, gpt-3.5*, base models) the explicit
// rate is 0; fillDefaults assigns 0.10 × Input as a defensive fallback,
// but that rate never binds in practice because the proxy never records
// cache_read_tokens for OpenAI cache-less models. The test asserts the
// `Input` and `Output` rates always; `cacheR < 0` is a sentinel meaning
// "skip the assertion (model has no real cache tier)".
func TestTable_OpenAI2026Q2Pricing(t *testing.T) {
	tb := NewTable()

	const skipCache = -1.0
	for _, tc := range []struct {
		name, model     string
		in, cacheR, out float64
	}{
		// GPT-5 family — current frontier (rates per
		// docs/pricing-reference.md, OpenAI snapshot 2026-04-29).
		{"gpt-5", "gpt-5", 1.07, 0.107, 8.50},
		// GPT-5.6 family (limited preview, 2026-06-25). CacheRead is the
		// explicit 90%-discount read rate; the 1.25×-input cache-WRITE
		// tier is asserted separately in TestTable_GPT56CacheWriteTier.
		// Terra/Luna are the CURRENT (post-2026-07-30-cut) rates — the
		// PRE-cut rates are pinned separately in
		// TestDated_GPT56TerraLunaPriceCut (dated_test.go). Sol is
		// unaffected by the cut.
		{"gpt-5.6-sol", "gpt-5.6-sol", 5, 0.50, 30},
		{"gpt-5.6-terra", "gpt-5.6-terra", 2.00, 0.20, 12.00},
		{"gpt-5.6-luna", "gpt-5.6-luna", 0.20, 0.02, 1.20},
		// Family fallback: a hypothetical future variant resolves via the
		// longest-prefix "gpt-5.6" family row → Sol (flagship) rates.
		{"gpt-5.6-nova → gpt-5.6 family (Sol rates)", "gpt-5.6-nova", 5, 0.50, 30},
		// ChatGPT web-UI dashed slugs (browser-extension chatgpt-web
		// adapter) — explicit exact-match aliases, same Sol rates.
		{"gpt-5-6-thinking (chatgpt-web dashed slug)", "gpt-5-6-thinking", 5, 0.50, 30},
		{"gpt-5-6 (chatgpt-web dashed slug)", "gpt-5-6", 5, 0.50, 30},
		{"gpt-5.5", "gpt-5.5", 5, 0.50, 30},
		{"gpt-5.4", "gpt-5.4", 2.50, 0.25, 15},
		{"gpt-5.4-mini", "gpt-5.4-mini", 0.75, 0.075, 4.50},
		{"gpt-5.4-nano", "gpt-5.4-nano", 0.20, 0.02, 1.25},
		{"gpt-5.3-codex", "gpt-5.3-codex", 1.75, 0.175, 14},
		{"gpt-5.2", "gpt-5.2", 1.75, 0.175, 14},
		{"gpt-5.1", "gpt-5.1", 1.07, 0.107, 8.50},
		{"gpt-5.1-codex-max", "gpt-5.1-codex-max", 1.25, 0.125, 10},
		{"gpt-5-mini", "gpt-5-mini", 0.25, 0.025, 2},
		{"gpt-5-nano free", "gpt-5-nano", 0, 0, 0},
		{"gpt-5-pro legacy", "gpt-5-pro", 15, skipCache, 120},
		{"gpt-5.5-pro cached=input", "gpt-5.5-pro", 30, 30, 180},
		// GPT-4.1.
		{"gpt-4.1", "gpt-4.1", 2, 0.50, 8},
		{"gpt-4.1-nano", "gpt-4.1-nano", 0.10, 0.025, 0.40},
		// o-series.
		{"o3", "o3", 2, 0.50, 8},
		{"o4-mini", "o4-mini", 1.10, 0.275, 4.40},
		{"o1", "o1", 15, 7.50, 60},
		{"o1-pro no cache", "o1-pro", 150, skipCache, 600},
		// Legacy.
		{"gpt-3.5-turbo no cache", "gpt-3.5-turbo", 0.50, skipCache, 1.50},
		{"davinci-002 no cache", "davinci-002", 2, skipCache, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, ok := tb.Lookup(tc.model)
			if !ok {
				t.Fatalf("Lookup(%q) returned ok=false", tc.model)
			}
			if p.Input != tc.in {
				t.Errorf("input: got %v want %v", p.Input, tc.in)
			}
			if p.Output != tc.out {
				t.Errorf("output: got %v want %v", p.Output, tc.out)
			}
			if tc.cacheR != skipCache && p.CacheRead != tc.cacheR {
				t.Errorf("cache_read: got %v want %v", p.CacheRead, tc.cacheR)
			}
		})
	}
}

// TestTable_GPT56CacheWriteTier pins GPT-5.6's explicit cache-WRITE tier
// — the first non-Anthropic explicit write tier. GPT-5.6 bills cache
// writes at 1.25× the uncached input rate. It also pins that
// CacheCreation1h == CacheCreation exactly: OpenAI has no 5m/1h split,
// and fillDefaults would otherwise derive CacheCreation1h = 2×Input (an
// Anthropic-shape default) — the explicit pin keeps that fabricated rate
// out of the card.
func TestTable_GPT56CacheWriteTier(t *testing.T) {
	tb := NewTable()
	for _, tc := range []struct {
		name, model string
		wantInput   float64
	}{
		{"sol", "gpt-5.6-sol", 5},
		{"terra", "gpt-5.6-terra", 2.00},
		{"luna", "gpt-5.6-luna", 0.20},
		{"family → sol", "gpt-5.6", 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, ok := tb.Lookup(tc.model)
			if !ok {
				t.Fatalf("Lookup(%q) ok=false", tc.model)
			}
			wantWrite := tc.wantInput * 1.25
			if diff := p.CacheCreation - wantWrite; diff > 1e-9 || diff < -1e-9 {
				t.Errorf("CacheCreation: got %v want %v (1.25×input)", p.CacheCreation, wantWrite)
			}
			// fillDefaults' Anthropic 2×-Input default must NOT bind — the
			// explicit pin holds 1h == 5m.
			if p.CacheCreation1h != p.CacheCreation {
				t.Errorf("CacheCreation1h: got %v want %v (pinned == 5m, not 2×input)",
					p.CacheCreation1h, p.CacheCreation)
			}
		})
	}
}

// TestTable_ChatGPTWebDashedGPT56Slugs pins the browser-extension
// chatgpt-web adapter's dashed model slugs ("gpt-5-6-thinking",
// "gpt-5-6") to explicit exact-match table rows. The ChatGPT web UI
// echoes the model with dashes where the API uses dots
// (message.metadata.resolved_model_slug / model_slug / request `model`
// — see browser-extension/src/parsers.js, LIVE-CONFIRMED 2026-07-10:
// observed value "gpt-5-6-thinking"). Before these rows existed, the
// family-prefix ladder in LookupWithSource couldn't bridge dash-vs-dot
// and fell through to the unrelated "gpt-5" family row ($1.07/$8.50 —
// roughly a 5x underpricing of the real $5/$30 GPT-5.6 rate). The
// source must report PricingSourceExact (a real table entry), not
// PricingSourceFamily fallback.
func TestTable_ChatGPTWebDashedGPT56Slugs(t *testing.T) {
	tb := NewTable()
	for _, tc := range []struct {
		name, model string
	}{
		{"thinking slug", "gpt-5-6-thinking"},
		{"bare dashed slug", "gpt-5-6"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, src, ok := tb.LookupWithSource(tc.model)
			if !ok {
				t.Fatalf("LookupWithSource(%q) ok=false", tc.model)
			}
			if src != PricingSourceExact {
				t.Errorf("LookupWithSource(%q): source=%q want %q", tc.model, src, PricingSourceExact)
			}
			if p.Input != 5 {
				t.Errorf("input: got %v want 5", p.Input)
			}
			if p.Output != 30 {
				t.Errorf("output: got %v want 30", p.Output)
			}
		})
	}
}

// TestTable_GeminiPricing pins the Google Gemini text-model rates.
// Tiered pricing (Gemini 2.5 Pro / 3.1 Pro Preview ≤200k vs >200k):
// we pin the lower tier — see docs/pricing-reference.md.
func TestTable_GeminiPricing(t *testing.T) {
	tb := NewTable()
	for _, tc := range []struct {
		name, model     string
		in, cacheR, out float64
	}{
		{"gemini-3.1-pro-preview", "gemini-3.1-pro-preview", 2, 0.20, 12},
		{"gemini-3-flash-preview", "gemini-3-flash-preview", 0.50, 0.05, 3},
		// Gemini 3.5 Flash — Standard tier per Google's Developer API
		// pricing card (2026-05-19). No 3.5 Pro on the official page.
		{"gemini-3.5-flash", "gemini-3.5-flash", 1.50, 0.15, 9},
		// 3.5 Flash family fallback: gemini-3.5-flash is a longest-prefix
		// match for any future flash-suffix SKU (e.g. -experimental),
		// since familyKeys promotes every exact entry without a date
		// suffix into a family candidate.
		{"gemini-3.5-flash-experimental fallback", "gemini-3.5-flash-experimental", 1.50, 0.15, 9},
		{"gemini-2.5-pro", "gemini-2.5-pro", 1.25, 0.125, 10},
		{"gemini-2.5-flash", "gemini-2.5-flash", 0.30, 0.03, 2.50},
		{"gemini-2.5-flash-lite", "gemini-2.5-flash-lite", 0.10, 0.01, 0.40},
		{"gemini-2.0-flash deprecated", "gemini-2.0-flash", 0.10, 0.025, 0.40},
		// Family fallback: future SKU "gemini-3.1-something" inherits
		// gemini-3.1 family prefix (same as 3.1-pro-preview rates).
		{"gemini-3.1 family fallback", "gemini-3.1-something-new", 2, 0.20, 12},
		// Unknown 3.5 SKU (e.g. hypothetical "gemini-3.5-pro" not on
		// the official pricing page as of 2026-05-19) falls through
		// gemini-3.5-flash (doesn't match) to gemini-3 family → Pro
		// rates ($2/$12/$0.20). Conservative default.
		{"unknown 3.5 SKU falls to gemini-3 family (Pro rates)", "gemini-3.5-pro-hypothetical", 2, 0.20, 12},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, ok := tb.Lookup(tc.model)
			if !ok {
				t.Fatalf("Lookup(%q) returned ok=false", tc.model)
			}
			if p.Input != tc.in || p.Output != tc.out || p.CacheRead != tc.cacheR {
				t.Errorf("got %+v want input=%v cache_r=%v out=%v", p, tc.in, tc.cacheR, tc.out)
			}
		})
	}
}

// TestTable_AntigravityInternalSKUs pins the model identifiers the
// Antigravity IDE writes for each model + effort selector. Pre-2026-05-13
// these matched via family-prefix fallback (or missed entirely for
// `gemini-pro-agent`); the bug surfaced as silent $0 on Pro-high and
// silent 4× overpricing on Flash (which inherited the gemini-3 family's
// Pro-rate fallback). Pin each SKU to PricingSourceExact so future
// pricing-table churn can't silently re-break the alignment.
func TestTable_AntigravityInternalSKUs(t *testing.T) {
	tb := NewTable()
	for _, tc := range []struct {
		name, model     string
		in, cacheR, out float64
		wantLC          bool
	}{
		// Pro variants — all map to Gemini 3.1 Pro rates incl. 200K LC tier.
		{"pro-agent (high)", "gemini-pro-agent", 2, 0.20, 12, true},
		{"pro-high explicit", "gemini-3.1-pro-high", 2, 0.20, 12, true},
		{"pro-medium explicit", "gemini-3.1-pro-medium", 2, 0.20, 12, true},
		{"pro-low explicit", "gemini-3.1-pro-low", 2, 0.20, 12, true},
		// Gemini 3 Pro effort SKUs — pinned in v1.6.19 paralleling
		// gemini-3.1-pro-*. Pre-v1.6.19 resolved via the gemini-3
		// family-prefix fallback (Pro rates, correct by happy accident).
		{"gemini-3 pro-high explicit", "gemini-3-pro-high", 2, 0.20, 12, true},
		{"gemini-3 pro-medium explicit", "gemini-3-pro-medium", 2, 0.20, 12, true},
		{"gemini-3 pro-low explicit", "gemini-3-pro-low", 2, 0.20, 12, true},
		// Flash variants — must map to Flash rates ($0.50/$3), NOT Pro
		// rates via family fallback. The pre-fix bug.
		{"flash-agent (default)", "gemini-3-flash-agent", 0.50, 0.05, 3, false},
		{"flash-high explicit", "gemini-3-flash-high", 0.50, 0.05, 3, false},
		{"flash-medium explicit", "gemini-3-flash-medium", 0.50, 0.05, 3, false},
		{"flash-low explicit", "gemini-3-flash-low", 0.50, 0.05, 3, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, src, ok := tb.LookupWithSource(tc.model)
			if !ok {
				t.Fatalf("Lookup(%q): ok=false", tc.model)
			}
			if src != PricingSourceExact {
				t.Errorf("Lookup(%q) source=%q want exact (alias must pin, not fall through)",
					tc.model, src)
			}
			if p.Input != tc.in || p.CacheRead != tc.cacheR || p.Output != tc.out {
				t.Errorf("Lookup(%q): got input=%v cache_r=%v out=%v; want %v / %v / %v",
					tc.model, p.Input, p.CacheRead, p.Output, tc.in, tc.cacheR, tc.out)
			}
			hasLC := p.LongContextThreshold > 0
			if hasLC != tc.wantLC {
				t.Errorf("Lookup(%q): LC threshold present=%v want %v",
					tc.model, hasLC, tc.wantLC)
			}
		})
	}
}

// TestTable_Gemini3FlashFamilyResilience locks in the gemini-3-flash
// family-prefix entry added in v1.6.19. The antigravity audit
// (docs/antigravity-audit-2026-05-19.md §B1) identified that hypothetical
// future gemini-3-flash-* SKUs would otherwise fall through to the
// gemini-3 family and bill at Pro rates ($2/$12) instead of Flash
// ($0.50/$3) — ~4× over-bill. The family entry catches the gap.
func TestTable_Gemini3FlashFamilyResilience(t *testing.T) {
	tb := NewTable()
	for _, tc := range []struct {
		name, model string
		wantInput   float64
		wantOutput  float64
		wantSource  PricingSource
	}{
		{"flash family exact", "gemini-3-flash", 0.50, 3, PricingSourceExact},
		{"hypothetical experimental flash", "gemini-3-flash-experimental", 0.50, 3, PricingSourceFamily},
		{"unknown flash suffix routes to flash family, not pro family", "gemini-3-flash-foo-bar", 0.50, 3, PricingSourceFamily},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, src, ok := tb.LookupWithSource(tc.model)
			if !ok {
				t.Fatalf("Lookup(%q) returned ok=false", tc.model)
			}
			if p.Input != tc.wantInput || p.Output != tc.wantOutput {
				t.Errorf("Lookup(%q): got input=%v output=%v; want %v / %v (Flash, not Pro)",
					tc.model, p.Input, p.Output, tc.wantInput, tc.wantOutput)
			}
			if src != tc.wantSource {
				t.Errorf("Lookup(%q): source=%q want %q", tc.model, src, tc.wantSource)
			}
		})
	}
}

// TestTable_OtherProviderPricing covers xAI / Moonshot / Cursor own.
func TestTable_OtherProviderPricing(t *testing.T) {
	tb := NewTable()
	for _, tc := range []struct {
		name, model     string
		in, cacheR, out float64
	}{
		// xAI moved to a unified $1.25/$2.50 rate card for the
		// grok-4.x line on 2026-05-15 (concurrent with grok-code-fast-1
		// retirement). CacheRead falls back to 10% × Input via
		// fillDefaults = $0.125.
		{"grok-4.3", "grok-4.3", 1.25, 0.125, 2.50},
		{"grok-4-20 historical alias", "grok-4-20", 1.25, 0.125, 2.50},
		{"grok-code-fast-1 redirects to grok-4.3", "grok-code-fast-1", 1.25, 0.125, 2.50},
		// grok-4.5 flagship (2026-07, 500k ctx) + grok-build-0.1 agentic
		// coder (early access, 256k ctx). No published cached-input rate →
		// CacheRead defaults to 10% × Input ($0.20 / $0.10).
		{"grok-4.5 flagship", "grok-4.5", 2, 0.20, 6},
		{"grok-build-0.1", "grok-build-0.1", 1, 0.10, 2},
		{"grok-build family", "grok-build-0.2", 1, 0.10, 2},
		// Family fallback follows the current flagship's base (<200K) tier
		// — grok-4.6 ($2/$6, real $0.50 cached-input rate), bumped from
		// grok-4.5's fillDefault-only $2/$6/$0.20 (2026-08). Same precedent
		// as the kimi-k2-6 family bump.
		{"grok family fallback → flagship", "grok-5", 2, 0.50, 6},
		{"kimi-k2-5", "kimi-k2-5", 0.60, 0.10, 3},
		// Kimi K2.6 — added 2026-06-07; family prefix bumped to K2.6 rates.
		{"kimi-k2-6", "kimi-k2-6", 0.684, 0.144, 3.42},
		// Kimi K3 flagship — first-party platform.kimi.ai/docs/pricing/chat-k3
		// (2026-07-17): $3 input / $15 output / $0.30 cached-input.
		{"kimi-k3", "kimi-k3", 3, 0.30, 15},
		// K3-family fallback: a K3 SKU variant lands on the explicit
		// "kimi-k3" prefix (longest-first beats bare "kimi"), so it gets K3
		// rates — NOT the K2.6 family rate it used to fall to before the
		// exact row existed.
		{"kimi-k3-1 → kimi-k3 family", "kimi-k3-1", 3, 0.30, 15},
		// Bare "kimi" family fallback deliberately stays at K2.6 (the
		// mainstream generation), so an unknown K2.x SKU does NOT inherit
		// the 4.4× K3 rate.
		{"kimi-k2-7 → kimi family (K2.6)", "kimi-k2-7", 0.684, 0.144, 3.42},
		{"composer-1", "composer-1", 1.25, 0.125, 10},
		{"composer-1.5", "composer-1.5", 3.50, 0.35, 17.50},
		{"composer-2", "composer-2", 0.50, 0.20, 2.50},
		{"composer-2.5", "composer-2.5", 0.50, 0.20, 2.50},
		{"composer-2.5-fast", "composer-2.5-fast", 3, 0.30, 15},
		// Cursor sends model="default" when the user picks Auto in
		// the model picker; Composer 2.5 Fast is the underlying
		// default backbone per cursor.com/blog/composer-2-5.
		{"default (cursor Auto)", "default", 3, 0.30, 15},
		// Family-prefix wins over miss: "composer-future-x" → composer
		// family rates ($0.50/$2.50).
		{"composer family fallback", "composer-future-x", 0.50, 0.20, 2.50},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, ok := tb.Lookup(tc.model)
			if !ok {
				t.Fatalf("Lookup(%q) returned ok=false", tc.model)
			}
			if p.Input != tc.in || p.Output != tc.out || p.CacheRead != tc.cacheR {
				t.Errorf("got %+v want input=%v cache_r=%v out=%v", p, tc.in, tc.cacheR, tc.out)
			}
		})
	}
}

// TestTable_Opus48ExplicitSourceExact pins that the v1.8.2 explicit
// claude-opus-4-8 row resolves as PricingSourceExact rather than the
// pre-pin family-fallback path (PricingSourceFamily via "claude-opus-4").
// Same rates either way ($5/$25), but the upgrade keeps the dashboard's
// "~" fallback badge off the flagship row AND gives a stable home for
// the FastMultiplier field (set on this entry only; not on the family
// prefix — fast mode is 4.8+ only).
func TestTable_Opus48ExplicitSourceExact(t *testing.T) {
	tb := NewTable()
	p, src, ok := tb.LookupWithSource("claude-opus-4-8")
	if !ok {
		t.Fatalf("Lookup claude-opus-4-8: ok=false")
	}
	if src != PricingSourceExact {
		t.Errorf("source=%q want exact (explicit row, not family fallback)", src)
	}
	if p.Input != 5 || p.Output != 25 || p.CacheRead != 0.50 ||
		p.CacheCreation != 6.25 || p.CacheCreation1h != 10 || p.WebSearchPerRequest != 0.01 {
		t.Errorf("rates: %+v", p)
	}
}

// TestTable_Opus5PricingAndFamilyFallback pins the 2026-07-25 Claude Opus 5
// rows. Before them `claude-opus-5` resolved to PricingSourceMiss and costed
// at $0.00 (measured live: 78 turns over ~3 days re-costed $0.00 → $18.04):
// there was no bare `claude-opus` key, and "claude-opus-4" is not a prefix of
// "claude-opus-5", so the family ladder could not save it. Same defect CLASS
// as the 2026-07-12 claude-fable-5 wrong-anchor incident — a flagship SKU
// silently mispriced.
//
// Rates are IDENTICAL to claude-opus-4-8 ($5/$25, cache 0.50/6.25/10, web
// search $0.01/call) including FastMultiplier=2 (Opus 5 fast mode is $10/$50
// = exactly 2× every per-token dimension). Verified against
// platform.claude.com/docs/en/about-claude/pricing 2026-07-25. Do NOT "fix"
// these to a higher tier — $10/$50 is Fable 5 / Mythos 5, not Opus 5.
//
// The four cases below cover the exact row, the family safety net, the
// long-context tag, and a shadowing regression guard.
func TestTable_Opus5PricingAndFamilyFallback(t *testing.T) {
	tb := NewTable()
	for _, tc := range []struct {
		name, model                       string
		wantSource                        PricingSource
		in, out, cacheR, cacheW, cacheW1h float64
		webSearch, fastMult               float64
	}{
		// (a) The explicit pinned SKU — exact match, full rate card, and the
		// FastMultiplier premium tier lives here (never on a family prefix).
		{"opus-5 explicit", "claude-opus-5", PricingSourceExact, 5, 25, 0.50, 6.25, 10, 0.01, 2},
		// (b) The bare `claude-opus` safety net: a hypothetical future SKU
		// inherits the CURRENT tier via family fallback rather than MISSing
		// to $0. FastMultiplier stays 0 — a fast tier is a per-SKU
		// capability future models must opt into explicitly.
		{"future opus-6 inherits current tier, not MISS", "claude-opus-6", PricingSourceFamily, 5, 25, 0.50, 6.25, 10, 0.01, 0},
		// (c) The `[1m]` long-context tag. The bracket tail defeats the
		// date-strip ladder, but `claude-opus-5` is itself date-suffix-free
		// so it doubles as a family prefix and — being longer than
		// "claude-opus" — wins familyKeys' longest-first sort. It therefore
		// carries the SAME rates AND FastMultiplier as the exact row: it is
		// the same SKU under a context tag, not a different model.
		{"opus-5 [1m] long-context tag", "claude-opus-5[1m]", PricingSourceFamily, 5, 25, 0.50, 6.25, 10, 0.01, 2},
		// (d) REGRESSION GUARD for the new bare `claude-opus` key: the
		// legacy Opus 4.1 row must stay EXACT at $15/$75. "claude-opus-4-1"
		// is longer than "claude-opus" so it wins the sort; a bug that let
		// the family key shadow it would silently 3× under-bill legacy
		// traffic. (`claude-3-opus` is safe by construction — it does not
		// start with "claude-opus" at all.)
		{"legacy opus-4-1 unshadowed", "claude-opus-4-1", PricingSourceExact, 15, 75, 1.5, 18.75, 30, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, src, ok := tb.LookupWithSource(tc.model)
			if !ok {
				t.Fatalf("LookupWithSource(%q): ok=false (MISS → $0.00 — the bug this pins)", tc.model)
			}
			if src != tc.wantSource {
				t.Errorf("source: got %q want %q", src, tc.wantSource)
			}
			if p.Input != tc.in {
				t.Errorf("input: got %v want %v", p.Input, tc.in)
			}
			if p.Output != tc.out {
				t.Errorf("output: got %v want %v", p.Output, tc.out)
			}
			if p.CacheRead != tc.cacheR {
				t.Errorf("cache_read: got %v want %v", p.CacheRead, tc.cacheR)
			}
			if p.CacheCreation != tc.cacheW {
				t.Errorf("cache_creation: got %v want %v", p.CacheCreation, tc.cacheW)
			}
			if p.CacheCreation1h != tc.cacheW1h {
				t.Errorf("cache_creation_1h: got %v want %v", p.CacheCreation1h, tc.cacheW1h)
			}
			if p.WebSearchPerRequest != tc.webSearch {
				t.Errorf("web_search_per_request: got %v want %v", p.WebSearchPerRequest, tc.webSearch)
			}
			if p.FastMultiplier != tc.fastMult {
				t.Errorf("fast_multiplier: got %v want %v", p.FastMultiplier, tc.fastMult)
			}
		})
	}
}

// TestTable_BareAnthropicFamilyRowsAndLegacyAlias pins the 2026-07-25
// completion of the bare-family-row set plus the one legacy alias that the
// current-gen family row was silently under-billing.
//
// Two defects, one root cause — the family ladder is a plain longest-PREFIX
// match, so a generation bump breaks it ("claude-sonnet-5" is not a prefix of
// "claude-sonnet-6") while a legacy alias that still shares the current-gen
// prefix silently inherits the WRONG (cheaper) tier:
//
//   - `claude-sonnet` / `claude-haiku` bare rows: without them the next
//     generation MISSes to $0.00 — the identical hole `claude-opus-5` fell
//     through before its pin. internal/routing/tiers.go already carried both
//     bare tiers, so the two registries disagreed until this change.
//   - `claude-opus-4-0`: Anthropic's documented undated alias for LEGACY
//     Claude Opus 4 at $15/$75. It had no row, so it resolved through the
//     `claude-opus-4` family row — which is deliberately pinned to
//     CURRENT-gen $5/$25 for future SKUs — and billed at 1/3 the real rate.
//
// Deliberate rate choices pinned here (do NOT "simplify" them to match a
// sibling row):
//
//   - bare `claude-sonnet` is the STANDARD $3/$15 card, NOT Sonnet 5's
//     $2/$10 INTRODUCTORY rate. The intro window closes 2026-08-31; a family
//     fallback carrying it would under-bill every unpinned Sonnet SKU from
//     2026-09-01. The explicit `claude-sonnet-5` row (longer → wins the
//     longest-first sort) keeps billing the intro rate for the one SKU that
//     actually has it, and its guard case below must stay $2/$10.
//   - neither bare row gets a FastMultiplier (fast mode is Opus-tier only)
//     or a LongContextThreshold (the LC tier is per-SKU: Sonnet 4 / 4.5 have
//     it, 4.6 and 5 do not) — a family fallback must not invent either.
//
// Everything after the three new cases is a REGRESSION GUARD asserting the
// new bare prefixes shadow nothing. The legacy `claude-3-5-*` / `claude-3-*`
// ids are safe by construction (they do not START with "claude-sonnet" /
// "claude-haiku"), and every existing `claude-sonnet-*` / `claude-haiku-*`
// key is strictly longer than its bare prefix so it wins familyKeys' sort.
func TestTable_BareAnthropicFamilyRowsAndLegacyAlias(t *testing.T) {
	tb := NewTable()
	for _, tc := range []struct {
		name, model                       string
		wantSource                        PricingSource
		in, out, cacheR, cacheW, cacheW1h float64
		fastMult                          float64
		wantLCThreshold                   int64
	}{
		// ---- the three rows this change adds ----
		//
		// (a) Next-gen Sonnet via the new bare family row — standard
		// $3/$15, not the expiring $2/$10 intro rate, and no LC tier.
		{"future sonnet-6 → bare claude-sonnet at STANDARD rates", "claude-sonnet-6", PricingSourceFamily, 3, 15, 0.30, 3.75, 6, 0, 0},
		// (b) Next-gen Haiku via the new bare family row — current-gen
		// (4.5) rates, never the cheaper legacy 3.5 / 3 Haiku tiers.
		{"future haiku-5 → bare claude-haiku at current-gen rates", "claude-haiku-5", PricingSourceFamily, 1, 5, 0.10, 1.25, 2, 0, 0},
		// (c) The legacy alias trap: EXACT now, at the real legacy
		// $15/$75. Resolving this via family (→ $5/$25) is a 3× under-bill.
		{"opus-4-0 legacy alias EXACT at legacy rates", "claude-opus-4-0", PricingSourceExact, 15, 75, 1.5, 18.75, 30, 0, 0},

		// ---- regression guards: these MUST be unchanged ----
		//
		// Sonnet 5 keeps the introductory $2/$10 through 2026-08-31.
		{"guard: sonnet-5 keeps INTRO 2/10", "claude-sonnet-5", PricingSourceExact, 2, 10, 0.20, 2.50, 4, 0, 0},
		{"guard: sonnet-4-6 exact", "claude-sonnet-4-6", PricingSourceExact, 3, 15, 0.30, 3.75, 6, 0, 0},
		// Sonnet 4.5 keeps its per-SKU 200K long-context tier — the bare
		// family row carries none and must not have displaced it.
		{"guard: sonnet-4-5 keeps its LC tier", "claude-sonnet-4-5", PricingSourceExact, 3, 15, 0.30, 3.75, 6, 0, 200_000},
		{"guard: sonnet-3-7 deprecated exact", "claude-sonnet-3-7", PricingSourceExact, 3, 15, 0.30, 3.75, 6, 0, 0},
		{"guard: haiku-4-5 exact", "claude-haiku-4-5", PricingSourceExact, 1, 5, 0.10, 1.25, 2, 0, 0},
		{"guard: haiku-4.5 dot variant exact", "claude-haiku-4.5", PricingSourceExact, 1, 5, 0.10, 1.25, 2, 0, 0},
		// Legacy 3.5 rows — do NOT start with "claude-sonnet"/"claude-haiku",
		// so the new bare prefixes cannot reach them.
		{"guard: 3-5-sonnet legacy rates", "claude-3-5-sonnet", PricingSourceExact, 3, 15, 0.30, 3.75, 6, 0, 0},
		{"guard: 3-5-haiku legacy rates", "claude-3-5-haiku", PricingSourceExact, 0.80, 4, 0.08, 1.00, 1.6, 0, 0},
		{"guard: 3-sonnet dated legacy rates", "claude-3-sonnet-20240229", PricingSourceExact, 3, 15, 0.30, 3.75, 6, 0, 0},
		{"guard: 3-haiku dated legacy rates", "claude-3-haiku-20240307", PricingSourceExact, 0.25, 1.25, 0.03, 0.30, 0.50, 0, 0},
		// Opus guards: the sibling legacy alias and the current flagship.
		{"guard: opus-4-1 legacy exact", "claude-opus-4-1", PricingSourceExact, 15, 75, 1.5, 18.75, 30, 0, 0},
		{"guard: opus-5 flagship exact w/ fast tier", "claude-opus-5", PricingSourceExact, 5, 25, 0.50, 6.25, 10, 2, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, src, ok := tb.LookupWithSource(tc.model)
			if !ok {
				t.Fatalf("LookupWithSource(%q): ok=false (MISS → $0.00)", tc.model)
			}
			if src != tc.wantSource {
				t.Errorf("source: got %q want %q", src, tc.wantSource)
			}
			if p.Input != tc.in {
				t.Errorf("input: got %v want %v", p.Input, tc.in)
			}
			if p.Output != tc.out {
				t.Errorf("output: got %v want %v", p.Output, tc.out)
			}
			if p.CacheRead != tc.cacheR {
				t.Errorf("cache_read: got %v want %v", p.CacheRead, tc.cacheR)
			}
			if p.CacheCreation != tc.cacheW {
				t.Errorf("cache_creation: got %v want %v", p.CacheCreation, tc.cacheW)
			}
			if p.CacheCreation1h != tc.cacheW1h {
				t.Errorf("cache_creation_1h: got %v want %v", p.CacheCreation1h, tc.cacheW1h)
			}
			if p.FastMultiplier != tc.fastMult {
				t.Errorf("fast_multiplier: got %v want %v", p.FastMultiplier, tc.fastMult)
			}
			if p.LongContextThreshold != tc.wantLCThreshold {
				t.Errorf("long_context_threshold: got %v want %v", p.LongContextThreshold, tc.wantLCThreshold)
			}
		})
	}
}

// TestTable_DottedVendorPrefixStillMisses pins a KNOWN, DELIBERATELY UNFIXED
// limitation so it cannot change silently.
//
// normalizeUnpricedModel — the last-resort reducer — strips only `capi:` /
// `sweagent-capi:` router prefixes and leading path segments. It never strips
// a DOTTED vendor prefix, so Bedrock/Vertex-style ids
// (`us.anthropic.claude-opus-5:v1`, `anthropic.claude-opus-5`) do not start
// with any family key and resolve to PricingSourceMiss → $0.00 even though
// the bare `claude-opus` family row now exists.
//
// This gap is PRE-EXISTING and CLASS-WIDE (Opus 4.8 has it too, as the third
// case shows) — it is out of scope for the family-row work and is recorded
// here only so nobody assumes the family "safety net" catches it. If a future
// change teaches normalizeUnpricedModel about dotted vendor prefixes, this
// test SHOULD fail: update it deliberately rather than assuming a regression.
func TestTable_DottedVendorPrefixStillMisses(t *testing.T) {
	tb := NewTable()
	for _, model := range []string{
		"us.anthropic.claude-opus-5:v1",
		"anthropic.claude-opus-5",
		"us.anthropic.claude-opus-4-8:v1", // same class, pre-dates the opus-5 rows
	} {
		t.Run(model, func(t *testing.T) {
			p, src, ok := tb.LookupWithSource(model)
			if ok || src != PricingSourceMiss {
				t.Fatalf("LookupWithSource(%q) = (%+v, %q, %v); want MISS — the dotted-vendor-prefix gap is documented as unfixed in pricing.go's claude-opus row", model, p, src, ok)
			}
		})
	}
}

// TestTable_LastResortNormalization pins the §11.A central last-resort
// reducer in LookupWithSource: router-prefixed (capi:/sweagent-capi:) and
// provider-path-qualified (openrouter/anthropic/…) model strings that the
// exact + family ladders can't see past now resolve via one normalized retry
// (PricingSourceFamily) instead of silently billing $0. The "auto" router
// sentinel and the empty string still MISS (they name no real model — the
// cure is adapter-side, e.g. Copilot CLI Patch A). A curated host-rate
// provider-qualified key (deepseek/deepseek-v4-flash) still resolves EXACT,
// proving the last-resort step runs AFTER the curated lookups and never
// shadows them.
func TestTable_LastResortNormalization(t *testing.T) {
	tb := NewTable()
	for _, tc := range []struct {
		name, model string
		wantOK      bool
		wantSource  PricingSource
		wantInput   float64 // checked only when wantOK
		wantOutput  float64 // checked only when wantOK
	}{
		// capi: router prefix → strip → claude-sonnet-4 (was a MISS).
		{"capi prefix", "capi:claude-sonnet-4", true, PricingSourceFamily, 3, 15},
		{"sweagent-capi prefix", "sweagent-capi:claude-sonnet-4", true, PricingSourceFamily, 3, 15},
		// Provider path segments → drop all → claude-sonnet-4.6 (dot) routes
		// to the claude-sonnet-4 family (was a MISS via the openrouter/ head).
		{"provider path", "openrouter/anthropic/claude-sonnet-4.6", true, PricingSourceFamily, 3, 15},
		// Curated provider-qualified host rate still wins EXACT, not shadowed.
		{"curated host-rate key stays exact", "deepseek/deepseek-v4-flash", true, PricingSourceExact, 0.098, 0.197},
		// Router sentinels / empty name no model — still MISS.
		{"auto sentinel still miss", "auto", false, PricingSourceMiss, 0, 0},
		{"empty still miss", "", false, PricingSourceMiss, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, src, ok := tb.LookupWithSource(tc.model)
			if ok != tc.wantOK {
				t.Fatalf("LookupWithSource(%q): ok=%v want %v", tc.model, ok, tc.wantOK)
			}
			if src != tc.wantSource {
				t.Errorf("LookupWithSource(%q): source=%q want %q", tc.model, src, tc.wantSource)
			}
			if tc.wantOK && (p.Input != tc.wantInput || p.Output != tc.wantOutput) {
				t.Errorf("LookupWithSource(%q): got input=%v output=%v; want %v / %v",
					tc.model, p.Input, p.Output, tc.wantInput, tc.wantOutput)
			}
		})
	}
}

// TestTable_CursorGrokPricing pins Cursor's own Grok catalog rows. Cursor's
// effort-labelled ids have explicit entries, keeping them on Cursor's card
// rather than inheriting direct xAI's long-context surcharge or Grok 4.5's
// lower direct-provider cache rate.
func TestTable_CursorGrokPricing(t *testing.T) {
	tb := NewTable()
	for _, tc := range []struct {
		name, model string
		wantSource  PricingSource
		input       float64
		cacheRead   float64
		output      float64
	}{
		{"grok 4.6 base exact", "cursor-grok-4.6", PricingSourceExact, 2, 0.50, 6},
		{"grok 4.6 low exact", "cursor-grok-4.6-low", PricingSourceExact, 2, 0.50, 6},
		{"grok 4.6 medium exact", "cursor-grok-4.6-medium", PricingSourceExact, 2, 0.50, 6},
		{"grok 4.6 high exact", "cursor-grok-4.6-high", PricingSourceExact, 2, 0.50, 6},
		{"grok 4.6 xhigh exact", "cursor-grok-4.6-xhigh", PricingSourceExact, 2, 0.50, 6},
		{"grok 4.6 low fast exact", "cursor-grok-4.6-low-fast", PricingSourceExact, 4, 1.00, 12},
		{"grok 4.6 medium fast exact", "cursor-grok-4.6-medium-fast", PricingSourceExact, 4, 1.00, 12},
		{"grok 4.6 high fast exact", "cursor-grok-4.6-high-fast", PricingSourceExact, 4, 1.00, 12},
		{"grok 4.6 xhigh fast exact", "cursor-grok-4.6-xhigh-fast", PricingSourceExact, 4, 1.00, 12},
		{"grok 4.5 base exact", "cursor-grok-4.5", PricingSourceExact, 2, 0.50, 6},
		{"grok 4.5 low exact", "cursor-grok-4.5-low", PricingSourceExact, 2, 0.50, 6},
		{"grok 4.5 medium exact", "cursor-grok-4.5-medium", PricingSourceExact, 2, 0.50, 6},
		{"grok 4.5 high exact", "cursor-grok-4.5-high", PricingSourceExact, 2, 0.50, 6},
		{"grok 4.5 low fast exact", "cursor-grok-4.5-low-fast", PricingSourceExact, 4, 1.00, 18},
		{"grok 4.5 medium fast exact", "cursor-grok-4.5-medium-fast", PricingSourceExact, 4, 1.00, 18},
		{"grok 4.5 high fast exact", "cursor-grok-4.5-high-fast", PricingSourceExact, 4, 1.00, 18},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, src, ok := tb.LookupWithSource(tc.model)
			if !ok {
				t.Fatalf("LookupWithSource(%q) ok=false", tc.model)
			}
			if src != tc.wantSource {
				t.Fatalf("source=%q want %q", src, tc.wantSource)
			}
			if p.Input != tc.input || p.CacheRead != tc.cacheRead || p.Output != tc.output {
				t.Fatalf("rates=%+v want input=%v cacheRead=%v output=%v", p, tc.input, tc.cacheRead, tc.output)
			}
			if p.LongContextThreshold != 0 {
				t.Fatalf("Cursor row unexpectedly carries direct-xAI long-context threshold: %+v", p)
			}
		})
	}

	// A Cursor model outside the known families must remain a miss rather than
	// inheriting direct xAI pricing.
	if _, src, ok := tb.LookupWithSource("cursor-grok-4.7-medium"); ok || src != PricingSourceMiss {
		t.Fatalf("unknown Cursor id resolved as (%q, %v), want miss", src, ok)
	}

	// Direct xAI Grok keeps its own >=200K tier; Cursor rows above must not
	// mutate or inherit these fields.
	xai, src, ok := tb.LookupWithSource("grok-4.6")
	if !ok || src != PricingSourceExact {
		t.Fatalf("direct xAI grok-4.6 = (%+v, %q, %v), want exact", xai, src, ok)
	}
	if xai.LongContextThreshold != 200_000 || xai.LongContextInput != 4 ||
		xai.LongContextOutput != 12 || xai.LongContextCacheRead != 1.00 {
		t.Fatalf("direct xAI long-context tier changed: %+v", xai)
	}

	// Fast is encoded in the Cursor SKU itself. TokenBundle.Fast must not
	// apply another multiplier to the already-fast card.
	fast, src, ok := tb.LookupWithSource("cursor-grok-4.6-medium-fast")
	if !ok || src != PricingSourceExact {
		t.Fatalf("Cursor fast lookup = (%+v, %q, %v), want exact", fast, src, ok)
	}
	standardCost := ComputeBreakdown(fast, TokenBundle{Input: 100_000}).Total
	flaggedCost := ComputeBreakdown(fast, TokenBundle{Input: 100_000, Fast: true}).Total
	if flaggedCost != standardCost {
		t.Fatalf("Cursor fast SKU changed with TokenBundle.Fast: standard=%v flagged=%v", standardCost, flaggedCost)
	}

	// The free guard still wins before any explicit paid Cursor family row.
	free, src, ok := tb.LookupWithSource("cursor-grok-4.6-medium:free")
	if !ok || src != PricingSourceExact || free.Input != 0 || free.Output != 0 {
		t.Fatalf("free Cursor id = (%+v, %q, %v), want known-$0 exact", free, src, ok)
	}
}

// TestTable_CursorExactOverrideWins pins the normal precedence rule: an
// operator override for a captured Cursor id wins as an exact row.
func TestTable_CursorExactOverrideWins(t *testing.T) {
	tb := NewTable()
	override := Pricing{Input: 99, Output: 111, CacheRead: 7}
	tb.Merge(map[string]Pricing{"cursor-grok-4.6-medium": override})

	p, src, ok := tb.LookupWithSource("cursor-grok-4.6-medium")
	if !ok {
		t.Fatal("LookupWithSource(cursor-grok-4.6-medium) ok=false")
	}
	if src != PricingSourceExact {
		t.Fatalf("source=%q want %q", src, PricingSourceExact)
	}
	want := fillDefaults(override)
	if p != want {
		t.Fatalf("override result = %+v, want %+v", p, want)
	}
}

// TestTable_CodexFastModeMultiplier pins the Codex Fast mode
// (service_tier:"priority") per-SKU FastMultiplier added 2026-06-08:
// gpt-5.5 = 2.5×, gpt-5.4 = 2× (developers.openai.com/codex/speed + the
// Codex rate card, operator-confirmed). The multiplier is set ONLY on
// these two explicit SKUs — the family prefix + mini/nano/codex variants
// have no documented Fast tier and stay at 0 (standard pricing always
// applies). Also exercises ComputeBreakdown end-to-end so a fast turn
// bills the per-SKU premium. Inputs are kept below the 272K long-context
// threshold so the standard (not LC) rate is the baseline under test.
func TestTable_CodexFastModeMultiplier(t *testing.T) {
	tb := NewTable()
	for _, tc := range []struct {
		model    string
		wantMult float64
	}{
		{"gpt-5.5", 2.5},
		{"gpt-5.4", 2},
		{"gpt-5.4-mini", 0}, // no documented Fast tier
		{"gpt-5.3-codex", 0},
		{"gpt-5", 0},
	} {
		p, ok := tb.Lookup(tc.model)
		if !ok {
			t.Fatalf("Lookup %q: ok=false", tc.model)
		}
		if p.FastMultiplier != tc.wantMult {
			t.Errorf("%s FastMultiplier = %v, want %v", tc.model, p.FastMultiplier, tc.wantMult)
		}
	}

	// End-to-end: a sub-threshold (100K, < 272K LC) input-only turn bills
	// the standard input rate at standard speed and the per-SKU premium
	// when Fast is set.
	for _, tc := range []struct {
		model    string
		wantStd  float64
		wantFast float64
	}{
		{"gpt-5.5", 0.50, 1.25}, // 100K × $5/1M = $0.50 → ×2.5 = $1.25
		{"gpt-5.4", 0.25, 0.50}, // 100K × $2.50/1M = $0.25 → ×2 = $0.50
	} {
		p, _ := tb.Lookup(tc.model)
		std := ComputeBreakdown(p, TokenBundle{Input: 100_000})
		if std.Total != tc.wantStd {
			t.Errorf("%s standard total = %v, want %v", tc.model, std.Total, tc.wantStd)
		}
		fast := ComputeBreakdown(p, TokenBundle{Input: 100_000, Fast: true})
		if fast.Total != tc.wantFast {
			t.Errorf("%s fast total = %v, want %v", tc.model, fast.Total, tc.wantFast)
		}
	}
}

// TestTable_OpenWeightFamilies2026Q2Pricing pins the v1.8.2 open-weight
// model additions. Anchored to first-party / OpenRouter representative
// rates per docs/plans/open-weight-models-pricing-review-2026-06-06.md
// Problem 1 recommendation (A). Per-family `:free` cases live in
// TestTable_FreeSuffixGuard (the suffix guard covers all of them).
//
// One row per family covering an explicit SKU + the family prefix
// (longest-prefix fallback). Cross-host variants live in
// TestTable_OpenRouterServedOpenWeightPricing once the §A6 commit lands.
func TestTable_OpenWeightFamilies2026Q2Pricing(t *testing.T) {
	tb := NewTable()
	for _, tc := range []struct {
		name, model     string
		in, cacheR, out float64
		wantSource      PricingSource
	}{
		// OpenAI GPT-OSS (open weight).
		{"gpt-oss-120b", "gpt-oss-120b", 0.039, 0.0039, 0.18, PricingSourceExact},
		{"gpt-oss-20b", "gpt-oss-20b", 0.03, 0.003, 0.14, PricingSourceExact},
		{"gpt-oss family", "gpt-oss-unknown-sku", 0.039, 0.0039, 0.18, PricingSourceFamily},
		// Nvidia Nemotron 3 (canonical OpenRouter ids).
		{"nemotron-3-ultra-550b-a55b", "nemotron-3-ultra-550b-a55b", 0.50, 0.05, 2.50, PricingSourceExact},
		{"nemotron-3-super-120b-a12b", "nemotron-3-super-120b-a12b", 0.09, 0.009, 0.45, PricingSourceExact},
		{"nemotron-3-nano-30b-a3b", "nemotron-3-nano-30b-a3b", 0.04, 0.004, 0.15, PricingSourceExact},
		{"nemotron-3-ultra shorthand", "nemotron-3-ultra", 0.50, 0.05, 2.50, PricingSourceExact},
		{"nemotron family → super representative", "nemotron-unknown", 0.09, 0.009, 0.45, PricingSourceFamily},
		// Nous Hermes — flat in/out. hermes-4 rates are placeholder (= Hermes 3).
		{"hermes-3-llama-3.1-405b", "hermes-3-llama-3.1-405b", 1.00, 0.10, 1.00, PricingSourceExact},
		{"hermes-4-405b placeholder", "hermes-4-405b", 1.00, 0.10, 1.00, PricingSourceExact},
		{"hermes family", "hermes-future-sku", 1.00, 0.10, 1.00, PricingSourceFamily},
		// Alibaba Qwen — implicit cache = 20% of input on first-party.
		{"qwen3-max", "qwen3-max", 0.78, 0.156, 3.90, PricingSourceExact},
		{"qwen3-coder", "qwen3-coder", 1.50, 0.30, 7.50, PricingSourceExact},
		{"qwen family → qwen3-max", "qwen-unknown", 0.78, 0.156, 3.90, PricingSourceFamily},
		// Zhipu GLM — 5.3 latest (bumped 2026-09-07); family prefix points
		// at 5.3, which happens to be numerically identical to 5.2.
		{"glm-5", "glm-5", 1.00, 0.20, 3.20, PricingSourceExact},
		{"glm-5.1", "glm-5.1", 0.98, 0.182, 3.08, PricingSourceExact},
		{"glm-5.3", "glm-5.3", 1.40, 0.26, 4.40, PricingSourceExact},
		{"glm family → 5.3", "glm-future", 1.40, 0.26, 4.40, PricingSourceFamily},
		// Mistral — batch 50% off known-unmodelled.
		{"mistral-large", "mistral-large", 2.00, 0.20, 6.00, PricingSourceExact},
		{"mistral-medium-3", "mistral-medium-3", 1.00, 0.10, 3.00, PricingSourceExact},
		{"mistral-small", "mistral-small", 0.15, 0.015, 0.60, PricingSourceExact},
		{"mistral family → medium-3", "mistral-future", 1.00, 0.10, 3.00, PricingSourceFamily},
		// MiniMax — family → m2.7 latest.
		{"minimax-m2.7", "minimax-m2.7", 0.279, 0.0279, 1.20, PricingSourceExact},
		{"minimax-m2.5", "minimax-m2.5", 0.15, 0.015, 1.15, PricingSourceExact},
		{"minimax family → m2.7", "minimax-future", 0.279, 0.0279, 1.20, PricingSourceFamily},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, src, ok := tb.LookupWithSource(tc.model)
			if !ok {
				t.Fatalf("Lookup(%q) ok=false", tc.model)
			}
			if src != tc.wantSource {
				t.Errorf("Lookup(%q) source=%q want %q", tc.model, src, tc.wantSource)
			}
			// Epsilon-tolerant comparisons. CacheRead defaults via
			// fillDefaults = 0.10 × Input, which produces representation
			// noise for non-binary-fraction inputs (e.g. 0.039, 0.279).
			if diff := p.Input - tc.in; diff > 1e-9 || diff < -1e-9 {
				t.Errorf("Lookup(%q) input=%v want %v", tc.model, p.Input, tc.in)
			}
			if diff := p.Output - tc.out; diff > 1e-9 || diff < -1e-9 {
				t.Errorf("Lookup(%q) output=%v want %v", tc.model, p.Output, tc.out)
			}
			if diff := p.CacheRead - tc.cacheR; diff > 1e-9 || diff < -1e-9 {
				t.Errorf("Lookup(%q) cache_read=%v want %v", tc.model, p.CacheRead, tc.cacheR)
			}
			// Auto-cache shape — no separate cache-write charge.
			if p.CacheCreation != 0 {
				t.Errorf("Lookup(%q) CacheCreation=%v want 0 (auto-cache shape)",
					tc.model, p.CacheCreation)
			}
		})
	}
}

// TestTable_OpenRouterServedOpenWeightPricing pins the v1.8.2 OpenRouter
// open-weight catalog snapshot. String keys exactly as OpenRouter emits
// them — see provider-model-price-catalog-2026-06-06.md §14 + brief A6.
// Each row resolves PricingSourceExact (verbatim match wins before any
// prefix strip can pull the lookup onto a bare-id row). The host-anchor
// policy from open-weight-models-pricing-review-2026-06-06.md is what
// makes this safe: bare ids anchor to first-party / representative rate,
// provider-qualified ids preserve the per-host delta.
func TestTable_OpenRouterServedOpenWeightPricing(t *testing.T) {
	tb := NewTable()
	for _, tc := range []struct {
		name, model     string
		in, cacheR, out float64
	}{
		// OpenAI GPT-OSS via OpenRouter.
		{"openai/gpt-oss-120b", "openai/gpt-oss-120b", 0.039, 0.0039, 0.18},
		{"openai/gpt-oss-20b", "openai/gpt-oss-20b", 0.03, 0.003, 0.14},
		// Nvidia Nemotron 3 via OpenRouter.
		{"nvidia/nemotron-3-ultra-550b-a55b", "nvidia/nemotron-3-ultra-550b-a55b", 0.50, 0.05, 2.50},
		{"nvidia/nemotron-3-super-120b-a12b", "nvidia/nemotron-3-super-120b-a12b", 0.09, 0.009, 0.45},
		// Nous Hermes via OpenRouter.
		{"nousresearch/hermes-3-llama-3.1-405b", "nousresearch/hermes-3-llama-3.1-405b", 1.00, 0.10, 1.00},
		{"nousresearch/hermes-4-405b", "nousresearch/hermes-4-405b", 1.00, 0.10, 1.00},
		// Alibaba Qwen via OpenRouter (qwen/ prefix != bare qwen3-* first-party).
		{"qwen/qwen3.7-max", "qwen/qwen3.7-max", 1.25, 0.25, 3.75},
		{"qwen/qwen3.6-flash", "qwen/qwen3.6-flash", 0.1875, 0.01875, 1.125},
		// Zhipu GLM via OpenRouter (z-ai/ prefix).
		{"z-ai/glm-5.1", "z-ai/glm-5.1", 0.98, 0.182, 3.08},
		{"z-ai/glm-5-turbo", "z-ai/glm-5-turbo", 1.20, 0.24, 4.00},
		// Mistral via OpenRouter.
		{"mistralai/mistral-small-2603", "mistralai/mistral-small-2603", 0.15, 0.015, 0.60},
		{"mistralai/mistral-medium-3-5", "mistralai/mistral-medium-3-5", 1.50, 0.15, 7.50},
		// MiniMax via OpenRouter.
		{"minimax/minimax-m2.7", "minimax/minimax-m2.7", 0.26, 0.026, 1.20},
		// xAI via OpenRouter — multi-agent variant priced higher than 4.3 base.
		{"x-ai/grok-4.3", "x-ai/grok-4.3", 1.25, 0.20, 2.50},
		{"x-ai/grok-4.20-multi-agent", "x-ai/grok-4.20-multi-agent", 2.00, 0.20, 6.00},
		{"x-ai/grok-build-0.1", "x-ai/grok-build-0.1", 1.00, 0.20, 2.00},
		// Moonshot via OpenRouter.
		{"moonshotai/kimi-k2.6", "moonshotai/kimi-k2.6", 0.684, 0.144, 3.42},
		// Kimi K3 via OpenRouter — OpenRouter's own listing ($2.80/$14,
		// re-verified 2026-08-15), deliberately DIFFERENT from Moonshot's
		// first-party $3/$15 card; CacheRead mirrors Moonshot's own $0.30
		// cache-hit (OpenRouter lists no exact rate).
		{"moonshotai/kimi-k3", "moonshotai/kimi-k3", 2.80, 0.30, 14},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, src, ok := tb.LookupWithSource(tc.model)
			if !ok {
				t.Fatalf("Lookup(%q) ok=false", tc.model)
			}
			if src != PricingSourceExact {
				t.Errorf("Lookup(%q) source=%q want exact (provider-qualified, verbatim match)",
					tc.model, src)
			}
			if diff := p.Input - tc.in; diff > 1e-9 || diff < -1e-9 {
				t.Errorf("Lookup(%q) input=%v want %v", tc.model, p.Input, tc.in)
			}
			if diff := p.Output - tc.out; diff > 1e-9 || diff < -1e-9 {
				t.Errorf("Lookup(%q) output=%v want %v", tc.model, p.Output, tc.out)
			}
			if diff := p.CacheRead - tc.cacheR; diff > 1e-9 || diff < -1e-9 {
				t.Errorf("Lookup(%q) cache_read=%v want %v", tc.model, p.CacheRead, tc.cacheR)
			}
		})
	}
}

// TestTable_OllamaLocalFreeFamily pins the explicit `ollama` family-prefix
// row added in v1.8.2. Local inference runs on user hardware → $0
// per-token, but pre-this-pin `ollama/gemma3:1b`-shape strings hit
// PricingSourceMiss and the cost rollup tagged the row reliability as
// "unknown" — visually noisy on dashboards. With the row in place, the
// family-prefix ladder catches `ollama/<anything>`, returns Pricing{0,0}
// as PricingSourceFamily, and the rollup tags reliability as
// "approximate" (known-priced model with a zero rate).
//
// Also pins the Engine.Compute contract: ok=true on a known-$0 row
// (only PricingSourceMiss returns ok=false; explicit / date-stripped /
// family all return ok=true regardless of rate magnitude).
func TestTable_OllamaLocalFreeFamily(t *testing.T) {
	tb := NewTable()
	for _, model := range []string{
		"ollama/gemma4:e4b",
		"ollama/gemma3:1b",
		"ollama/qwen3-coder:30b",
		"ollama/some-future-model",
		"ollama", // bare family id resolves exact.
	} {
		t.Run(model, func(t *testing.T) {
			p, src, ok := tb.LookupWithSource(model)
			if !ok {
				t.Fatalf("Lookup(%q) ok=false; ollama should resolve via family",
					model)
			}
			if src == PricingSourceMiss {
				t.Errorf("Lookup(%q) source=miss; want exact or family", model)
			}
			if p.Input != 0 || p.Output != 0 {
				t.Errorf("Lookup(%q) non-zero rates: %+v", model, p)
			}
		})
	}

	// Engine-level: Compute returns ok=true on known-$0 rows.
	e := NewEngine(emptyIntelConfigForTest())
	cost, ok := e.Compute("ollama/gemma3:1b", TokenBundle{Input: 1_000_000, Output: 500_000})
	if !ok {
		t.Errorf("Compute(ollama/...) ok=false; known-$0 must return ok=true")
	}
	if cost != 0 {
		t.Errorf("Compute(ollama/...) cost=%v; want 0", cost)
	}
}

// emptyIntelConfigForTest returns a zero IntelligenceConfig — the engine
// boots with only baked-in defaults. Test-only helper so the ollama
// engine-level case doesn't import config in the file's main body.
func emptyIntelConfigForTest() config.IntelligenceConfig {
	return config.IntelligenceConfig{}
}

// TestTable_DeepSeek2026Q2Pricing pins the CURRENT (post 2026-08-16T16:00Z
// peak/off-peak overhaul) DeepSeek V4 rates (api-docs.deepseek.com,
// confirmed live 2026-09-07). These are the OFF-PEAK rates — the flat
// table's representative choice, since peak (2× every dimension,
// 01:00-04:00 + 06:00-10:00 UTC Mon-Fri) has no field on this struct to
// express (see the pricing.go comment above the deepseek-v4-flash row).
// The pre-overhaul flat rate ($0.14/$0.28/$0.0028 flash,
// $0.435/$0.87/$0.003625 pro) is preserved as history in dated.go — see
// TestTable_DeepSeekDatedTimeline. Cache hit → CacheRead; no separate
// cache-write charge (auto-cache, OpenAI-shape).
//
// Pins BOTH the first-party rate (bare model id) AND the OpenRouter-
// served rate (provider-qualified key) so the host-variance is
// captured cleanly. The two must NOT collapse — that would silently
// drop the OpenRouter delta on v4-flash (unaffected by DeepSeek's own
// peak/off-peak overhaul — OpenRouter runs its own flat rate).
func TestTable_DeepSeek2026Q2Pricing(t *testing.T) {
	tb := NewTable()
	for _, tc := range []struct {
		name, model     string
		in, cacheR, out float64
	}{
		// First-party (bare ids) — current off-peak rate.
		{"v4-flash", "deepseek-v4-flash", 0.22, 0.007, 0.66},
		{"v4-flash-vision-exp", "deepseek-v4-flash-vision-exp", 0.22, 0.007, 0.66},
		{"v4-pro", "deepseek-v4-pro", 0.66, 0.022, 1.98},
		{"chat alias → v4-flash", "deepseek-chat", 0.22, 0.007, 0.66},
		{"reasoner alias → v4-flash", "deepseek-reasoner", 0.22, 0.007, 0.66},
		{"v4 family → flash", "deepseek-v4", 0.22, 0.007, 0.66},
		{"deepseek family → flash", "deepseek", 0.22, 0.007, 0.66},
		// OpenRouter-served (provider-qualified) — different rates,
		// must NOT collapse to the bare rate via prefix strip.
		{"OR v4-flash 30% off", "deepseek/deepseek-v4-flash", 0.098, 0.0197, 0.197},
		{"OR v4-pro matches FP", "deepseek/deepseek-v4-pro", 0.435, 0.0036, 0.87},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, src, ok := tb.LookupWithSource(tc.model)
			if !ok {
				t.Fatalf("Lookup(%q) ok=false", tc.model)
			}
			if src != PricingSourceExact {
				t.Errorf("Lookup(%q) source=%q want exact", tc.model, src)
			}
			if p.Input != tc.in {
				t.Errorf("Lookup(%q) input=%v want %v", tc.model, p.Input, tc.in)
			}
			if p.Output != tc.out {
				t.Errorf("Lookup(%q) output=%v want %v", tc.model, p.Output, tc.out)
			}
			if p.CacheRead != tc.cacheR {
				t.Errorf("Lookup(%q) cache_read=%v want %v", tc.model, p.CacheRead, tc.cacheR)
			}
			// No cache_write — OpenAI-shape, auto-cache.
			if p.CacheCreation != 0 || p.CacheCreation1h != 0 {
				t.Errorf("Lookup(%q): CacheCreation should stay 0 (auto-cache shape): %+v",
					tc.model, p)
			}
		})
	}
	// Cross-host delta: provider-qualified MUST differ from bare for flash.
	pBare, _ := tb.Lookup("deepseek-v4-flash")
	pOR, _ := tb.Lookup("deepseek/deepseek-v4-flash")
	if pBare.Input == pOR.Input || pBare.Output == pOR.Output {
		t.Errorf("v4-flash bare ($%v/$%v) and OpenRouter ($%v/$%v) MUST differ",
			pBare.Input, pBare.Output, pOR.Input, pOR.Output)
	}
}

// TestTable_FreeSuffixGuard pins the `:free` suffix guard added to
// LookupWithSource. Open-weight free tiers on OpenRouter / Kilo Gateway
// (nemotron-3-super-120b-a12b:free, gpt-oss-120b:free,
// deepseek/deepseek-v4-flash:free, hermes-4-405b:free, etc.) genuinely
// cost $0 — but the moment any paid `<family>` row is added, a
// `<family>:free` string would fall through the date-strip and
// family-prefix ladder and inherit the paid family rate. The guard
// returns Pricing{Input:0, Output:0} as PricingSourceExact (so cost
// rollups tag the row as known-$0, not "unknown" or "approximate")
// for ANY model id ending in `:free`, BEFORE the ladder runs.
//
// The verbatim exact-match check still wins, so a user can pin a
// non-zero rate by adding an explicit `<model>:free` entry above —
// the guard is a defensive default, not a hard override.
func TestTable_FreeSuffixGuard(t *testing.T) {
	tb := NewTable()
	for _, model := range []string{
		"nemotron-3-super-120b-a12b:free",
		"gpt-oss-120b:free",
		"hermes-4-405b:free",
		"deepseek-v4-flash:free",
		// Provider-qualified shape (OpenRouter ids):
		"deepseek/deepseek-v4-flash:free",
		"nvidia/nemotron-3-super-120b-a12b:free",
		"moonshotai/kimi-k2.6:free",
		"openai/gpt-oss-120b:free",
		// Case variations: OpenRouter sometimes capitalises in user-
		// supplied catalog mirrors. The guard lowercases before suffix
		// check, so :Free / :FREE resolve identically.
		"some-model:Free",
		"another-model:FREE",
	} {
		t.Run(model, func(t *testing.T) {
			p, src, ok := tb.LookupWithSource(model)
			if !ok {
				t.Fatalf("LookupWithSource(%q) ok=false; want ok=true", model)
			}
			if src != PricingSourceExact {
				t.Errorf("LookupWithSource(%q) source=%q want exact (known-$0, not family fallback)",
					model, src)
			}
			if p.Input != 0 || p.Output != 0 || p.CacheRead != 0 {
				t.Errorf("LookupWithSource(%q) rates non-zero: %+v", model, p)
			}
		})
	}
}

// TestTable_FreeSuffixGuardOverridable verifies the guard doesn't block
// an explicit override. Users who want to pin a non-zero `:free` rate
// (e.g. a private host that's about to stop being free) add an explicit
// row; the verbatim exact-match check above the guard returns that row.
func TestTable_FreeSuffixGuardOverridable(t *testing.T) {
	tb := NewTable()
	tb.Merge(map[string]Pricing{
		"some-private-host/model:free": {Input: 0.50, Output: 1.50},
	})
	p, src, ok := tb.LookupWithSource("some-private-host/model:free")
	if !ok || src != PricingSourceExact {
		t.Fatalf("explicit override: ok=%v src=%q want ok=true exact", ok, src)
	}
	if p.Input != 0.50 || p.Output != 1.50 {
		t.Errorf("explicit override rates lost: %+v", p)
	}
}

// TestTable_ProviderQualifiedExactWinsOverBare pins the lookup-precedence
// invariant the open-weight pricing additions rely on: a verbatim
// `<provider>/<model>` row resolves as PricingSourceExact BEFORE any
// date-strip / family-prefix reduction can pull it onto the bare
// `<model>` rate. This is what lets DeepSeek's first-party
// (deepseek-v4-flash $0.14/$0.28) and OpenRouter-served
// (deepseek/deepseek-v4-flash $0.098/$0.197) rows coexist with
// different rates — same model string after stripProviderPrefix, but
// the adapter that emits the qualified id (e.g. clinecli passing
// `deepseek/deepseek-v4-flash` through verbatim) bills at the
// OpenRouter rate; an adapter that pre-strips to the bare id bills at
// the first-party rate.
//
// Uses a synthetic Table rather than the baked-in defaults so a future
// pricing-table edit can't accidentally pass this test by changing the
// rates to coincide.
func TestTable_ProviderQualifiedExactWinsOverBare(t *testing.T) {
	tb := &Table{exact: map[string]Pricing{
		"some-model":           {Input: 1.00, Output: 5.00},
		"some-host/some-model": {Input: 0.50, Output: 2.50}, // host serves it cheaper
	}}
	// Bare id: first-party rate.
	pBare, srcBare, ok := tb.LookupWithSource("some-model")
	if !ok || srcBare != PricingSourceExact {
		t.Fatalf("bare: ok=%v src=%q want ok=true exact", ok, srcBare)
	}
	if pBare.Input != 1.00 || pBare.Output != 5.00 {
		t.Errorf("bare rates: %+v want $1/$5", pBare)
	}
	// Provider-qualified: host rate, NOT bare rate via prefix-strip.
	pHost, srcHost, ok := tb.LookupWithSource("some-host/some-model")
	if !ok || srcHost != PricingSourceExact {
		t.Fatalf("host: ok=%v src=%q want ok=true exact", ok, srcHost)
	}
	if pHost.Input != 0.50 || pHost.Output != 2.50 {
		t.Errorf("host rates lost to prefix-strip: %+v want $0.50/$2.50", pHost)
	}
	// The two MUST differ — proves the lookup didn't collapse them.
	if pBare.Input == pHost.Input || pBare.Output == pHost.Output {
		t.Errorf("bare and host rates collapsed: bare=%+v host=%+v", pBare, pHost)
	}
}

func TestTable_LookupDateStripped(t *testing.T) {
	tb := &Table{exact: map[string]Pricing{
		"claude-test-4": {Input: 2, Output: 8},
	}}
	// Date-suffixed variants fall back to the bare family entry.
	p, ok := tb.Lookup("claude-test-4-20250101")
	if !ok {
		t.Fatalf("expected date-stripped fallback")
	}
	if p.Input != 2 {
		t.Errorf("got %+v", p)
	}
}

func TestTable_LookupPrefix(t *testing.T) {
	tb := &Table{exact: map[string]Pricing{
		"custom-family-v2":    {Input: 1, Output: 2},
		"custom-family-v2-sm": {Input: 0.5, Output: 1},
	}}
	// Longer prefix wins when both match.
	p, ok := tb.Lookup("custom-family-v2-sm-20260101")
	if !ok {
		t.Fatalf("expected match")
	}
	if p.Input != 0.5 {
		t.Errorf("expected longer-prefix pricing, got %+v", p)
	}
}

func TestTable_LookupUnknown(t *testing.T) {
	tb := NewTable()
	if _, ok := tb.Lookup("some-bogus-model-xyz"); ok {
		t.Errorf("unknown model should not match")
	}
	if _, ok := tb.Lookup(""); ok {
		t.Errorf("empty model should not match")
	}
}

func TestFillDefaults_CacheFromInput(t *testing.T) {
	// Only Input set — CacheRead defaults to 10% (universal across
	// providers). CacheCreation stays 0 (Anthropic-only concept; we
	// don't speculatively assign cache_write rates to non-Anthropic
	// entries — that would over-bill if a stray cache_creation_tokens
	// ever appeared on an OpenAI/Gemini row). See pricing.go
	// fillDefaults doc comment.
	p := fillDefaults(Pricing{Input: 10, Output: 50})
	if p.CacheRead != 1 {
		t.Errorf("CacheRead default wrong: %+v", p)
	}
	if p.CacheCreation != 0 {
		t.Errorf("CacheCreation should NOT be defaulted (non-Anthropic shape): %+v", p)
	}
	if p.CacheCreation1h != 0 {
		t.Errorf("CacheCreation1h should NOT be defaulted without explicit CacheCreation: %+v", p)
	}
}

func TestFillDefaults_RespectsExplicit(t *testing.T) {
	p := fillDefaults(Pricing{Input: 10, Output: 50, CacheRead: 0.05, CacheCreation: 9})
	if p.CacheRead != 0.05 || p.CacheCreation != 9 {
		t.Errorf("explicit cache rates overwritten: %+v", p)
	}
}

func TestTable_Merge(t *testing.T) {
	tb := NewTable()
	tb.Merge(map[string]Pricing{
		"claude-sonnet-4-20250514": {Input: 99, Output: 999},
	})
	p, _ := tb.Lookup("claude-sonnet-4-20250514")
	if p.Input != 99 || p.Output != 999 {
		t.Errorf("override not applied: %+v", p)
	}
}

func TestCompute_Basic(t *testing.T) {
	p := Pricing{Input: 3, Output: 15, CacheRead: 0.3, CacheCreation: 3.75}
	got := Compute(p, TokenBundle{
		Input:         1_000_000,
		Output:        500_000,
		CacheRead:     200_000,
		CacheCreation: 100_000,
	})
	// 3 + 7.5 + 0.06 + 0.375 = 10.935
	want := 10.935
	if diff := got - want; diff > 1e-9 || diff < -1e-9 {
		t.Errorf("Compute: got %v want %v", got, want)
	}
}

func TestCompute_ZeroTokens(t *testing.T) {
	if got := Compute(Pricing{Input: 3, Output: 15}, TokenBundle{}); got != 0 {
		t.Errorf("zero tokens: got %v", got)
	}
}

func TestStripDateSuffix(t *testing.T) {
	cases := []struct {
		in, out string
	}{
		{"claude-sonnet-4-20250514", "claude-sonnet-4"},
		{"claude-sonnet-4", "claude-sonnet-4"},
		{"gpt-4o", "gpt-4o"},
		{"x-2025", "x-2025"},
		{"x-99990101", "x"},
	}
	for _, tc := range cases {
		if got := stripDateSuffix(tc.in); got != tc.out {
			t.Errorf("stripDateSuffix(%q) = %q, want %q", tc.in, got, tc.out)
		}
	}
}

// TestTable_OpusUniformPricingNoLongContext pins audit F2 (2026-06-08):
// Opus has UNIFORM pricing with NO context-size tier, even on the 1M-context
// beta (platform.claude.com/docs/en/about-claude/pricing, operator-confirmed).
// The `[1m]` suffix that claude-code / cowork append for 1M-context turns
// therefore resolves — via the family-prefix fallback — to the SAME flat
// rates as the base SKU, never a long-context premium. This guards against
// (a) someone adding a phantom Opus LC tier, and (b) a future auditor
// re-opening the "is Opus [1m] under-billed above 200K?" question.
func TestTable_OpusUniformPricingNoLongContext(t *testing.T) {
	tbl := NewTable()
	// A 300K-prompt turn (well past the 200K Sonnet threshold) must cost the
	// same on the [1m] variant as on the base SKU — proving no LC dispatch.
	bundle := TokenBundle{Input: 300_000, Output: 5_000}
	for _, base := range []string{"claude-opus-4-7", "claude-opus-4-8", "claude-opus-4-6"} {
		bp, _, ok := tbl.LookupWithSource(base)
		if !ok {
			t.Fatalf("%s: not priced", base)
		}
		if bp.LongContextThreshold != 0 {
			t.Errorf("%s: LongContextThreshold=%d, want 0 (Opus is uniform by context)", base, bp.LongContextThreshold)
		}
		lp, _, ok := tbl.LookupWithSource(base + "[1m]")
		if !ok {
			t.Fatalf("%s[1m]: not priced", base)
		}
		if lp.Input != bp.Input || lp.Output != bp.Output || lp.CacheRead != bp.CacheRead {
			t.Errorf("%s[1m] rates (%v/%v/%v) != base (%v/%v/%v) — Opus 1M-context is flat-priced",
				base, lp.Input, lp.Output, lp.CacheRead, bp.Input, bp.Output, bp.CacheRead)
		}
		if got, want := Compute(lp, bundle), Compute(bp, bundle); got != want {
			t.Errorf("%s[1m] 300K-prompt cost %.6f != base %.6f", base, got, want)
		}
	}
}

// TestTable_2026Q3ResearchBatch pins the 2026-07-23 research batch (new
// providers + Mythos 5): exact rates for one representative row per new
// family. Cache-less rows check only Input/Output; the free rows check
// Input==Output==0 explicitly.
func TestTable_2026Q3ResearchBatch(t *testing.T) {
	tb := NewTable()
	const skipCache = -1.0
	for _, tc := range []struct {
		name, model     string
		in, out, cacheR float64
	}{
		{"claude-mythos-5", "claude-mythos-5", 10, 50, 1},
		// claude-mythos family prefix stays at the UNIVERSAL 0.10x cache-read
		// ($1) — the 0.025x discount is scoped by Anthropic's own footnote
		// to the two NAMED Mythos 5.1 / Fable 5.1 SKUs, not to a family row
		// pricing an unknown future SKU (see the pricing.go comment next to
		// the claude-mythos row, and the fable-6 case in
		// TestTable_Anthropic2026Q2Pricing). Identical to claude-mythos-5.
		{"claude-mythos (family, universal cache-read)", "claude-mythos", 10, 50, 1},
		{"qwen3.5-plus", "qwen3.5-plus", 0.40, 2.40, 0.04},
		{"qwen3.5-flash", "qwen3.5-flash", 0.10, 0.40, 0.01},
		{"qwen3.5-omni-plus", "qwen3.5-omni-plus", 1.40, 8.30, skipCache},
		{"qwen3.5-omni-flash", "qwen3.5-omni-flash", 0.40, 2.20, skipCache},
		{"qwen3.7-plus", "qwen3.7-plus", 0.40, 1.60, 0.04},
		{"qwen/qwen3.7-plus", "qwen/qwen3.7-plus", 0.40, 1.60, 0.04},
		{"qwen3.8-max-preview", "qwen3.8-max-preview", 1.25, 3.75, 0.25},
		// qwen/qwen3.5-plus alias uses the REAL OpenRouter rate, which
		// deliberately differs from the bare DashScope key above (P1-2 fix).
		{"qwen/qwen3.5-plus", "qwen/qwen3.5-plus", 0.30, 1.80, skipCache},
		{"qwen/qwen3.5-flash", "qwen/qwen3.5-flash", 0.10, 0.40, 0.01},
		{"glm-5.2", "glm-5.2", 1.40, 4.40, 0.26},
		{"z-ai/glm-5.2", "z-ai/glm-5.2", 1.40, 4.40, 0.26},
		// minimax-m3 pins the LIST rate ($0.60/$2.40/$0.12), not the
		// running "permanent" 50%-off promo ($0.30/$1.20/$0.06) — a promo,
		// however framed, can revert without notice (2026-08 sweep).
		{"minimax-m3", "minimax-m3", 0.60, 2.40, 0.12},
		{"minimax/minimax-m3", "minimax/minimax-m3", 0.60, 2.40, 0.12},
		{"hy3", "hy3", 0.15, 0.59, 0.037},
		{"tencent/hy3", "tencent/hy3", 0.15, 0.59, 0.037},
		{"step-3.5-flash", "step-3.5-flash", 0.10, 0.30, skipCache},
		{"stepfun/step-3.5-flash", "stepfun/step-3.5-flash", 0.10, 0.30, skipCache},
		{"ernie-5.1", "ernie-5.1", 0.59, 2.65, skipCache},
		{"doubao-seed-2.0-pro", "doubao-seed-2.0-pro", 0.47, 2.35, 0.094},
		{"doubao-seed-2.0-code", "doubao-seed-2.0-code", 0.47, 2.35, 0.094},
		{"doubao-seed-2.0-lite", "doubao-seed-2.0-lite", 0.088, 0.53, 0.018},
		{"doubao-seed-2.0-mini", "doubao-seed-2.0-mini", 0.029, 0.29, 0.006},
		{"doubao-seed-2-0-pro", "doubao-seed-2-0-pro", 0.47, 2.35, 0.094},
		{"doubao-seed-2-0-code", "doubao-seed-2-0-code", 0.47, 2.35, 0.094},
		{"doubao-seed-2-0-lite", "doubao-seed-2-0-lite", 0.088, 0.53, 0.018},
		{"doubao-seed-2-0-mini", "doubao-seed-2-0-mini", 0.029, 0.29, 0.006},
		{"muse-spark-1.1", "muse-spark-1.1", 1.25, 4.25, 0.15},
		{"muse-spark-1.2", "muse-spark-1.2", 1.25, 4.25, 0.15},
		{"muse-spark-1.2-contributor", "muse-spark-1.2-contributor", 0.10, 0.20, 0.002},
		{"muse-spark (family) → standard rate", "muse-spark-1.3", 1.25, 4.25, 0.15},
		{"north-mini-code-1-0 (free)", "north-mini-code-1-0", 0, 0, skipCache},
		{"cohere/north-mini-code (free)", "cohere/north-mini-code", 0, 0, skipCache},
		{"fugu-ultra", "fugu-ultra", 5, 30, 0.50},
		{"sakana/fugu-ultra", "sakana/fugu-ultra", 5, 30, 0.50},
		{"thinkingmachines/inkling", "thinkingmachines/inkling", 1, 4.05, skipCache},
		{"inkling (bare alias)", "inkling", 1, 4.05, skipCache},
		{"jamba-mini-2", "jamba-mini-2", 0.20, 0.40, skipCache},
		{"gemini-omni-flash-preview", "gemini-omni-flash-preview", 1.50, 9, skipCache},
		{"sarvam-30b (free)", "sarvam-30b", 0, 0, skipCache},
		{"sarvam-105b (free)", "sarvam-105b", 0, 0, skipCache},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, ok := tb.Lookup(tc.model)
			if !ok {
				t.Fatalf("Lookup(%q) ok=false", tc.model)
			}
			if p.Input != tc.in {
				t.Errorf("input: got %v want %v", p.Input, tc.in)
			}
			if p.Output != tc.out {
				t.Errorf("output: got %v want %v", p.Output, tc.out)
			}
			if tc.cacheR != skipCache && p.CacheRead != tc.cacheR {
				t.Errorf("cache_read: got %v want %v", p.CacheRead, tc.cacheR)
			}
		})
	}

	// north-mini-code-1-0 is genuinely free — both dimensions exactly zero,
	// not merely "cheap".
	p, ok := tb.Lookup("north-mini-code-1-0")
	if !ok {
		t.Fatalf("Lookup(north-mini-code-1-0) ok=false")
	}
	if p.Input != 0 || p.Output != 0 {
		t.Errorf("north-mini-code-1-0 should be exactly free: %+v", p)
	}
}

// TestTable_MuseSpark1_2Wave pins the 2026-08-05 Muse Spark 1.2 release
// (ai.developer.meta.com/docs/pricing-rate-limits): 1.2 launches at the
// SAME standard rate as 1.1, plus the discounted "contributor" (opt-in
// data-sharing) tier and the "muse-spark" family fallback. Also pins
// WebSearchPerRequest ($2.50/1,000 queries flattened to $0.0025/call)
// and that CacheCreation stays 0 across every Muse Spark row (Meta's
// pricing page states no cache-write rate — unstated, never invented).
func TestTable_MuseSpark1_2Wave(t *testing.T) {
	tb := NewTable()
	for _, tc := range []struct {
		name, model                string
		in, out, cacheR, webSearch float64
		wantSource                 PricingSource
	}{
		{"1.1 standard", "muse-spark-1.1", 1.25, 4.25, 0.15, 0.0025, PricingSourceExact},
		{"1.2 standard, same rate as 1.1", "muse-spark-1.2", 1.25, 4.25, 0.15, 0.0025, PricingSourceExact},
		{"1.2 contributor tier: NOT swallowed by the family row", "muse-spark-1.2-contributor", 0.10, 0.20, 0.002, 0.0025, PricingSourceExact},
		{"unrecognized future version falls to the family row", "muse-spark-1.3", 1.25, 4.25, 0.15, 0.0025, PricingSourceFamily},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, src, ok := tb.LookupWithSource(tc.model)
			if !ok {
				t.Fatalf("Lookup(%q) ok=false", tc.model)
			}
			if src != tc.wantSource {
				t.Errorf("source: got %q want %q", src, tc.wantSource)
			}
			if p.Input != tc.in {
				t.Errorf("input: got %v want %v", p.Input, tc.in)
			}
			if p.Output != tc.out {
				t.Errorf("output: got %v want %v", p.Output, tc.out)
			}
			if p.CacheRead != tc.cacheR {
				t.Errorf("cache_read: got %v want %v", p.CacheRead, tc.cacheR)
			}
			if p.WebSearchPerRequest != tc.webSearch {
				t.Errorf("web_search_per_request: got %v want %v", p.WebSearchPerRequest, tc.webSearch)
			}
			if p.CacheCreation != 0 {
				t.Errorf("cache_creation: got %v want 0 (Meta publishes no cache-write rate)", p.CacheCreation)
			}
			if p.LongContextThreshold != 0 {
				t.Errorf("long_context_threshold: got %v want 0 (Meta: no premium for long context)", p.LongContextThreshold)
			}
		})
	}
}

// TestTable_2026Q3DatedSuffixFamilyResolution pins that a hypothetical
// dated Fugu Ultra SKU resolves via the "fugu-ultra" family key (the
// row itself is undated so it's eligible as a family prefix candidate;
// the dateSuffix regexp strips the trailing -YYYYMMDD before the family
// ladder is even consulted, landing on the exact "fugu-ultra" row via
// PricingSourceDateStripped).
func TestTable_2026Q3DatedSuffixFamilyResolution(t *testing.T) {
	tb := NewTable()
	base, srcBase, ok := tb.LookupWithSource("fugu-ultra")
	if !ok {
		t.Fatalf("Lookup(fugu-ultra) ok=false")
	}
	if srcBase != PricingSourceExact {
		t.Errorf("fugu-ultra source=%q want exact", srcBase)
	}

	dated, srcDated, ok := tb.LookupWithSource("fugu-ultra-20260615")
	if !ok {
		t.Fatalf("Lookup(fugu-ultra-20260615) ok=false")
	}
	if srcDated != PricingSourceDateStripped {
		t.Errorf("fugu-ultra-20260615 source=%q want date-stripped", srcDated)
	}
	if dated.Input != base.Input || dated.Output != base.Output || dated.CacheRead != base.CacheRead {
		t.Errorf("fugu-ultra-20260615 rates %+v != base %+v", dated, base)
	}
	if dated.Input != 5 || dated.Output != 30 || dated.CacheRead != 0.50 {
		t.Errorf("fugu-ultra-20260615 unexpected rates: %+v", dated)
	}
}

// TestTable_2026Q3LongestPrefixShadowing pins that every new explicit row
// added in the 2026-07-23 research batch wins longest-prefix family
// resolution against a PRE-EXISTING shorter family it could otherwise be
// shadowed by. Each case uses a synthetic dateless suffix (not a real
// -YYYYMMDD date, so the date-strip path doesn't short-circuit the family
// ladder) to force family-prefix resolution, then asserts the new row's
// rates win over the shorter pre-existing family's rates.
func TestTable_2026Q3LongestPrefixShadowing(t *testing.T) {
	tb := NewTable()
	for _, tc := range []struct {
		name           string
		probe          string // a superstring of the new key, not itself a table entry
		newKey         string // the new row expected to win
		shadowedFamily string // the shorter pre-existing family it must beat
	}{
		{"glm-5.2 over glm-5/glm", "glm-5.2-turbo", "glm-5.2", "glm-5"},
		{"minimax-m3 over minimax", "minimax-m3-turbo", "minimax-m3", "minimax"},
		{"qwen3.5-plus over qwen3", "qwen3.5-plus-turbo", "qwen3.5-plus", "qwen3"},
		{"qwen3.8-max-preview over qwen3", "qwen3.8-max-preview-turbo", "qwen3.8-max-preview", "qwen3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			newRates, ok := tb.Lookup(tc.newKey)
			if !ok {
				t.Fatalf("Lookup(%q) (new key) ok=false", tc.newKey)
			}
			shadowedRates, ok := tb.Lookup(tc.shadowedFamily)
			if !ok {
				t.Fatalf("Lookup(%q) (shadowed family) ok=false", tc.shadowedFamily)
			}
			// Sanity: the two families must actually price differently,
			// otherwise this test can't distinguish a win from a collision.
			if newRates.Input == shadowedRates.Input && newRates.Output == shadowedRates.Output {
				t.Fatalf("new key %q and shadowed family %q price identically (%+v) — test can't discriminate",
					tc.newKey, tc.shadowedFamily, newRates)
			}

			probe, src, ok := tb.LookupWithSource(tc.probe)
			if !ok {
				t.Fatalf("Lookup(%q) (probe) ok=false", tc.probe)
			}
			if src != PricingSourceFamily {
				t.Errorf("probe %q source=%q want family", tc.probe, src)
			}
			if probe.Input != newRates.Input || probe.Output != newRates.Output {
				t.Errorf("probe %q resolved to %+v, want the longer family %q's rates %+v (was shadowed by %q %+v)",
					tc.probe, probe, tc.newKey, newRates, tc.shadowedFamily, shadowedRates)
			}
		})
	}
}

// TestTable_2026Q3ClaudeMythosOverFamily pins "claude-mythos-5" beating
// "claude-mythos" in the longest-prefix ladder specifically. This uses a
// synthetic table (same
// technique as TestTable_LookupPrefix) with deliberately different rates
// on the two keys, to mechanically prove the sorted-longest-first
// familyKeys() ladder picks "claude-mythos-5" over "claude-mythos" when a
// probe string is a prefix-match for both.
func TestTable_2026Q3ClaudeMythosOverFamily(t *testing.T) {
	tb := &Table{exact: map[string]Pricing{
		"claude-mythos":   {Input: 10, Output: 50},
		"claude-mythos-5": {Input: 99, Output: 199}, // deliberately distinct from the family rate
	}}
	p, src, ok := tb.LookupWithSource("claude-mythos-5-turbo")
	if !ok {
		t.Fatalf("Lookup(claude-mythos-5-turbo) ok=false")
	}
	if src != PricingSourceFamily {
		t.Errorf("source=%q want family", src)
	}
	if p.Input != 99 || p.Output != 199 {
		t.Errorf("resolved to %+v, want the longer claude-mythos-5 rates (99/199), not the shorter claude-mythos family (10/50)", p)
	}
}

// TestTable_2026Q3PricingSourceExactVsFamily pins the exact-vs-family
// PricingSource distinction for one dated case from the research batch:
// the bare "doubao-seed-2.0-pro" row resolves PricingSourceExact, while a
// dashed, non-8-digit-dated wire ID
// ("doubao-seed-2-0-pro-260215" — Volcengine's dash-form, 6-digit YYMMDD
// suffix that dateSuffix's `-\d{8}$` regexp does NOT strip) only resolves
// via the separately-added "doubao-seed-2-0" dash-form family prefix,
// because dots and dashes are never normalized against each other
// anywhere in the lookup ladder.
func TestTable_2026Q3PricingSourceExactVsFamily(t *testing.T) {
	tb := NewTable()

	exact, src, ok := tb.LookupWithSource("doubao-seed-2.0-pro")
	if !ok {
		t.Fatalf("Lookup(doubao-seed-2.0-pro) ok=false")
	}
	if src != PricingSourceExact {
		t.Errorf("doubao-seed-2.0-pro source=%q want exact", src)
	}
	if exact.Input != 0.47 || exact.Output != 2.35 || exact.CacheRead != 0.094 {
		t.Errorf("doubao-seed-2.0-pro rates: %+v", exact)
	}

	dashed, srcDashed, ok := tb.LookupWithSource("doubao-seed-2-0-pro-260215")
	if !ok {
		t.Fatalf("Lookup(doubao-seed-2-0-pro-260215) ok=false — dash-form family prefix missing")
	}
	if srcDashed != PricingSourceFamily {
		t.Errorf("doubao-seed-2-0-pro-260215 source=%q want family (not exact, not date-stripped — "+
			"6-digit YYMMDD suffix doesn't match the 8-digit dateSuffix regexp)", srcDashed)
	}
	if dashed.Input != exact.Input || dashed.Output != exact.Output || dashed.CacheRead != exact.CacheRead {
		t.Errorf("doubao-seed-2-0-pro-260215 rates %+v != doubao-seed-2.0-pro rates %+v", dashed, exact)
	}
}

// TestTable_2026Q3DoubaoDashFormVariantsPinP1Fix pins the P1-1 fix
// (2026-07-23 codex adversarial pass): a single bare "doubao-seed-2-0"
// dash-form family key used to price EVERY dash-form dated variant —
// including the cheaper lite/mini tiers — at Pro rates, because it was
// the only dash-form entry and every dash-form dated ID is a superstring
// of it. The Pro-only case in TestTable_2026Q3PricingSourceExactVsFamily
// couldn't detect this (Pro correctly resolving to Pro rates masks a bug
// that only shows up on OTHER variants). This test exercises dated
// dash-form lite AND mini wire IDs specifically, asserting each resolves
// to ITS OWN variant's rate — not Pro's — via the per-variant dash-form
// keys added by the fix.
func TestTable_2026Q3DoubaoDashFormVariantsPinP1Fix(t *testing.T) {
	tb := NewTable()
	for _, tc := range []struct {
		name                   string
		dotForm, datedDashForm string
		in, out, cacheR        float64
	}{
		// lite and mini are the discriminating cases — their rates are
		// genuinely cheaper than Pro's, so a P1-1-style regression (a
		// single over-broad dash-form family key defaulting everything to
		// Pro rates) is caught. "code" is deliberately NOT included here:
		// by design it's priced identically to Pro (see the dot-form rows
		// in defaultPricing), so it can't discriminate a Pro-rate
		// regression — it's still covered for lookup correctness in
		// TestTable_2026Q3ResearchBatch.
		{"lite", "doubao-seed-2.0-lite", "doubao-seed-2-0-lite-260215", 0.088, 0.53, 0.018},
		{"mini", "doubao-seed-2.0-mini", "doubao-seed-2-0-mini-260215", 0.029, 0.29, 0.006},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Sanity: prove this variant's rate genuinely differs from Pro's
			// (0.47/2.35/0.094), so a wrongly-Pro-priced result would be
			// caught rather than accidentally matching.
			proRate := Pricing{Input: 0.47, Output: 2.35, CacheRead: 0.094}
			if tc.in == proRate.Input && tc.out == proRate.Output {
				t.Fatalf("%s variant rate equals Pro rate — test can't discriminate a P1-1 regression", tc.name)
			}

			dotExact, ok := tb.Lookup(tc.dotForm)
			if !ok {
				t.Fatalf("Lookup(%q) ok=false", tc.dotForm)
			}
			if dotExact.Input != tc.in || dotExact.Output != tc.out || dotExact.CacheRead != tc.cacheR {
				t.Fatalf("%q rates %+v, want {%v %v %v}", tc.dotForm, dotExact, tc.in, tc.out, tc.cacheR)
			}

			dashDated, src, ok := tb.LookupWithSource(tc.datedDashForm)
			if !ok {
				t.Fatalf("Lookup(%q) ok=false", tc.datedDashForm)
			}
			if src != PricingSourceFamily {
				t.Errorf("%q source=%q want family", tc.datedDashForm, src)
			}
			if dashDated.Input != tc.in || dashDated.Output != tc.out || dashDated.CacheRead != tc.cacheR {
				t.Errorf("P1-1 REGRESSION: %q resolved to %+v, want its own %s-tier rates {%v %v %v} — "+
					"NOT the Pro rate %+v it would get from a single over-broad dash-form family key",
					tc.datedDashForm, dashDated, tc.name, tc.in, tc.out, tc.cacheR, proRate)
			}
		})
	}
}

// TestTable_2026Q3FreeSuffixGuardCoversCohere pins that the universal
// `:free`-suffix guard (not a new explicit row) is what makes
// "cohere/north-mini-code:free" resolve to $0 — see the NOTE left next to
// the cohere/north-mini-code row in defaultPricing explaining why no
// explicit "...:free" row was added.
func TestTable_2026Q3FreeSuffixGuardCoversCohere(t *testing.T) {
	tb := NewTable()
	p, src, ok := tb.LookupWithSource("cohere/north-mini-code:free")
	if !ok {
		t.Fatalf("Lookup(cohere/north-mini-code:free) ok=false")
	}
	if src != PricingSourceExact {
		t.Errorf("cohere/north-mini-code:free source=%q want exact (via the universal :free guard)", src)
	}
	if p.Input != 0 || p.Output != 0 {
		t.Errorf("cohere/north-mini-code:free rates non-zero: %+v", p)
	}
}

// TestTable_2026Q3QwenDatedProviderQualifiedPinsP1Fix pins the P1-2 fix
// (2026-07-23 codex adversarial pass): real captured traffic contains the
// dated wire ID "qwen/qwen3.5-plus-20260420" (see
// docs/plans/provider-model-price-catalog-2026-06-06.md). Date-stripping
// that (`-\d{8}$`) yields "qwen/qwen3.5-plus", which was ABSENT from the
// table before the fix and fell through to the generic "qwen3" family
// row ($0.78/$3.90) — the wrong tier entirely. This test resolves the
// exact dated ID end-to-end and asserts it lands on the new
// "qwen/qwen3.5-plus" alias's real OpenRouter rate via
// PricingSourceDateStripped, not the qwen3 family fallback.
func TestTable_2026Q3QwenDatedProviderQualifiedPinsP1Fix(t *testing.T) {
	tb := NewTable()

	genericFamily, ok := tb.Lookup("qwen3")
	if !ok {
		t.Fatalf("Lookup(qwen3) ok=false")
	}

	p, src, ok := tb.LookupWithSource("qwen/qwen3.5-plus-20260420")
	if !ok {
		t.Fatalf("Lookup(qwen/qwen3.5-plus-20260420) ok=false")
	}
	if src != PricingSourceDateStripped {
		t.Errorf("qwen/qwen3.5-plus-20260420 source=%q want date-stripped", src)
	}
	if p.Input != 0.30 || p.Output != 1.80 {
		t.Errorf("qwen/qwen3.5-plus-20260420 rates %+v, want the real OpenRouter rate {0.30 1.80}", p)
	}
	if p.Input == genericFamily.Input && p.Output == genericFamily.Output {
		t.Errorf("P1-2 REGRESSION: qwen/qwen3.5-plus-20260420 resolved to the generic qwen3 family rate %+v "+
			"instead of its own alias rate", genericFamily)
	}

	// Bare-key alias sanity: "qwen/qwen3.5-plus" resolves exact, and
	// deliberately differs from the first-party bare "qwen3.5-plus" rate
	// (0.40/2.40) — it's real OpenRouter data, not a literal mirror.
	exact, srcExact, ok := tb.LookupWithSource("qwen/qwen3.5-plus")
	if !ok {
		t.Fatalf("Lookup(qwen/qwen3.5-plus) ok=false")
	}
	if srcExact != PricingSourceExact {
		t.Errorf("qwen/qwen3.5-plus source=%q want exact", srcExact)
	}
	if exact.Input != p.Input || exact.Output != p.Output {
		t.Errorf("qwen/qwen3.5-plus rates %+v != date-stripped resolution %+v", exact, p)
	}
	bare, ok := tb.Lookup("qwen3.5-plus")
	if !ok {
		t.Fatalf("Lookup(qwen3.5-plus) ok=false")
	}
	if exact.Input == bare.Input && exact.Output == bare.Output {
		t.Errorf("qwen/qwen3.5-plus (%+v) unexpectedly equals bare qwen3.5-plus (%+v) — "+
			"expected the real OpenRouter rate to differ from the first-party mirror", exact, bare)
	}
}

// TestTable_2026Q3MythosMatchesFableFull asserts FULL Pricing-struct
// equality (every field, including CacheCreation/CacheCreation1h/
// WebSearchPerRequest — not just Input/Output) between claude-mythos-5
// and claude-fable-5, and between their respective family keys, against
// the PRODUCTION table (NewTable(), not a synthetic one) — proving the
// real defaultPricing rows exist and mirror Fable's exactly, by design.
// It also probes a hypothetical future SKU ("claude-mythos-6") to prove
// the production "claude-mythos" family row itself resolves via
// PricingSourceFamily (the earlier TestTable_2026Q3ClaudeMythosOverFamily
// only proves the longest-prefix MECHANICS with a synthetic table and
// would still pass if the real claude-mythos row were deleted).
func TestTable_2026Q3MythosMatchesFableFull(t *testing.T) {
	tb := NewTable()

	mythos5, ok := tb.Lookup("claude-mythos-5")
	if !ok {
		t.Fatalf("Lookup(claude-mythos-5) ok=false")
	}
	fable5, ok := tb.Lookup("claude-fable-5")
	if !ok {
		t.Fatalf("Lookup(claude-fable-5) ok=false")
	}
	if mythos5 != fable5 {
		t.Errorf("claude-mythos-5 full struct %+v != claude-fable-5 full struct %+v", mythos5, fable5)
	}

	// 5.1 generation (2026-09-01): Mythos 5.1 mirrors Fable 5.1 exactly,
	// and the 5.1 pair differs from the 5 pair in EXACTLY one field —
	// CacheRead $0.25 vs $1 (the 0.025x-vs-0.1x multiplier split on the
	// pricing card, verified 2026-09-02).
	mythos51, ok := tb.Lookup("claude-mythos-5-1")
	if !ok {
		t.Fatalf("Lookup(claude-mythos-5-1) ok=false")
	}
	fable51, ok := tb.Lookup("claude-fable-5-1")
	if !ok {
		t.Fatalf("Lookup(claude-fable-5-1) ok=false")
	}
	if mythos51 != fable51 {
		t.Errorf("claude-mythos-5-1 full struct %+v != claude-fable-5-1 full struct %+v", mythos51, fable51)
	}
	wantFable51 := fable5
	wantFable51.CacheRead = 0.25
	if fable51 != wantFable51 {
		t.Errorf("claude-fable-5-1 %+v must equal claude-fable-5 with only CacheRead swapped to 0.25 (%+v)", fable51, wantFable51)
	}

	mythosFamily, ok := tb.Lookup("claude-mythos")
	if !ok {
		t.Fatalf("Lookup(claude-mythos) ok=false")
	}
	fableFamily, ok := tb.Lookup("claude-fable")
	if !ok {
		t.Fatalf("Lookup(claude-fable) ok=false")
	}
	if mythosFamily != fableFamily {
		t.Errorf("claude-mythos family full struct %+v != claude-fable family full struct %+v", mythosFamily, fableFamily)
	}

	// Prove the PRODUCTION "claude-mythos" row itself is a live family
	// prefix — not just provable via a disconnected synthetic table.
	future, src, ok := tb.LookupWithSource("claude-mythos-6")
	if !ok {
		t.Fatalf("Lookup(claude-mythos-6) ok=false — production claude-mythos family row missing or deleted")
	}
	if src != PricingSourceFamily {
		t.Errorf("claude-mythos-6 source=%q want family (production claude-mythos row must still exist)", src)
	}
	if future != mythosFamily {
		t.Errorf("claude-mythos-6 resolved to %+v, want the production claude-mythos family rate %+v", future, mythosFamily)
	}
}

// TestTable_2026Q3UnboundedPrefixKnownLimitation documents (per the P2
// finding, 2026-07-23 codex adversarial pass) that bare undated keys
// added in this batch — "hy3" and "inkling" — are, like every other
// undated bare key already in this table, unbounded strings.HasPrefix
// family roots: they will also match an unrelated future model ID that
// merely happens to start with the same characters. This is a systemic
// property of familyKeys() shared by pre-existing rows too (qwen, grok,
// mistral, ...), not a defect specific to hy3/inkling, and is
// deliberately NOT "fixed" by a 2-file patch — it's pinned here as a
// known, acknowledged limitation so a future change to the ladder's
// matching semantics is a conscious decision, not an accidental
// behavior change caught only by this test going red.
func TestTable_2026Q3UnboundedPrefixKnownLimitation(t *testing.T) {
	tb := NewTable()

	hy3Base, ok := tb.Lookup("hy3")
	if !ok {
		t.Fatalf("Lookup(hy3) ok=false")
	}
	// An unrelated hypothetical model "hy3d-turbo" (NOT a Tencent Hunyuan
	// SKU) currently resolves via the "hy3" family prefix rather than
	// missing — this is the known limitation, not a desired feature.
	collision, src, ok := tb.LookupWithSource("hy3d-turbo")
	if !ok {
		t.Fatalf("Lookup(hy3d-turbo) ok=false")
	}
	if src != PricingSourceFamily {
		t.Errorf("hy3d-turbo source=%q want family (documenting the known unbounded-prefix limitation)", src)
	}
	if collision != hy3Base {
		t.Errorf("hy3d-turbo rates %+v != hy3 base rates %+v", collision, hy3Base)
	}

	inklingBase, ok := tb.Lookup("inkling")
	if !ok {
		t.Fatalf("Lookup(inkling) ok=false")
	}
	// An unrelated hypothetical model "inklinglabs-x" currently resolves
	// via the "inkling" family prefix rather than missing.
	inklingCollision, srcInkling, ok := tb.LookupWithSource("inklinglabs-x")
	if !ok {
		t.Fatalf("Lookup(inklinglabs-x) ok=false")
	}
	if srcInkling != PricingSourceFamily {
		t.Errorf("inklinglabs-x source=%q want family (documenting the known unbounded-prefix limitation)", srcInkling)
	}
	if inklingCollision != inklingBase {
		t.Errorf("inklinglabs-x rates %+v != inkling base rates %+v", inklingCollision, inklingBase)
	}
}

// TestTable_20260816Sweep pins the 2026-08-16 price-sweep additions that
// had no dedicated exact-row test yet: grok-4.6 (base tier + its 200K
// long-context tier fields) and gemini-3.6-flash (the flash-class row
// that must NOT fall through to the Pro-class bare "gemini-3" family,
// per the family-shadow note on that row). Both rows already existed in
// defaultPricing before this sweep; this test is the mutation-proof
// harness the sweep was missing.
func TestTable_20260816Sweep(t *testing.T) {
	tb := NewTable()

	t.Run("grok-4.6 base tier (<200K)", func(t *testing.T) {
		p, src, ok := tb.LookupWithSource("grok-4.6")
		if !ok {
			t.Fatalf("Lookup(grok-4.6) ok=false")
		}
		if src != PricingSourceExact {
			t.Errorf("source=%q want exact", src)
		}
		if p.Input != 2 || p.Output != 6 || p.CacheRead != 0.50 {
			t.Errorf("base rates: %+v want input=2 output=6 cacheRead=0.50", p)
		}
		if p.LongContextThreshold != 200_000 || p.LongContextInput != 4 ||
			p.LongContextOutput != 12 || p.LongContextCacheRead != 1.00 {
			t.Errorf("long-context fields: %+v want threshold=200000 input=4 output=12 cacheRead=1.00", p)
		}
	})

	t.Run("gemini-3.6-flash exact, not shadowed by bare gemini-3", func(t *testing.T) {
		p, src, ok := tb.LookupWithSource("gemini-3.6-flash")
		if !ok {
			t.Fatalf("Lookup(gemini-3.6-flash) ok=false")
		}
		if src != PricingSourceExact {
			t.Errorf("source=%q want exact", src)
		}
		if p.Input != 0.75 || p.Output != 3.75 || p.CacheRead != 0.075 {
			t.Errorf("rates: %+v want input=0.75 output=3.75 cacheRead=0.075 (flash, not the Pro-class bare gemini-3 family)", p)
		}
	})
}

// TestTable_OrgObserverUnpricedIDs2026Q3 pins the four high-volume model ids
// that resolved to PricingSourceMiss → $0.00 on the org estate (F-COST1 /
// F-MODELS3, org-observer UI review 2026-09-02). Each must now price non-zero
// (or known-$0 for the cloaked stealth alias) rather than silently drop spend.
func TestTable_OrgObserverUnpricedIDs2026Q3(t *testing.T) {
	tb := NewTable()

	// Cursor Grok routing — API-list-equivalent to the underlying xAI SKU.
	// Every observed catalog effort variant is now an explicit pin (see the
	// cursorGrok4{5,6}Standard/Fast catalog in pricing.go); Cursor publishes
	// no xAI-style >=200K surcharge, so no long-context tier is modelled
	// (verified 2026-09-09, see TestTable_CursorGrok + engine_test.go).
	for _, tc := range []struct {
		model        string
		wantInput    float64
		wantOutput   float64
		wantLCThresh int64
		wantExactSrc bool
	}{
		{"cursor-grok-4.6-high", 2, 6, 0, true},
		{"cursor-grok-4.5-high", 2, 6, 0, true},
		// Effort variants are pinned explicitly (exact), no LC surcharge.
		{"cursor-grok-4.6-medium", 2, 6, 0, true},
		{"cursor-grok-4.5-low", 2, 6, 0, true},
		// codex cloud auto-review → Codex-codex line rate.
		{"codex-auto-review", 1.75, 14, 0, true},
	} {
		t.Run(tc.model, func(t *testing.T) {
			p, src, ok := tb.LookupWithSource(tc.model)
			if !ok {
				t.Fatalf("LookupWithSource(%q) ok=false; want priced (was a $0 MISS)", tc.model)
			}
			if p.Input != tc.wantInput || p.Output != tc.wantOutput {
				t.Errorf("LookupWithSource(%q) = input %v output %v; want %v/%v",
					tc.model, p.Input, p.Output, tc.wantInput, tc.wantOutput)
			}
			if p.LongContextThreshold != tc.wantLCThresh {
				t.Errorf("LookupWithSource(%q) LC threshold = %d; want %d",
					tc.model, p.LongContextThreshold, tc.wantLCThresh)
			}
			if tc.wantExactSrc && src != PricingSourceExact {
				t.Errorf("LookupWithSource(%q) source=%q; want exact", tc.model, src)
			}
			// Non-zero spend must now be produced.
			cost := Compute(p, TokenBundle{Input: 1_000_000, Output: 1_000_000})
			if cost <= 0 {
				t.Errorf("Compute(%q) = %v; want > 0", tc.model, cost)
			}
		})
	}

	// Stealth / cloaked preview — known-$0 (exact/family), NOT a silent MISS.
	for _, model := range []string{"stealth/ox-alpha", "stealth/ox-beta"} {
		t.Run(model, func(t *testing.T) {
			p, src, ok := tb.LookupWithSource(model)
			if !ok {
				t.Fatalf("LookupWithSource(%q) ok=false; want known-$0 (not a MISS)", model)
			}
			if src == PricingSourceMiss {
				t.Errorf("LookupWithSource(%q) source=miss; want exact/family known-$0", model)
			}
			if p.Input != 0 || p.Output != 0 {
				t.Errorf("LookupWithSource(%q) rates non-zero: %+v (cloaked window is $0)", model, p)
			}
		})
	}
}

// TestTable_20260907Sweep pins the 2026-09-07 pricing-refresh wave: the
// Anthropic Fable 5.1 / Mythos 5.1 cache-read discount (covered by
// TestTable_Anthropic2026Q2Pricing above), OpenAI's new gpt-6-astra
// flagship (base + 272K long-context tier + Fast mode), Gemini 3.8 Flash
// (its own family-shadow note, mirrored here), the Qwen3.8 Flash /
// Max-0902 additions, GLM-5.3 / GLM-5.3-Flash, the DeepSeek V4
// peak/off-peak repricing (covered by TestTable_DeepSeek2026Q2Pricing and
// TestTable_DeepSeekPeakOffPeakOverhaul in dated_test.go), and the new
// Mistral Large 3 / Medium 3.5 / Ministral 3 rows.
func TestTable_20260907Sweep(t *testing.T) {
	tb := NewTable()

	t.Run("gpt-6-astra base tier", func(t *testing.T) {
		p, src, ok := tb.LookupWithSource("gpt-6-astra")
		if !ok {
			t.Fatalf("Lookup(gpt-6-astra) ok=false")
		}
		if src != PricingSourceExact {
			t.Errorf("source=%q want exact", src)
		}
		if p.Input != 10 || p.Output != 50 || p.CacheRead != 1 || p.CacheCreation != 12.50 || p.CacheCreation1h != 12.50 {
			t.Errorf("base rates: %+v want input=10 output=50 cacheRead=1 cacheWrite=12.50/12.50", p)
		}
		if p.FastMultiplier != 2 {
			t.Errorf("FastMultiplier=%v want 2", p.FastMultiplier)
		}
		if p.LongContextThreshold != 272_000 || p.LongContextInput != 20 || p.LongContextOutput != 75 ||
			p.LongContextCacheRead != 2 || p.LongContextCacheCreation != 25 || p.LongContextCacheCreation1h != 25 {
			t.Errorf("long-context fields: %+v want threshold=272000 input=20 output=75 (1.5x) cacheRead=2 cacheWrite=25/25", p)
		}
	})

	t.Run("gpt-6 family prefix mirrors Astra", func(t *testing.T) {
		p, src, ok := tb.LookupWithSource("gpt-6-hypothetical-future-sku")
		if !ok {
			t.Fatalf("Lookup(gpt-6-hypothetical-future-sku) ok=false")
		}
		if src != PricingSourceFamily {
			t.Errorf("source=%q want family", src)
		}
		if p.Input != 10 || p.Output != 50 {
			t.Errorf("family rates: %+v want the Astra flagship shape (10/50)", p)
		}
	})

	t.Run("gemini-3.8-flash exact, not shadowed by bare gemini-3", func(t *testing.T) {
		p, src, ok := tb.LookupWithSource("gemini-3.8-flash")
		if !ok {
			t.Fatalf("Lookup(gemini-3.8-flash) ok=false")
		}
		if src != PricingSourceExact {
			t.Errorf("source=%q want exact", src)
		}
		if p.Input != 0.75 || p.Output != 3.75 || p.CacheRead != 0.075 {
			t.Errorf("rates: %+v want input=0.75 output=3.75 cacheRead=0.075 (flash, not the Pro-class bare gemini-3 family)", p)
		}
	})

	t.Run("qwen3.8-flash", func(t *testing.T) {
		p, ok := tb.Lookup("qwen3.8-flash")
		if !ok {
			t.Fatalf("Lookup(qwen3.8-flash) ok=false")
		}
		if p.Input != 0.15 || p.Output != 0.47 {
			t.Errorf("rates: %+v want input=0.15 output=0.47 (first-party DashScope rate)", p)
		}
	})

	t.Run("qwen3.8-max-0902 matches qwen3.8-max", func(t *testing.T) {
		p, src, ok := tb.LookupWithSource("qwen3.8-max-0902")
		if !ok {
			t.Fatalf("Lookup(qwen3.8-max-0902) ok=false")
		}
		if src != PricingSourceExact {
			t.Errorf("source=%q want exact", src)
		}
		want, _ := tb.Lookup("qwen3.8-max")
		if p != want {
			t.Errorf("qwen3.8-max-0902 %+v != qwen3.8-max %+v (same-price post-training refresh)", p, want)
		}
	})

	t.Run("glm-5.3 matches glm-5.2", func(t *testing.T) {
		p, ok := tb.Lookup("glm-5.3")
		if !ok {
			t.Fatalf("Lookup(glm-5.3) ok=false")
		}
		if p.Input != 1.40 || p.Output != 4.40 || p.CacheRead != 0.26 {
			t.Errorf("rates: %+v want input=1.40 output=4.40 cacheRead=0.26 (same as glm-5.2)", p)
		}
	})

	t.Run("glm-5.3-flash list rate (not the temporary 50%-off promo)", func(t *testing.T) {
		p, ok := tb.Lookup("glm-5.3-flash")
		if !ok {
			t.Fatalf("Lookup(glm-5.3-flash) ok=false")
		}
		if p.Input != 0.15 || p.Output != 0.50 {
			t.Errorf("rates: %+v want input=0.15 output=0.50 (list, not the promo 0.075/0.25)", p)
		}
		// CacheRead must be the LIST cached-input rate ($0.03), set
		// EXPLICITLY — if this were left 0, fillDefaults' 10%-of-input
		// floor would derive $0.015, which is the PROMO cache-read figure,
		// not list, silently smuggling the promo back in through the one
		// field this row didn't otherwise set.
		if p.CacheRead != 0.03 {
			t.Errorf("cacheRead: %+v want 0.03 (list), not the fillDefaults-derived 0.015 (promo)", p)
		}
	})

	t.Run("glm family prefix bumped to 5.3", func(t *testing.T) {
		p, src, ok := tb.LookupWithSource("glm-hypothetical-future-sku")
		if !ok {
			t.Fatalf("Lookup(glm-hypothetical-future-sku) ok=false")
		}
		if src != PricingSourceFamily {
			t.Errorf("source=%q want family", src)
		}
		if p.Input != 1.40 || p.Output != 4.40 {
			t.Errorf("family rates: %+v want the glm-5.3 shape (1.40/4.40), not the stale glm-5.1 anchor (0.98/3.08)", p)
		}
	})

	t.Run("mistral-large-3", func(t *testing.T) {
		p, ok := tb.Lookup("mistral-large-3")
		if !ok {
			t.Fatalf("Lookup(mistral-large-3) ok=false")
		}
		if p.Input != 0.5 || p.Output != 1.5 {
			t.Errorf("rates: %+v want input=0.5 output=1.5", p)
		}
	})

	t.Run("mistral-medium-3-5 first-party matches OpenRouter", func(t *testing.T) {
		p, ok := tb.Lookup("mistral-medium-3-5")
		if !ok {
			t.Fatalf("Lookup(mistral-medium-3-5) ok=false")
		}
		or, ok := tb.Lookup("mistralai/mistral-medium-3-5")
		if !ok {
			t.Fatalf("Lookup(mistralai/mistral-medium-3-5) ok=false")
		}
		if p != or {
			t.Errorf("bare mistral-medium-3-5 %+v != OpenRouter mistralai/mistral-medium-3-5 %+v (same upstream)", p, or)
		}
	})

	t.Run("mistral-medium-latest alias matches mistral-medium-3-5", func(t *testing.T) {
		// mistral-medium-latest is the literal API alias for Mistral Medium
		// 3.5. Without its own row it falls through to the bare "mistral"
		// family prefix ($1.00/$3.00, the medium-3 anchor) instead of the
		// real 3.5 rate ($1.50/$7.50).
		p, ok := tb.Lookup("mistral-medium-latest")
		if !ok {
			t.Fatalf("Lookup(mistral-medium-latest) ok=false")
		}
		medium35, ok := tb.Lookup("mistral-medium-3-5")
		if !ok {
			t.Fatalf("Lookup(mistral-medium-3-5) ok=false")
		}
		if p != medium35 {
			t.Errorf("mistral-medium-latest %+v != mistral-medium-3-5 %+v", p, medium35)
		}
		familyOnly, ok := tb.Lookup("mistral")
		if !ok {
			t.Fatalf("Lookup(mistral) ok=false")
		}
		if p.Input == familyOnly.Input && p.Output == familyOnly.Output {
			t.Errorf("mistral-medium-latest (%+v) unexpectedly equals the bare mistral family fallback (%+v) — "+
				"the alias should resolve to its own explicit row", p, familyOnly)
		}
	})

	t.Run("ministral 3 tiers", func(t *testing.T) {
		for _, tc := range []struct {
			model   string
			in, out float64
		}{
			{"ministral-3b", 0.1, 0.1},
			{"ministral-8b", 0.15, 0.15},
			{"ministral-14b", 0.2, 0.2},
		} {
			p, ok := tb.Lookup(tc.model)
			if !ok {
				t.Fatalf("Lookup(%q) ok=false", tc.model)
			}
			if p.Input != tc.in || p.Output != tc.out {
				t.Errorf("%s: %+v want input=%v output=%v", tc.model, p, tc.in, tc.out)
			}
		}
	})
}

// TestResolveModelKey pins the ladder ResolveModelKey shares with
// LookupWithSourceAt — it is the product's only answer to "are these two model
// strings the same model?", which the per-model BUDGET caps depend on.
func TestResolveModelKey(t *testing.T) {
	tbl := NewTable()
	cases := []struct {
		name  string
		model string
		want  string
		ok    bool
	}{
		{name: "empty resolves to nothing", model: ""},
		{name: "an exact key is itself", model: "claude-sonnet-4-5", want: "claude-sonnet-4-5", ok: true},
		{
			name:  "a dated id folds onto the same key as its family",
			model: "claude-sonnet-4-5-20250929", want: "claude-sonnet-4-5", ok: true,
		},
		{name: "a free tier is one $0 subject", model: "Some-Model:Free", want: "some-model:free", ok: true},
		{name: "an unknown model keeps no key", model: "big-pickle-9000"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := tbl.ResolveModelKey(tc.model)
			if ok != tc.ok || (tc.ok && got != tc.want) {
				t.Fatalf("ResolveModelKey(%q) = (%q, %v), want (%q, %v)", tc.model, got, ok, tc.want, tc.ok)
			}
		})
	}
	// THE PROPERTY THAT MATTERS: the family id and its dated sibling resolve to
	// ONE key, which is what makes an org cap on either spelling bite on both.
	family, fok := tbl.ResolveModelKey("claude-sonnet-4-5")
	dated, dok := tbl.ResolveModelKey("claude-sonnet-4-5-20250929")
	if !fok || !dok || family != dated {
		t.Fatalf("alias pair resolved to %q / %q", family, dated)
	}
	// A nil table never invents a key.
	if _, ok := (*Table)(nil).ResolveModelKey("claude-sonnet-4-5"); ok {
		t.Errorf("a nil table resolved a key")
	}
}

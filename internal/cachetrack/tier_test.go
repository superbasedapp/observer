package cachetrack

import (
	"testing"
	"time"
)

// TestTier_String pins the strings persisted to *.tier columns.
// Schema-stable; changing them is a schema break.
func TestTier_String(t *testing.T) {
	t.Parallel()
	tests := []struct {
		tier Tier
		want string
	}{
		{TierUnknown, "unknown"},
		{TierProxy, "proxy"},
		{TierTranscript, "transcript"},
		{TierCounts, "counts"},
		{Tier(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.tier.String(); got != tt.want {
			t.Errorf("Tier(%d).String() = %q, want %q", tt.tier, got, tt.want)
		}
	}
}

// TestCapabilitiesFor verifies the SINGLE tier → capability
// boundary (spec §24.3). Adding a new tier means adding a row
// here AND a case in CapabilitiesFor — nowhere else.
func TestCapabilitiesFor(t *testing.T) {
	t.Parallel()
	tests := []struct {
		tier Tier
		want Capabilities
	}{
		{
			tier: TierProxy,
			want: Capabilities{
				ToolsVisible:        true,
				SystemVisible:       true,
				MarkersVisible:      true,
				UsageObserved:       true,
				BlocksAreCumulative: true,
				ImplicitCache:       false,
			},
		},
		{
			tier: TierTranscript,
			want: Capabilities{
				ToolsVisible:        false,
				SystemVisible:       false,
				MarkersVisible:      false,
				UsageObserved:       true,
				BlocksAreCumulative: false,
				ImplicitCache:       false,
			},
		},
		{
			tier: TierCounts,
			want: Capabilities{
				ToolsVisible:        false,
				SystemVisible:       false,
				MarkersVisible:      false,
				UsageObserved:       true,
				BlocksAreCumulative: false,
				ImplicitCache:       false,
			},
		},
		{
			tier: TierUnknown,
			want: Capabilities{},
		},
	}
	for _, tt := range tests {
		got := CapabilitiesFor(tt.tier)
		if got != tt.want {
			t.Errorf("CapabilitiesFor(%v) = %+v, want %+v", tt.tier, got, tt.want)
		}
	}
}

// TestCapabilitiesFor_BlocksAreCumulative_Pinning is the operator-
// requested §15.3 (c) phase-2 invariant. The BlocksAreCumulative
// flag is the load-bearing capability for predictKind's
// suffix-token slicing: a wrong value silently mislabels a Tier-1
// caller as delta (predictKind sees the cumulative conversation
// summed as the "new tail" → CacheableTokens always true →
// always predict Write → no-op fix). This test pins the per-tier
// values so a future tier addition can't accidentally inherit a
// zero-value default in this critical column.
//
// Pair invariant — Capabilities is only ever constructed via
// CapabilitiesFor outside this package: verified manually via
// `grep -rn 'cachetrack.Capabilities{' internal/`; the only
// constructions are inside CapabilitiesFor itself. The engine's
// boundary backfill at ObserveTurn (`if in.Tier != TierUnknown &&
// in.Caps == (Capabilities{})`) ensures a Tier-1 caller that
// passes only `Tier=TierProxy` gets the full Capabilities derived
// at the seam.
func TestCapabilitiesFor_BlocksAreCumulative_Pinning(t *testing.T) {
	t.Parallel()
	pinned := []struct {
		tier Tier
		want bool
	}{
		{TierProxy, true},       // Anthropic API request body is cumulative
		{TierTranscript, false}, // adapter accumulator emits per-turn delta
		{TierCounts, false},     // counts tier is delta-emit
		{TierUnknown, false},    // zero-value default — safe (treats as delta)
	}
	for _, p := range pinned {
		got := CapabilitiesFor(p.tier).BlocksAreCumulative
		if got != p.want {
			t.Errorf("CapabilitiesFor(%v).BlocksAreCumulative = %v, want %v — §15.3 (c) predictKind slice anchor depends on this; a wrong value re-opens the rate-blind growth-turn regression",
				p.tier, got, p.want)
		}
	}
}

// TestCapabilitiesFor_ImplicitCache_Pinning guards the §15.3
// invariant: ImplicitCache is FALSE by tier default for every tier.
// Provider identity (OpenAI vs Anthropic) is not carried by Tier
// alone, so the proxy/adapter boundary MUST overlay ImplicitCache=
// true when observed traffic is implicit-cache shape. A future tier
// addition that silently inherits ImplicitCache=true via a copy-
// paste would route Anthropic traffic into the reduced attribution
// path, breaking §10. This test surfaces that drift.
func TestCapabilitiesFor_ImplicitCache_Pinning(t *testing.T) {
	t.Parallel()
	pinned := []struct {
		tier Tier
		want bool
	}{
		{TierProxy, false},      // Default Anthropic at the proxy seam; OpenAI overlays at boundary.
		{TierTranscript, false}, // Default Anthropic transcripts; implicit-routed adapters overlay at boundary.
		{TierCounts, false},     // Counts tier is implicit-routed-by-default expectation, BUT the
		// resolved capability is still overlaid by the adapter
		// boundary so a future Tier-1-counts adapter (codex live
		// emitter) can opt in or out without re-wiring CapabilitiesFor.
		{TierUnknown, false}, // zero-value default — safe (no implicit-cache assumptions).
	}
	for _, p := range pinned {
		got := CapabilitiesFor(p.tier).ImplicitCache
		if got != p.want {
			t.Errorf("CapabilitiesFor(%v).ImplicitCache = %v, want %v — §15.3 boundary-overlay invariant: never set true by tier default; provider/adapter MUST overlay at the seam",
				p.tier, got, p.want)
		}
	}
}

// TestAssumedBreakpoints pins the R1(a)-resolved 2-entry model:
// one system-boundary breakpoint + one rolling last-message-block
// breakpoint, BOTH at 1h tier per the live opus-4-8 capture
// (2026-06-08). The system entry models the system[1]+system[2]
// pair collapsed (Tier-2 can't tell them apart). C8 Tier-1
// detection enumerates real markers and bypasses this function.
//
// A future SDK behavior change that drops or adds breakpoints
// fails this test first — the single adjustment site is
// assumedBreakpoints() itself.
func TestAssumedBreakpoints(t *testing.T) {
	t.Parallel()
	got := assumedBreakpoints()
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2 (system + rolling-message per R1(a))", len(got))
	}
	want := []AssumedBreakpoint{
		{Level: LevelSystem, Rolling: false, TTL: TTL1h},
		{Level: LevelMessage, Rolling: true, TTL: TTL1h},
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("breakpoint %d = %+v, want %+v", i, got[i], w)
		}
	}
}

// TestWithinLookback covers the §7 row 8 / §6 lookback predicate.
func TestWithinLookback(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name                  string
		blocksSinceBreakpoint int
		want                  bool
	}{
		{"at breakpoint", 0, true},
		{"one back", 1, true},
		{"at window edge", LookbackWindow, true},
		{"one past window", LookbackWindow + 1, false},
		{"far past", 200, false},
		{"negative is out of range (defensive)", -1, false},
	}
	for _, tt := range tests {
		if got := WithinLookback(tt.blocksSinceBreakpoint); got != tt.want {
			t.Errorf("%s: WithinLookback(%d) = %v, want %v", tt.name, tt.blocksSinceBreakpoint, got, tt.want)
		}
	}
}

// TestTTLDuration covers the BlockTTL → time.Duration mapping.
// Unset / unknown defaults to 5m per §6.
func TestTTLDuration(t *testing.T) {
	t.Parallel()
	tests := []struct {
		ttl  BlockTTL
		want time.Duration
	}{
		{TTL5m, TTL5mDuration},
		{TTL1h, TTL1hDuration},
		{TTLUnset, TTL5mDuration},
		{BlockTTL(99), TTL5mDuration},
	}
	for _, tt := range tests {
		if got := TTLDuration(tt.ttl); got != tt.want {
			t.Errorf("TTLDuration(%v) = %v, want %v", tt.ttl, got, tt.want)
		}
	}
}

// TestMinCacheableTokens pins the model-family → min-cacheable
// table against the vendor page
// (platform.claude.com/docs/en/build-with-claude/prompt-caching,
// "Minimum cacheable prompt length", verified 2026-07-25). One row
// per family; any future provider update is a one-line table
// addition (§24.5 discipline).
//
// Every `want` here is a LITERAL, deliberately — including the
// 1,024 rows that land on defaultMinCacheable. Writing those as
// `defaultMinCacheable` would pin the identifier rather than the
// value: the assertion would still pass if someone redefined the
// constant to 512, which is exactly the regression the rows claim
// to guard.
func TestMinCacheableTokens(t *testing.T) {
	t.Parallel()
	tests := []struct {
		model string
		want  int
	}{
		// 512 — Opus 5 / Fable 5 / Mythos 5. Opus 5 halved the Opus
		// 4.8 minimum.
		{"claude-opus-5", 512},
		{"claude-opus-5-20260610", 512},
		{"claude-fable-5", 512},
		{"claude-mythos-5", 512},
		// Fable 5.1 / Mythos 5.1 (2026-09-01) are also 512 per the
		// vendor page (re-verified 2026-09-02); they resolve via the
		// SAME "fable-5"/"mythos-5" substring rows — no new table
		// entry needed, these rows pin that coverage.
		{"claude-fable-5-1", 512},
		{"claude-mythos-5-1", 512},
		// Case normalization: MinCacheableTokens lowercases before
		// the scan, matching the pricing registry's family scan. An
		// upper/mixed-case or vendor-decorated id must resolve to the
		// same 512 tier, not silently fall through to 1,024.
		{"CLAUDE-OPUS-5", 512},
		{"us.anthropic.Claude-Opus-5-v1:0", 512},
		{"Claude-Haiku-3-5", 2048},
		// 1024 — the fall-through default: Sonnet 5, Opus 4.8,
		// Sonnet 4.5/4.6, Sonnet 4, Opus 4/4.1. claude-sonnet-5 is
		// the shadow guard for the 512 rows: a sloppier Match (e.g.
		// "-5") would capture it.
		{"claude-sonnet-5", 1024},
		{"claude-opus-4-8", 1024},
		{"claude-sonnet-4-6", 1024},
		{"claude-sonnet-4-5", 1024},
		{"claude-sonnet-4", 1024},
		{"claude-opus-4", 1024},
		{"claude-opus-4-1", 1024},
		// 4096 — Opus 4.5 / 4.6 + Haiku 4.5. Regression guards:
		// these must NOT be shadowed by the 512 rows placed above
		// them.
		{"claude-opus-4-5", 4096},
		{"claude-opus-4-6-20250101", 4096},
		{"claude-haiku-4-5", 4096},
		// 2048 — Opus 4.7 + older Haiku 3.5. Opus 4.7 is NOT a 4,096
		// model: it sat in the 4,096 group until 2026-07-25 on a
		// stale research-doc figure, which made every
		// 2,048–4,095-token Opus 4.7 prefix report below_min for a
		// prefix the provider actually caches.
		{"claude-opus-4-7", 2048},
		{"claude-opus-4-7-20260401", 2048},
		{"claude-haiku-3-5", 2048},
		// 2048 — Mythos Preview. Distinct from claude-mythos-5
		// (512): "mythos-5" does not substring-match
		// "claude-mythos-preview", so without its own row this id
		// fell through to 1,024 — the dangerous direction (engine
		// predicts a write on a 1,024–2,047-token prefix the
		// provider never caches, then grades a mispredict).
		{"claude-mythos-preview", 2048},
		{"claude-mythos-preview-20260501", 2048},
		// Unknown model → default.
		{"gpt-5", 1024},
		{"", 1024},
	}
	for _, tt := range tests {
		if got := MinCacheableTokens(tt.model); got != tt.want {
			t.Errorf("MinCacheableTokens(%q) = %d, want %d", tt.model, got, tt.want)
		}
	}
}

// TestMaxBreakpoints documents the constant — a regression here
// would mean a provider behavior change. Pinned at 4 per
// Anthropic docs.
func TestMaxBreakpoints(t *testing.T) {
	t.Parallel()
	if MaxBreakpoints != 4 {
		t.Errorf("MaxBreakpoints = %d, want 4 (Anthropic provider cap)", MaxBreakpoints)
	}
}

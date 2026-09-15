package cachetrack

import (
	"strings"
	"time"
)

// Tier labels the provenance of a cache observation. The tier
// string survives only as a DATA LABEL on persisted rows
// (cache_segments.tier, cache_entries.tier, cache_events.tier);
// engine logic NEVER branches on a Tier value. Differences in
// what a source can see are encoded into [Capabilities] at the
// boundary; the core state machine + attribution tree read
// capability flags, not tier strings (spec §24.3).
type Tier uint8

// Tier values. The String form is persisted to the *.tier
// columns — stable across releases.
const (
	TierUnknown    Tier = iota
	TierProxy           // byte-exact: sees tools + system + markers
	TierTranscript      // claudecode JSONL reconstruction
	TierCounts          // adapters with only token counts + cadence
)

// String returns the canonical tier label persisted to the
// *.tier columns.
func (t Tier) String() string {
	switch t {
	case TierProxy:
		return "proxy"
	case TierTranscript:
		return "transcript"
	case TierCounts:
		return "counts"
	default:
		return "unknown"
	}
}

// Capabilities is the load-bearing structure of spec §24.3: the
// state machine + attribution tree read capability flags, never
// tier strings. Adding a new adapter, a new tier, or a new
// provider means setting capability flags at the boundary; the
// core logic in this package never changes.
//
// The four flags are independent — a future Tier could carry e.g.
// ToolsVisible without SystemVisible if it ever made sense. Don't
// add convenience methods that bundle them (it would re-introduce
// tier-coupling under a different name).
type Capabilities struct {
	// ToolsVisible is true when the source can observe the tools
	// array bytes (Tier 1 only). Gates §7 row 4
	// (tools_changed cause). When false, attribution falls back
	// to the residual `tools_or_system_changed`.
	ToolsVisible bool
	// SystemVisible is true when the source can observe the
	// system prompt bytes (Tier 1 only). Gates §7 row 5
	// (system_changed cause).
	SystemVisible bool
	// MarkersVisible is true when the source can observe real
	// cache_control marker positions (Tier 1 only). When false,
	// the engine assumes breakpoints via [assumedBreakpoints].
	MarkersVisible bool
	// UsageObserved is true when the source can observe per-turn
	// usage envelopes (Tier 1 + Tier 2; false for Tier 3 streaming
	// pre-final). Required for any read/write classification —
	// without it the engine cannot reconcile predictions.
	UsageObserved bool
	// BlocksAreCumulative reports whether ObserveInput.Blocks
	// carries the full prior conversation prefix in addition to the
	// new turn (Tier-1 proxy: API request body always includes the
	// entire conversation) or only the per-turn new content since
	// the last observation (Tier-2 transcript adapter: accumulator
	// emit shape resets pendingBlocks after each turn).
	//
	// Drives the predictKind suffix-token estimate at engine.go:
	// when true, estimateNewSuffixTokens slices in.Blocks from the
	// matched entry's BlockCount (the cumulative-block index at the
	// turn that created it) so the estimate scopes to the NEW tail
	// only. When false, in.Blocks is already the per-turn delta and
	// the full slice IS the new tail.
	//
	// MUST be set via [CapabilitiesFor] only — see engine.go's
	// boundary backfill at the top of ObserveTurn. A direct
	// Capabilities{} literal anywhere outside this package would
	// inherit zero-value false and silently mislabel a Tier-1 path
	// as delta; the predictKind path would then sum the entire
	// cumulative conversation and the CacheableTokens gate would
	// fire TRUE on every non-cold turn — the no-op trap §15.3 (c)
	// closes. The CapabilitiesFor pinning test
	// (TestCapabilitiesFor_BlocksAreCumulative_Pinning) guards
	// the per-tier values.
	BlocksAreCumulative bool
	// ImplicitCache reports that the provider caches automatically
	// with no explicit cache_control markers and reports only a
	// scalar cached-input count (OpenAI cached_tokens /
	// cached_input_tokens). When true the engine runs the REDUCED
	// implicit-cache attribution path ([attributeImplicit] in
	// implicit.go), NOT the Anthropic marker-based decision tree,
	// and the resulting events are EXCLUDED from the §10 Anthropic
	// MispredictRateGraded gate (numerator AND denominator) via
	// [bucketOf]'s bucketSkipped + [isRateSkipped]'s implicit-kinds
	// addition. The capability is the §15.3 seam: provider differences
	// resolve at the BOUNDARY (proxy.go for Tier-1 OpenAI; codex /
	// cline-cli / opencode / kilo adapters for Tier-2 implicit
	// routing), then the engine reads a single capability flag.
	// Never branch on provider/tier identity downstream of the
	// boundary.
	//
	// MUST be set via [CapabilitiesFor] OR resolved at the boundary
	// (proxy / adapter) before handing to [Engine.ObserveTurn]. Tier
	// alone does NOT carry the provider, so Tier-1 OpenAI starts as
	// TierProxy but the proxy seam overlays ImplicitCache=true; the
	// engine's boundary backfill respects already-set flags (the
	// `in.Caps == (Capabilities{})` guard only fills when the caller
	// left it zero). [TestCapabilitiesFor_ImplicitCache_Pinning]
	// guards the per-tier default values.
	ImplicitCache bool
}

// CapabilitiesFor returns the standard capability set for a tier.
// This is the SINGLE boundary where a tier label collapses into
// flags — every call site inside the engine consumes the returned
// Capabilities, never the Tier itself.
//
// ImplicitCache defaults to FALSE on every tier — provider identity
// (OpenAI vs Anthropic) is NOT carried by Tier alone, so the
// proxy/adapter boundary MUST overlay ImplicitCache=true when the
// observed traffic is implicit-cache shape (no markers, scalar
// cached_tokens). See [Capabilities.ImplicitCache].
func CapabilitiesFor(t Tier) Capabilities {
	switch t {
	case TierProxy:
		return Capabilities{
			ToolsVisible:        true,
			SystemVisible:       true,
			MarkersVisible:      true,
			UsageObserved:       true,
			BlocksAreCumulative: true,
			ImplicitCache:       false,
		}
	case TierTranscript:
		return Capabilities{
			ToolsVisible:        false,
			SystemVisible:       false,
			MarkersVisible:      false,
			UsageObserved:       true,
			BlocksAreCumulative: false,
			ImplicitCache:       false,
		}
	case TierCounts:
		return Capabilities{
			ToolsVisible:        false,
			SystemVisible:       false,
			MarkersVisible:      false,
			UsageObserved:       true,
			BlocksAreCumulative: false,
			ImplicitCache:       false,
		}
	default:
		return Capabilities{}
	}
}

// AssumedBreakpoint describes one inferred cache_control marker
// for a Tier-2 / Tier-3 turn where the engine cannot see the real
// request body. The engine creates one cache_entries row per
// AssumedBreakpoint per emitted observation (when
// MarkersVisible=false), nested in the order returned.
//
// Level is the chain level the breakpoint anchors at (tools /
// system / message). Rolling=true means the marker re-anchors at
// the tail on every turn (typical for the last message block);
// Rolling=false means it sits at a fixed boundary (typical for
// system breakpoints set by client conventions like Claude Code's
// system[1]+system[2]).
//
// TTL is the breakpoint's tier — drives `cache_entries.ttl_tier`
// at insert time.
type AssumedBreakpoint struct {
	Level   BlockLevel
	Rolling bool
	TTL     BlockTTL
}

// assumedBreakpoints returns the inferred cache_control breakpoint
// model the engine uses when MarkersVisible=false (Tier 2 / Tier 3).
//
// **R1(a) live capture (2026-06-08 operator) — RESOLVED.** A real
// Claude Code 2.1+ opus-4-8 request carries 3 explicit `cache_control`
// markers of the 4-max budget: two in the system array
// (`system[1]`, `system[2]`) plus one rolling marker on the last
// message block. All 1h tier. Tools blocks carry zero own markers
// but are cached under the first system breakpoint via the
// provider's hierarchy (tools → system → messages).
//
// Tier-2 transcripts cannot see system bytes, so the engine cannot
// anchor a precise prefix_hash for the system entries here — they
// are MODELED as placeholders the engine knows exist by client
// convention. The rolling message-level breakpoint is observable
// in transcripts and gets a real prefix_hash. Tier-1 (proxy, C8)
// enumerates real markers and does NOT consult this function.
//
// Spec §24.4 isolation rule: this is the SINGLE adjustment site if
// a future Claude Code SDK behavior change drops a breakpoint or
// adds a fourth. Engine call sites read it through this function;
// the returned slice's order maps to chain nesting order.
func assumedBreakpoints() []AssumedBreakpoint {
	return []AssumedBreakpoint{
		// R1(a) shape: 2 system breakpoints + 1 rolling last-message
		// breakpoint. We collapse the two system entries into one
		// "system-boundary" model here — Tier-2 can't tell them apart
		// (system bytes are invisible) and a single system-level entry
		// captures the same invalidation semantics. C8 Tier-1 detection
		// emits two real entries when the request body shows them
		// both.
		{Level: LevelSystem, Rolling: false, TTL: TTL1h},
		{Level: LevelMessage, Rolling: true, TTL: TTL1h},
	}
}

// LookbackWindow is the provider's per-breakpoint backward-walk
// bound (research doc §2.1, spec §6). Entries created more than
// this many blocks behind the current breakpoint predict a MISS
// even though they still exist in the model state
// (cause='lookback_window_missed', §7 row 8). Constant per
// Anthropic's documented behavior; not configurable.
const LookbackWindow = 20

// WithinLookback returns true when an entry created
// blocksSinceBreakpoint positions ago is still reachable from
// the current breakpoint position via the provider's backward
// walk. Negative inputs are out of range (defensive — should not
// occur, but a wrong-sign bug shouldn't produce false HITs).
func WithinLookback(blocksSinceBreakpoint int) bool {
	return blocksSinceBreakpoint >= 0 && blocksSinceBreakpoint <= LookbackWindow
}

// MaxBreakpoints is the provider's hard cap on cache_control
// markers per request (research doc §2.1, spec §6). Tier-1
// requests with more are provider-invalid; the engine logs a
// warning event and proceeds (skip, don't crash). Constant per
// Anthropic's documented limit.
const MaxBreakpoints = 4

// TTL5mDuration and TTL1hDuration are the two ephemeral cache
// TTL tiers Anthropic exposes (research doc §2.1). The state
// machine refreshes expires_at by adding the chosen duration.
const (
	TTL5mDuration = 5 * time.Minute
	TTL1hDuration = time.Hour
)

// TTLDuration returns the time.Duration for a BlockTTL. Unknown
// values fall back to the 5m default per spec §6.
func TTLDuration(ttl BlockTTL) time.Duration {
	switch ttl {
	case TTL1h:
		return TTL1hDuration
	default:
		return TTL5mDuration
	}
}

// minCacheableEntry maps a model-name substring to the per-family
// minimum prefix size required for an Anthropic provider cache to
// engage (research doc §2.1). Walked in order, first match wins;
// no match → defaultMinCacheable.
type minCacheableEntry struct {
	Match string
	Min   int
}

// minCacheableTable encodes the model-family → min-cacheable
// thresholds. Walked top-down by [MinCacheableTokens] against a
// LOWERCASED model id; one row per family, so every Match string
// here MUST be lowercase.
//
// Values verified 2026-07-25 against the vendor page
// (https://platform.claude.com/docs/en/build-with-claude/prompt-caching
// — "Minimum cacheable prompt length"), which states the minimums
// apply on every platform the model is available on. Where this
// table and the older internal research doc §2.1 disagree, the
// vendor page wins: §2.1 listed Opus 4.7 at 4,096, which was a 2×
// overstatement and is corrected to 2,048 below.
//
// Per the §24.5 table-driven discipline: keeping these as data
// (not an if/else ladder) means a future provider update is one
// row insertion — and the matching test (TestMinCacheableTokens)
// gets a one-line row for the new family.
var minCacheableTable = []minCacheableEntry{
	// MOST-SPECIFIC MATCH FIRST. `mythos-preview` (2,048) is
	// listed ABOVE the `mythos-5` row (512) purely as a
	// shadow-proofing convention: the two match strings are
	// disjoint today (`claude-mythos-preview` has 'p' after
	// "mythos-", `claude-mythos-5` has '5'), so neither can
	// capture the other's ids at any position — but if a future
	// SKU ever decorated a preview id with a `-5` generation tail,
	// first-match-wins would still resolve it to the preview row
	// rather than silently halving its threshold. Before this row
	// existed `claude-mythos-preview` fell through to
	// defaultMinCacheable (1,024), which errs in the DANGEROUS
	// direction: the engine treats a 1,024–2,047-token prefix as
	// cacheable, predicts a write, and then grades a mispredict
	// when the provider caches nothing.
	{"mythos-preview", 2048},

	// 512 tier — Opus 5, Fable 5/5.1, Mythos 5/5.1. Opus 5 HALVED
	// the Opus 4.8 minimum from 1,024 to 512, so a 512–1,023-token
	// prefix on these DOES cache upstream; before these rows
	// existed the walk fell through to defaultMinCacheable and
	// mislabelled those turns kind='below_min' /
	// cause='below_min_cacheable'. Fable 5.1 / Mythos 5.1
	// (released 2026-09-01) are also 512 per the vendor page
	// (re-verified 2026-09-02) and resolve via the SAME
	// "fable-5" / "mythos-5" substring rows — "fable-5" is a
	// substring of "claude-fable-5-1", so no new entry is needed
	// (pinned by TestMinCacheableTokens).
	//
	// Match-string choice (the walk is a substring scan over the
	// lowercased id, first match wins, so both shadow directions
	// matter):
	//
	//   - These rows sit ahead of the 4,096 / 2,048 groups
	//     deliberately. Nothing below can capture a 512-family id
	//     today — `claude-opus-5` / `claude-fable-5` /
	//     `claude-mythos-5` (with or without a `-YYYYMMDD` date
	//     tail, a `[1m]` context tag, or a `us.anthropic.…:v1`
	//     vendor decoration) contain none of "opus-4-5" /
	//     "opus-4-6" / "opus-4-7" / "haiku-4-5" / "haiku-3-5" —
	//     but ordering them first keeps that true even if a future
	//     SKU decoration ever introduced such a digit-hyphen-digit
	//     run.
	//   - Conversely these matches cannot shadow the rows below.
	//     "opus-5" requires the character right after "opus-" to
	//     be '5'; in every 1024/4096/2048-tier Opus id it is '4'
	//     (`opus-4-5`, `opus-4-6`, `opus-4-7`, `opus-4-8`,
	//     `opus-4-1`, `opus-4`). No Haiku or Sonnet id contains
	//     "opus-" / "fable-" / "mythos-" at all — notably
	//     `claude-sonnet-5`, the one other id where '5' follows a
	//     family token, matches nothing here and correctly falls
	//     through to defaultMinCacheable (1,024).
	{"opus-5", 512},
	{"fable-5", 512},
	{"mythos-5", 512},

	// 4,096 tier — Opus 4.5 / 4.6 + Haiku 4.5. NOTE this group is
	// Opus 4.5 and 4.6 ONLY: Opus 4.7 is a 2,048 model per the
	// vendor page and lives in the group below.
	{"opus-4-5", 4096},
	{"opus-4-6", 4096},
	{"haiku-4-5", 4096},

	// 2,048 tier — Opus 4.7 + older Haiku 3.5. Opus 4.7 sat in the
	// 4,096 group until 2026-07-25 on the strength of research doc
	// §2.1; the vendor page puts it at 2,048, and the 2× error made
	// every 2,048–4,095-token Opus 4.7 prefix report
	// kind='below_min' / cause='below_min_cacheable' for a prefix
	// the provider actually cached.
	//
	// Non-collision with the 4,096 group above is positional, not
	// ordering-dependent: "opus-4-7" and "opus-4-5"/"opus-4-6"
	// differ in their final character, so no id can contain both
	// (any single id has exactly one generation token there), and
	// "haiku-3-5" vs "haiku-4-5" likewise. Swapping the two groups
	// would not change any result.
	{"opus-4-7", 2048},
	{"haiku-3-5", 2048},
}

// defaultMinCacheable is the fall-through threshold for Anthropic
// models with no [minCacheableTable] row — 1,024 tokens (vendor
// page, verified 2026-07-25). It is NOT the provider-wide floor: a
// lower 512 tier sits in the table (Opus 5 / Fable 5 / Mythos 5),
// and higher 4,096 / 2,048 tiers sit there too. Models that
// legitimately land on this default today include Sonnet 5, Opus
// 4.8, Sonnet 4.5/4.6, Sonnet 4 and Opus 4/4.1 — treat that as an
// example list, not an enumeration; any unlisted or non-Anthropic
// model string lands here as well.
const defaultMinCacheable = 1024

// MinCacheableTokens returns the per-model-family minimum prefix
// size required for an Anthropic provider cache to engage. Below
// threshold → no entry, kind='below_min', cause=
// 'below_min_cacheable' (§7 row 10).
//
// Family matching is a substring scan because model strings carry
// SKU suffixes (e.g. `claude-opus-4-7`,
// `claude-haiku-3-5-20240620`) that include the family marker
// verbatim. The id is LOWERCASED first, so a caller that hands in
// a vendor-decorated or upper-case id (`CLAUDE-OPUS-5`,
// `US.ANTHROPIC.CLAUDE-OPUS-5-V1:0`) resolves to the same family
// the pricing registry's family scan resolves it to — that scan
// also lowercases, and the divergence used to hand Opus 5 the
// 1,024 default here while pricing billed it at Opus-5 rates.
// Every [minCacheableTable] Match string is therefore lowercase by
// construction. A future provider id scheme that breaks the
// substring assumption is a one-line table fix.
func MinCacheableTokens(model string) int {
	m := strings.ToLower(model)
	for _, e := range minCacheableTable {
		if strings.Contains(m, e.Match) {
			return e.Min
		}
	}
	return defaultMinCacheable
}

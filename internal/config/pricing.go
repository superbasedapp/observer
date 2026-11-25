package config

// This file holds the config types of [pricing] and the [intelligence]
// pricing table types.

// DefaultPricingFeedURL is the public edge route serving the signed pricing
// feed (docs/plans/pricing-sync-tokenomics-to-platform-plan-2026-09-11.md §B.4).
// The body names no org and no subject, so it is cacheable and verified offline
// against the compiled-in PricingFeedPublicKeyV1.
const DefaultPricingFeedURL = "https://superbased.app/api/pricing/v1/observer-pricing"

// PricingSectionConfig is the [pricing] surface. It is a thin holder for the
// [pricing.feed] sub-block today (D7 chose a NEW top-level namespace over
// [intelligence.pricing.feed] so the feed reads as its own concern). LOCAL-ONLY.
type PricingSectionConfig struct {
	// Feed is the [pricing.feed] sub-block — the standalone-node pricing feed
	// client.
	Feed PricingFeedConfig `toml:"feed"`
}

// PricingFeedConfig is the [pricing.feed] surface — the pricing feed client for
// a STANDALONE (non-enrolled) node (plan §C.3). It is the case that needs a new
// node->internet path, and it is ON by default (operator decision 2026-09-20,
// reversing the former zero-egress-by-default invariant D3): with this Default()
// seed the node fetches prices from the public feed so its costing tracks the
// Tokenomics source without a per-node opt-in. A standalone operator who wants
// zero egress opts OUT with `[pricing.feed] enabled = false`.
//
// An ENROLLED node (individual or managed) ignores this block entirely — it
// receives prices through the org rail, which is the one authority per enrolled
// node (§C.3/D8); the standalone-vs-enrolled resolution lives next to
// orgpricing.Mode (Wave N), not here.
//
// Same partial-merge invariant as CacheTrackConfig/PredictConfig: an install
// with no [pricing.feed] section gets the Default() seed (URL/interval set,
// Enabled=true), NOT a zero-valued struct, because Load() starts from
// Default() and unmarshals TOML on top. LOCAL-ONLY, never distributed.
type PricingFeedConfig struct {
	// Enabled gates the whole feed client. Default TRUE (operator decision
	// 2026-09-20): the feed is live so a standalone node's prices track the
	// public source. A node that wants zero egress sets this false, which
	// makes the feed inert — no feed is fetched and no feed source badge
	// renders — leaving it drivable only by a manual `observer pricing sync`.
	Enabled bool `toml:"enabled"`
	// Auto turns on the BACKGROUND poller (in addition to the manual sync).
	// Default TRUE (operator decision 2026-09-20): an Enabled node polls on
	// the PollIntervalHours cadence without further setup. Set false to keep
	// the feed enabled but fetch only on an explicit `observer pricing sync`.
	Auto bool `toml:"auto"`
	// URL is the feed endpoint. Default DefaultPricingFeedURL (the public
	// edge); overridable for testing / a self-hosted mirror.
	URL string `toml:"url"`
	// PollIntervalHours is the Auto poller cadence. Default 24 (D2: the feed
	// moves daily at most and a 304 is cheap). Ignored when Auto is false.
	PollIntervalHours int `toml:"poll_interval_hours"`
}

// PricingConfig carries per-model input/output/cache pricing.
//
// Models holds CURRENT rates — one entry per model id, replacing the
// baked-in row wholesale. Dated optionally holds a HISTORICAL rate
// timeline per model id, so a provider's mid-life price change doesn't
// silently reprice everything that came before it. Zero Dated entries =
// zero behaviour change.
type PricingConfig struct {
	Models map[string]ModelPricing `toml:"models"`
	// Dated maps a model id to its rate timeline, newest-last (order in
	// file doesn't matter; the cost engine sorts by effective_from).
	// The rate for usage at time T is the LAST entry whose
	// effective_from is <= T; if T precedes every entry, or the model
	// has no timeline, Models / the baked-in table applies.
	//
	// Because the flat table always represents CURRENT rates, a price
	// CUT needs BOTH periods spelled out — the historical one AND the
	// new one:
	//
	//	[[intelligence.pricing.dated."gpt-5.6-terra"]]
	//	effective_from = ""            # empty = since forever
	//	input = 2.50
	//	output = 15
	//	cache_read = 0.25
	//
	//	[[intelligence.pricing.dated."gpt-5.6-terra"]]
	//	effective_from = "2026-08-01"  # bare date = midnight UTC
	//	input = 1.75
	//	output = 10
	//	cache_read = 0.175
	//
	// effective_from accepts a bare date or an RFC3339 stamp. A row with
	// an unparseable date is SKIPPED (never fails closed) and reported
	// through cost.Engine.PricingWarnings.
	Dated map[string][]DatedModelPricing `toml:"dated"`
}

// DatedModelPricing is one period of a model's rate timeline: the rates
// that took effect at EffectiveFrom. Every ModelPricing field is
// available (including the long-context and fast-multiplier tiers) —
// a provider can change any of them.
//
// EffectiveFrom is inclusive: usage at exactly this instant bills at
// THIS entry's rates. Empty means "since forever", the idiomatic way to
// spell a timeline's oldest period.
type DatedModelPricing struct {
	EffectiveFrom string `toml:"effective_from"`
	ModelPricing
}

// ModelPricing is per-million-token pricing for a single model. CacheCreation
// is optional — when zero, the cost engine defaults it to 1.25 × Input
// (Anthropic's published cache-write premium). CacheCreation1h is the
// 1-hour ephemeral tier rate; defaults to 2 × CacheCreation when zero.
//
// LongContextThreshold + LongContext* model providers that reprice an
// entire request when the prompt exceeds a token threshold (Anthropic
// Sonnet 4 / 4.5 at 200K, OpenAI gpt-5.4 / gpt-5.5 at 272K, Gemini
// 2.5 Pro / 3.1 Pro at 200K). Threshold zero disables the tier; each
// LongContext* rate falls back to its standard counterpart when zero.
type ModelPricing struct {
	Input           float64 `toml:"input"`
	Output          float64 `toml:"output"`
	CacheRead       float64 `toml:"cache_read"`
	CacheCreation   float64 `toml:"cache_creation"`
	CacheCreation1h float64 `toml:"cache_creation_1h"`

	LongContextThreshold       int64   `toml:"long_context_threshold"`
	LongContextInput           float64 `toml:"long_context_input"`
	LongContextOutput          float64 `toml:"long_context_output"`
	LongContextCacheRead       float64 `toml:"long_context_cache_read"`
	LongContextCacheCreation   float64 `toml:"long_context_cache_creation"`
	LongContextCacheCreation1h float64 `toml:"long_context_cache_creation_1h"`

	// FastMultiplier scales every per-token rate when the turn was
	// served in the provider's low-latency "fast" tier (Anthropic Opus
	// 4.8 speed:"fast" → 2× across all dimensions). Zero means no fast
	// tier. Operators can pin per-model overrides for future SKUs that
	// adopt fast mode.
	FastMultiplier float64 `toml:"fast_multiplier"`
}

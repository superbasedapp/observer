package cost

import (
	"regexp"
	"strings"
	"time"
)

// Pricing is USD per 1M tokens for one model. Zero fields are treated as
// "unknown" rather than "free" — Compute returns ok=false when the looked-up
// pricing has zero Input AND zero Output.
//
// CacheCreation is the 5-minute ephemeral cache-write rate (Anthropic's
// default cache duration). CacheCreation1h is the 1-hour ephemeral tier.
// Anthropic AND OpenAI GPT-5.6+ carry a separate cache-write tier
// (GPT-5.6+ bills explicit cache writes at 1.25× the uncached input
// rate — the first non-Anthropic explicit write tier); for the other
// OpenAI SKUs / xAI / Moonshot / Cursor entries leave both at 0.
//
// Gemini rows also leave both at 0, but for the OPPOSITE reason and with
// the opposite result: Google publishes no cache-write line at all
// because a Gemini cache write IS an ordinary input token, so the
// per-provider cacheWriteRules table derives CacheCreation = Input at
// lookup time. See applyCacheWriteRule.
//
// fillDefaults supplies these defaults when the entry leaves them blank:
//
//	CacheRead       = 0.10 × Input            (universal — every provider has cache-read)
//	CacheCreation   = (no default, stays 0)   (Anthropic-only; non-Anthropic stays 0)
//	CacheCreation1h = 2.00 × Input            (only when CacheCreation > 0)
//
// applyCacheWriteRule then runs on the resolved key and may fill a still-
// blank CacheCreation from Input for provider families whose rate card
// has no write term (Gemini today).
//
// See docs/pricing-reference.md for the full table. Pre-2026-04-29 the 1h
// default was 2 × CacheCreation = 2.5 × Input (25% over) AND CacheCreation
// was unconditionally defaulted to 1.25 × Input (which would over-bill
// non-Anthropic rows that ever carried cache_creation_tokens). Both fixed
// in v1.4.12 / v1.4.14.
//
// LongContextThreshold and the LongContext* fields model providers that
// reprice an entire request at a higher tier when the prompt is large.
// Anthropic Sonnet 4 / 4.5 reprice above 200K input tokens; OpenAI
// gpt-5.4 / gpt-5.5 above 272K; Gemini 2.5 Pro / 3.1 Pro Preview above
// 200K. Threshold is compared against (Input + CacheRead + CacheCreation)
// at Compute time — that's the full prompt window the provider sees,
// including the cached portion. When Threshold is zero the entry has no
// LC tier and standard rates always apply. Each LongContext* rate falls
// back to its standard counterpart when zero, so an entry can override
// only the dimensions that actually change at the LC tier.
type Pricing struct {
	Input           float64 `json:"input"`
	Output          float64 `json:"output"`
	CacheRead       float64 `json:"cache_read"`
	CacheCreation   float64 `json:"cache_creation"`
	CacheCreation1h float64 `json:"cache_creation_1h"`

	LongContextThreshold       int64   `json:"long_context_threshold,omitempty"`
	LongContextInput           float64 `json:"long_context_input,omitempty"`
	LongContextOutput          float64 `json:"long_context_output,omitempty"`
	LongContextCacheRead       float64 `json:"long_context_cache_read,omitempty"`
	LongContextCacheCreation   float64 `json:"long_context_cache_creation,omitempty"`
	LongContextCacheCreation1h float64 `json:"long_context_cache_creation_1h,omitempty"`

	// WebSearchPerRequest is USD per server-side web_search call (Anthropic's
	// "$10 per 1,000 searches" → 0.01). Charged as a flat per-request fee on
	// top of any input/output tokens. Zero means the provider doesn't bill
	// web_search separately (or the entry was authored before this field
	// existed). Has no long-context tier.
	WebSearchPerRequest float64 `json:"web_search_per_request,omitempty"`

	// FastMultiplier scales every per-token rate when the turn was served
	// in the provider's low-latency "fast" tier. Two providers use it:
	//
	//   - Anthropic Opus 4.8 Fast mode (request `speed:"fast"`) — a flat
	//     2× across input/output/cache. Published rates are $10/$50 vs
	//     $5/$25, and 2× of the standard rate set is mathematically the
	//     same as multiplying the final token cost by 2.
	//   - OpenAI / Codex Fast mode (request `service_tier:"priority"`) —
	//     a per-SKU credit premium: gpt-5.5 = 2.5×, gpt-5.4 = 2× (per
	//     developers.openai.com/codex/speed + the Codex rate card,
	//     operator-confirmed 2026-06-08). The OpenAI metered-API priority
	//     tier is a flat 2× across the board; the Codex *credit* framing
	//     (what an operator on a Codex plan actually incurs) is the
	//     per-SKU multiplier baked here. Override via config.toml to the
	//     flat-2× API-list-equivalent framing if preferred. Only gpt-5.5
	//     and gpt-5.4 document a Fast mode today; other SKUs stay 0.
	//
	// Zero means the model has no fast tier; Compute treats 0 as 1×
	// (standard pricing always applies). Set ONLY on the explicit SKU
	// entry — not on the family prefix — so future models opt in
	// explicitly. Preserves LC dispatch intact (LC rates are swapped in
	// first by lcAdjusted, then the multiplier post-multiplies).
	//
	// EXCEPTION: the OpenAI "gpt-5.6" and "gpt-6" bare family prefix rows
	// DO carry a non-zero FastMultiplier, deliberately breaking the rule
	// above. Unlike Anthropic's per-SKU cache-read discount (see the
	// claude-fable / claude-mythos family-vs-SKU split), OpenAI's Fast
	// mode premium is a flat, generation-wide multiplier documented at
	// the FAMILY level ("Fast mode doubles them"), not a named-SKU
	// carve-out — so inheriting it on the family row is the accurate
	// default for an as-yet-unseen SKU of that generation, not an
	// over-bill risk the way inheriting a cache-read discount would be.
	//
	// The flat WebSearchPerRequest fee is NOT scaled by FastMultiplier:
	// fast mode is a throughput premium on inference, not on server-tool
	// invocations.
	FastMultiplier float64 `json:"fast_multiplier,omitempty"`
}

// Table maps normalized model IDs to Pricing. Lookup is exact first; on miss,
// the date suffix (e.g. "-20250514") is stripped and retried; on miss again,
// family prefixes ("claude-sonnet-4", "gpt-4o") are tried. The zero value is
// a usable empty table.
//
// `exact` always holds CURRENT rates. `dated` optionally holds a HISTORICAL
// rate timeline per key, applied only by the *At lookups; see dated.go for
// the full contract ("the date dimension lives at the rate, not at the
// resolution"). A table with no dated timelines behaves exactly as it did
// before dated pricing existed.
type Table struct {
	exact map[string]Pricing
	dated map[string][]DatedPricing
	// enrollmentBinding is immutable provenance for the published table. It
	// is set by Engine.rebuild before the pointer is atomically published; a
	// caller that holds this Table therefore holds the exact rates and the
	// enrollment epoch that admitted them as one snapshot.
	enrollmentBinding string
	// pricingDocumentWitness is immutable provenance for the durable org
	// document that produced this table. It is paired with enrollmentBinding
	// and the rates by Engine.rebuild before atomic publication.
	pricingDocumentWitness PricingDocumentWitness
	// local is the set of keys whose rate came from this node's own
	// [intelligence.pricing] block and WON. Provenance only, like org below.
	local map[string]bool
	// org is the set of keys whose rate came from the ORG's signed price
	// document and WON (enterprise-pricing plan §3.3). It exists so a lookup
	// can report provenance — "org (negotiated)" beside a rate is the
	// difference between a surface an admin can audit and one that just shows
	// a number. It is PROVENANCE ONLY: the pricing math never reads it, and
	// composing the ladder is the engine's job, not the table's.
	org map[string]bool
}

// EnrollmentBinding reports the enrollment epoch that authenticated the org
// rows in this table. Empty means the table has no enrollment-bound org
// document, such as the seed table or a standalone public feed.
func (t *Table) EnrollmentBinding() string {
	if t == nil {
		return ""
	}
	return t.enrollmentBinding
}

// PricingDocumentWitness reports the durable org pricing document state that
// produced this table snapshot. A zero value means the source was local,
// standalone, or otherwise has no known durable org document.
func (t *Table) PricingDocumentWitness() PricingDocumentWitness {
	if t == nil {
		return PricingDocumentWitness{}
	}
	return t.pricingDocumentWitness
}

// markOrg records which keys the org owns and drops their dated timelines.
//
// The two halves belong together, which is why this is one method: an
// org-owned key's flat rate IS the org's authored rate, so a leftover seed or
// config timeline for the same id would make LookupAt answer a different
// number than Lookup for the same model on the same day — the proxy's
// capture-time stamp and the session-detail re-price would disagree, and
// neither would be wrong about its own rule. The org's document carries its
// own effective_from and the server already resolved it (F13), so there is
// nothing lost.
// markLocal records which keys this node's own overrides own.
//
// It does NOT drop dated timelines the way markOrg does: a developer's
// [intelligence.pricing.dated] block is an authored history, and the flat
// override and the timeline are two halves of one intent rather than two
// owners of one number.
func (t *Table) markLocal(keys map[string]bool) {
	if len(keys) == 0 {
		return
	}
	if t.local == nil {
		t.local = make(map[string]bool, len(keys))
	}
	for k := range keys {
		t.local[k] = true
	}
}

func (t *Table) markOrg(keys map[string]bool) {
	if len(keys) == 0 {
		return
	}
	if t.org == nil {
		t.org = make(map[string]bool, len(keys))
	}
	for k := range keys {
		t.org[k] = true
		delete(t.dated, k)
	}
}

// NewTable seeds a Table with the baked-in defaults from spec §24 and public
// pricing as of 2026-07 (Claude-family rows verified against
// platform.claude.com/docs/en/about-claude/pricing on 2026-07-12; other
// providers last synced 2026-04-29). Callers should then Merge() user
// overrides from config.toml on top.
func NewTable() *Table {
	t := &Table{exact: map[string]Pricing{}}
	for k, v := range defaultPricing {
		t.exact[k] = v
	}
	// Baked-in historical rate timelines (dated.go). Verified entries only
	// (e.g. the GPT-5.6 Terra/Luna 2026-07-30 price cut); a model with no
	// verified rate change stays on the pre-dated lookup code path.
	t.MergeDated(datedPricing)
	return t
}

// Merge copies overrides into t. Existing entries with the same key are
// replaced wholesale — partial overrides should load the current pricing and
// patch before calling Merge.
func (t *Table) Merge(overrides map[string]Pricing) {
	if t.exact == nil {
		t.exact = map[string]Pricing{}
	}
	for k, v := range overrides {
		t.exact[k] = v
	}
}

// PricingSource categorises how a Lookup resolved a model id, so callers
// can flag rows priced via fallback rather than an exact-match entry. The
// dashboard surfaces a "~" badge for non-exact rows so users can see which
// numbers came from the family prefix and which came from a baked-in rate.
type PricingSource string

const (
	// PricingSourceExact: the model id matched a table entry verbatim.
	PricingSourceExact PricingSource = "exact"
	// PricingSourceDateStripped: a date suffix (-YYYYMMDD) was stripped
	// to find a match. Same family + version, just an undated alias.
	PricingSourceDateStripped PricingSource = "date-stripped"
	// PricingSourceFamily: matched via longest-prefix family lookup
	// (e.g. claude-opus-4-7 → claude-opus-4 family rates). The exact
	// SKU isn't in our table, so the rate is inferred from the family.
	PricingSourceFamily PricingSource = "family"
	// PricingSourceMiss: nothing matched. Caller should treat as $0
	// and tag the row reliability as "unknown".
	PricingSourceMiss PricingSource = "miss"
	// PricingSourceLocal: the rate came from this node's own
	// [intelligence.pricing] override and won its place on the ladder.
	// Distinguished from PricingSourceExact because "a developer typed this"
	// and "this is the compiled default" are different facts to an operator
	// reading a price table, and the config file alone cannot say which one
	// is in force once an org can also supply rates.
	PricingSourceLocal PricingSource = "local"
	// PricingSourceOrg: the rate came from the ORG's signed price document
	// (enterprise-pricing plan §3.3) and won its place on the ladder.
	//
	// PROVENANCE BEATS THE RUNG for an org rate, deliberately. The other
	// three values answer "how confident are we that we identified this
	// SKU"; this one answers "whose rate is this", and where the two
	// disagree an admin needs the second. An org that authored the family
	// key "claude-opus-4" authored it AS a family rate on purpose, and
	// rendering the resulting match with the approximate badge would
	// describe a number the org itself chose as a guess we made. Nothing
	// branches on exact-vs-family today except that badge and
	// ingesthealth's MISS check, which is unaffected.
	PricingSourceOrg PricingSource = "org"
)

// Lookup returns pricing for the given model id. When the exact id is absent,
// it tries the date-stripped variant, then family prefixes. Returns ok=false
// only when nothing matches.
func (t *Table) Lookup(model string) (Pricing, bool) {
	p, _, ok := t.LookupWithSource(model)
	return p, ok
}

// LookupWithSource is the source-aware variant of Lookup. The second
// return value is a PricingSource describing how the match resolved
// (exact / date-stripped / family) so callers can surface a fallback
// indicator. Match precedence is identical to Lookup.
//
// Returns CURRENT rates. Callers pricing HISTORICAL usage must use
// LookupWithSourceAt with the usage timestamp — see dated.go.
func (t *Table) LookupWithSource(model string) (Pricing, PricingSource, bool) {
	return t.LookupWithSourceAt(model, time.Time{})
}

// LookupWithSourceAt is the date-aware LookupWithSource: it returns the
// rate in force for `model` at `at`.
//
// The RESOLUTION ladder below is identical for both — `at` is consulted
// only when a rung has already picked a table key, so PricingSource is
// unaffected by the date. A zero `at`, a model with no dated timeline,
// or an `at` that precedes every dated entry all resolve to the flat
// (current) rate, making this byte-identical to LookupWithSource in the
// zero-dated-entries case.
func (t *Table) LookupWithSourceAt(model string, at time.Time) (Pricing, PricingSource, bool) {
	if t == nil || t.exact == nil || model == "" {
		return Pricing{}, PricingSourceMiss, false
	}
	if _, ok := t.exact[model]; ok {
		return t.rate(model, at), t.sourceFor(model, PricingSourceExact), true
	}
	// `:free` suffix guard: every open-weight free tier on OpenRouter /
	// Kilo Gateway / first-party portals costs $0 regardless of family
	// (e.g. nemotron-3-super-120b-a12b:free, gpt-oss-120b:free,
	// deepseek/deepseek-v4-flash:free, kilo-auto/free already explicit).
	// Run BEFORE the date-strip and family-prefix ladders so adding a
	// paid `<family>` row never silently over-bills `<family>:free`
	// traffic. Returns PricingSourceExact (known-$0) so reliability tags
	// as "exact", not "unknown" or "approximate". An explicit table
	// entry for `<model>:free` above still wins because the verbatim
	// exact-match check ran first.
	if strings.HasSuffix(strings.ToLower(model), ":free") {
		return Pricing{}, PricingSourceExact, true
	}
	stripped := stripDateSuffix(model)
	if stripped != model {
		if _, ok := t.exact[stripped]; ok {
			return t.rate(stripped, at), t.sourceFor(stripped, PricingSourceDateStripped), true
		}
	}
	// Longest-prefix fallback: try progressively shorter family prefixes.
	// e.g. "claude-opus-4-1-20250805" → "claude-opus-4-1" → "claude-opus-4"
	// → "claude-opus".
	lower := strings.ToLower(model)
	for _, family := range familyKeys(t.exact) {
		if strings.HasPrefix(lower, family) {
			return t.rate(family, at), t.sourceFor(family, PricingSourceFamily), true
		}
	}
	// Last-resort normalization: strip router/provider prefixes the family
	// ladder above can't see past (capi:, sweagent-capi:, and leading
	// provider path segments like openrouter/anthropic/…), then retry
	// exact + family ONCE. The curated exact, :free, date-strip, and family
	// lookups all ran first, so a host-rate provider-qualified key
	// (e.g. deepseek/deepseek-v4-flash) still wins before we get here.
	// "auto"/"" name no real model, so normalizeUnpricedModel returns "" and
	// they correctly fall through to MISS (their cure is adapter-side).
	if norm := normalizeUnpricedModel(model); norm != "" {
		if _, ok := t.exact[norm]; ok {
			return t.rate(norm, at), t.sourceFor(norm, PricingSourceFamily), true
		}
		lnorm := strings.ToLower(norm)
		for _, family := range familyKeys(t.exact) {
			if strings.HasPrefix(lnorm, family) {
				return t.rate(family, at), t.sourceFor(family, PricingSourceFamily), true
			}
		}
	}
	return Pricing{}, PricingSourceMiss, false
}

// sourceFor reports the provenance of a resolved key: PricingSourceOrg when
// the org's signed document owns it, otherwise the resolution rung the caller
// arrived on. One helper rather than five inline conditionals so the rule has
// exactly one home — see PricingSourceOrg's doc for why provenance wins.
func (t *Table) sourceFor(key string, rung PricingSource) PricingSource {
	switch {
	case t.org[key]:
		return PricingSourceOrg
	case t.local[key]:
		return PricingSourceLocal
	default:
		return rung
	}
}

// normalizeUnpricedModel is a LAST-RESORT reducer applied only after exact,
// :free, date-strip, and family lookups have all missed in LookupWithSource.
// It strips router prefixes (capi:, sweagent-capi:) and leading provider path
// segments (openrouter/anthropic/foo -> foo) that the family-prefix ladder
// can't see past, returning a candidate to retry once. It deliberately does
// NOT touch the "auto" router sentinel or an empty string — neither names a
// real model, so both correctly remain a MISS (the fix for those lives in the
// adapter, e.g. the Copilot CLI response-body / sibling-events recovery).
// Returns "" when nothing was stripped.
func normalizeUnpricedModel(model string) string {
	out := model
	switch {
	case strings.HasPrefix(out, "capi:"):
		out = strings.TrimPrefix(out, "capi:")
	case strings.HasPrefix(out, "sweagent-capi:"):
		out = strings.TrimPrefix(out, "sweagent-capi:")
	}
	if i := strings.LastIndex(out, "/"); i >= 0 {
		out = out[i+1:] // drop ALL leading provider segments (a/b/c/model -> model)
	}
	if out == model || out == "" {
		return ""
	}
	return out
}

// Known returns the set of exact model IDs in the table. Intended for
// debugging (`observer cost --debug-pricing`).
func (t *Table) Known() []string {
	if t == nil {
		return nil
	}
	out := make([]string, 0, len(t.exact))
	for k := range t.exact {
		out = append(out, k)
	}
	return out
}

// fillDefaults applies the cache-tier defaults when the caller left them
// zero. This only runs at Lookup time so tests can assert Merge() round-trips
// exactly what was provided.
//
// CacheRead default (10% × Input) applies universally — every provider
// has a cache-read concept (cached_input on OpenAI, context-cache on
// Gemini, cache_read on Anthropic) so the default is a safe floor.
//
// CacheCreation defaults (5m and 1h) are Anthropic-specific. We do NOT
// auto-derive them from Input because Anthropic is the only provider
// with a separate cache-write tier — OpenAI bills caching automatically
// without a write charge, Gemini bills storage by time. Pre-2026-04-29
// fillDefaults set CacheCreation = 1.25 × Input unconditionally, which
// silently inflated rates for any non-Anthropic row that happened to
// carry cache_creation_tokens (a hypothetical adapter bug). After this
// fix:
//
//   - CacheCreation stays zero unless explicitly set; non-Anthropic
//     entries can never accidentally inherit Anthropic-style defaults.
//   - CacheCreation1h is defaulted to 2 × Input ONLY when CacheCreation
//     is explicit non-zero — i.e. the entry is Anthropic-shape. This
//     preserves the v1.4.12 fix where a custom Anthropic config that
//     sets only 5m can still get a sensible 1h rate.
func fillDefaults(p Pricing) Pricing {
	if p.CacheRead == 0 && p.Input > 0 {
		p.CacheRead = p.Input * 0.10
	}
	if p.CacheCreation > 0 && p.CacheCreation1h == 0 && p.Input > 0 {
		// Anthropic-shape entry with explicit 5m rate but missing 1h —
		// default to 2 × Input per Anthropic's published ratios.
		p.CacheCreation1h = p.Input * 2
	}
	return p
}

// cacheWritePolicy says how a provider bills the tokens a request WRITES
// into a prompt cache. It is a property of the provider's rate card, not
// of the AI tool that produced the turn — resolve it from the pricing
// key's provider family, never from a tool/adapter name (CLAUDE.md §3).
type cacheWritePolicy uint8

const (
	// cacheWriteRowPriced — the provider publishes a cache-write rate
	// that differs from its uncached-input rate, so the write price has
	// to live on the pricing row itself. A row that leaves CacheCreation
	// blank under this policy is billed at $0, which is the correct
	// answer for a provider that charges nothing for writes. This is the
	// DEFAULT for every family absent from cacheWriteRules: we never
	// invent a write charge we have not grounded.
	//
	// Anthropic (1.25 × input for the 5m tier, 2 × for 1h) and OpenAI
	// GPT-5.6+ (1.25 × input) are deliberately NOT in the rule table —
	// their write price is not derivable from Input, so their rows carry
	// it explicitly and must keep doing so.
	cacheWriteRowPriced cacheWritePolicy = iota

	// cacheWriteAtInputRate — the provider has no separate cache-write
	// tier: tokens written into a cache are billed as ordinary input
	// tokens, and the only cache-specific charges are the discounted
	// read rate and (for explicit caches) a per-hour storage fee. A row
	// under this policy that leaves CacheCreation blank derives it from
	// its own Input rate rather than billing writes at $0.
	cacheWriteAtInputRate
)

// cacheWriteRule maps a provider family (matched as a prefix of the
// resolved pricing-table key) to that provider's cacheWritePolicy.
type cacheWriteRule struct {
	// Family is a lower-case prefix of the pricing-table key. Matching
	// happens against the resolved key — the exact SKU row, the
	// date-stripped row, or the family-prefix row that Lookup landed on
	// — so `gemini-3-pro-high`, `gemini-3` and a user override keyed
	// `google/gemini-2.5-pro` all resolve through the same rule.
	Family string
	Policy cacheWritePolicy
	// Source records where the policy was grounded, so a future rate
	// re-verification knows what to re-check.
	Source string
}

// cacheWriteRules is the per-provider cache-write fallback table. Ordered
// rows, walked top-down, first prefix match wins; a family with no row
// keeps cacheWriteRowPriced. Add a row ONLY with a citation in Source.
//
// Grounded 2026-09-03 against Google's published rate cards:
//
//	https://ai.google.dev/gemini-api/docs/pricing
//
// Every Gemini paid-tier row on that page has exactly four price lines —
// Input, Output, "Context caching", and "Context caching (storage)" —
// and the "Context caching" line is the READ rate (10% of input across
// the whole line-up: 2.5 Pro $1.25 → $0.125, 2.5 Flash $0.30 → $0.03,
// 3.5 Flash $1.50 → $0.15, 3.6/3.7/3.8 Flash $0.75 → $0.075). There is
// no cache-CREATION line anywhere on the card, for either implicit or
// explicit caching: the tokens you put into a cache are billed once, as
// ordinary input, and the only extra term is the hourly storage fee on
// an explicit cache. So a Gemini cache write costs 1.00 × Input — not
// $0, which is what a blank CacheCreation field means everywhere else.
//
// Storage ($4.50/1M-tokens/hour on 2.5 Pro, $1.00 on the Flash line) is
// deliberately NOT modelled: it is a time-integral over a cache handle's
// TTL, we hold no cache-handle lifetime, and it applies only to EXPLICIT
// caches — the implicit caching that Antigravity/Gemini turns actually
// exercise carries no storage charge at all.
var cacheWriteRules = []cacheWriteRule{
	{
		Family: "gemini",
		Policy: cacheWriteAtInputRate,
		Source: "ai.google.dev/gemini-api/docs/pricing, verified 2026-09-03: paid-tier rows list Input / Output / Context caching (= read) / Context caching storage only; no cache-creation line, so writes bill as ordinary input",
	},
}

// applyCacheWriteRule derives the cache-write rates for a resolved
// pricing key whose row left them blank, per cacheWriteRules.
//
// It runs AFTER fillDefaults (so the universal CacheRead floor is
// already in place) and only ever fills a ZERO field: an explicit rate
// on the baked row, on a config.toml override, or on a dated timeline
// entry always wins. That keeps the rule a fallback, not an override.
//
// Both the 5m and 1h write fields are filled, and both LongContext
// counterparts when the row carries an LC tier. Providers under
// cacheWriteAtInputRate have no ephemeral write tiers at all, so
// "5m rate == 1h rate == input rate" is not an approximation — it is
// the shape of their rate card, and it means a bundle that ever splits
// writes into the 1h bucket still prices correctly instead of falling
// into a silent $0 hole.
func applyCacheWriteRule(key string, p Pricing) Pricing {
	if cacheWritePolicyFor(key) != cacheWriteAtInputRate {
		return p
	}
	if p.Input > 0 {
		if p.CacheCreation == 0 {
			p.CacheCreation = p.Input
		}
		if p.CacheCreation1h == 0 {
			p.CacheCreation1h = p.Input
		}
	}
	// LC tier: Google reprices the ENTIRE request above the threshold
	// (2.5 Pro / 3.x Pro double every dimension past 200K), so the write
	// follows the LC input rate the same way the read follows
	// LongContextCacheRead.
	if p.LongContextThreshold > 0 && p.LongContextInput > 0 {
		if p.LongContextCacheCreation == 0 {
			p.LongContextCacheCreation = p.LongContextInput
		}
		if p.LongContextCacheCreation1h == 0 {
			p.LongContextCacheCreation1h = p.LongContextInput
		}
	}
	return p
}

// cacheWritePolicyFor resolves a pricing-table key to its provider's
// cache-write policy. The key is lower-cased and, when it carries
// provider path segments (a user override keyed `google/gemini-2.5-pro`,
// say), also tried on its last segment — the same shape
// normalizeUnpricedModel reduces at the tail of the Lookup ladder.
func cacheWritePolicyFor(key string) cacheWritePolicy {
	if key == "" {
		return cacheWriteRowPriced
	}
	lower := strings.ToLower(key)
	bare := lower
	if i := strings.LastIndex(bare, "/"); i >= 0 {
		bare = bare[i+1:]
	}
	for _, r := range cacheWriteRules {
		if strings.HasPrefix(lower, r.Family) || strings.HasPrefix(bare, r.Family) {
			return r.Policy
		}
	}
	return cacheWriteRowPriced
}

// dateSuffix matches a trailing "-YYYYMMDD" on a model id.
var dateSuffix = regexp.MustCompile(`-\d{8}$`)

func stripDateSuffix(model string) string {
	return dateSuffix.ReplaceAllString(model, "")
}

// familyKeys returns the exact keys in the table that *look like* family
// prefixes (no date suffix, no version disambiguator longer than 2 chars),
// sorted longest-first so the most-specific family wins. Picked at runtime
// so users can add their own families in config.toml.
func familyKeys(exact map[string]Pricing) []string {
	out := []string{}
	for k := range exact {
		if dateSuffix.MatchString(k) {
			continue
		}
		out = append(out, strings.ToLower(k))
	}
	// Sort longest-first: a simple length-desc sort is enough because
	// "claude-opus-4-1" beats "claude-opus" without alphabetic ordering.
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if len(out[j]) > len(out[i]) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

// BakedInDefaults returns a fresh copy of the baked-in pricing table.
// The dashboard's Settings page uses this to render a "defaults"
// reference list alongside the user's overrides — clicking a default
// pre-fills an override row with that model's baked-in rates so users
// can tweak from a known-good starting point.
//
// The returned map is a copy; mutating it has no effect on engine state.
func BakedInDefaults() map[string]Pricing {
	out := make(map[string]Pricing, len(defaultPricing))
	for k, v := range defaultPricing {
		out[k] = v
	}
	return out
}

// Cursor's own Grok cards use explicit wire IDs for each effort/speed
// combination. Keep these as private shared values so the 14 catalog aliases
// cannot drift from one another; a Fast suffix already selects the Fast rate
// and must never be multiplied again by TokenBundle.Fast.
var (
	cursorGrok45Standard = Pricing{Input: 2, Output: 6, CacheRead: 0.50}
	cursorGrok45Fast     = Pricing{Input: 4, Output: 18, CacheRead: 1.00}
	cursorGrok46Standard = Pricing{Input: 2, Output: 6, CacheRead: 0.50}
	cursorGrok46Fast     = Pricing{Input: 4, Output: 12, CacheRead: 1.00}
)

// defaultPricing is the baked-in pricing table. Values are USD per 1M tokens.
// Source-of-truth: docs/pricing-reference.md (last synced 2026-04-29); the
// Claude-family rows were re-verified against the published pricing card at
// platform.claude.com/docs/en/about-claude/pricing on 2026-07-12 (Fable 5
// corrected $5/$25 → $10/$50; Sonnet 5 confirmed at the $2/$10 intro rate).
// Users can override any entry via [intelligence.pricing.models."<id>"]
// in config.toml.
//
// Family prefixes (no date suffix) are included so new dated releases
// inherit sensible defaults until a user pins them — but where Anthropic
// has changed pricing within a family (e.g. Opus 4.5+ dropped to 1/3 of
// Opus 4 / 4.1 rates), the family prefix is set to the LATEST rates so
// new releases inherit the current family pricing, not the legacy.
//
// Pre-2026-04-29 this table priced Opus 4.5+ at $15/$75 (legacy Opus 4
// rates) and used CacheCreation1h = 2.5 × Input (vs the actual 2 × Input).
// Combined this over-billed Opus 4.5+ traffic by ~3× and over-billed all
// 1h cache writes by 25%.
var defaultPricing = map[string]Pricing{
	// Anthropic — Claude Opus 5 (`claude-opus-5`), the current Opus
	// flagship. Verified against platform.claude.com/docs/en/about-claude/
	// pricing on 2026-07-25: $5 input / $25 output, cache read $0.50,
	// 5m-write $6.25, 1h-write $10, web search $10/1000 calls ($0.01/call).
	// Numerically IDENTICAL to the claude-opus-4-8 row above/below,
	// FastMultiplier included — do NOT "fix" this row to a higher tier on
	// the assumption that a newer flagship must cost more. Opus 5 is a
	// drop-in upgrade at Opus 4.8's pricing; the $10/$50 tier belongs to
	// Fable 5 / Mythos 5, not here.
	//
	// Dateless pinned snapshot — Anthropic stopped putting dates in IDs as
	// of the 4.6 gen, so there is NO `-YYYYMMDD` variant to add. The long-
	// context tag `claude-opus-5[1m]` is not an exact key either; because
	// this bare key carries no date suffix it doubles as a family prefix,
	// so `claude-opus-5[1m]` matches HERE (PricingSourceFamily, this row's
	// rates, FastMultiplier included) rather than falling through to the
	// generic `claude-opus` row — "claude-opus-5" is longer and wins the
	// longest-first sort in familyKeys. Same path a dated Opus-5 SKU would
	// take. Inheriting FastMultiplier is correct here: it is the same SKU
	// under a context tag, not a different model.
	//
	// Added 2026-07-25 to close a MISS-to-$0 defect: before this row
	// `claude-opus-5` resolved to PricingSourceMiss and costed at $0.00,
	// because the family ladder had no bare `claude-opus` key and
	// "claude-opus-4" is not a prefix of "claude-opus-5". Measured on the
	// author's own node the day the row landed: 78 Opus-5 turns over ~3 days
	// (16.76M cache-read + 1.26M cache-write tokens) reported $0.00, which
	// re-costed to $18.04 once this row existed — the under-count grew with
	// every turn until then. Same defect CLASS as the
	// 2026-07-12 claude-fable-5 incident (a wrong-tier anchor under-billing
	// 299 rows), caught the same way: a flagship SKU silently mispriced.
	//
	// FastMultiplier=2: fast mode IS supported on Opus 5 at $10 input /
	// $50 output — exactly 2× every per-token dimension, so the flat
	// multiplier is mathematically equivalent to a second rate card. Set
	// ONLY on this explicit SKU, never on the family prefix.
	//
	// Batch API pricing (50% off — $2.50 / $12.50) is context only: the
	// Pricing struct carries no batch field and one must not be invented
	// here.
	"claude-opus-5": {Input: 5, Output: 25, CacheRead: 0.50, CacheCreation: 6.25, CacheCreation1h: 10, WebSearchPerRequest: 0.01, FastMultiplier: 2},
	// Anthropic — Claude Opus 4.5 / 4.6 / 4.7 / 4.8 (current generation,
	// $5/$25 input/output — 1/3 of Opus 4.x legacy rates). Web search billed
	// at $10/1000 calls ($0.01 per call) on top of token costs.
	//
	// Opus 4.8 (released 2026-05-28) is a dateless pinned snapshot — Anthropic
	// stopped putting dates in IDs as of the 4.6 gen, so there is no
	// `-YYYYMMDD` variant to add. Standard pricing is identical to 4.7
	// (confirmed against platform.claude.com pricing 2026-06-06). The 4.8
	// row resolved correctly via the `claude-opus-4` family prefix prior
	// to this pin; the explicit row upgrades it to PricingSourceExact for
	// a flagship-model SKU and gives a stable home for the FastMultiplier
	// premium tier ($10 input / $50 output when speed=fast on the request).
	//
	// FastMultiplier=2: speed:"fast" on the Anthropic Messages API doubles
	// every per-token dimension (input/output/cache_read/cache_write) for
	// ~2.5× throughput. Set ONLY on 4.8 — the `claude-opus-4` family
	// prefix keeps FastMultiplier at 0 so future SKUs opt in explicitly.
	// Compute multiplies the final AI token cost by FastMultiplier when
	// the turn was fast and the rate is non-zero; web_search fees stay
	// flat (inference premium, not server-tool premium).
	"claude-opus-4-8": {Input: 5, Output: 25, CacheRead: 0.50, CacheCreation: 6.25, CacheCreation1h: 10, WebSearchPerRequest: 0.01, FastMultiplier: 2},
	// Fable 5 — now the LEGACY Fable SKU (claude-fable-5; the [1m]
	// long-context tag normalizes away upstream, same as Opus). Priced from
	// the published first-party card at $10/$50 — 2× the Opus-4.8 flagship
	// tier, NOT the same tier. Cache: 5m-write $12.50, 1h-write $20, read $1.
	// Full 1M context at standard pricing (no long-context tier). NOT
	// fast-capable — fast mode is Opus 5 / 4.8 only per the pricing card,
	// so no FastMultiplier here.
	//
	// Fable 5 KEEPS the standard 0.1x cache-read multiplier ($1) after the
	// Fable 5.1 launch — the 0.025x read rate below is specific to the 5.1
	// generation per the pricing page footnote ("All other models use the
	// standard 0.1x multiplier", re-verified 2026-09-02). Do NOT "fix" this
	// row's CacheRead down to $0.25; a dated Fable-5 SKU
	// (claude-fable-5-2026xxxx) longest-prefix-matches HERE, not the 5.1
	// row, and must keep billing reads at $1.
	//
	// Corrected 2026-07-12 (verified against
	// platform.claude.com/docs/en/about-claude/pricing): the row previously
	// carried the Opus-4.8 anchor ($5/$25) as a placeholder pending a
	// first-party card. That card now exists and is 2× higher — the anchor
	// under-billed every Fable turn by 2× (299 live rows / 137M window
	// tokens were affected before the fix).
	"claude-fable-5": {Input: 10, Output: 50, CacheRead: 1, CacheCreation: 12.50, CacheCreation1h: 20, WebSearchPerRequest: 0.01},
	// Fable 5.1 — succeeds Fable 5 at the SAME per-token input/output/
	// cache-write rates ($10/$50, 5m-write $12.50, 1h-write $20), but with
	// a 75%-cheaper cache-READ multiplier: 0.025× input ($0.25/MTok)
	// instead of the universal 0.10× default every other model (including
	// Fable 5 itself) uses. Verified against
	// platform.claude.com/docs/en/about-claude/pricing, fetched 2026-09-07:
	// "Cache hits and refreshes on Claude Fable 5.1 and Claude Mythos 5.1
	// are priced at 0.025x the base input price. All other models use the
	// standard 0.1x multiplier." Must be set EXPLICITLY here — fillDefaults'
	// universal CacheRead=0.10×Input floor only fires when CacheRead==0, so
	// leaving it blank would silently 4×-over-bill every Fable 5.1 cache
	// read ($1.00 vs the real $0.25). Not fast-capable (fast mode is Opus
	// 4.8 / Opus 5 only), so no FastMultiplier.
	"claude-fable-5-1": {Input: 10, Output: 50, CacheRead: 0.25, CacheCreation: 12.50, CacheCreation1h: 20, WebSearchPerRequest: 0.01},
	// Dot-form alias — some surfaces spell the minor version with a dot
	// ("5.1") rather than a dash ("5-1"). Without this explicit alias,
	// "claude-fable-5.1" does NOT match the "claude-fable-5-1" key (dots
	// and dashes are never normalized against each other anywhere in the
	// lookup ladder — see the doubao-seed dash-form precedent) and instead
	// falls through to the shorter "claude-fable-5" family match, pricing
	// it at the WRONG generation's $1 cache-read instead of $0.25. Same
	// precedent as the "gpt-5-6" / "gpt-5.6" dual keys below.
	"claude-fable-5.1": {Input: 10, Output: 50, CacheRead: 0.25, CacheCreation: 12.50, CacheCreation1h: 20, WebSearchPerRequest: 0.01},
	// claude-fable family prefix — a family row prices UNKNOWN future SKUs,
	// so it stays on the UNIVERSAL 0.10× cache-read multiplier ($1), NOT
	// the 0.025× rate. Anthropic's own footnote scopes the discount to two
	// NAMED models: "Cache hits and refreshes on Claude Fable 5.1 and
	// Claude Mythos 5.1 are priced at 0.025x the base input price. All
	// other models use the standard 0.1x multiplier." (platform.claude.com/
	// docs/en/about-claude/pricing, fetched 2026-09-07). A hypothetical
	// future claude-fable-6 is an "other model" per that footnote until it
	// gets its own explicit row — bumping the family prefix to 0.025× would
	// silently UNDER-bill it by 4× the moment it's released. Base
	// input/output/cache-write stay at the current-generation $10/$50/
	// $12.50/$20 card (unchanged from Fable 5).
	"claude-fable": {Input: 10, Output: 50, CacheRead: 1, CacheCreation: 12.50, CacheCreation1h: 20, WebSearchPerRequest: 0.01},
	// Mythos 5 — identical pricing/behavior to Fable 5, available only via
	// Project Glasswing. Verified against platform.claude.com/docs/en/
	// about-claude/pricing 2026-07-23 (same card, same rates as Fable 5:
	// $10/$50, cache read $1, 5m-write $12.50, 1h-write $20). Placed next
	// to the claude-fable pair per house convention (mirror rates, own
	// family prefix so future dated SKUs don't MISS to $0).
	"claude-mythos-5": {Input: 10, Output: 50, CacheRead: 1, CacheCreation: 12.50, CacheCreation1h: 20, WebSearchPerRequest: 0.01},
	// Mythos 5.1 — mirrors Fable 5.1 exactly (same card, same 0.025×
	// cache-read multiplier). Verified against platform.claude.com/docs/en/
	// about-claude/pricing, fetched 2026-09-07.
	"claude-mythos-5-1": {Input: 10, Output: 50, CacheRead: 0.25, CacheCreation: 12.50, CacheCreation1h: 20, WebSearchPerRequest: 0.01},
	// Dot-form alias — same reasoning as "claude-fable-5.1" above.
	"claude-mythos-5.1": {Input: 10, Output: 50, CacheRead: 0.25, CacheCreation: 12.50, CacheCreation1h: 20, WebSearchPerRequest: 0.01},
	// claude-mythos family prefix — mirrors claude-fable's reasoning above:
	// a family row prices unknown future SKUs, which Anthropic's footnote
	// scopes OUT of the 0.025× discount, so this stays at the universal
	// 0.10× ($1) cache-read, not 0.025×. Base input/output/cache-write
	// unchanged (mirrors claude-fable's family row exactly).
	"claude-mythos":            {Input: 10, Output: 50, CacheRead: 1, CacheCreation: 12.50, CacheCreation1h: 20, WebSearchPerRequest: 0.01},
	"claude-opus-4-7":          {Input: 5, Output: 25, CacheRead: 0.50, CacheCreation: 6.25, CacheCreation1h: 10, WebSearchPerRequest: 0.01},
	"claude-opus-4-6":          {Input: 5, Output: 25, CacheRead: 0.50, CacheCreation: 6.25, CacheCreation1h: 10, WebSearchPerRequest: 0.01},
	"claude-opus-4-6-20251001": {Input: 5, Output: 25, CacheRead: 0.50, CacheCreation: 6.25, CacheCreation1h: 10, WebSearchPerRequest: 0.01},
	"claude-opus-4-5":          {Input: 5, Output: 25, CacheRead: 0.50, CacheCreation: 6.25, CacheCreation1h: 10, WebSearchPerRequest: 0.01},
	// claude-opus-4 (no minor) — family prefix set to LATEST so new SKUs
	// (claude-opus-4-8, claude-opus-4-9...) inherit current pricing rather
	// than legacy.
	"claude-opus-4": {Input: 5, Output: 25, CacheRead: 0.50, CacheCreation: 6.25, CacheCreation1h: 10, WebSearchPerRequest: 0.01},
	// claude-opus (no generation) — the family-prefix SAFETY NET, added
	// 2026-07-25 alongside the claude-opus-5 pin. Set to the current
	// generation tier ($5/$25) per the same platform.claude.com card, so a
	// future `claude-opus-6` inherits current pricing instead of MISSing to
	// $0 — the exact hole `claude-opus-5` fell through, since
	// "claude-opus-4" is not a prefix of "claude-opus-5". (Opus-5 context
	// tags and dated variants do NOT land here — they match the longer
	// `claude-opus-5` key first; see that row.) Extends the bare-family-row
	// convention started by claude-fable / claude-mythos to EVERY current-gen
	// Anthropic family: the sibling `claude-sonnet` and `claude-haiku` rows
	// below were added in the same change, because until then they had the
	// identical hole (`claude-sonnet-5` is not a prefix of a future
	// `claude-sonnet-6`, nor `claude-haiku-4` of `claude-haiku-5`). The
	// convention is only worth stating because it is now actually complete —
	// do not add a new Anthropic family without its bare row.
	//
	// NO FastMultiplier — deliberately left 0 so future SKUs opt in
	// explicitly, exactly as the claude-opus-4 comment above reasons. A
	// fast tier is a per-SKU capability, never inherited by prefix.
	//
	// Verified non-shadowing (familyKeys sorts longest-first and returns
	// the first prefix match): `claude-3-opus` does NOT start with
	// "claude-opus" so the legacy $15/$75 rows are untouched, and every
	// `claude-opus-4*` key is strictly longer than "claude-opus" so they
	// all win the sort — including the legacy claude-opus-4-1 row.
	//
	// HONEST LIMIT of this safety net: it does NOT catch vendor-decorated
	// ids. normalizeUnpricedModel strips only `capi:` / `sweagent-capi:`
	// prefixes and leading path segments — never a DOTTED vendor prefix — so
	// Bedrock/Vertex-style ids like `us.anthropic.claude-opus-5:v1` and
	// `anthropic.claude-opus-5` still resolve to PricingSourceMiss → $0.00
	// despite this row. That gap is pre-existing and class-wide (Opus 4.8
	// has it too); it is recorded here so nobody assumes the family row
	// covers it. Pinned by TestTable_DottedVendorPrefixStillMisses.
	"claude-opus": {Input: 5, Output: 25, CacheRead: 0.50, CacheCreation: 6.25, CacheCreation1h: 10, WebSearchPerRequest: 0.01},
	// Anthropic — Claude Opus 4 / 4.1 (legacy rates, $15/$75).
	//
	// `claude-opus-4-0` is Anthropic's documented undated ALIAS for legacy
	// Claude Opus 4 — the same model as the dated `claude-opus-4-20250514`
	// row below, at the same legacy $15/$75. It needs its own row because of
	// a LEGACY-ALIAS TRAP: the `claude-opus-4` family row is deliberately
	// pinned to CURRENT-gen rates ($5/$25) so future SKUs inherit current
	// pricing, and `claude-opus-4-0` is the one LEGACY id that shares that
	// prefix. Without this row it fell through to the family row and billed
	// at $5/$25 — a 3× UNDER-bill of real legacy-Opus-4 traffic. Rates
	// mirror the claude-opus-4-1 row exactly, including the absence of
	// WebSearchPerRequest (matching its legacy siblings, which predate the
	// server-side web_search fee being modelled).
	"claude-opus-4-0":          {Input: 15, Output: 75, CacheRead: 1.5, CacheCreation: 18.75, CacheCreation1h: 30},
	"claude-opus-4-1":          {Input: 15, Output: 75, CacheRead: 1.5, CacheCreation: 18.75, CacheCreation1h: 30},
	"claude-opus-4-1-20250805": {Input: 15, Output: 75, CacheRead: 1.5, CacheCreation: 18.75, CacheCreation1h: 30},
	"claude-opus-4-20250514":   {Input: 15, Output: 75, CacheRead: 1.5, CacheCreation: 18.75, CacheCreation1h: 30},
	// Anthropic — Sonnet 5 (current flagship Sonnet, new tokenizer, full 1M
	// context at standard pricing → NO long-context tier). $2/$10 (cache
	// 2.50/4/0.20) launched as INTRODUCTORY pricing through 2026-08-31 with
	// a scheduled rise to $3/$15 on 2026-09-01 — RESOLVED 2026-09-07:
	// Anthropic confirmed on platform.claude.com/docs/en/about-claude/pricing
	// that "The $2/$10 ... pricing for Claude Sonnet 5, announced at launch
	// as introductory pricing through August 31, 2026, is now the standard
	// price. The previously scheduled increase to $3/$15 ... will not
	// occur." $2/$10 is therefore the permanent standard rate, not a
	// time-boxed intro — no dated-pricing pair is needed (the rate never
	// actually changed; only the plan to change it was cancelled).
	//
	// This $2/$10 row is CORRECT — do NOT "fix" it to $3/$15. The Track-2
	// pilot (benchmarks/preregistration/pilot-report-2026-07-12.md §7.3)
	// observed the Claude Agent SDK's self-reported total_cost_usd running a
	// constant ×1.5 above this table, implying $3/$15. That is the SDK's
	// bundled table NOT applying the introductory discount (it bills at the
	// standard Sonnet-5 rate), not an error here: $2/$10 is the authoritative
	// published, now-permanent, list price. Changing this row to $3/$15
	// would over-bill every displayed sonnet-5 cost by 1.5×.
	//
	// The bare "claude-sonnet-5" doubles as the family prefix so dated SKUs
	// (claude-sonnet-5-2026xxxx) resolve instead of MISSing to $0 — the bug
	// this row fixes (handoff/estimate priced sonnet-5 carries at $0).
	"claude-sonnet-5": {Input: 2, Output: 10, CacheRead: 0.20, CacheCreation: 2.50, CacheCreation1h: 4, WebSearchPerRequest: 0.01},
	// Anthropic — Sonnet 4 family. Pricing identical across 3.7 / 4 / 4.5 / 4.6.
	// 4.5 + 4 (incl. dated -20250514) carry the 200K long-context tier:
	// $6 input, $22.50 output, $0.60 cache_read, $7.50 cache_write 5m,
	// $12 cache_write 1h. 4.6 is flat-rate per the 2026-04-29 snapshot;
	// 3.7 is deprecated. The "claude-sonnet-4" family prefix carries the
	// LC tier so future undated 4.x SKUs (other than 4-6) inherit it.
	"claude-sonnet-4-6": {Input: 3, Output: 15, CacheRead: 0.30, CacheCreation: 3.75, CacheCreation1h: 6, WebSearchPerRequest: 0.01},
	"claude-sonnet-4-5": {
		Input: 3, Output: 15, CacheRead: 0.30, CacheCreation: 3.75, CacheCreation1h: 6, WebSearchPerRequest: 0.01,
		LongContextThreshold: 200_000,
		LongContextInput:     6, LongContextOutput: 22.50, LongContextCacheRead: 0.60,
		LongContextCacheCreation: 7.50, LongContextCacheCreation1h: 12,
	},
	"claude-sonnet-4-20250514": {
		Input: 3, Output: 15, CacheRead: 0.30, CacheCreation: 3.75, CacheCreation1h: 6, WebSearchPerRequest: 0.01,
		LongContextThreshold: 200_000,
		LongContextInput:     6, LongContextOutput: 22.50, LongContextCacheRead: 0.60,
		LongContextCacheCreation: 7.50, LongContextCacheCreation1h: 12,
	},
	"claude-sonnet-4": {
		Input: 3, Output: 15, CacheRead: 0.30, CacheCreation: 3.75, CacheCreation1h: 6, WebSearchPerRequest: 0.01,
		LongContextThreshold: 200_000,
		LongContextInput:     6, LongContextOutput: 22.50, LongContextCacheRead: 0.60,
		LongContextCacheCreation: 7.50, LongContextCacheCreation1h: 12,
	},
	"claude-sonnet-3-7": {Input: 3, Output: 15, CacheRead: 0.30, CacheCreation: 3.75, CacheCreation1h: 6}, // deprecated
	// claude-sonnet (no generation) — the Sonnet family-prefix SAFETY NET,
	// the sibling of the bare `claude-opus` row above. Without it a future
	// `claude-sonnet-6` MISSes to $0.00: "claude-sonnet-5" is not a prefix
	// of "claude-sonnet-6", and neither is "claude-sonnet-4" — the exact
	// hole `claude-opus-5` fell through. internal/routing/tiers.go already
	// carried a bare `claude-sonnet` tier, so before this row the two
	// registries disagreed about whether the family was known.
	//
	// Rates are the STANDARD $3/$15 card (cache 0.30 / 3.75 / 6), NOT
	// Sonnet 5's $2/$10 INTRODUCTORY rate. That is deliberate: the intro
	// window closes 2026-08-31, after which standard Sonnet pricing is
	// $3/$15 — a family fallback that inherited the intro rate would
	// silently UNDER-bill every unpinned Sonnet SKU from 2026-09-01 onward.
	// A fallback should err toward the durable published rate, and the
	// explicit `claude-sonnet-5` row keeps billing the intro rate correctly
	// for the SKU that actually has it (it is longer, so it wins
	// familyKeys' longest-first sort).
	//
	// NO FastMultiplier — fast mode is an Opus-tier capability today; leave
	// 0 so a future fast-capable Sonnet opts in explicitly on its own row.
	//
	// NO LongContextThreshold — the LC tier is a per-SKU property (4 / 4.5
	// have it, 4.6 and 5 do not), so the family fallback must not invent one.
	//
	// Non-shadowing: `claude-3-5-sonnet*` and `claude-3-sonnet-*` do not
	// START with "claude-sonnet", so the legacy rows are untouched; every
	// existing `claude-sonnet-*` key is strictly longer and wins the sort.
	"claude-sonnet": {Input: 3, Output: 15, CacheRead: 0.30, CacheCreation: 3.75, CacheCreation1h: 6, WebSearchPerRequest: 0.01},
	// Anthropic — Haiku 4.5. Web search billed at $0.01/call.
	"claude-haiku-4-5-20251001": {Input: 1, Output: 5, CacheRead: 0.10, CacheCreation: 1.25, CacheCreation1h: 2, WebSearchPerRequest: 0.01},
	"claude-haiku-4-5":          {Input: 1, Output: 5, CacheRead: 0.10, CacheCreation: 1.25, CacheCreation1h: 2, WebSearchPerRequest: 0.01},
	"claude-haiku-4.5":          {Input: 1, Output: 5, CacheRead: 0.10, CacheCreation: 1.25, CacheCreation1h: 2, WebSearchPerRequest: 0.01}, // dot variant — GitHub Copilot CLI emits this name
	"claude-haiku-4":            {Input: 1, Output: 5, CacheRead: 0.10, CacheCreation: 1.25, CacheCreation1h: 2, WebSearchPerRequest: 0.01},
	// claude-haiku (no generation) — the Haiku family-prefix SAFETY NET,
	// completing the bare-row set with `claude-opus` / `claude-sonnet`.
	// Without it a future `claude-haiku-5` MISSes to $0.00 ("claude-haiku-4"
	// is not a prefix of "claude-haiku-5"), the same hole `claude-opus-5`
	// fell through. internal/routing/tiers.go already carried a bare
	// `claude-haiku` tier, so the two registries disagreed until now.
	//
	// Rates are the current-generation Haiku 4.5 card ($1/$5, cache
	// 0.10 / 1.25 / 2, web search $0.01/call) — family prefixes point at
	// the LATEST tier so new SKUs inherit current pricing, never legacy.
	// The legacy 3.5 / 3 Haiku rows are cheaper but they are pinned
	// explicitly and unreachable from this prefix.
	//
	// NO FastMultiplier — fast mode is Opus-tier only; a future fast-capable
	// Haiku must opt in on its own row.
	//
	// Non-shadowing: `claude-3-5-haiku*` and `claude-3-haiku-*` do not START
	// with "claude-haiku", so the legacy rows are untouched; every existing
	// `claude-haiku-*` key (including the `claude-haiku-4.5` dot variant
	// Copilot CLI emits) is strictly longer and wins the longest-first sort.
	"claude-haiku": {Input: 1, Output: 5, CacheRead: 0.10, CacheCreation: 1.25, CacheCreation1h: 2, WebSearchPerRequest: 0.01},
	// Anthropic — Claude 3.5.
	"claude-3-5-sonnet-20241022": {Input: 3, Output: 15, CacheRead: 0.30, CacheCreation: 3.75, CacheCreation1h: 6},
	"claude-3-5-sonnet-20240620": {Input: 3, Output: 15, CacheRead: 0.30, CacheCreation: 3.75, CacheCreation1h: 6},
	"claude-3-5-sonnet":          {Input: 3, Output: 15, CacheRead: 0.30, CacheCreation: 3.75, CacheCreation1h: 6},
	"claude-3-5-haiku-20241022":  {Input: 0.80, Output: 4, CacheRead: 0.08, CacheCreation: 1.00, CacheCreation1h: 1.6},
	"claude-3-5-haiku":           {Input: 0.80, Output: 4, CacheRead: 0.08, CacheCreation: 1.00, CacheCreation1h: 1.6},
	// Anthropic — Claude 3 (deprecated).
	"claude-3-opus-20240229":   {Input: 15, Output: 75, CacheRead: 1.5, CacheCreation: 18.75, CacheCreation1h: 30},
	"claude-3-opus":            {Input: 15, Output: 75, CacheRead: 1.5, CacheCreation: 18.75, CacheCreation1h: 30},
	"claude-3-sonnet-20240229": {Input: 3, Output: 15, CacheRead: 0.30, CacheCreation: 3.75, CacheCreation1h: 6},
	"claude-3-haiku-20240307":  {Input: 0.25, Output: 1.25, CacheRead: 0.03, CacheCreation: 0.30, CacheCreation1h: 0.50},
	// OpenAI — GPT-5 family. Cached input → CacheRead. No separate
	// cache-write charge (caching is automatic) so CacheCreation /
	// CacheCreation1h stay 0. The post-2026-04-29 fillDefaults
	// changes don't fold Anthropic-style cache_write defaults in
	// when CacheCreation is left zero, so OpenAI rows can never
	// over-bill via a phantom 1.25×Input rate even if a stray
	// cache_creation_tokens leaked into a row.
	//
	// 5.5 / 5.4 introduce ≤272K vs >272K long-context tiers (entire
	// request reprices when crossed at 2× across input/output/cache_read).
	// The Pro variants don't advertise a separate LC tier so they stay
	// flat. mini/nano lack public LC numbers; left at standard rates and
	// users on >272K mini/nano prompts will see slight under-billing.
	// WebSearchPerRequest: OpenAI's Responses-API web_search tool is
	// billed per request at $10/1000 calls = $0.01/call (operator-
	// confirmed against OpenAI's published 2026-05-15 pricing —
	// matches Anthropic's flat rate). "Search content tokens are
	// free" per the published rate card — no separate token billing
	// layer. Cost-engine applies this as a flat $/call (no /1M
	// scaling, no LC tier dispatch) per Invariant #57.
	// OpenAI's long-context rule for gpt-5.4 / gpt-5.5 is 2× input,
	// 1.5× output above 272K — NOT 2×/2×. Pre-2026-05-19 this table
	// had LongContextOutput at 2× std ($60 for 5.5, $30 for 5.4), which
	// over-billed every >272K turn by 33%. Verified against OpenAI's
	// 2026-05 pricing page + multiple independent 2026 pricing guides.
	// Codex Fast mode (request `service_tier:"priority"`) carries a per-SKU
	// credit premium — gpt-5.5 = 2.5×, gpt-5.4 = 2× — captured via the
	// FastMultiplier field. Set ONLY on these two explicit SKUs (the family
	// prefix + mini/nano/codex variants have no documented Fast tier and
	// stay at 0). The flag is sourced node-side from `~/.codex/config.toml`
	// service_tier (watcher path) and the proxy's served service_tier
	// (api_turns path); see internal/adapter/codex/adapter.go +
	// internal/proxy/provider.go.
	// OpenAI — GPT-5.6 family. Launched 2026-06-25 as a LIMITED PREVIEW
	// (API + Codex only, ~20 approved orgs; preview rates may change at
	// GA). SKUs follow the family convention gpt-5.6-{sol,terra,luna};
	// no primary source lists literal ID strings, so the family prefix
	// (→ Sol flagship rates) backstops any as-yet-unseen variant.
	//
	// FIRST non-Anthropic explicit cache-WRITE tier: 5.6 introduces
	// explicit cache breakpoints + a 30-minute minimum cache life and
	// bills cache writes at 1.25× the uncached input rate → $6.25 / $3.125
	// / $1.25 (Sol unchanged by the 2026-07-30 cut; Terra/Luna's write
	// rates recompute to 1.25× their NEW input rates below). Cache reads
	// keep the OpenAI 90%-discount shape. CacheCreation1h is PINNED equal
	// to CacheCreation: OpenAI has no 5m/1h tier split, and fillDefaults
	// auto-derives CacheCreation1h = 2×Input whenever CacheCreation>0 (an
	// Anthropic-shape default), so pinning it keeps a fabricated 2×-Input
	// 1h rate out of the rate card.
	//
	// The 1.25× write rate is INERT today: the proxy's OpenAI usage parse
	// (internal/proxy/provider.go ~L519, streaming.go ~L299) only carries
	// prompt_tokens_details.cached_tokens — the cache-write token field
	// name is not yet grounded on a live 5.6 response. Wire it into
	// provider.go/streaming.go once a live capture lands.
	//
	// PRICE CUT, effective 2026-07-30 (developers.openai.com/api/docs/
	// changelog: "Starting July 30, GPT-5.6 Luna costs 80% less, while
	// GPT-5.6 Terra costs 20% less"). Terra/Luna's OLD rates are
	// preserved as the first entry of their datedPricing timeline
	// (dated.go) — see TestDatedSeedIsSelfConsistent. Sol is UNCHANGED
	// by this cut.
	//
	// Long-context + Fast tiers, added alongside the 2026-07-30 cut
	// (developers.openai.com/api/docs/pricing): threshold 272K tokens,
	// input/cache-read/cache-write at 2× standard, output at 1.5×
	// standard. Fast mode (renamed from "Priority Processing" on
	// 2026-07-30) bills at 2× standard. "Sol Ultra" is a high-effort
	// mode of Sol, not a separate rate card. WebSearchPerRequest stays
	// 0.01 like the other OpenAI rows.
	"gpt-5.6-sol": {
		Input: 5, Output: 30, CacheRead: 0.50, CacheCreation: 6.25, CacheCreation1h: 6.25, WebSearchPerRequest: 0.01,
		LongContextThreshold: 272_000,
		LongContextInput:     10.00, LongContextOutput: 45.00, LongContextCacheRead: 1.00,
		LongContextCacheCreation: 12.50, LongContextCacheCreation1h: 12.50,
		FastMultiplier: 2,
	},
	// Terra — NEW rate post-2026-07-30 cut (20% less). OLD rate ($2.50 /
	// $15 / $0.25 / $3.125) is dated.go's timeline entry 1.
	"gpt-5.6-terra": {
		Input: 2.00, Output: 12.00, CacheRead: 0.20, CacheCreation: 2.50, CacheCreation1h: 2.50, WebSearchPerRequest: 0.01,
		LongContextThreshold: 272_000,
		LongContextInput:     4.00, LongContextOutput: 18.00, LongContextCacheRead: 0.40,
		LongContextCacheCreation: 5.00, LongContextCacheCreation1h: 5.00,
		FastMultiplier: 2,
	},
	// Luna — NEW rate post-2026-07-30 cut (80% less). OLD rate ($1 / $6
	// / $0.10 / $1.25) is dated.go's timeline entry 1.
	"gpt-5.6-luna": {
		Input: 0.20, Output: 1.20, CacheRead: 0.02, CacheCreation: 0.25, CacheCreation1h: 0.25, WebSearchPerRequest: 0.01,
		LongContextThreshold: 272_000,
		LongContextInput:     0.40, LongContextOutput: 1.80, LongContextCacheRead: 0.04,
		LongContextCacheCreation: 0.50, LongContextCacheCreation1h: 0.50,
		FastMultiplier: 2,
	},
	// family prefix → Sol (flagship) rates, same convention as the `grok` family row
	"gpt-5.6": {
		Input: 5, Output: 30, CacheRead: 0.50, CacheCreation: 6.25, CacheCreation1h: 6.25, WebSearchPerRequest: 0.01,
		LongContextThreshold: 272_000,
		LongContextInput:     10.00, LongContextOutput: 45.00, LongContextCacheRead: 1.00,
		LongContextCacheCreation: 12.50, LongContextCacheCreation1h: 12.50,
		FastMultiplier: 2,
	},
	// ChatGPT web-UI dashed slugs (browser-extension chatgpt-web adapter,
	// browser-extension/src/parsers.js) — the ChatGPT frontend echoes the
	// model as "gpt-5-6-thinking" (dot-in-name replaced with a dash,
	// LIVE-CONFIRMED 2026-07-10), not the API's dotted "gpt-5.6" slug. The
	// family-prefix ladder in LookupWithSource can't bridge dash-vs-dot, so
	// without an explicit alias these fell through to the unrelated "gpt-5"
	// row (~5x underpriced). Pinned at Sol (flagship) rates — the same
	// convention as the "gpt-5.6" family row above (incl. the 2026-07-30
	// long-context/Fast additions; Sol's base rate is unaffected by the
	// price cut). KNOWN (accepted, LOW): like every exact key, the bare
	// "gpt-5-6" also acts as a family PREFIX in LookupWithSource, so a
	// hypothetical future "gpt-5-6x" slug would inherit these rates until
	// given its own row — the ladder is not delimiter-aware by design
	// (GPT-5.6 review 2026-07-18 #5).
	"gpt-5-6-thinking": {
		Input: 5, Output: 30, CacheRead: 0.50, CacheCreation: 6.25, CacheCreation1h: 6.25, WebSearchPerRequest: 0.01,
		LongContextThreshold: 272_000,
		LongContextInput:     10.00, LongContextOutput: 45.00, LongContextCacheRead: 1.00,
		LongContextCacheCreation: 12.50, LongContextCacheCreation1h: 12.50,
		FastMultiplier: 2,
	},
	"gpt-5-6": {
		Input: 5, Output: 30, CacheRead: 0.50, CacheCreation: 6.25, CacheCreation1h: 6.25, WebSearchPerRequest: 0.01,
		LongContextThreshold: 272_000,
		LongContextInput:     10.00, LongContextOutput: 45.00, LongContextCacheRead: 1.00,
		LongContextCacheCreation: 12.50, LongContextCacheCreation1h: 12.50,
		FastMultiplier: 2,
	},
	// OpenAI — GPT-6 Astra, the current flagship (released 2026-09-03,
	// API model id `gpt-6-astra`, developers.openai.com/api/docs/models/
	// gpt-6-astra, fetched 2026-09-07): $10 input / $50 output / $1 cached
	// input / $12.50 cache write. 1,050,000-token context window (922K max
	// input, 128K max output). Cache-write follows the GPT-5.6 precedent
	// (an explicit non-zero CacheCreation, the second non-Anthropic line
	// with one) at exactly 1.25× input ($12.50 = 1.25×$10); CacheCreation1h
	// is PINNED equal to CacheCreation for the same reason as GPT-5.6 —
	// OpenAI has no 5m/1h split, so leaving it 0 would let fillDefaults'
	// Anthropic-shape 2×-input default fabricate a 1h rate OpenAI doesn't
	// publish.
	//
	// Long-context: "any prompt past 272K input tokens reprices the entire
	// request" at 2× input/cached-input and 1.5× output — the SAME 272K
	// threshold and 2×/1.5× split already modeled for gpt-5.4/5.5/5.6 (not
	// 2×/2× — see the gpt-5.4 LC correction note above). LongContext cache
	// dimensions mirror the input-side 2× per the "and cache rates" phrase
	// on the source page, matching how gpt-5.6's LC tier doubles its own
	// cache-write dimension too.
	//
	// Fast mode: "Fast mode doubles them" — modeled as a flat
	// FastMultiplier=2 across every dimension, the same shape as
	// Anthropic Opus fast mode and the GPT-5.6 family's Fast tier.
	//
	// Batch/Flex (50% off) is NOT modeled — no batch dimension exists on
	// this struct (same as every other OpenAI/Anthropic/Mistral batch
	// discount; see docs/pricing-reference.md "Out of scope").
	//
	// WebSearchPerRequest carries the same $10/1000-searches ($0.01/call)
	// fee applied to every other OpenAI row in this table; the source page
	// did not restate it per-model, so this is the inherited platform-wide
	// convention, not an independently re-verified gpt-6-astra-specific
	// figure — flag for re-verification if OpenAI ever prices web_search
	// per-flagship.
	"gpt-6-astra": {
		Input: 10, Output: 50, CacheRead: 1, CacheCreation: 12.50, CacheCreation1h: 12.50, WebSearchPerRequest: 0.01,
		LongContextThreshold: 272_000,
		LongContextInput:     20, LongContextOutput: 75, LongContextCacheRead: 2,
		LongContextCacheCreation: 25, LongContextCacheCreation1h: 25,
		FastMultiplier: 2,
	},
	// gpt-6 family prefix → Astra (flagship) rates, same convention as the
	// "gpt-5.6" bare family row: a future gpt-6-x SKU with no row of its
	// own inherits the current flagship's shape rather than MISSing to $0.
	"gpt-6": {
		Input: 10, Output: 50, CacheRead: 1, CacheCreation: 12.50, CacheCreation1h: 12.50, WebSearchPerRequest: 0.01,
		LongContextThreshold: 272_000,
		LongContextInput:     20, LongContextOutput: 75, LongContextCacheRead: 2,
		LongContextCacheCreation: 25, LongContextCacheCreation1h: 25,
		FastMultiplier: 2,
	},
	"gpt-5.5": {
		Input: 5, Output: 30, CacheRead: 0.50,
		LongContextThreshold: 272_000,
		LongContextInput:     10, LongContextOutput: 45, LongContextCacheRead: 1,
		WebSearchPerRequest: 0.01,
		FastMultiplier:      2.5,
	},
	"gpt-5.5-pro": {Input: 30, Output: 180, CacheRead: 30, WebSearchPerRequest: 0.01}, // OpenCode reports cached = input for Pro
	"gpt-5.4": {
		Input: 2.50, Output: 15, CacheRead: 0.25,
		LongContextThreshold: 272_000,
		LongContextInput:     5, LongContextOutput: 22.50, LongContextCacheRead: 0.50,
		WebSearchPerRequest: 0.01,
		FastMultiplier:      2,
	},
	"gpt-5.4-pro":         {Input: 30, Output: 180, CacheRead: 30, WebSearchPerRequest: 0.01}, // see note above
	"gpt-5.4-mini":        {Input: 0.75, Output: 4.50, CacheRead: 0.075, WebSearchPerRequest: 0.01},
	"gpt-5.4-nano":        {Input: 0.20, Output: 1.25, CacheRead: 0.02, WebSearchPerRequest: 0.01},
	"gpt-5.3-codex":       {Input: 1.75, Output: 14, CacheRead: 0.175, WebSearchPerRequest: 0.01},
	"gpt-5.3-codex-spark": {Input: 1.75, Output: 14, CacheRead: 0.175, WebSearchPerRequest: 0.01},
	"gpt-5.2":             {Input: 1.75, Output: 14, CacheRead: 0.175, WebSearchPerRequest: 0.01},
	"gpt-5.2-codex":       {Input: 1.75, Output: 14, CacheRead: 0.175, WebSearchPerRequest: 0.01},
	"gpt-5.2-pro":         {Input: 21, Output: 168, WebSearchPerRequest: 0.01}, // no cache tier
	"gpt-5.1":             {Input: 1.07, Output: 8.50, CacheRead: 0.107, WebSearchPerRequest: 0.01},
	"gpt-5.1-codex":       {Input: 1.07, Output: 8.50, CacheRead: 0.107, WebSearchPerRequest: 0.01},
	"gpt-5.1-codex-max":   {Input: 1.25, Output: 10, CacheRead: 0.125, WebSearchPerRequest: 0.01},
	"gpt-5.1-codex-mini":  {Input: 0.25, Output: 2, CacheRead: 0.025, WebSearchPerRequest: 0.01},
	"gpt-5":               {Input: 1.07, Output: 8.50, CacheRead: 0.107, WebSearchPerRequest: 0.01},
	"gpt-5-codex":         {Input: 1.07, Output: 8.50, CacheRead: 0.107, WebSearchPerRequest: 0.01},
	"gpt-5-mini":          {Input: 0.25, Output: 2, CacheRead: 0.025, WebSearchPerRequest: 0.01},
	"gpt-5-nano":          {Input: 0, Output: 0, CacheRead: 0, WebSearchPerRequest: 0.01}, // Free per OpenAI 2026-04-29 catalog
	"gpt-5-pro":           {Input: 15, Output: 120, WebSearchPerRequest: 0.01},            // legacy; no cache tier
	// Codex cloud auto-review. Codex's automated PR/code-review runs bill under
	// the alias `codex-auto-review` (LIVE on the org estate at 12.9M tokens); the
	// exact backing SKU is not published, so no fresh number is invented — the
	// row aliases to the documented Codex-codex line rate ($1.75 / $14, the
	// gpt-5.x-codex SKUs above). Before this row `codex-auto-review` was a
	// PricingSourceMiss → $0.00 (F-MODELS3 / F-COST1). Override via
	// `[intelligence.pricing.models]` if the backing SKU is confirmed.
	"codex-auto-review": {Input: 1.75, Output: 14, CacheRead: 0.175, WebSearchPerRequest: 0.01},
	// OpenAI — GPT-4.1 family.
	"gpt-4.1":      {Input: 2.00, Output: 8, CacheRead: 0.50},
	"gpt-4.1-mini": {Input: 0.40, Output: 1.60, CacheRead: 0.10},
	"gpt-4.1-nano": {Input: 0.10, Output: 0.40, CacheRead: 0.025},
	// OpenAI — GPT-4o family.
	"gpt-4o":            {Input: 2.50, Output: 10, CacheRead: 1.25},
	"gpt-4o-mini":       {Input: 0.15, Output: 0.60, CacheRead: 0.075},
	"gpt-4o-2024-05-13": {Input: 5, Output: 15}, // legacy, no cache tier
	// OpenAI — GPT-4 turbo and earlier.
	"gpt-4-turbo-2024-04-09":    {Input: 10, Output: 30},
	"gpt-4-0125-preview":        {Input: 10, Output: 30},
	"gpt-4-1106-preview":        {Input: 10, Output: 30},
	"gpt-4-1106-vision-preview": {Input: 10, Output: 30},
	"gpt-4-0613":                {Input: 30, Output: 60},
	"gpt-4-0314":                {Input: 30, Output: 60},
	"gpt-4-32k":                 {Input: 60, Output: 120},
	// OpenAI — reasoning (o-series).
	"o4-mini": {Input: 1.10, Output: 4.40, CacheRead: 0.275},
	"o3":      {Input: 2.00, Output: 8, CacheRead: 0.50},
	"o3-mini": {Input: 1.10, Output: 4.40, CacheRead: 0.55},
	"o3-pro":  {Input: 20, Output: 80}, // no cache tier
	"o1":      {Input: 15, Output: 60, CacheRead: 7.50},
	"o1-mini": {Input: 1.10, Output: 4.40, CacheRead: 0.55},
	"o1-pro":  {Input: 150, Output: 600}, // no cache tier
	// OpenAI — GPT-3.5 family (legacy).
	"gpt-3.5-turbo":          {Input: 0.50, Output: 1.50},
	"gpt-3.5-turbo-0125":     {Input: 0.50, Output: 1.50},
	"gpt-3.5-turbo-1106":     {Input: 1, Output: 2},
	"gpt-3.5-turbo-0613":     {Input: 1.50, Output: 2},
	"gpt-3.5-0301":           {Input: 1.50, Output: 2},
	"gpt-3.5-turbo-instruct": {Input: 1.50, Output: 2},
	"gpt-3.5-turbo-16k-0613": {Input: 3, Output: 4},
	// OpenAI — base models (legacy).
	"davinci-002": {Input: 2, Output: 2},
	"babbage-002": {Input: 0.40, Output: 0.40},

	// Google Gemini. The published "Context caching" line is the READ
	// rate (10% of input line-wide) → CacheRead. There is no cache-WRITE
	// line on Google's card because a Gemini cache write is billed as an
	// ordinary input token — so these rows deliberately leave
	// CacheCreation blank and the `gemini` row in cacheWriteRules
	// derives CacheCreation = Input (and LongContextCacheCreation =
	// LongContextInput) at lookup time. Do NOT restate that per row: one
	// owner, one fact. Corrected 2026-09-03 — before then a blank
	// CacheCreation meant $0, which under-billed every Antigravity turn
	// (its usage submessage splits the prompt Anthropic-style, so the
	// growing cached prefix lands in cache_creation, not input).
	// The Pro tiers (2.5 Pro, 3.1 Pro) carry a
	// 200K long-context tier that doubles every dimension; flash and
	// flash-lite are flat-rate. Family prefixes for 3.x are pointed at
	// the Pro rates (incl. LC) so future SKUs without an explicit
	// entry inherit the same shape — flash variants have explicit
	// entries that override the family fallback.
	// Google publishes Gemini Pro long-context as 2× input but only
	// 1.5× output above 200K (3.1 Pro: 2→4 input, 12→18 output;
	// 2.5 Pro: 1.25→2.50 input, 10→15 output). Pre-2026-05-19 this
	// table used 2×/2× across the board ($24 and $20 LongContextOutput),
	// over-billing every >200K Pro turn by 33%. Verified against
	// ai.google.dev/gemini-api/docs/pricing on 2026-05-19.
	"gemini-3.1-pro-preview": {
		Input: 2, Output: 12, CacheRead: 0.20,
		LongContextThreshold: 200_000,
		LongContextInput:     4, LongContextOutput: 18, LongContextCacheRead: 0.40,
	},
	"gemini-3.1-flash-lite-preview": {Input: 0.25, Output: 1.50, CacheRead: 0.025},
	"gemini-3-flash-preview":        {Input: 0.50, Output: 3, CacheRead: 0.05},
	// Gemini 3.5 Flash — Google's speed-focused 3.5 SKU. Standard-tier
	// rates per ai.google.dev/gemini-api/docs/pricing (2026-05-19 user
	// research): $1.50 / $9.00 / $0.15 per 1M tokens. Output rate
	// includes thinking tokens (no separate reasoning split surfaced
	// in the Developer API pricing card). No Long-Context tier is
	// documented for 3.5 Flash. Batch ($0.75/$4.50/$0.075), Flex
	// ($0.75/$4.50/$0.08), and Priority ($2.70/$16.20/$0.27) tiers
	// exist on the pricing page but aren't currently modelled — our
	// Pricing struct carries one tier per model, and Standard is the
	// conservative default for cost estimates. Grounding ($14/1000
	// queries = $0.014/call) is the next-deferred surface; tracked in
	// the prior pricing audit §B6 + post-v1.6.18 kickoff Workstream B.
	"gemini-3.5-flash": {Input: 1.50, Output: 9, CacheRead: 0.15},
	// Gemini 3.6 Flash — launched 2026-07-21. CORRECTED 2026-08-15:
	// ai.google.dev now lists 3.6 Flash on the SAME introductory rate as
	// 3.7 Flash — $0.75 / $3.75 / $0.075 through 2026-12-31, both rising
	// to $1.50 / $7.50 / $0.15 on 2027-01-01 (the prior $1.50 row here
	// was over-billing 2×). This row must be bumped together with the
	// 3.7 Flash row below at the 2027-01 flip. 1M context, 64K max
	// output. NOT covered by the "gemini-3" bare family fallback below
	// despite the shared "gemini-3" prefix — that family carries
	// Pro-class LC rates, so a Flash SKU needs its own exact row or it
	// silently prices over the real rate.
	"gemini-3.6-flash": {Input: 0.75, Output: 3.75, CacheRead: 0.075},
	// Gemini 3.7 Flash — launched 2026-08-11. Google is running an
	// introductory rate through 2026-12-31: $0.75 / $3.75 / $0.075.
	// Standard rate from 2027-01-01 is $1.50 / $7.50 (== 3.6 Flash's
	// rate above) — this exact row must be bumped to the standard rate
	// on/after that date, mirroring the claude-sonnet-5 intro-pricing
	// pattern elsewhere in this table. 1M context, 65,536 max output.
	// Same family-shadow note as 3.6 Flash above: the bare "gemini-3"
	// family fallback is Pro-class and must NOT be allowed to catch
	// this id.
	"gemini-3.7-flash": {Input: 0.75, Output: 3.75, CacheRead: 0.075},
	// Gemini 3.8 Flash — launched 2026-09-02 (ai.google.dev/gemini-api/
	// docs/pricing, fetched 2026-09-07). Same introductory-rate shape as
	// 3.6/3.7 Flash: $0.75 / $3.75 / $0.075 through 2026-12-31, standard
	// rate $1.50 / $7.50 / $0.15 from 2027-01-01 — bump this row (and its
	// 3.6/3.7 siblings) together at that flip. 1M context. Needs its own
	// EXPLICIT row for the same reason as 3.6/3.7 Flash: it prefix-matches
	// the bare "gemini-3" family fallback below, which carries Pro-class
	// LC rates — without this row a Flash-class request would misclassify
	// as Opus/Pro-class (silently overbilled ~1.6-8×, per the 3.6/3.7
	// Flash precedent).
	"gemini-3.8-flash": {Input: 0.75, Output: 3.75, CacheRead: 0.075},
	"gemini-2.5-pro": {
		Input: 1.25, Output: 10, CacheRead: 0.125,
		LongContextThreshold: 200_000,
		LongContextInput:     2.50, LongContextOutput: 15, LongContextCacheRead: 0.25,
	},
	"gemini-2.5-flash":                      {Input: 0.30, Output: 2.50, CacheRead: 0.03},
	"gemini-2.5-flash-lite":                 {Input: 0.10, Output: 0.40, CacheRead: 0.01},
	"gemini-2.5-flash-lite-preview-09-2025": {Input: 0.10, Output: 0.40, CacheRead: 0.01},
	"gemini-2.0-flash":                      {Input: 0.10, Output: 0.40, CacheRead: 0.025}, // deprecated
	"gemini-2.0-flash-lite":                 {Input: 0.075, Output: 0.30},                  // deprecated
	// Family prefixes — set to LATEST (3.x) so future SKUs inherit
	// current generation rates rather than legacy. 3.1 / 3 family
	// fallback inherits Pro LC rates since the 3.1 Pro Preview is the
	// representative; 2.5 family fallback inherits 2.5 Pro LC rates.
	"gemini-3.1": {
		Input: 2, Output: 12, CacheRead: 0.20,
		LongContextThreshold: 200_000,
		LongContextInput:     4, LongContextOutput: 18, LongContextCacheRead: 0.40,
	},
	"gemini-3": {
		Input: 2, Output: 12, CacheRead: 0.20,
		LongContextThreshold: 200_000,
		LongContextInput:     4, LongContextOutput: 18, LongContextCacheRead: 0.40,
	},
	"gemini-2.5": {
		Input: 1.25, Output: 10, CacheRead: 0.125,
		LongContextThreshold: 200_000,
		LongContextInput:     2.50, LongContextOutput: 15, LongContextCacheRead: 0.25,
	},
	"gemini-2": {Input: 0.10, Output: 0.40, CacheRead: 0.025},

	// Antigravity-internal model SKUs. The Antigravity IDE encodes the
	// model + effort selector into a single identifier string rather
	// than exposing a separate effort field on the wire. Two naming
	// conventions co-exist:
	//
	//   `<family>-agent`              — default / high effort
	//   `<version>-<family>-<effort>` — explicit effort selection
	//
	// Verified empirically across 4 user sessions on 2026-05-12:
	//   gemini-pro-agent       → Gemini 3.1 Pro, high effort
	//   gemini-3.1-pro-{low,medium,high}  → Gemini 3.1 Pro, explicit effort
	//   gemini-3-flash-agent   → Gemini 3 Flash
	//
	// Pre-2026-05-13 these landed via family-prefix fallback (or as
	// PricingSourceMiss for `gemini-pro-agent`):
	//   - gemini-pro-agent      → miss → $0 (silently)
	//   - gemini-3-flash-agent  → matched `gemini-3` family → Pro rates,
	//                             4× over the actual Flash rate
	//   - gemini-3.1-pro-low    → matched `gemini-3.1` → Pro rates
	//                             (correct by accident)
	//
	// Pinned explicitly here so every variant gets PricingSourceExact and
	// the Flash variants don't silently inherit Pro rates.
	"gemini-pro-agent": {
		Input: 2, Output: 12, CacheRead: 0.20,
		LongContextThreshold: 200_000,
		LongContextInput:     4, LongContextOutput: 18, LongContextCacheRead: 0.40,
	},
	"gemini-3.1-pro-high": {
		Input: 2, Output: 12, CacheRead: 0.20,
		LongContextThreshold: 200_000,
		LongContextInput:     4, LongContextOutput: 18, LongContextCacheRead: 0.40,
	},
	"gemini-3.1-pro-medium": {
		Input: 2, Output: 12, CacheRead: 0.20,
		LongContextThreshold: 200_000,
		LongContextInput:     4, LongContextOutput: 18, LongContextCacheRead: 0.40,
	},
	"gemini-3.1-pro-low": {
		Input: 2, Output: 12, CacheRead: 0.20,
		LongContextThreshold: 200_000,
		LongContextInput:     4, LongContextOutput: 18, LongContextCacheRead: 0.40,
	},
	// Gemini 3 Pro effort SKUs — explicit pins paralleling the
	// gemini-3.1-pro-* set. Pre-pin these resolved via the gemini-3
	// family-prefix fallback (which happens to be Pro rates) — correct
	// today but load-bearing on the matcher. The 2026-05-19 antigravity
	// audit (docs/antigravity-audit-2026-05-19.md §B2) recommended
	// hardening; 3,831 live gemini-3-pro-high rows in the maintainer DB
	// are the bulk of the antigravity corpus.
	"gemini-3-pro-high": {
		Input: 2, Output: 12, CacheRead: 0.20,
		LongContextThreshold: 200_000,
		LongContextInput:     4, LongContextOutput: 18, LongContextCacheRead: 0.40,
	},
	"gemini-3-pro-medium": {
		Input: 2, Output: 12, CacheRead: 0.20,
		LongContextThreshold: 200_000,
		LongContextInput:     4, LongContextOutput: 18, LongContextCacheRead: 0.40,
	},
	"gemini-3-pro-low": {
		Input: 2, Output: 12, CacheRead: 0.20,
		LongContextThreshold: 200_000,
		LongContextInput:     4, LongContextOutput: 18, LongContextCacheRead: 0.40,
	},
	"gemini-3-flash-agent":  {Input: 0.50, Output: 3, CacheRead: 0.05},
	"gemini-3-flash-high":   {Input: 0.50, Output: 3, CacheRead: 0.05},
	"gemini-3-flash-medium": {Input: 0.50, Output: 3, CacheRead: 0.05},
	"gemini-3-flash-low":    {Input: 0.50, Output: 3, CacheRead: 0.05},
	// Gemini 3 Flash family-prefix entry — without this, a hypothetical
	// gemini-3-flash-experimental (or any flash SKU not in the explicit
	// set above) falls through to the `gemini-3` family fallback and
	// bills at Pro rates ($2/$12) — ~4× over-bill. Mirrors how the
	// gemini-2.5-flash + gemini-2.5-flash-lite family entries already
	// pin the 2.5 line. Zero current live rows; pure resilience.
	// 2026-05-19 antigravity audit §B1.
	"gemini-3-flash": {Input: 0.50, Output: 3, CacheRead: 0.05},

	// xAI. Current line-up per docs.x.ai/developers/models (2026-07/08):
	// grok-4.5 was the flagship ($2/$6, 500k ctx); grok-4.6 (2026-08)
	// supersedes it and introduces xAI's first context-length-tiered
	// pricing: <200K ctx bills at the same $2/$6 as 4.5, but a request
	// whose context crosses 200K reprices the ENTIRE call at $4/$12
	// (doubled) — modelled with the LongContextThreshold/LongContext*
	// fields, the same mechanism already used for Gemini 2.5/3.x Pro
	// and GPT-5.4+. Cached input is $0.50 (<200K) / $1.00 (>=200K), a
	// real published rate (unlike 4.5, see below). grok-build-0.1 is a
	// dedicated agentic-coding model in early access ($1/$2, 256k ctx).
	// These were silently falling through to the `grok` family prefix at
	// grok-4.3's $1.25/$2.50 (under-billing 1.6×/2.4×) before these rows.
	// grok-4.3 + the grok-4.20-0309-* family stay at $1.25/$2.50
	// (unchanged). docs.x.ai publishes no cached-input rate for grok-4.5
	// / grok-build-0.1, so CacheRead is left unset on those two and
	// fillDefaults' universal 10%-of-input default applies ($0.20 /
	// $0.10). `grok-code-fast-1` was retired 2026-05-15 and redirects to
	// grok-4.3 pricing. The `grok` family prefix follows the current
	// flagship (grok-4.6's <200K tier — numerically identical to 4.5's
	// $2/$6, but now carries the real $0.50 cached rate rather than the
	// 10%-of-input default), same precedent as the kimi-k2-6 family
	// bump. The family prefix intentionally does NOT carry the >=200K
	// long-context tier — an unknown/future grok-* SKU that falls
	// through to this row is priced at the base tier, never the
	// doubled one.
	"grok-4.6": {
		Input: 2, Output: 6, CacheRead: 0.50,
		LongContextThreshold: 200_000,
		LongContextInput:     4, LongContextOutput: 12, LongContextCacheRead: 1.00,
	},
	"grok-4.5":         {Input: 2, Output: 6}, // flagship since 2026-07 (500k ctx), superseded by grok-4.6 2026-08; was silently falling to the `grok` family row at 4.3 rates
	"grok-build-0.1":   {Input: 1, Output: 2}, // agentic-coding model, early access (256k ctx)
	"grok-build":       {Input: 1, Output: 2}, // family prefix for future build-x SKUs
	"grok-4.3":         {Input: 1.25, Output: 2.50},
	"grok-4.20":        {Input: 1.25, Output: 2.50},            // covers grok-4.20-0309-* family
	"grok-4-20":        {Input: 1.25, Output: 2.50},            // historical alias
	"grok-code-fast-1": {Input: 1.25, Output: 2.50},            // retired 2026-05-15 → redirects to grok-4.3 pricing
	"grok-code":        {Input: 1.25, Output: 2.50},            // family prefix
	"grok":             {Input: 2, Output: 6, CacheRead: 0.50}, // family prefix → grok-4.6's base (<200K) tier

	// Moonshot.
	"kimi-k2-5": {Input: 0.60, Output: 3, CacheRead: 0.10},
	// Kimi K2.6 — newer than K2.5; OpenRouter price (matches first-party
	// per the 2026-06-06 catalog cross-check).
	"kimi-k2-6": {Input: 0.684, Output: 3.42, CacheRead: 0.144},
	// Kimi K3 — flagship, released 2026-07-16 (2.8T-param open-weight
	// multimodal reasoning, 1M ctx, reasoning_effort=max only). First-party
	// rate card platform.kimi.ai/docs/pricing/chat-k3 (fetched 2026-07-17):
	// $3.00 input (cache miss) / $15.00 output / $0.30 cached-input (cache
	// hit) per 1M — a 4.4× jump over K2.6, matching Claude Sonnet 5's
	// standard $3/$15. Cache hit is Moonshot's automatic context cache (no
	// cache_creation charge → CacheCreation stays 0). This bare key also
	// serves as the K3 family prefix (kimi-k3-*), winning over "kimi"
	// longest-first.
	//
	// RESOLVED (2026-08-15): the $2.80/$14 figure was never a competing
	// claim about this first-party card — it is OpenRouter's own separate
	// listing (live at openrouter.ai/moonshotai/kimi-k3), captured
	// accurately at the "moonshotai/kimi-k3" row below. This bare row's
	// $3/$15/$0.30 is confirmed directly against
	// platform.kimi.ai/docs/pricing/chat-k3 (re-fetched 2026-08-15).
	"kimi-k3": {Input: 3, Output: 15, CacheRead: 0.30},
	// kimi family prefix stays at K2.6 (the mainstream/cheaper generation:
	// K2.6 and K2.7-Code both list ~$0.95/$4). NOT bumped to K3 on purpose
	// — K3 is a 4.4× outlier, so a bare "kimi" fallback for an unknown
	// K2.x SKU (e.g. kimi-k2-7) must NOT silently inherit K3 rates. K3
	// variants land on the explicit "kimi-k3" prefix above instead.
	"kimi": {Input: 0.684, Output: 3.42, CacheRead: 0.144}, // family prefix → K2.6 rates

	// Open-weight model families. Anchored to first-party / representative
	// rates (the "single host" anchor per
	// docs/plans/open-weight-models-pricing-review-2026-06-06.md Problem 1
	// recommendation (A)). OpenRouter-served variants live as
	// provider-qualified keys further down so the host delta is preserved
	// for adapters that route through OpenRouter (hermes, pi, opencode).
	// Per-family `:free` rows are NOT needed — the `:free` suffix guard
	// in LookupWithSource returns known-$0 for any of these strings.
	//
	// OpenAI GPT-OSS — open-weight; reaches the cost engine via antigravity
	// (decoded model strings) and OpenRouter (hermes/pi). Median across
	// hosts spans ~7× — OpenRouter is the cheapest representative anchor.
	"gpt-oss-120b": {Input: 0.039, Output: 0.18},
	"gpt-oss-20b":  {Input: 0.03, Output: 0.14},
	"gpt-oss":      {Input: 0.039, Output: 0.18}, // family prefix → 120b
	// Nvidia Nemotron 3 — launched 2026-06-04. Reaches via hermes (Nous
	// Research's multi-provider router) and OpenRouter.
	"nemotron-3-ultra-550b-a55b": {Input: 0.50, Output: 2.50},
	"nemotron-3-super-120b-a12b": {Input: 0.09, Output: 0.45},
	"nemotron-3-nano-30b-a3b":    {Input: 0.04, Output: 0.15},
	"nemotron-3-ultra":           {Input: 0.50, Output: 2.50}, // shorthand id
	"nemotron-3":                 {Input: 0.09, Output: 0.45}, // family (super as default representative)
	// Nemotron 3.5 Lightning — a DIFFERENT generation from the "nemotron-3"
	// family above, not caught by it: "nemotron-3.5-lightning" and
	// "nemotron-3-ultra" diverge at the character right after
	// "nemotron-3" ('.' vs '-'), so neither prefix-matches the other, but
	// the bare "nemotron-3" family row above WOULD still catch this id via
	// strings.HasPrefix (both start with the literal 10-char "nemotron-3")
	// — hence this exact row is required, not optional; without it the id
	// silently resolves to the wrong generation's rate (0.09/0.45 vs the
	// real 0.08/0.20). Used via OpenRouter in this project's demo; the
	// `nvidia/` provider-qualified row below mirrors it. A `:free`-suffixed
	// id (e.g. "nvidia/nemotron-3.5-lightning:free") never reaches this
	// row — LookupWithSource's `:free` suffix guard resolves to known-$0
	// BEFORE any family/exact lookup runs, so no separate :free row is
	// needed here (same precedent as the north-mini-code / gpt-oss free
	// rows elsewhere in this table).
	"nemotron-3.5-lightning": {Input: 0.08, Output: 0.20},
	"nemotron":               {Input: 0.09, Output: 0.45}, // family
	// Nous Hermes — host-priced; flat in/out on the 3.x and 4.x lines.
	// hermes-4 rates are the placeholder per the catalog "confirm exact"
	// note; revisit when Nous publishes definitive numbers on Portal.
	"hermes-3-llama-3.1-405b": {Input: 1.00, Output: 1.00},
	"hermes-4-405b":           {Input: 1.00, Output: 1.00}, // placeholder = Hermes 3 rate
	"hermes-4-70b":            {Input: 1.00, Output: 1.00}, // placeholder
	"hermes-4":                {Input: 1.00, Output: 1.00}, // family
	"hermes":                  {Input: 1.00, Output: 1.00}, // family
	// Alibaba Qwen — DashScope first-party; implicit cache = 20% of input.
	// SKUs route via hermes/pi/opencode through OpenRouter (variants below).
	"qwen3-max":   {Input: 0.78, Output: 3.90, CacheRead: 0.156},
	"qwen3-coder": {Input: 1.50, Output: 7.50, CacheRead: 0.30},
	"qwen3":       {Input: 0.78, Output: 3.90, CacheRead: 0.156}, // family
	"qwen":        {Input: 0.78, Output: 3.90, CacheRead: 0.156}, // family
	// Zhipu GLM — prices rose with 5.1 to close the US gap (deliberate).
	"glm-5":   {Input: 1.00, Output: 3.20, CacheRead: 0.20},
	"glm-5.1": {Input: 0.98, Output: 3.08, CacheRead: 0.182},
	// glm-5.3 — released 2026-08-14, current Zhipu flagship. Same rate as
	// glm-5.2 (docs.z.ai/guides/overview/pricing, fetched 2026-09-07:
	// $1.40/$4.40, cached $0.26 — byte-identical to the glm-5.2 row below).
	"glm-5.3": {Input: 1.40, Output: 4.40, CacheRead: 0.26},
	// glm-5.3-flash — the budget tier of the same generation. LIST rate
	// (docs.z.ai, fetched 2026-09-07): $0.15/$0.50, cached input $0.03;
	// the page currently displays a 50%-off promo ($0.075/$0.25/$0.015,
	// "ends 24:00 September 9, 2026 UTC+8") struck through against those
	// list prices — using LIST per house policy (a promo is still a
	// promo; see the minimax-m3 / glm-5.2 precedent above/below).
	// CacheRead is set EXPLICITLY to the LIST cached-input rate: leaving
	// it 0 would let fillDefaults' 10%-of-input floor derive $0.015 —
	// which is the PROMO cache-read figure, not list — silently smuggling
	// the promo back in through the one field this row didn't set.
	"glm-5.3-flash": {Input: 0.15, Output: 0.50, CacheRead: 0.03},
	// FIXED 2026-09-07: bare "glm" family prefix was still pinned to 5.1's
	// rates even though 5.2 (2026-07-23) and now 5.3 (2026-08-14) have
	// since superseded it as the actual latest generation — an oversight
	// from the sessions that added those two rows without revisiting this
	// one. Bumped to glm-5.3 (== glm-5.2's numbers; the flagship rate did
	// not change between those two generations).
	"glm": {Input: 1.40, Output: 4.40, CacheRead: 0.26}, // family → 5.3 (latest)
	// Mistral — batch 50% off is known-unmodelled (no batch dimension on
	// the struct). Family prefix points at medium-3 (the typical paid
	// "middle of the road" anchor).
	"mistral-large":    {Input: 2.00, Output: 6.00},
	"mistral-medium-3": {Input: 1.00, Output: 3.00},
	"mistral-small":    {Input: 0.15, Output: 0.60, CacheRead: 0.015},
	"mistral":          {Input: 1.00, Output: 3.00}, // family → medium-3
	// mistral.ai/pricing/api (fetched 2026-09-07). Mistral Large 3 (API
	// alias `mistral-large-latest`, released 2025-12-02 per vals.ai —
	// pre-dates this sweep's window but was never previously registered
	// under a "-3"-suffixed key) and Mistral Medium 3.5 (alias
	// `mistral-medium-latest`). Registered as NEW exact keys, not merged
	// into the existing bare "mistral-large" / "mistral-medium-3" rows
	// above: we have no confirmation that the literal strings "mistral-large"
	// / "mistral-medium-3" an adapter might already have on disk are the
	// SAME model as these newer generations (vs. still-served legacy Large
	// 2 / Medium 3 SKUs), so overwriting those rows risked silently
	// repricing unrelated historical traffic. If a live capture ever shows
	// an adapter emitting the bare "mistral-large" string post-Large-3, add
	// a dated timeline (dated.go) rather than editing the row directly.
	//
	// "mistral-medium-3-5" bare row was previously registered ONLY as the
	// OpenRouter-qualified "mistralai/mistral-medium-3-5" key below at this
	// exact rate ($1.50/$7.50) — this fills the missing first-party key at
	// the SAME published price (one upstream, same tokens).
	"mistral-large-3":      {Input: 0.5, Output: 1.5},
	"mistral-large-latest": {Input: 0.5, Output: 1.5}, // literal API alias string, in case an adapter passes it through verbatim
	"mistral-medium-3-5":   {Input: 1.50, Output: 7.50},
	// mistral-medium-latest — the literal API alias for Mistral Medium
	// 3.5 (same model, same rate as mistral-medium-3-5 above). Without
	// this key an adapter emitting the alias verbatim falls through to
	// the bare "mistral" family row ($1.00/$3.00, the medium-3 anchor) —
	// the wrong generation's price, silently under-billing every Medium
	// 3.5 turn. Registered as its OWN key rather than merged into
	// "mistral-medium-3-5", mirroring the "mistral-large-latest" pattern
	// immediately above.
	"mistral-medium-latest": {Input: 1.50, Output: 7.50}, // literal API alias string, in case an adapter passes it through verbatim
	// Ministral 3 — small/edge tier, same page. No cache-read published;
	// left at 0 for fillDefaults' 10%-of-input floor.
	"ministral-3b":  {Input: 0.1, Output: 0.1},
	"ministral-8b":  {Input: 0.15, Output: 0.15},
	"ministral-14b": {Input: 0.2, Output: 0.2},
	// MiniMax — family prefix → m2.7 (the latest).
	"minimax-m2.7": {Input: 0.279, Output: 1.20},
	"minimax-m2.5": {Input: 0.15, Output: 1.15},
	"minimax":      {Input: 0.279, Output: 1.20}, // family → m2.7
	// Local — Ollama runs on user hardware → $0 per-token. Adapter strings
	// arrive as `ollama/gemma4:e4b`, `ollama/gemma3:1b`, etc. via hermes /
	// pi / openclaw. Explicit family-prefix row so any `ollama/*` lookup
	// resolves PricingSourceFamily with rates (0, 0) — the reliability
	// tagger then stamps the row as "approximate" (known-priced model with
	// zero rate) rather than "unknown" (PricingSourceMiss). Note:
	// LookupWithSource's verbatim and `:free` paths return early; family-
	// prefix wins only when neither hits. Compute returns ok=true on a
	// Pricing{0,0,...} row (only PricingSourceMiss → ok=false), so local
	// inference is correctly billed as known-$0.
	"ollama": {Input: 0, Output: 0},

	// DeepSeek — V4 family (api-docs.deepseek.com, snapshot 2026-06-06).
	// Cache hit = cached-input read → CacheRead. No separate cache-write
	// charge (auto-cache, OpenAI-shape) so CacheCreation stays 0.
	//
	// PEAK/OFF-PEAK OVERHAUL LANDED 2026-08-16T16:00Z, confirmed live
	// 2026-09-07 (api-docs.deepseek.com/quick_start/pricing): the flat
	// rate below is GONE, replaced by an off-peak / peak split — off-peak
	// (all hours except the peak windows) at the rates baked into this
	// table, peak (01:00-04:00 and 06:00-10:00 UTC, Mon-Fri) at EXACTLY
	// 2× every dimension. This is a genuine PRICE CHANGE relative to the
	// pre-overhaul flat rate (the off-peak rate is itself higher than the
	// old flat rate — DeepSeek signaled "a future overall increase" ahead
	// of this rollout), so the old flat numbers are preserved as the
	// pre-2026-08-16T16:00Z period of each key's dated.go timeline rather
	// than being silently overwritten (see dated.go).
	//
	// Our Pricing struct has no time-of-day dimension (same documented
	// limitation as MiniMax's >512K doubling and Sakana's >272K tier), so
	// ONE rate must be baked into the flat table — off-peak is used as the
	// representative because it covers the large majority of hours (all
	// weekend plus 17 of 24 UTC hours on weekdays); PEAK IS UNMODELED
	// (documented, not modeled, per docs/pricing-reference.md "Out of
	// scope") — a request actually served in a peak window will be
	// under-billed 2× until this struct grows a time dimension.
	//
	// `deepseek-chat` / `deepseek-reasoner` are legacy aliases that
	// DeepSeek still resolves; both map to v4-flash and carry the same
	// dated timeline. NOTE: neither alias is listed on the current
	// api-docs.deepseek.com/quick_start/pricing page any more (only the
	// v4-flash/v4-pro/v4-flash-vision-exp SKU names appear) — the → v4-flash
	// mapping below is INFERRED from the aliases' historical behavior, not
	// re-confirmed against a published row for these exact strings.
	"deepseek-v4-flash": {Input: 0.22, Output: 0.66, CacheRead: 0.007},
	// deepseek-v4-flash-vision-exp — a new experimental vision SKU listed
	// alongside v4-flash/v4-pro on the same pricing page (fetched
	// 2026-09-07), billed at the SAME off-peak rate as v4-flash. No prior
	// row existed for this id, so no dated timeline is needed (nothing to
	// preserve).
	"deepseek-v4-flash-vision-exp": {Input: 0.22, Output: 0.66, CacheRead: 0.007},
	"deepseek-v4-pro":              {Input: 0.66, Output: 1.98, CacheRead: 0.022},
	"deepseek-chat":                {Input: 0.22, Output: 0.66, CacheRead: 0.007}, // alias → v4-flash non-thinking
	"deepseek-reasoner":            {Input: 0.22, Output: 0.66, CacheRead: 0.007}, // alias → v4-flash thinking
	"deepseek-v4":                  {Input: 0.22, Output: 0.66, CacheRead: 0.007}, // family prefix → flash (default/cheapest)
	"deepseek":                     {Input: 0.22, Output: 0.66, CacheRead: 0.007}, // family prefix
	// OpenRouter-served DeepSeek (provider-qualified keys, exact match
	// wins before stripProviderPrefix-equivalent ladder reductions).
	// OpenRouter serves v4-flash at 30% off first-party ($0.098/$0.197)
	// — captured here so an adapter that passes the qualified id
	// verbatim (clinecli routing through OpenRouter, hermes openrouter/*
	// routes) bills at the host rate. Adapters that pre-strip the
	// provider prefix continue to land on the bare row above.
	"deepseek/deepseek-v4-flash": {Input: 0.098, Output: 0.197, CacheRead: 0.0197},
	"deepseek/deepseek-v4-pro":   {Input: 0.435, Output: 0.87, CacheRead: 0.0036},

	// OpenRouter open-weight catalog snapshot — string keys exactly as
	// OpenRouter emits them (see openrouter.ai/api/v1/models). Live
	// snapshot 2026-06-06 from provider-model-price-catalog §14; brief
	// A6 lists the required ids verbatim. Same model as the bare rows
	// above, different price (the per-host delta the bare-id table key
	// can't express). Re-fetching via a `make sync-openrouter-pricing`
	// target is deferred per the catalog "bake now" choice.
	"openai/gpt-oss-120b": {Input: 0.039, Output: 0.18},
	"openai/gpt-oss-20b":  {Input: 0.03, Output: 0.14},
	// Nvidia Nemotron 3 via OpenRouter (matches first-party canonical ids).
	"nvidia/nemotron-3-ultra-550b-a55b": {Input: 0.50, Output: 2.50},
	"nvidia/nemotron-3-super-120b-a12b": {Input: 0.09, Output: 0.45},
	"nvidia/nemotron-3.5-lightning":     {Input: 0.08, Output: 0.20}, // see bare "nemotron-3.5-lightning" comment above
	// Nous Hermes via OpenRouter (rates = first-party placeholder until
	// Nous publishes definitive numbers — same caveat as the bare rows).
	"nousresearch/hermes-3-llama-3.1-405b": {Input: 1.00, Output: 1.00},
	"nousresearch/hermes-4-405b":           {Input: 1.00, Output: 1.00},
	"nousresearch/hermes-4-70b":            {Input: 1.00, Output: 1.00},
	// Alibaba Qwen via OpenRouter. qwen3.7-max + qwen3.6-* are the live
	// catalog SKUs; qwen/* prefix differs from first-party `qwen3-*` bare
	// ids so both can coexist.
	//
	// NOTE (2026-08 sweep): this OpenRouter-qualified rate ($1.25/$3.75)
	// does NOT match either figure surfaced by the 2026-08 research pass
	// for Qwen3.7-Max — official first-party Alibaba pricing is
	// $2.50/$7.50 (added as the bare "qwen3.7-max" row below), and a
	// separately-observed OpenRouter listing showed $1.475/$4.425. Left
	// AS-IS pending re-verification against a live OpenRouter catalog
	// pull — this row predates that research pass and may reflect an
	// intro/promo rate OpenRouter has since changed. Flagged, not
	// touched, to avoid overwriting a previously-verified number with an
	// unreconciled one.
	"qwen/qwen3.7-max":         {Input: 1.25, Output: 3.75, CacheRead: 0.25},
	"qwen/qwen3.6-max-preview": {Input: 1.04, Output: 6.24},
	"qwen/qwen3.6-plus":        {Input: 0.325, Output: 1.95},
	"qwen/qwen3.6-flash":       {Input: 0.1875, Output: 1.125},
	"qwen/qwen3.6-35b-a3b":     {Input: 0.14, Output: 1.00},
	// Zhipu GLM via OpenRouter (z-ai/ prefix).
	"z-ai/glm-5.1":      {Input: 0.98, Output: 3.08, CacheRead: 0.182},
	"z-ai/glm-5-turbo":  {Input: 1.20, Output: 4.00, CacheRead: 0.24},
	"z-ai/glm-5v-turbo": {Input: 1.20, Output: 4.00, CacheRead: 0.24},
	// Mistral via OpenRouter (mistralai/ prefix).
	"mistralai/mistral-medium-3-5": {Input: 1.50, Output: 7.50},
	"mistralai/mistral-small-2603": {Input: 0.15, Output: 0.60, CacheRead: 0.015},
	// MiniMax via OpenRouter.
	"minimax/minimax-m2.7": {Input: 0.26, Output: 1.20},
	// xAI via OpenRouter. The multi-agent variant is priced higher
	// ($2/$6 vs $1.25/$2.50 base) — model captures it explicitly so the
	// family fallback doesn't undercount.
	"x-ai/grok-4.3":              {Input: 1.25, Output: 2.50, CacheRead: 0.20},
	"x-ai/grok-4.20-multi-agent": {Input: 2.00, Output: 6.00, CacheRead: 0.20},
	"x-ai/grok-build-0.1":        {Input: 1.00, Output: 2.00, CacheRead: 0.20},
	// Moonshot via OpenRouter.
	"moonshotai/kimi-k2.6": {Input: 0.684, Output: 3.42, CacheRead: 0.144},
	// Kimi K3 via OpenRouter (openrouter.ai/moonshotai/kimi-k3, re-fetched
	// 2026-08-15): OpenRouter's live listing is $2.80 input / $14 output —
	// a genuinely DIFFERENT rate from Moonshot's first-party $3/$15 card,
	// not a data error (the earlier "$2.80/$14 variance" note on the bare
	// kimi-k3 row was this listing). OpenRouter publishes NO exact cache
	// rate (only a vague "60-80% cheaper with prompt caching" note), so
	// CacheRead mirrors Moonshot's own first-party cache-hit rate ($0.30)
	// — the same single upstream serves the tokens — rather than
	// fabricating an OpenRouter-specific number.
	"moonshotai/kimi-k3": {Input: 2.80, Output: 14, CacheRead: 0.30},

	// --- 2026-07-23 research batch (new providers/models) ---

	// Alibaba Qwen — additional 3.5/3.7 generation SKUs, first-party
	// DashScope rates (alibabacloud.com/help/en/model-studio/model-pricing,
	// standard ≤256K tier; thinking output billed at the same output rate
	// as non-thinking). qwen3.5-plus is selectable directly in Qwen Code CLI.
	"qwen3.5-plus":  {Input: 0.40, Output: 2.40, CacheRead: 0.04},
	"qwen3.5-flash": {Input: 0.10, Output: 0.40, CacheRead: 0.01},
	// OpenRouter-qualified aliases. ADDED post-review (2026-07-23 codex
	// adversarial pass, P1): real captured traffic already contains the
	// dated wire ID "qwen/qwen3.5-plus-20260420" (see
	// docs/plans/provider-model-price-catalog-2026-06-06.md). Date-strip
	// (`-\d{8}$`) reduces that to "qwen/qwen3.5-plus", which without this
	// row was ABSENT from the table and fell through to the generic
	// "qwen3" family fallback ($0.78/$3.90 — wrong tier entirely).
	//
	// "qwen/qwen3.5-plus" deliberately uses the REAL OpenRouter list rate
	// ($0.30/$1.80, no cache rate published — CacheRead left at 0 so
	// fillDefaults' 10%-of-input floor applies) from the price catalog
	// above, NOT a literal mirror of the first-party DashScope bare rate
	// ($0.40/$2.40/$0.04) — OpenRouter's own price for this route is
	// verified real data and takes precedence over an assumption that the
	// two channels bill identically.
	"qwen/qwen3.5-plus": {Input: 0.30, Output: 1.80},
	// "qwen/qwen3.5-flash" has no corresponding real OpenRouter data point
	// in the catalog, so this one DOES mirror the bare DashScope rate for
	// symmetry with the -plus alias above, per the original request.
	"qwen/qwen3.5-flash": {Input: 0.10, Output: 0.40, CacheRead: 0.01},
	// qwen3.5-omni-* are TEXT-tier rates only — Omni also bills audio
	// input/output at a separate, much higher per-token rate ($11 in /
	// $44 out per M for -plus; $3 in / $11.90 out per M for -flash) that
	// this struct has no modality dimension to express. Text-only turns
	// bill correctly; a turn carrying audio tokens will under-bill until
	// the schema grows a modality split.
	"qwen3.5-omni-plus":  {Input: 1.40, Output: 8.30},
	"qwen3.5-omni-flash": {Input: 0.40, Output: 2.20},
	// UNVERIFIED (2026-08 sweep): OpenRouter availability for qwen3.7-plus
	// was not directly confirmed — the alias row below is carried
	// forward from the original DashScope-mirroring rationale, not a
	// freshly re-verified OpenRouter listing.
	"qwen3.7-plus": {Input: 0.40, Output: 1.60, CacheRead: 0.04},
	// OpenRouter alias — list price. OR currently runs a 20%-off promo on
	// top of this (not modeled; promos are time-boxed and this is the
	// standing list rate).
	"qwen/qwen3.7-plus": {Input: 0.40, Output: 1.60, CacheRead: 0.04},
	// qwen3.7-max — official first-party Alibaba/DashScope rate (2026-08
	// sweep): $2.50/$7.50, cache-read $0.25 (10%-of-input, consistent
	// with the rest of the Qwen family). Distinct from the
	// OpenRouter-qualified "qwen/qwen3.7-max" row above, which carries a
	// lower, unreconciled rate — see the NOTE on that row. Before this
	// row existed, a bare "qwen3.7-max" id fell through to the generic
	// "qwen3"/"qwen" family fallback ($0.78/$3.90) — a real but
	// wrong-tier (69% under-billed) rate for the actual flagship SKU.
	"qwen3.7-max": {Input: 2.50, Output: 7.50, CacheRead: 0.25},
	// qwen3.8-max-preview — NO official per-token rate as of 2026-07-23.
	// Announced 2026-07-19 as a Token Plan preview only (no metered API
	// pricing published). PLACEHOLDER anchored to qwen3.7-max's exact
	// then-current OpenRouter rate ($1.25/$3.75, cache $0.25). GA'd
	// 2026-08-03 as "qwen3.8-max" (no "-preview" suffix, a distinct id)
	// at real, official rates — see that row below. This preview row is
	// kept as-is (not deleted, not repointed) since historical
	// preview-tagged sessions may still carry the "-preview" id verbatim
	// and should keep resolving to the placeholder they actually saw,
	// not be silently retargeted at the GA rate.
	"qwen3.8-max-preview": {Input: 1.25, Output: 3.75, CacheRead: 0.25},
	// qwen3.8-max — GA'd 2026-08-03. Official flagship rate: $2.00/$6.00,
	// cache-read $0.25, 1M context. Supersedes the preview placeholder
	// above for any id WITHOUT the "-preview" suffix.
	"qwen3.8-max": {Input: 2, Output: 6, CacheRead: 0.25},
	// qwen3.8-max-0902 — a post-training refresh of qwen3.8-max released
	// 2026-09-02 at the SAME price (alibabacloud.com/help/en/model-studio/
	// model-pricing, fetched 2026-09-07: both list $2/$6). The dated
	// "-0902" suffix is 4 digits, not 8, so it is NOT caught by the
	// dateSuffix (-\d{8}$) strip and would otherwise resolve only via the
	// "qwen3.8-max" family-prefix fallback (PricingSourceFamily, same
	// dollar amount) — registered as its own exact row for an accurate
	// PricingSourceExact tag, mirroring the "qwen3.8-max-preview" row's
	// same-shape precedent.
	"qwen3.8-max-0902": {Input: 2, Output: 6, CacheRead: 0.25},
	// qwen3.8-flash — released 2026-08-26. Official DashScope rate
	// (alibabacloud.com/help/en/model-studio/model-pricing, fetched
	// 2026-09-07): $0.15/$0.47. A secondary aggregator quoted $0.14/$0.42
	// with a separate $0.016 cache-read figure; the first-party page is
	// used here per house policy (primary source over aggregator), and no
	// cache-read rate is stated on it, so CacheRead is left at 0 for
	// fillDefaults' 10%-of-input floor ($0.015) rather than the
	// unconfirmed $0.016 aggregator number. Distinct from "qwen3.8-max" —
	// not caught by any existing family prefix shadow (no bare "qwen3.8"
	// key exists), so this exact row is purely additive.
	"qwen3.8-flash": {Input: 0.15, Output: 0.47},

	// Z.AI — GLM 5.2 (docs.z.ai/guides/overview/pricing, fetched
	// 2026-07-23). Cache storage is limited-time free per the same page.
	"glm-5.2": {Input: 1.40, Output: 4.40, CacheRead: 0.26},
	// OpenRouter alias — list price (OR currently shows a 45%-off promo on
	// top of this; not modeled, same reasoning as the Qwen 3.7-plus alias).
	"z-ai/glm-5.2": {Input: 1.40, Output: 4.40, CacheRead: 0.26},

	// MiniMax M3 — platform.minimax.io, ≤512K tier. >512K doubles ALL
	// rates (documented, not modeled — no long-context dimension wired
	// for MiniMax the way Anthropic/OpenAI/Gemini have one).
	//
	// Uses the LIST rate ($0.60/$2.40), not the currently-running promo
	// ($0.30/$1.20, described by MiniMax as "permanent" 50% off) —
	// deliberate per repo convention that a "permanent" promo is still a
	// promo and can revert without notice; the defensible standing rate
	// is list. CacheRead scales with the list rate (20% of input, same
	// ratio as the promo's $0.06/$0.30).
	"minimax-m3":         {Input: 0.60, Output: 2.40, CacheRead: 0.12},
	"minimax/minimax-m3": {Input: 0.60, Output: 2.40, CacheRead: 0.12},

	// Tencent Hunyuan — "hy3" GA'd 2026-07-06 on TokenHub. Rates are
	// ¥1/¥4/¥0.25-cache per 1M converted at ~7.0 CNY/USD ($0.1429/
	// $0.5714/$0.0357), cross-checked against the OpenRouter tencent/hy3
	// listing and rounded to the published-precision figures below.
	//
	// KNOWN LIMITATION (2026-07-23 codex adversarial pass, P2): the bare
	// "hy3" key is, like every other undated bare key in this whole
	// table (qwen, grok, mistral, etc. — a systemic property of
	// familyKeys()'s unbounded strings.HasPrefix, not something specific
	// to this row), an unbounded family prefix: it will also match any
	// future unrelated model whose ID happens to start with "hy3", e.g.
	// a hypothetical "hy3d-turbo" from a different line. Documented, not
	// redesigned, here — see
	// TestTable_2026Q3UnboundedPrefixKnownLimitation in pricing_test.go.
	"hy3":         {Input: 0.15, Output: 0.59, CacheRead: 0.037},
	"tencent/hy3": {Input: 0.15, Output: 0.59, CacheRead: 0.037},

	// StepFun — openrouter.ai/stepfun/step-3.5-flash. No cache rate is
	// published on the listing — CacheRead left at 0 so fillDefaults'
	// 10%-of-input floor applies rather than a fabricated exact number.
	"step-3.5-flash":         {Input: 0.10, Output: 0.30},
	"stepfun/step-3.5-flash": {Input: 0.10, Output: 0.30},
	// StepFun Step 3.7 Flash — newer/distinct SKU from 3.5 Flash above
	// (2026-08 sweep): $0.20/$1.15, 262,144 context. No cache rate
	// published — same fillDefaults-floor treatment as 3.5 Flash. Not
	// caught by any existing "step" family prefix (none exists in this
	// table today), so both bare and OpenRouter-qualified exact rows are
	// added rather than relying on a fallback.
	"step-3.7-flash":         {Input: 0.20, Output: 1.15},
	"stepfun/step-3.7-flash": {Input: 0.20, Output: 1.15},

	// Baidu ERNIE 5.1 — Baidu's own Qianfan rate card is not directly
	// reachable from here; this rate is the consensus of 3+ independent
	// third-party trackers (cross-checked, not first-party-verified).
	// Qianfan exposes no prompt-caching primitive for this model, so
	// CacheRead is genuinely N/A (left at 0; fillDefaults' 10% floor
	// still applies as the defensive fallback like every other row).
	"ernie-5.1": {Input: 0.59, Output: 2.65},

	// ByteDance Doubao Seed 2.0 — PROVISIONAL. Volcengine's official
	// pricing table is JS-rendered and not fetchable by static tooling;
	// these CNY-sourced rates come from secondary CN coverage,
	// cross-checked against an independent USD tracker, but are NOT
	// first-party-confirmed. Whole group flagged provisional; revisit
	// when Volcengine's rate card can be fetched directly.
	"doubao-seed-2.0-pro":  {Input: 0.47, Output: 2.35, CacheRead: 0.094},
	"doubao-seed-2.0-code": {Input: 0.47, Output: 2.35, CacheRead: 0.094},
	"doubao-seed-2.0-lite": {Input: 0.088, Output: 0.53, CacheRead: 0.018},
	"doubao-seed-2.0-mini": {Input: 0.029, Output: 0.29, CacheRead: 0.006},
	// doubao-seed-2.0 family prefix (dot form) — catches an unrecognized
	// FUTURE dot-form variant at pro rates only; the four explicit rows
	// above are all longer strings so they win the longest-prefix ladder
	// for every KNOWN variant (pro/code/lite/mini never fall through to
	// this row).
	"doubao-seed-2.0": {Input: 0.47, Output: 2.35, CacheRead: 0.094},
	// Volcengine ALSO emits dash-form dated IDs, e.g.
	// "doubao-seed-2-0-pro-260215" / "doubao-seed-2-0-lite-260215" /
	// "doubao-seed-2-0-mini-260215". LookupWithSource does not normalize
	// dashes/dots against each other (confirmed: no such transform exists
	// in the lookup ladder), and that suffix is only 6 digits (YYMMDD),
	// so dateSuffix's `-\d{8}$` regex won't strip it either — every
	// dash-form dated ID resolves via family-prefix, never date-strip.
	//
	// FIXED post-review (2026-07-23 codex adversarial pass, P1): a single
	// bare "doubao-seed-2-0" family key here priced EVERY dash-form
	// variant — including the ~5.3×-cheaper lite tier and the
	// ~16×-cheaper mini tier — at PRO rates, because it was the only
	// dash-form entry in the table and every dash-form dated ID is a
	// superstring of it. The fix is one dash-form key PER variant,
	// mirroring the four dot-form rows above 1:1, so the longest-prefix
	// ladder picks the matching variant (not just "some doubao-seed-2-0
	// row") before it can ever reach a shorter fallback.
	"doubao-seed-2-0-pro":  {Input: 0.47, Output: 2.35, CacheRead: 0.094},
	"doubao-seed-2-0-code": {Input: 0.47, Output: 2.35, CacheRead: 0.094},
	"doubao-seed-2-0-lite": {Input: 0.088, Output: 0.53, CacheRead: 0.018},
	"doubao-seed-2-0-mini": {Input: 0.029, Output: 0.29, CacheRead: 0.006},
	// Bare "doubao-seed-2-0" dash-form family kept ONLY as the same kind
	// of last-resort fallback as its dot-form counterpart above — an
	// unrecognized FUTURE dash-form variant lands at pro rates rather
	// than MISSing to $0. All four KNOWN variants have their own longer
	// key above and are never shadowed by this one.
	"doubao-seed-2-0": {Input: 0.47, Output: 2.35, CacheRead: 0.094},

	// Meta — Muse Spark (ai.developer.meta.com/docs/pricing-rate-limits),
	// public API preview. 1.1 launched 2026-07-09; 1.2 released
	// 2026-08-05 at the SAME standard rate. 1M context. Reasoning tokens
	// bill at the output rate (same convention as Anthropic — no
	// separate reasoning dimension on this struct). WebSearchPerRequest
	// is Meta's own "$2.50 per 1,000 search queries" flattened to a
	// per-call rate ($2.50 / 1,000 = $0.0025), same unit convention as
	// the Anthropic/OpenAI WebSearchPerRequest rows. CacheCreation stays
	// 0 for every Muse Spark row — Meta's pricing page states no
	// cache-write rate (unstated ⇒ uncharged, never invented). Meta also
	// states "no premium for long context" for this line, so no
	// LongContext* fields are set on any Muse Spark row.
	"muse-spark-1.1": {Input: 1.25, Output: 4.25, CacheRead: 0.15, WebSearchPerRequest: 0.0025},
	"muse-spark-1.2": {Input: 1.25, Output: 4.25, CacheRead: 0.15, WebSearchPerRequest: 0.0025},
	// 1.2's discounted data-sharing tier (opt in to Meta using your
	// traffic for model improvement) — Meta's own pricing page. Exact
	// key so this contributor SKU is never shadowed by the family row
	// below.
	"muse-spark-1.2-contributor": {Input: 0.10, Output: 0.20, CacheRead: 0.002, WebSearchPerRequest: 0.0025},
	// Bare "muse-spark" family prefix → standard (non-contributor) rate,
	// so an unrecognized future version (e.g. "muse-spark-1.3") inherits
	// the standard tier rather than MISSing to $0.
	"muse-spark": {Input: 1.25, Output: 4.25, CacheRead: 0.15, WebSearchPerRequest: 0.0025},

	// Cohere — North Mini Code 1.0. Genuinely free / $0, rate-limited per
	// docs.cohere.com and the OpenRouter listing (not a promo). A paid
	// dedicated tier may appear later — revisit this row if/when Cohere
	// publishes metered pricing for it.
	"north-mini-code-1-0":    {Input: 0, Output: 0},
	"cohere/north-mini-code": {Input: 0, Output: 0},
	// NOTE: an explicit "cohere/north-mini-code:free" row is deliberately
	// NOT added — LookupWithSource's universal `:free`-suffix guard (see
	// above) already returns PricingSourceExact $0 for ANY model string
	// ending in ":free" (case-insensitive) that doesn't already have its
	// own explicit entry, before the family ladder even runs. (An
	// explicit exact-match row for a specific "...:free" key, were one
	// ever added, would still be checked FIRST and win over the guard —
	// the guard is the fallback for un-enumerated ":free" strings, not an
	// override.) Adding a duplicate explicit row here would be redundant
	// with that guard, not a fix for a gap.

	// Sakana AI — Fugu Ultra (console.sakana.ai/pricing,
	// openrouter.ai/sakana/fugu-ultra). >272K tier is $10/$45/$1
	// (documented, not modeled — no long-context dimension wired for
	// Sakana). Orchestration tokens bill at the SAME rates as regular
	// tokens per the pricing page (no separate orchestration tier to
	// model). Family key (no date suffix) so dated IDs like
	// "fugu-ultra-20260615" resolve via the dateSuffix strip to this
	// exact row, or via family-prefix if some other dated suffix shape
	// shows up.
	"fugu-ultra":        {Input: 5, Output: 30, CacheRead: 0.50},
	"sakana/fugu-ultra": {Input: 5, Output: 30, CacheRead: 0.50},

	// Thinking Machines Lab — Inkling, via OpenRouter
	// (openrouter.ai/thinkingmachines/inkling). TML has no first-party
	// per-token API endpoint of its own (TML's product is Tinker
	// fine-tuning, not a metered inference endpoint); multi-provider price
	// variance for this model is real across hosts, but OpenRouter's
	// number is the one verifiable, checkable standard, so it's used here
	// rather than an unverifiable first-party figure.
	// Bare "inkling" alias: same KNOWN LIMITATION as "hy3" above (P2) — an
	// unbounded family prefix that would also match an unrelated future
	// ID like "inklinglabs-x". Documented in
	// TestTable_2026Q3UnboundedPrefixKnownLimitation, not redesigned.
	"thinkingmachines/inkling": {Input: 1, Output: 4.05},
	"inkling":                  {Input: 1, Output: 4.05}, // bare alias

	// AI21 — Jamba Mini 2 (docs.ai21.com/docs/jamba-foundation-models).
	// 256K context. No cache pricing offered by AI21 for this line —
	// CacheRead left at 0 so fillDefaults' 10%-of-input floor applies
	// rather than a fabricated exact number (same pattern as the StepFun
	// and ERNIE rows above). Doubles as the family prefix for dated
	// wire-ID variants.
	"jamba-mini-2": {Input: 0.20, Output: 0.40},

	// Google — a video-generation model that shares Gemini 3.5 Flash's
	// TEXT rates (ai.google.dev/gemini-api/docs/pricing). Video output is
	// billed separately at $17.50/M and is not modeled (no video-output
	// dimension on this struct). No cache tier while in preview —
	// CacheRead left at 0 so fillDefaults' 10%-of-input floor applies
	// rather than a fabricated exact number (same pattern as StepFun/
	// ERNIE/Jamba above). Verified no shorter existing "gemini-*" family
	// key (gemini-2, gemini-2.5, gemini-3, gemini-3.1 — there is no bare
	// "gemini" row) is a string prefix of "gemini-omni-flash-preview", so
	// this explicit row can't be shadowed by an unrelated family fallback
	// either way; it wins as a verbatim PricingSourceExact match
	// regardless.
	"gemini-omni-flash-preview": {Input: 1.50, Output: 9},

	// Sarvam AI — sarvam.ai/api-pricing. Genuinely free, 60rpm rate limit.
	"sarvam-30b":  {Input: 0, Output: 0},
	"sarvam-105b": {Input: 0, Output: 0},

	// Researched-but-not-priced (2026-07-23) — do NOT re-research these;
	// no table row exists because none of them have a real per-token rate
	// to record:
	//   - Cohere Command A+: open-weight + contact-sales hosted tier only,
	//     no published rate card.
	//   - Meta Muse Spark (original, pre-1.1): private partner preview,
	//     never had a public endpoint or rate.
	//   - Microsoft Phi-4-reasoning-vision-15B: Azure AI Foundry Labs
	//     experimental listing, no token rate; ships as open weights
	//     instead (self-host, no metered price to record).
	//   - TII Falcon H1R 7B: open weights only, no hosted listing/rate
	//     card from TII or a first-party endpoint.
	//   - Hy3 preview-era third-party host rates: superseded by the GA
	//     "hy3" row above (2026-07-06 TokenHub launch); the preview-era
	//     numbers some trackers still list are stale.

	// Cursor — Composer family. Cursor's stop hook carries `model` per
	// generation and the cursor adapter (since v1.4.45) lands a
	// TokenEvent for every completed turn via BuildStopTokenEvent.
	// Rates per cursor.com/blog/composer-2-5 (Composer 2.5 announcement)
	// and cursor.com/blog/composer-2 (Composer 2 launch).
	// Cursor's own Grok rows are separate from the xAI rows above: Cursor's
	// model cards publish no xAI-style >=200K surcharge, and Cursor's Grok
	// 4.5 cache-read rate is $0.50 rather than xAI's $0.20. The installed
	// Cursor model catalog (3.x, verified 2026-09-09) emits the provider
	// namespace plus effort and, for Fast, a `-fast` suffix. Keep a family
	// base for future effort labels, but pin every observed catalog ID.
	"cursor-grok-4.6":             cursorGrok46Standard,
	"cursor-grok-4.6-low":         cursorGrok46Standard,
	"cursor-grok-4.6-medium":      cursorGrok46Standard,
	"cursor-grok-4.6-high":        cursorGrok46Standard,
	"cursor-grok-4.6-xhigh":       cursorGrok46Standard,
	"cursor-grok-4.6-low-fast":    cursorGrok46Fast,
	"cursor-grok-4.6-medium-fast": cursorGrok46Fast,
	"cursor-grok-4.6-high-fast":   cursorGrok46Fast,
	"cursor-grok-4.6-xhigh-fast":  cursorGrok46Fast,
	"cursor-grok-4.5":             cursorGrok45Standard,
	"cursor-grok-4.5-low":         cursorGrok45Standard,
	"cursor-grok-4.5-medium":      cursorGrok45Standard,
	"cursor-grok-4.5-high":        cursorGrok45Standard,
	"cursor-grok-4.5-low-fast":    cursorGrok45Fast,
	"cursor-grok-4.5-medium-fast": cursorGrok45Fast,
	"cursor-grok-4.5-high-fast":   cursorGrok45Fast,

	"composer-1":        {Input: 1.25, Output: 10, CacheRead: 0.125},
	"composer-1.5":      {Input: 3.50, Output: 17.50, CacheRead: 0.35},
	"composer-2":        {Input: 0.50, Output: 2.50, CacheRead: 0.20},
	"composer-2.5":      {Input: 0.50, Output: 2.50, CacheRead: 0.20},
	"composer-2.5-fast": {Input: 3, Output: 15, CacheRead: 0.30},
	"composer":          {Input: 0.50, Output: 2.50, CacheRead: 0.20}, // family prefix → composer base rates
	// `default` is what Cursor's `model` field carries when the user
	// picks "Auto" in the model picker. Composer 2.5 Fast is the
	// underlying default model per the Composer 2.5 announcement
	// ("Fast is the default option, similar to Composer 2"). Pricing
	// is API-list-equivalent — Cursor Pro / Free users on subscription
	// bundles see different per-request economics. Override via
	// Settings → Pricing (or `[intelligence.pricing.models."default"]`
	// in config.toml) when Cursor changes the default backbone.
	"default": {Input: 3, Output: 15, CacheRead: 0.30},

	// Cursor — Grok routing rows live above (the cursorGrok4{5,6}Standard/
	// Fast catalog next to the Composer rows). Cursor's model cards publish
	// no xAI-style >=200K surcharge, so no long-context tier is modelled;
	// unknown future effort labels deliberately MISS rather than resolving
	// to a bare family row (see TestTable_CursorGrok's cursor-grok-4.7
	// case). Before those rows the `cursor-` prefix resolved to
	// PricingSourceMiss → $0.00 (F-MODELS3 / F-COST1, org-observer UI review
	// 2026-09-02).

	// Stealth / cloaked previews. Gateways (OpenRouter et al.) route
	// pre-release models under a codename (`stealth/<codename>`, e.g.
	// stealth/ox-alpha, LIVE on the org estate at 3.8M-23.5M tokens) and, during
	// the cloaked window, bill them at $0 to the user — the provider eats
	// inference cost to gather eval data. Priced known-$0 (PricingSourceExact/
	// Family → reliability "approximate", NOT a silent unknown MISS which reads
	// as $0 with reliability "unknown"). No rate is invented: the cloaked-window
	// price genuinely IS zero. Revisit + repoint if the codename GAs with a
	// published rate. The `stealth` family prefix covers future cloaked
	// codenames (stealth/ox-beta, ...); override in config.toml.
	"stealth/ox-alpha": {},
	"stealth":          {}, // family prefix → cloaked-window $0

	// Kilo Gateway routing — the bundled @kilocode/kilo-gateway provider
	// (providerID=kilo, pkg=@kilocode/kilo-gateway) emits model strings
	// of the form `kilo-auto/<tier>` when the operator picks Gateway
	// auto-routing. Free tier is hosted-by-Kilo at zero cost-to-user;
	// `kilo-auto/small` is Kilo's title-generation slot routed to a
	// small-model family (Haiku 4.5 / GPT-4o-mini class). When the
	// operator picks a direct provider/model instead, the model string
	// is `<provider>/<model>` (e.g. `anthropic/claude-sonnet-4-6`) and
	// the family-prefix fallback ladder picks up the right pricing.
	//
	// Reliability tagging on Kilo-sourced rows is `approximate` — the
	// token bundle is the upstream provider's usage envelope persisted
	// verbatim, but `cost` on the message rolls up Kilo's view (free
	// tier reports 0 even for non-zero-token turns).
	//
	// `kilo-auto/free` is zero per the live-confirmed 2026-06-06
	// capture (cost: 0 on every assistant message; provider-tier free
	// Gateway routing). Keeping the entry explicit ensures
	// reliability=approximate rather than reliability=unknown, so cost
	// rollups treat it as a known-priced model with zero rate.
	"kilo-auto/free": {Input: 0, Output: 0, CacheRead: 0},
	// kilo-auto/small is Kilo's title-generation slot — alias to the
	// Haiku 4.5 family rates (cheapest priced small-model class we
	// reliably price). Operator can override via
	// `[intelligence.pricing.models."kilo-auto/small"]` in config.toml
	// when Kilo Gateway changes the underlying routing.
	"kilo-auto/small": {Input: 1, Output: 5, CacheRead: 0.10, CacheCreation: 1.25, CacheCreation1h: 2},
	// kilo-auto family prefix — catches future tiers (e.g.
	// `kilo-auto/medium`, `kilo-auto/large`) that Kilo may introduce.
	// Defaults to Sonnet 4 family rates per the Gateway's published
	// 2026-06 routing baseline (the typical paid tier surface).
	"kilo-auto": {Input: 3, Output: 15, CacheRead: 0.30, CacheCreation: 3.75, CacheCreation1h: 6, WebSearchPerRequest: 0.01},
}

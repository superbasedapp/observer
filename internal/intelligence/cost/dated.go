package cost

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// DatedPricing is ONE rate period for a model: the Pricing that took
// effect at EffectiveFrom (UTC) and stays in effect until the next
// entry's EffectiveFrom, or forever when it is the newest entry.
//
// The embedded Pricing's fields are promoted, so a DatedPricing marshals
// to the same JSON shape as a Pricing plus an `effective_from` key.
type DatedPricing struct {
	// EffectiveFrom is the instant the rate took effect, in UTC.
	// Inclusive: usage AT exactly this instant bills at THIS entry's
	// rates (see datedRate). The zero value means "since forever" and
	// is the idiomatic way to spell the oldest period of a timeline.
	EffectiveFrom time.Time `json:"effective_from"`
	Pricing
}

// datedPricing is the baked-in DATED rate table — the historical rate
// timeline for models whose published price CHANGED, keyed exactly like
// defaultPricing (see "Where the date dimension lives" below).
//
// It starts EMPTY and stays that way for any model until a rate change is
// verified against the provider's own published card, because a wrong
// entry silently reprices real history — the exact failure class this
// mechanism exists to prevent. defaultPricing stays the single source of
// CURRENT rates; this table only records what a model used to cost. As of
// 2026-08-06 it carries one verified entry: the OpenAI GPT-5.6 Terra/Luna
// price cut effective 2026-07-30 (developers.openai.com/api/docs/changelog).
//
// THE SHAPE TO USE (worked example — a mid-life price CUT, the
// gpt-5.6-terra / gpt-5.6-luna case). A cut needs TWO entries, not one:
// the OLD period must be stated explicitly, because "T before every
// entry" falls back to the flat (current) table and the flat table
// already holds the NEW, cheaper rates.
//
//	"gpt-5.6-terra": {
//	    // Launch → the cut. OLD (higher) rates, exactly what the row
//	    // in defaultPricing said before the cut landed.
//	    {EffectiveFrom: time.Time{}, Pricing: Pricing{
//	        Input: 2.50, Output: 15, CacheRead: 0.25,
//	        CacheCreation: 3.125, CacheCreation1h: 3.125,
//	        WebSearchPerRequest: 0.01,
//	    }},
//	    // The cut → forever. MUST equal the defaultPricing row for
//	    // this model (ValidateDated enforces it), because the flat
//	    // table is by contract the CURRENT rate card.
//	    {EffectiveFrom: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC), Pricing: Pricing{
//	        Input: 1.75, Output: 10, CacheRead: 0.175,
//	        CacheCreation: 2.1875, CacheCreation1h: 2.1875,
//	        WebSearchPerRequest: 0.01,
//	    }},
//	},
//
// Landing a rate change is therefore always a PAIR of edits:
//  1. update the model's defaultPricing row to the NEW rates, and
//  2. add its timeline here, whose LAST entry mirrors that new row and
//     whose earlier entries carry the rates being retired.
//
// Run TestDatedSeedIsSelfConsistent (dated_test.go) after any edit — it
// walks this table through ValidateDated so a half-landed pair is loud.
var datedPricing = map[string][]DatedPricing{
	// OpenAI GPT-5.6 Terra + Luna price cut, effective 2026-07-30
	// (developers.openai.com/api/docs/changelog: "Starting July 30,
	// GPT-5.6 Luna costs 80% less, while GPT-5.6 Terra costs 20% less").
	// Sol is unaffected — no timeline for gpt-5.6-sol.
	"gpt-5.6-terra": {
		// Launch (2026-06-25) → the cut. OLD rates — exactly what the
		// row in defaultPricing said before 2026-07-30. No LC/Fast
		// fields: those were never modeled pre-cut (added alongside it).
		{EffectiveFrom: time.Time{}, Pricing: Pricing{
			Input: 2.50, Output: 15, CacheRead: 0.25,
			CacheCreation: 3.125, CacheCreation1h: 3.125,
			WebSearchPerRequest: 0.01,
		}},
		// The cut → forever. Mirrors the current defaultPricing row.
		{EffectiveFrom: time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC), Pricing: Pricing{
			Input: 2.00, Output: 12.00, CacheRead: 0.20,
			CacheCreation: 2.50, CacheCreation1h: 2.50,
			WebSearchPerRequest:  0.01,
			LongContextThreshold: 272_000,
			LongContextInput:     4.00, LongContextOutput: 18.00, LongContextCacheRead: 0.40,
			LongContextCacheCreation: 5.00, LongContextCacheCreation1h: 5.00,
			FastMultiplier: 2,
		}},
	},
	"gpt-5.6-luna": {
		// Launch (2026-06-25) → the cut. OLD rates — exactly what the
		// row in defaultPricing said before 2026-07-30.
		{EffectiveFrom: time.Time{}, Pricing: Pricing{
			Input: 1, Output: 6, CacheRead: 0.10,
			CacheCreation: 1.25, CacheCreation1h: 1.25,
			WebSearchPerRequest: 0.01,
		}},
		// The cut → forever. Mirrors the current defaultPricing row.
		{EffectiveFrom: time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC), Pricing: Pricing{
			Input: 0.20, Output: 1.20, CacheRead: 0.02,
			CacheCreation: 0.25, CacheCreation1h: 0.25,
			WebSearchPerRequest:  0.01,
			LongContextThreshold: 272_000,
			LongContextInput:     0.40, LongContextOutput: 1.80, LongContextCacheRead: 0.04,
			LongContextCacheCreation: 0.50, LongContextCacheCreation1h: 0.50,
			FastMultiplier: 2,
		}},
	},

	// DeepSeek V4 peak/off-peak overhaul, effective 2026-08-16T16:00Z UTC
	// (api-docs.deepseek.com/quick_start/pricing, confirmed live
	// 2026-09-07 — see the "PEAK/OFF-PEAK OVERHAUL" comment above the
	// deepseek-v4-flash row in pricing.go for the full rationale,
	// including why off-peak is the flat-table representative and peak is
	// left unmodeled). The old flat rate applied identically to
	// deepseek-v4-flash, deepseek-chat, deepseek-reasoner, deepseek-v4 and
	// the bare "deepseek" family row — all five keys get their own
	// timeline since dated entries are per exact table key, not inherited
	// across aliases.
	"deepseek-v4-flash": {
		{EffectiveFrom: time.Time{}, Pricing: Pricing{
			Input: 0.14, Output: 0.28, CacheRead: 0.0028,
		}},
		{EffectiveFrom: time.Date(2026, 8, 16, 16, 0, 0, 0, time.UTC), Pricing: Pricing{
			Input: 0.22, Output: 0.66, CacheRead: 0.007,
		}},
	},
	"deepseek-chat": {
		{EffectiveFrom: time.Time{}, Pricing: Pricing{
			Input: 0.14, Output: 0.28, CacheRead: 0.0028,
		}},
		{EffectiveFrom: time.Date(2026, 8, 16, 16, 0, 0, 0, time.UTC), Pricing: Pricing{
			Input: 0.22, Output: 0.66, CacheRead: 0.007,
		}},
	},
	"deepseek-reasoner": {
		{EffectiveFrom: time.Time{}, Pricing: Pricing{
			Input: 0.14, Output: 0.28, CacheRead: 0.0028,
		}},
		{EffectiveFrom: time.Date(2026, 8, 16, 16, 0, 0, 0, time.UTC), Pricing: Pricing{
			Input: 0.22, Output: 0.66, CacheRead: 0.007,
		}},
	},
	"deepseek-v4": {
		{EffectiveFrom: time.Time{}, Pricing: Pricing{
			Input: 0.14, Output: 0.28, CacheRead: 0.0028,
		}},
		{EffectiveFrom: time.Date(2026, 8, 16, 16, 0, 0, 0, time.UTC), Pricing: Pricing{
			Input: 0.22, Output: 0.66, CacheRead: 0.007,
		}},
	},
	"deepseek": {
		{EffectiveFrom: time.Time{}, Pricing: Pricing{
			Input: 0.14, Output: 0.28, CacheRead: 0.0028,
		}},
		{EffectiveFrom: time.Date(2026, 8, 16, 16, 0, 0, 0, time.UTC), Pricing: Pricing{
			Input: 0.22, Output: 0.66, CacheRead: 0.007,
		}},
	},
	"deepseek-v4-pro": {
		{EffectiveFrom: time.Time{}, Pricing: Pricing{
			Input: 0.435, Output: 0.87, CacheRead: 0.003625,
		}},
		{EffectiveFrom: time.Date(2026, 8, 16, 16, 0, 0, 0, time.UTC), Pricing: Pricing{
			Input: 0.66, Output: 1.98, CacheRead: 0.022,
		}},
	},
}

// BakedInDatedDefaults returns a copy of the baked-in dated rate table.
// Mirrors BakedInDefaults for the flat table; surfaces that render "the"
// rate can use it to tell whether a model's history is date-split.
func BakedInDatedDefaults() map[string][]DatedPricing {
	out := make(map[string][]DatedPricing, len(datedPricing))
	for k, v := range datedPricing {
		out[k] = append([]DatedPricing(nil), v...)
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────
// Where the date dimension lives
// ─────────────────────────────────────────────────────────────────────
//
// The date dimension lives at the RATE, never at the RESOLUTION.
//
// LookupWithSource's ladder (exact → `:free` → date-suffix-strip →
// family-prefix → normalize-and-retry) resolves a model id to a table
// KEY and a PricingSource. That ladder is entirely date-independent and
// byte-for-byte unchanged. Only the final step — "turn this key into a
// Pricing" — consults the dated timeline:
//
//	rate(key, at) = last dated[key] entry whose EffectiveFrom <= at,
//	                else exact[key]                      (the flat table)
//
// Consequences, all deliberate:
//
//   - PricingSource is IDENTICAL for a dated and an undated lookup. A
//     dated Opus row still reports "exact"; a dated family row still
//     reports "family". Nothing downstream that branches on the source
//     changes behaviour.
//   - Dated entries are keyed EXACTLY like flat entries, so a dated
//     timeline on a FAMILY key (e.g. "claude-opus") automatically covers
//     every SKU that resolves to that family — the same inheritance the
//     flat table already has, with no second set of rules to learn.
//   - A model with no dated timeline is priced by exactly the code path
//     it used before this file existed.
//
// The alternative — a parallel dated ladder consulted at each rung —
// was rejected: it doubles the resolution surface, can disagree with the
// flat ladder about WHICH key won, and buys nothing, because seeding the
// flat entry from the newest dated entry (see MergeDated) already makes
// a dated-only model fully resolvable.
//
// Cost: a lookup on a table with NO dated entries does one extra
// `len(t.dated) > 0` test. A lookup on a table WITH dated entries does
// one map probe plus a linear scan of that model's timeline (one or two
// entries in practice). Callers that price historical rows gate the
// timestamp parse on Engine.HasDatedPricing so the common
// zero-dated-entries install pays no per-row time.Parse at all.

// MergeDated copies dated rate timelines into t. Each timeline is sorted
// ascending by EffectiveFrom and normalized to UTC. An existing timeline
// for the same key is REPLACED wholesale (same semantics as Merge).
//
// When a key has a dated timeline but NO flat entry, the NEWEST dated
// entry is copied into the flat table. That keeps the one invariant the
// whole design rests on — the flat table always represents CURRENT
// rates — and it is what makes a dated-only config entry resolvable at
// all (the resolution ladder only ever walks the flat key set).
func (t *Table) MergeDated(overrides map[string][]DatedPricing) {
	if len(overrides) == 0 {
		return
	}
	if t.dated == nil {
		t.dated = make(map[string][]DatedPricing, len(overrides))
	}
	if t.exact == nil {
		t.exact = map[string]Pricing{}
	}
	for k, entries := range overrides {
		if len(entries) == 0 {
			delete(t.dated, k)
			continue
		}
		cp := make([]DatedPricing, len(entries))
		for i, e := range entries {
			e.EffectiveFrom = e.EffectiveFrom.UTC()
			cp[i] = e
		}
		sort.SliceStable(cp, func(i, j int) bool {
			return cp[i].EffectiveFrom.Before(cp[j].EffectiveFrom)
		})
		t.dated[k] = cp
		if _, ok := t.exact[k]; !ok {
			// Flat table == CURRENT rates, and the newest dated entry
			// IS the current rate. Seeding it makes the key resolvable
			// through the ordinary ladder.
			t.exact[k] = cp[len(cp)-1].Pricing
		}
	}
}

// HasDated reports whether the table carries ANY dated rate timeline.
// Hot paths gate their per-row timestamp parsing on this: an install
// with no dated entries must pay nothing for the feature.
func (t *Table) HasDated() bool {
	return t != nil && len(t.dated) > 0
}

// DatedModels returns the keys that carry a dated rate timeline.
func (t *Table) DatedModels() []string {
	if t == nil {
		return nil
	}
	out := make([]string, 0, len(t.dated))
	for k := range t.dated {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// DatedFor returns a copy of the dated rate timeline registered for the
// exact key `model` (ascending by EffectiveFrom), or nil. It does NOT
// run the resolution ladder — callers that want "which timeline actually
// prices this SKU" should resolve first via LookupWithSource.
func (t *Table) DatedFor(model string) []DatedPricing {
	if t == nil || len(t.dated) == 0 {
		return nil
	}
	e, ok := t.dated[model]
	if !ok {
		return nil
	}
	return append([]DatedPricing(nil), e...)
}

// datedRate returns the dated Pricing in force for `key` at `at`, i.e.
// the LAST entry whose EffectiveFrom is <= at. Returns ok=false when the
// key has no timeline, when `at` is the zero time (no usable timestamp —
// the caller must fall back to current rates rather than silently
// reprice to the oldest tier), or when `at` precedes every entry.
func (t *Table) datedRate(key string, at time.Time) (Pricing, bool) {
	if t == nil || len(t.dated) == 0 || at.IsZero() {
		return Pricing{}, false
	}
	entries := t.dated[key]
	if len(entries) == 0 {
		return Pricing{}, false
	}
	at = at.UTC()
	idx := -1
	for i := range entries {
		// Inclusive boundary: usage AT exactly EffectiveFrom bills at
		// the NEW rate.
		if entries[i].EffectiveFrom.After(at) {
			break
		}
		idx = i
	}
	if idx < 0 {
		return Pricing{}, false
	}
	return entries[idx].Pricing, true
}

// rate turns a resolved table key into the Pricing to bill with. This is
// the ONLY place the date dimension is applied, and — because it is the
// one funnel every Lookup rung passes through with the resolved key in
// hand — the one place the per-provider cache-write fallback
// (applyCacheWriteRule) is applied. Doing it here covers baked rows,
// config.toml overrides, dated timeline entries and family-prefix
// fallbacks in a single owner, instead of restating the same fact on
// every Gemini row in the table.
func (t *Table) rate(key string, at time.Time) Pricing {
	if len(t.dated) > 0 {
		if p, ok := t.datedRate(key, at); ok {
			return applyCacheWriteRule(key, fillDefaults(p))
		}
	}
	return applyCacheWriteRule(key, fillDefaults(t.exact[key]))
}

// LookupAt is the date-aware Lookup: it returns the rate in force for
// `model` at `at`. Semantics for a model with no dated timeline — and
// for a zero `at` — are identical to Lookup.
func (t *Table) LookupAt(model string, at time.Time) (Pricing, bool) {
	p, _, ok := t.LookupWithSourceAt(model, at)
	return p, ok
}

// ValidateDated checks every dated timeline for the two mistakes that
// silently misprice history, and returns one human-readable warning per
// problem (empty slice when clean):
//
//   - DUPLICATE EffectiveFrom within one timeline — ambiguous which
//     entry wins.
//   - NEWEST entry disagrees with the flat table — the flat table is by
//     contract the CURRENT rate card, so LookupAt(now) would not equal
//     Lookup(). This is what a half-landed rate change looks like:
//     the timeline was added but defaultPricing / the config override
//     was never updated (or vice-versa).
//
// Callers treat warnings as advisory: pricing never fails closed.
func (t *Table) ValidateDated() []string {
	if t == nil || len(t.dated) == 0 {
		return nil
	}
	var out []string
	for _, k := range t.DatedModels() {
		entries := t.dated[k]
		for i := 1; i < len(entries); i++ {
			if entries[i].EffectiveFrom.Equal(entries[i-1].EffectiveFrom) {
				out = append(out, fmt.Sprintf(
					"pricing: model %q has two dated entries with the same effective_from %s — the later one in file order wins, which is almost certainly not what you meant",
					k, entries[i].EffectiveFrom.Format(time.RFC3339),
				))
			}
		}
		newest := entries[len(entries)-1].Pricing
		flat, ok := t.exact[k]
		if !ok {
			continue // MergeDated seeds it; only a hand-built Table can miss.
		}
		if flat != newest {
			out = append(out, fmt.Sprintf(
				"pricing: model %q newest dated entry (effective_from %s) does not match the current flat rate — the flat table must always hold CURRENT rates, so historical costs will be right but today's will not",
				k, entries[len(entries)-1].EffectiveFrom.Format(time.RFC3339),
			))
		}
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────
// Config boundary
// ─────────────────────────────────────────────────────────────────────

// datedConfigLayouts are the accepted spellings of `effective_from` in
// config.toml, tried in order. A bare date is interpreted as midnight
// UTC — the way provider price-change announcements are written.
var datedConfigLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05",
	"2006-01-02",
}

// ParseEffectiveFrom parses a config-supplied effective_from stamp into
// a UTC instant. An empty string means "since forever" (the zero time),
// which is how an operator spells the oldest period of a timeline.
func ParseEffectiveFrom(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	for _, layout := range datedConfigLayouts {
		if ts, err := time.Parse(layout, s); err == nil {
			return ts.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("cost.ParseEffectiveFrom: %q is not a recognised date (want e.g. 2026-08-01 or 2026-08-01T00:00:00Z)", s)
}

// DatedFromConfig converts the [intelligence.pricing.dated] config block
// into engine-shaped timelines. Malformed rows are SKIPPED (pricing
// never fails closed) and reported as warnings so a surface can show the
// operator that their override was ignored rather than silently applied.
//
// Returns (nil, nil) for a config with no dated block — the zero-config
// path, where the caller must not touch the table at all.
func DatedFromConfig(pc config.PricingConfig) (map[string][]DatedPricing, []string) {
	if len(pc.Dated) == 0 {
		return nil, nil
	}
	out := make(map[string][]DatedPricing, len(pc.Dated))
	var warnings []string
	keys := make([]string, 0, len(pc.Dated))
	for k := range pc.Dated {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, id := range keys {
		entries := pc.Dated[id]
		converted := make([]DatedPricing, 0, len(entries))
		for i, e := range entries {
			ts, err := ParseEffectiveFrom(e.EffectiveFrom)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf(
					"pricing: [intelligence.pricing.dated.%q] entry %d ignored: %v", id, i+1, err,
				))
				continue
			}
			converted = append(converted, DatedPricing{
				EffectiveFrom: ts,
				Pricing:       pricingFromConfig(e.ModelPricing),
			})
		}
		if len(converted) == 0 {
			continue
		}
		out[id] = converted
	}
	if len(out) == 0 {
		return nil, warnings
	}
	return out, warnings
}

// pricingFromConfig is the single config.ModelPricing → Pricing mapper,
// shared by the flat-override path (Engine.Reload) and the dated path.
func pricingFromConfig(mp config.ModelPricing) Pricing {
	return Pricing{
		Input:                      mp.Input,
		Output:                     mp.Output,
		CacheRead:                  mp.CacheRead,
		CacheCreation:              mp.CacheCreation,
		CacheCreation1h:            mp.CacheCreation1h,
		LongContextThreshold:       mp.LongContextThreshold,
		LongContextInput:           mp.LongContextInput,
		LongContextOutput:          mp.LongContextOutput,
		LongContextCacheRead:       mp.LongContextCacheRead,
		LongContextCacheCreation:   mp.LongContextCacheCreation,
		LongContextCacheCreation1h: mp.LongContextCacheCreation1h,
		FastMultiplier:             mp.FastMultiplier,
	}
}

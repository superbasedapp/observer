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
	// Unpriced marks a period in which NO rate is in force: a lookup at an
	// instant inside it is a MISS (cost unknown), never $0 and never another
	// period's rate. Its Pricing is the zero value. It is how a timeline says
	// "the price source states nothing before its first dated period": the
	// price database's history for an id that billed at a DIFFERENT,
	// unstated card before (deepseek-chat before 2025-09-05), and the
	// generated snapshot's reading of a history whose first period has a
	// start (setSnapshotHistory).
	Unpriced bool `json:"unpriced,omitempty"`
}

// datedPricing is the hand-authored DATED rate table — the historical rate
// timeline for models whose published price CHANGED, keyed exactly like
// defaultPricing (see "Where the date dimension lives" below).
//
// IT IS EMPTY, AND THAT IS THE POINT. The price database is the one authority
// for price data, and price data is date-dependent (operator directive
// 2026-09-27). Every timeline this table used to carry now lives, cited, in
// Tokenomics' observer_price_history (model-pricing migration 0028), reaches
// the node as the signed feed's per-row `history`, and is compiled in through
// the generated snapshot (snapshot.go, setSnapshotHistory), which REPLACES a
// hand timeline for any key it covers. Once the embedded snapshot carried
// them, TestHandTimelinesRetiredOnceSnapshotCovers asked for the hand copies
// to go, and they were retired (lane R2-RECONCILE, 2026-09-28):
//
//   - gpt-5.6-terra / gpt-5.6-luna: the 2026-07-30 cut;
//   - gpt-5.6-sol: the 2026-08-21 promotional card;
//   - grok-code-fast-1 / grok-code: the 2026-05-15T19:00Z retirement onto
//     grok-build-0.1's card;
//   - deepseek-v4-flash / deepseek-chat / deepseek-reasoner / deepseek-v4 /
//     deepseek / deepseek-v4-pro: the V3.1 and V3.2-Exp cards, the V4 launch,
//     the 2026-08-16T16:00Z peak/off-peak overhaul and the 2026-09-10T04:00Z
//     V4.1-Flash cut.
//
// Each period's citation (vendor URL and quoted words) is on its
// observer_price_history row. Before retiring them,
// TestHandTimelinesMatchSnapshot proved the database history prices every
// boundary, a nanosecond either side and inside every peak window exactly as
// the hand table did.
//
// Add a timeline here ONLY for a verified rate change the price database
// cannot state yet, and move it to observer_price_history as soon as it can:
// the moment a generated snapshot carries the key's history this entry is dead
// data, and the retirement test fails until it is deleted.
//
// THE SHAPE TO USE (worked example — a mid-life price CUT). A cut needs TWO
// entries, not one: the OLD period must be stated explicitly, because "T
// before every entry" falls back to the flat (current) table and the flat
// table already holds the NEW, cheaper rates.
//
//	"gpt-5.6-terra": {
//	    // Launch → the cut. OLD (higher) rates.
//	    {EffectiveFrom: time.Time{}, Pricing: Pricing{
//	        Input: 2.50, Output: 15, CacheRead: 0.25,
//	    }},
//	    // The cut → forever. MUST equal the defaultPricing row for
//	    // this model (ValidateDated enforces it), because the flat
//	    // table is by contract the CURRENT rate card.
//	    {EffectiveFrom: time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC), Pricing: Pricing{
//	        Input: 2.00, Output: 12, CacheRead: 0.20,
//	    }},
//	},
//
// Landing a rate change here is therefore always a PAIR of edits:
//  1. update the model's defaultPricing row to the NEW rates, and
//  2. add its timeline here, whose LAST entry mirrors that new row and
//     whose earlier entries carry the rates being retired.
//
// Run TestDatedSeedIsSelfConsistent (dated_test.go) after any edit — it
// walks this table through ValidateDated so a half-landed pair is loud.
var datedPricing = map[string][]DatedPricing{}

// BakedInDatedDefaults returns a copy of the EFFECTIVE compiled dated rate
// table: the hand-authored timelines plus any the embedded generated snapshot
// added (snapshot.go). Mirrors BakedInDefaults for the flat table; surfaces
// that render "the" rate can use it to tell whether a model's history is
// date-split.
func BakedInDatedDefaults() map[string][]DatedPricing {
	t := NewTable()
	out := make(map[string][]DatedPricing, len(t.dated))
	for k, v := range t.dated {
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
			// Flat table == CURRENT rates: the entry in force at the
			// table's clock (the newest one, unless later entries have
			// not started yet). Seeding it makes the key resolvable
			// through the ordinary ladder.
			t.exact[k] = currentOf(cp, t.clockNow())
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
	e, ok := t.datedPeriod(key, at)
	if !ok {
		return Pricing{}, false
	}
	return e.Pricing, true
}

// datedPeriod is datedRate returning the whole period, so a caller can see
// whether it is Unpriced. Same ok=false cases as datedRate.
func (t *Table) datedPeriod(key string, at time.Time) (DatedPricing, bool) {
	if t == nil || len(t.dated) == 0 || at.IsZero() {
		return DatedPricing{}, false
	}
	entries := t.dated[key]
	if len(entries) == 0 {
		return DatedPricing{}, false
	}
	// Inclusive boundary: usage AT exactly EffectiveFrom bills at the NEW
	// rate.
	idx := inForceIndex(entries, at.UTC())
	if idx < 0 {
		return DatedPricing{}, false
	}
	return entries[idx], true
}

// priced is the one exit every LookupWithSourceAt rung takes once it has a
// resolved key: the rate in force for the key at `at`, or a MISS when the key's
// timeline says no rate is in force at that instant (an Unpriced period). A
// zero `at` never lands in a period (datedPeriod), so an untimed Lookup is
// unaffected.
func (t *Table) priced(key string, at time.Time, src PricingSource) (Pricing, PricingSource, bool) {
	if e, ok := t.datedPeriod(key, at); ok && e.Unpriced {
		return Pricing{}, PricingSourceMiss, false
	}
	return t.rate(key, at), t.sourceFor(key, src), true
}

// rate turns a resolved table key into the Pricing to bill with. This is
// the ONLY place the date dimension is applied, and — because it is the
// one funnel every Lookup rung passes through with the resolved key in
// hand — the one place the per-provider cache-write fallback
// (applyCacheWriteRule) and the time-of-day peak overlay (peakAdjusted)
// are applied. Doing it here covers baked rows, config.toml overrides,
// dated timeline entries and family-prefix fallbacks in a single owner,
// instead of restating the same fact on every Gemini row in the table.
//
// Order matters: peakAdjusted runs FIRST on the resolved (base/off-peak)
// Pricing so its peak rate set — including any peak long-context sub-tier
// — is in place before fillDefaults supplies missing cache-read/write
// defaults and applyCacheWriteRule fills the provider write fallback. A
// zero `at` or a model with no Peak leaves peakAdjusted a no-op, so the
// no-peak path is byte-identical to before.
func (t *Table) rate(key string, at time.Time) Pricing {
	if len(t.dated) > 0 {
		if p, ok := t.datedRate(key, at); ok {
			return applyCacheWriteRule(key, fillDefaultsFor(key, peakAdjusted(p, at)))
		}
	}
	return applyCacheWriteRule(key, fillDefaultsFor(key, peakAdjusted(t.exact[key], at)))
}

// LookupAt is the date-aware Lookup: it returns the rate in force for
// `model` at `at`. Semantics for a model with no dated timeline — and
// for a zero `at` — are identical to Lookup.
func (t *Table) LookupAt(model string, at time.Time) (Pricing, bool) {
	p, _, ok := t.LookupWithSourceAt(model, at)
	return p, ok
}

// ValidateDated checks every dated timeline as of the table's clock; see
// ValidateDatedAt.
func (t *Table) ValidateDated() []string {
	return t.ValidateDatedAt(t.clockNow())
}

// ValidateDatedAt checks every dated timeline, as of `now`, for the two
// mistakes that silently misprice history, and returns one human-readable
// warning per problem (empty slice when clean):
//
//   - DUPLICATE EffectiveFrom within one timeline — ambiguous which
//     entry wins.
//   - the entry IN FORCE at `now` disagrees with the flat table — the flat
//     table is by contract the CURRENT rate card, so LookupAt(now) would not
//     equal Lookup(). This is what a half-landed rate change looks like: the
//     timeline was added but defaultPricing / the config override was never
//     updated (or vice-versa).
//
// Entries that start AFTER `now` are allowed: a price database can state a
// future change in advance (Gemini's 2027-01-01 card), and every timestamped
// lookup already prices by the usage's own instant. A timeline with no entry
// in force yet is not compared with the flat row.
//
// Callers treat warnings as advisory: pricing never fails closed.
func (t *Table) ValidateDatedAt(now time.Time) []string {
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
		flat, ok := t.exact[k]
		if !ok {
			continue // MergeDated seeds it; only a hand-built Table can miss.
		}
		cur := inForceIndex(entries, now)
		if cur < 0 || entries[cur].Unpriced {
			continue
		}
		if flat != entries[cur].Pricing {
			out = append(out, fmt.Sprintf(
				"pricing: model %q dated entry in force (effective_from %s) does not match the current flat rate — the flat table must always hold CURRENT rates, so historical costs will be right but today's will not",
				k, entries[cur].EffectiveFrom.Format(time.RFC3339),
			))
		}
	}
	return out
}

// clockNow is the table's notion of now: the instant it was composed at, or
// time.Now for a hand-built zero-value table.
func (t *Table) clockNow() time.Time {
	if t != nil && !t.builtAt.IsZero() {
		return t.builtAt
	}
	return time.Now().UTC()
}

// inForceIndex returns the index of the LAST entry whose EffectiveFrom is
// <= at (inclusive, like datedRate), or -1 when `at` precedes every entry.
// The zero `at` is treated as an instant like any other here (it precedes
// every real start), unlike datedRate, where a zero `at` means "no
// timestamp". entries must be ascending, which MergeDated guarantees.
func inForceIndex(entries []DatedPricing, at time.Time) int {
	idx := -1
	for i := range entries {
		if entries[i].EffectiveFrom.After(at) {
			break
		}
		idx = i
	}
	return idx
}

// currentOf is the flat (current) rate a timeline implies at `now`: the entry
// in force, or - when none is in force yet, or the one in force is Unpriced -
// the OLDEST priced entry (the closest thing to "the rate before the timeline
// starts" a timeline alone can say). entries must be non-empty and ascending.
func currentOf(entries []DatedPricing, now time.Time) Pricing {
	if i := inForceIndex(entries, now); i >= 0 && !entries[i].Unpriced {
		return entries[i].Pricing
	}
	for _, e := range entries {
		if !e.Unpriced {
			return e.Pricing
		}
	}
	return Pricing{}
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

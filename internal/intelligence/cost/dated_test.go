package cost

import (
	"context"
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// ─────────────────────────────────────────────────────────────────────
// Synthetic fixtures. Deliberately NOT real provider ids or rates: the
// mechanism is what's under test here, and inventing plausible-looking
// numbers for a real SKU is exactly how a wrong rate gets copied into
// the shipped table by someone skimming this file. `synth-*` ids cannot
// collide with anything in defaultPricing (no baked-in key starts with
// "synth"), so a fixture can never accidentally inherit a real family.
// ─────────────────────────────────────────────────────────────────────

const (
	synthDated   = "synth-dated-model"
	synthPlain   = "synth-plain-model"
	synthFamily  = "synth-family"
	synthDatedLC = "synth-lc-model"
)

var (
	boundary = time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC)

	// Old period: expensive. New period (from `boundary`): cheap.
	oldRates = Pricing{Input: 10, Output: 40, CacheRead: 1, CacheCreation: 12, CacheCreation1h: 20, WebSearchPerRequest: 0.02}
	newRates = Pricing{Input: 4, Output: 16, CacheRead: 0.4, CacheCreation: 5, CacheCreation1h: 8, WebSearchPerRequest: 0.01}
)

// datedTestTable builds a table whose flat entry holds the CURRENT (new)
// rates and whose timeline carries both periods — the canonical shape a
// price CUT must be landed in.
func datedTestTable(t *testing.T) *Table {
	t.Helper()
	tbl := NewTable()
	tbl.Merge(map[string]Pricing{
		synthDated: newRates,
		synthPlain: oldRates, // no timeline; the parity control
	})
	tbl.MergeDated(map[string][]DatedPricing{
		synthDated: {
			{EffectiveFrom: boundary, Pricing: newRates},
			{EffectiveFrom: time.Time{}, Pricing: oldRates}, // out of order on purpose
		},
	})
	return tbl
}

// newUndatedTable builds a table seeded with defaultPricing but WITHOUT
// the baked-in datedPricing timelines — the "zero dated entries at all"
// case NewTable() itself can no longer represent now that datedPricing
// carries real entries (the GPT-5.6 Terra/Luna 2026-07-30 price cut).
// Tests that specifically exercise the undated hot path use this
// instead of NewTable().
func newUndatedTable(t *testing.T) *Table {
	t.Helper()
	tbl := &Table{exact: map[string]Pricing{}}
	for k, v := range defaultPricing {
		tbl.exact[k] = v
	}
	return tbl
}

func approx(t *testing.T, got, want float64, what string) {
	t.Helper()
	if math.Abs(got-want) > 1e-9 {
		t.Fatalf("%s = %.12f, want %.12f", what, got, want)
	}
}

// ─────────────────────────────────────────────────────────────────────
// 1. Boundary semantics
// ─────────────────────────────────────────────────────────────────────

func TestDated_BoundarySemantics(t *testing.T) {
	tbl := datedTestTable(t)

	cases := []struct {
		name string
		at   time.Time
		want Pricing
	}{
		{"long before the boundary", boundary.Add(-365 * 24 * time.Hour), oldRates},
		{"one nanosecond before", boundary.Add(-time.Nanosecond), oldRates},
		{"EXACTLY at EffectiveFrom → new rate", boundary, newRates},
		{"one nanosecond after", boundary.Add(time.Nanosecond), newRates},
		{"long after", boundary.Add(365 * 24 * time.Hour), newRates},
		{"zero time → current (flat) rates", time.Time{}, newRates},
		{"non-UTC zone is normalized", boundary.Add(-time.Hour).In(time.FixedZone("x", 7200)), oldRates},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := tbl.LookupAt(synthDated, tc.at)
			if !ok {
				t.Fatal("LookupAt: ok=false")
			}
			if want := fillDefaults(tc.want); got != want {
				t.Fatalf("LookupAt(%s) = %+v, want %+v", tc.at, got, want)
			}
		})
	}
}

func TestDated_PricingSourceIsDateIndependent(t *testing.T) {
	tbl := datedTestTable(t)
	// A timeline attached to a FAMILY key must still report "family" for
	// a SKU that resolves through the prefix ladder — the date dimension
	// lives at the rate, never at the resolution.
	tbl.Merge(map[string]Pricing{synthFamily: newRates})
	tbl.MergeDated(map[string][]DatedPricing{
		synthFamily: {
			{EffectiveFrom: time.Time{}, Pricing: oldRates},
			{EffectiveFrom: boundary, Pricing: newRates},
		},
	})

	for _, at := range []time.Time{{}, boundary.Add(-time.Hour), boundary, boundary.Add(time.Hour)} {
		_, src, ok := tbl.LookupWithSourceAt(synthFamily+"-9-turbo", at)
		if !ok {
			t.Fatalf("at=%s: ok=false", at)
		}
		if src != PricingSourceFamily {
			t.Fatalf("at=%s: source = %q, want %q", at, src, PricingSourceFamily)
		}
	}
	// ...and it actually gets the historical rate through that ladder.
	got, _ := tbl.LookupAt(synthFamily+"-9-turbo", boundary.Add(-time.Hour))
	if want := fillDefaults(oldRates); got != want {
		t.Fatalf("family-resolved historical rate = %+v, want %+v", got, want)
	}
}

// TestDated_CursorAliasUsesOwnTimeline pins that a Cursor-qualified exact
// model keeps a historical timeline attached to its own table key.
func TestDated_CursorAliasUsesOwnTimeline(t *testing.T) {
	tbl := datedTestTable(t)
	const alias = "cursor-grok-4.6-medium"
	tbl.Merge(map[string]Pricing{alias: newRates})
	tbl.MergeDated(map[string][]DatedPricing{
		alias: {
			{EffectiveFrom: time.Time{}, Pricing: oldRates},
			{EffectiveFrom: boundary, Pricing: newRates},
		},
	})

	for _, tc := range []struct {
		name string
		at   time.Time
		want Pricing
	}{
		{name: "before boundary", at: boundary.Add(-time.Hour), want: oldRates},
		{name: "at boundary", at: boundary, want: newRates},
		{name: "current", at: time.Time{}, want: newRates},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, src, ok := tbl.LookupWithSourceAt(alias, tc.at)
			if !ok {
				t.Fatalf("LookupWithSourceAt(%q) ok=false", alias)
			}
			if src != PricingSourceExact {
				t.Fatalf("source=%q want %q", src, PricingSourceExact)
			}
			if want := fillDefaults(tc.want); got != want {
				t.Fatalf("rate at %s = %+v, want %+v", tc.at, got, want)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────
// 2. Fallback parity — the golden. A model with NO dated timeline, and
//    a table with NO dated entries at all, must be byte-identical to the
//    pre-dated behaviour at every rung of the resolution ladder.
// ─────────────────────────────────────────────────────────────────────

func TestDated_FallbackParity_UndatedTableIsUnchanged(t *testing.T) {
	tbl := newUndatedTable(t)
	if tbl.HasDated() {
		t.Fatal("newUndatedTable() reports dated entries — it must not carry the baked-in datedPricing seed")
	}

	bundle := TokenBundle{Input: 12_345, Output: 6_789, CacheRead: 500_000, CacheCreation: 4_321, CacheCreation1h: 1_000, Reasoning: 2_222, WebSearchRequests: 3}
	instants := []time.Time{
		{},
		time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC),
		time.Now().UTC(),
	}

	// Every rung of the ladder: exact, :free, date-stripped, family,
	// normalize-retry, and a hard miss.
	models := []string{
		"claude-opus-5",                    // exact
		"gpt-oss-120b:free",                // :free guard
		"claude-opus-4-6-20251001",         // exact (dated id, exact hit)
		"claude-sonnet-4-5-20991231",       // date-stripped
		"claude-opus-5[1m]",                // family
		"capi:claude-haiku-4-5",            // normalize-retry
		"openrouter/anthropic/gpt-5.6-sol", // normalize-retry (path segments)
		"us.anthropic.claude-opus-5:v1",    // documented MISS
		"totally-unknown-model-xyz",        // MISS
	}

	for _, m := range models {
		wantP, wantSrc, wantOK := tbl.LookupWithSource(m)
		wantCost := ComputeBreakdown(wantP, bundle)
		for _, at := range instants {
			gotP, gotSrc, gotOK := tbl.LookupWithSourceAt(m, at)
			if gotOK != wantOK || gotSrc != wantSrc || gotP != wantP {
				t.Fatalf("model %q at %s: (%+v,%q,%v), want (%+v,%q,%v)",
					m, at, gotP, gotSrc, gotOK, wantP, wantSrc, wantOK)
			}
			if got := ComputeBreakdown(gotP, bundle); got != wantCost {
				t.Fatalf("model %q at %s: breakdown %+v, want %+v", m, at, got, wantCost)
			}
		}
	}
}

func TestDated_ModelWithoutTimelineIgnoresTheDate(t *testing.T) {
	tbl := datedTestTable(t) // table HAS dated entries — for another model
	for _, at := range []time.Time{{}, boundary.Add(-time.Hour), boundary, time.Now()} {
		got, ok := tbl.LookupAt(synthPlain, at)
		if !ok {
			t.Fatalf("at=%s: ok=false", at)
		}
		if want := fillDefaults(oldRates); got != want {
			t.Fatalf("at=%s: %+v, want %+v (flat rate, no timeline)", at, got, want)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────
// 3. Mutation resistance — editing the FLAT rate of a dated model must
//    NOT move pre-boundary costs. This is the whole point of the
//    feature: "any rate edit silently repricing all history" is the bug
//    class being eliminated.
// ─────────────────────────────────────────────────────────────────────

func TestDated_FlatRateEditDoesNotRepriceHistory(t *testing.T) {
	bundle := TokenBundle{Input: 1_000_000, Output: 1_000_000}
	before := boundary.Add(-24 * time.Hour)
	after := boundary.Add(24 * time.Hour)

	tbl := datedTestTable(t)
	histBefore := Compute(mustLookupAt(t, tbl, synthDated, before), bundle)
	currBefore := Compute(mustLookupAt(t, tbl, synthDated, after), bundle)

	// Operator (or a future release) edits the CURRENT rate — the exact
	// action that used to reprice all of history.
	mutated := Pricing{Input: 999, Output: 999, CacheRead: 99, CacheCreation: 99, CacheCreation1h: 99, WebSearchPerRequest: 0.5}
	tbl.Merge(map[string]Pricing{synthDated: mutated})
	tbl.MergeDated(map[string][]DatedPricing{
		synthDated: {
			{EffectiveFrom: time.Time{}, Pricing: oldRates},
			{EffectiveFrom: boundary, Pricing: mutated},
		},
	})

	histAfter := Compute(mustLookupAt(t, tbl, synthDated, before), bundle)
	currAfter := Compute(mustLookupAt(t, tbl, synthDated, after), bundle)

	approx(t, histAfter, histBefore, "pre-boundary cost after a flat-rate edit")
	if currAfter <= currBefore {
		t.Fatalf("MUTATION NOT OBSERVED: post-boundary cost %.6f did not rise after the rate edit (was %.6f) — the test cannot prove history is protected if the mutation had no effect at all", currAfter, currBefore)
	}
	// And the historical rate is genuinely the OLD one, not a coincidence.
	approx(t, histBefore, Compute(fillDefaults(oldRates), bundle), "pre-boundary cost")
}

func mustLookupAt(t *testing.T, tbl *Table, model string, at time.Time) Pricing {
	t.Helper()
	p, ok := tbl.LookupAt(model, at)
	if !ok {
		t.Fatalf("LookupAt(%q, %s): ok=false", model, at)
	}
	return p
}

// ─────────────────────────────────────────────────────────────────────
// 4. Aggregation split across a boundary. The invariant that matters:
//    priced-then-summed == the manual per-row computation, and it is
//    NOT equal to summed-then-priced (which is the bug).
// ─────────────────────────────────────────────────────────────────────

func TestDated_AggregationSplitsAtTheBoundary(t *testing.T) {
	tbl := datedTestTable(t)

	rows := []struct {
		at     time.Time
		bundle TokenBundle
	}{
		{boundary.Add(-72 * time.Hour), TokenBundle{Input: 100_000, Output: 20_000, CacheRead: 400_000}},
		{boundary.Add(-time.Second), TokenBundle{Input: 50_000, Output: 10_000, CacheCreation: 30_000}},
		{boundary, TokenBundle{Input: 70_000, Output: 5_000, CacheRead: 900_000}},
		{boundary.Add(96 * time.Hour), TokenBundle{Input: 25_000, Output: 40_000, WebSearchRequests: 4}},
	}

	// (a) engine-style: price each row at its own instant, then sum.
	var summed float64
	var oldHalf, newHalf TokenBundle
	for _, r := range rows {
		p := mustLookupAt(t, tbl, synthDated, r.at)
		summed += Compute(p, r.bundle)
		if r.at.Before(boundary) {
			oldHalf.Add(r.bundle)
		} else {
			newHalf.Add(r.bundle)
		}
	}

	// (b) manual: bucket by rate period, price each half's SUM once.
	// Legal here only because none of these bundles trips a long-context
	// threshold — see the LC note in ComputeBreakdownAt's doc comment.
	manual := Compute(fillDefaults(oldRates), oldHalf) + Compute(fillDefaults(newRates), newHalf)
	approx(t, summed, manual, "split-half sum")

	// (c) the BUG: sum all tokens, price once at the current rate.
	var all TokenBundle
	all.Add(oldHalf)
	all.Add(newHalf)
	naive := Compute(fillDefaults(newRates), all)
	if math.Abs(naive-summed) < 1e-6 {
		t.Fatal("naive (sum-then-price-at-current) equals the split total — the fixture does not actually exercise the boundary")
	}
	if naive >= summed {
		t.Fatalf("naive %.6f >= split %.6f; the old rates are higher, so ignoring the boundary must UNDER-count", naive, summed)
	}
}

// ─────────────────────────────────────────────────────────────────────
// 5. Long-context interaction — a dated period can change the LC tier
//    too, and the LC dispatch still runs per-bundle on the dated rates.
// ─────────────────────────────────────────────────────────────────────

func TestDated_LongContextTierIsPerPeriod(t *testing.T) {
	oldLC := Pricing{Input: 3, Output: 15, CacheRead: 0.3, LongContextThreshold: 200_000, LongContextInput: 6, LongContextOutput: 30}
	newLC := Pricing{Input: 2, Output: 10, CacheRead: 0.2} // LC tier retired

	tbl := NewTable()
	tbl.Merge(map[string]Pricing{synthDatedLC: newLC})
	tbl.MergeDated(map[string][]DatedPricing{
		synthDatedLC: {
			{EffectiveFrom: time.Time{}, Pricing: oldLC},
			{EffectiveFrom: boundary, Pricing: newLC},
		},
	})

	big := TokenBundle{Input: 300_000, Output: 1_000}
	before := Compute(mustLookupAt(t, tbl, synthDatedLC, boundary.Add(-time.Hour)), big)
	after := Compute(mustLookupAt(t, tbl, synthDatedLC, boundary), big)

	approx(t, before, 300_000*6/1e6+1_000*30/1e6, "pre-boundary LC-tier cost")
	approx(t, after, 300_000*2/1e6+1_000*10/1e6, "post-boundary flat cost (LC tier retired)")
}

// ─────────────────────────────────────────────────────────────────────
// 6. Config round-trip
// ─────────────────────────────────────────────────────────────────────

func TestDated_ConfigRoundTrip(t *testing.T) {
	cfg := config.IntelligenceConfig{
		Pricing: config.PricingConfig{
			Models: map[string]config.ModelPricing{
				synthDated: {Input: 4, Output: 16, CacheRead: 0.4, CacheCreation: 5, CacheCreation1h: 8},
			},
			Dated: map[string][]config.DatedModelPricing{
				synthDated: {
					// Newest first + a bare-date spelling: both must survive.
					{EffectiveFrom: "2026-03-15", ModelPricing: config.ModelPricing{Input: 4, Output: 16, CacheRead: 0.4, CacheCreation: 5, CacheCreation1h: 8}},
					{EffectiveFrom: "", ModelPricing: config.ModelPricing{Input: 10, Output: 40, CacheRead: 1, CacheCreation: 12, CacheCreation1h: 20}},
				},
			},
		},
	}
	e := NewEngine(cfg)

	if !e.HasDatedPricing() {
		t.Fatal("engine reports no dated pricing after a [intelligence.pricing.dated] config")
	}
	if w := e.PricingWarnings(); len(w) != 0 {
		t.Fatalf("clean config produced warnings: %v", w)
	}

	got, ok := e.LookupAt(synthDated, boundary.Add(-time.Hour))
	if !ok {
		t.Fatal("LookupAt: ok=false")
	}
	if want := fillDefaults(Pricing{Input: 10, Output: 40, CacheRead: 1, CacheCreation: 12, CacheCreation1h: 20}); got != want {
		t.Fatalf("pre-boundary = %+v, want %+v", got, want)
	}
	got, _ = e.LookupAt(synthDated, boundary)
	if want := fillDefaults(Pricing{Input: 4, Output: 16, CacheRead: 0.4, CacheCreation: 5, CacheCreation1h: 8}); got != want {
		t.Fatalf("post-boundary = %+v, want %+v", got, want)
	}
	// The undated Lookup keeps returning CURRENT rates.
	flat, _ := e.Lookup(synthDated)
	if flat != got {
		t.Fatalf("Lookup() = %+v, want the current-period rate %+v", flat, got)
	}
}

func TestDated_ConfigParsesEveryAcceptedDateSpelling(t *testing.T) {
	want := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	for _, in := range []string{"2026-08-01", "2026-08-01T00:00:00Z", "2026-08-01T00:00:00", "2026-08-01 00:00:00", "  2026-08-01  "} {
		got, err := ParseEffectiveFrom(in)
		if err != nil {
			t.Fatalf("ParseEffectiveFrom(%q): %v", in, err)
		}
		if !got.Equal(want) {
			t.Fatalf("ParseEffectiveFrom(%q) = %s, want %s", in, got, want)
		}
	}
	if got, err := ParseEffectiveFrom(""); err != nil || !got.IsZero() {
		t.Fatalf(`ParseEffectiveFrom("") = (%s, %v), want (zero, nil)`, got, err)
	}
	if _, err := ParseEffectiveFrom("last tuesday"); err == nil {
		t.Fatal("ParseEffectiveFrom accepted garbage")
	}
}

func TestDated_MalformedConfigRowIsSkippedNotFatal(t *testing.T) {
	cfg := config.IntelligenceConfig{
		Pricing: config.PricingConfig{
			Models: map[string]config.ModelPricing{synthDated: {Input: 4, Output: 16}},
			Dated: map[string][]config.DatedModelPricing{
				synthDated: {
					{EffectiveFrom: "not-a-date", ModelPricing: config.ModelPricing{Input: 99}},
					{EffectiveFrom: "", ModelPricing: config.ModelPricing{Input: 10, Output: 40}},
					{EffectiveFrom: "2026-03-15", ModelPricing: config.ModelPricing{Input: 4, Output: 16}},
				},
			},
		},
	}
	e := NewEngine(cfg)
	warnings := e.PricingWarnings()
	if len(warnings) == 0 {
		t.Fatal("malformed effective_from produced no warning — it would be silently ignored")
	}
	// The two good rows still applied.
	p, ok := e.LookupAt(synthDated, boundary.Add(-time.Hour))
	if !ok || p.Input != 10 {
		t.Fatalf("pre-boundary Input = %v (ok=%v), want 10 — the good rows must survive a bad sibling", p.Input, ok)
	}
	if p, _ := e.LookupAt(synthDated, boundary); p.Input != 4 {
		t.Fatalf("post-boundary Input = %v, want 4", p.Input)
	}
}

// TestDated_ZeroConfigChangesNothing pins that an empty
// [intelligence.pricing.dated] config block adds NOTHING on top of the
// baked-in datedPricing seed — it does not mean "no dated entries at
// all" (the GPT-5.6 Terra/Luna 2026-07-30 price cut ships baked in
// regardless of config), only "no additional config-supplied timeline".
func TestDated_ZeroConfigChangesNothing(t *testing.T) {
	e := NewEngine(config.IntelligenceConfig{})
	if !e.HasDatedPricing() {
		t.Fatal("zero config lost the baked-in datedPricing seed (e.g. gpt-5.6-terra/gpt-5.6-luna)")
	}
	if w := e.PricingWarnings(); len(w) != 0 {
		t.Fatalf("zero config produced warnings: %v", w)
	}
	if e.Table().dated == nil {
		t.Fatal("zero config lost the baked-in dated map")
	}
	if got := e.Table().DatedFor("synth-does-not-exist"); got != nil {
		t.Fatalf("zero config invented a timeline for an unrelated model: %v", got)
	}
}

// ─────────────────────────────────────────────────────────────────────
// 7. MergeDated bookkeeping + validation
// ─────────────────────────────────────────────────────────────────────

func TestDated_MergeSortsAndNormalizes(t *testing.T) {
	tbl := datedTestTable(t)
	tl := tbl.DatedFor(synthDated)
	if len(tl) != 2 {
		t.Fatalf("timeline length %d, want 2", len(tl))
	}
	if !tl[0].EffectiveFrom.Before(tl[1].EffectiveFrom) {
		t.Fatalf("timeline not sorted ascending: %v", tl)
	}
	if tl[1].EffectiveFrom.Location() != time.UTC {
		t.Fatalf("EffectiveFrom not normalized to UTC: %v", tl[1].EffectiveFrom.Location())
	}
	// DatedFor returns a copy.
	tl[0].Input = 12345
	if tbl.DatedFor(synthDated)[0].Input == 12345 {
		t.Fatal("DatedFor leaked the internal slice")
	}
	// DatedModels() also carries the baked-in datedPricing seed (the
	// GPT-5.6 Terra/Luna price cut) alongside the merged synthetic
	// fixture — assert membership, not an exact list, so this test
	// doesn't need editing every time a future rate change adds a row.
	models := tbl.DatedModels()
	found := false
	for _, m := range models {
		if m == synthDated {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("DatedModels() = %v, want it to include %q", models, synthDated)
	}
	if len(models) < len(datedPricing)+1 {
		t.Fatalf("DatedModels() = %v, want at least the %d baked-in entries plus the merged fixture", models, len(datedPricing))
	}
}

func TestDated_DatedOnlyKeySeedsTheFlatEntry(t *testing.T) {
	tbl := NewTable()
	tbl.MergeDated(map[string][]DatedPricing{
		synthDated: {
			{EffectiveFrom: time.Time{}, Pricing: oldRates},
			{EffectiveFrom: boundary, Pricing: newRates},
		},
	})
	// Resolvable through the ordinary (undated) ladder…
	flat, ok := tbl.Lookup(synthDated)
	if !ok {
		t.Fatal("dated-only key is not resolvable — MergeDated failed to seed the flat entry")
	}
	if want := fillDefaults(newRates); flat != want {
		t.Fatalf("seeded flat entry = %+v, want the NEWEST dated entry %+v", flat, want)
	}
	// …and still date-aware.
	if got := mustLookupAt(t, tbl, synthDated, boundary.Add(-time.Hour)); got != fillDefaults(oldRates) {
		t.Fatalf("historical rate = %+v, want %+v", got, fillDefaults(oldRates))
	}
	if w := tbl.ValidateDated(); len(w) != 0 {
		t.Fatalf("self-seeded table should validate clean, got %v", w)
	}
}

func TestDated_ValidateFlagsHalfLandedRateChange(t *testing.T) {
	tbl := NewTable()
	tbl.Merge(map[string]Pricing{synthDated: oldRates}) // flat NOT updated…
	tbl.MergeDated(map[string][]DatedPricing{           // …but a timeline was added
		synthDated: {
			{EffectiveFrom: time.Time{}, Pricing: oldRates},
			{EffectiveFrom: boundary, Pricing: newRates},
		},
	})
	w := tbl.ValidateDated()
	if len(w) != 1 {
		t.Fatalf("want exactly 1 warning for a half-landed rate change, got %d: %v", len(w), w)
	}
}

func TestDated_ValidateFlagsDuplicateEffectiveFrom(t *testing.T) {
	tbl := NewTable()
	tbl.Merge(map[string]Pricing{synthDated: newRates})
	tbl.MergeDated(map[string][]DatedPricing{
		synthDated: {
			{EffectiveFrom: boundary, Pricing: oldRates},
			{EffectiveFrom: boundary, Pricing: newRates},
		},
	})
	found := false
	for _, msg := range tbl.ValidateDated() {
		if len(msg) > 0 && msg != "" {
			found = true
		}
	}
	if !found {
		t.Fatal("duplicate effective_from produced no warning")
	}
}

// TestDatedSeedIsSelfConsistent walks the BAKED-IN dated table through
// the same validator the config path uses. Run it after landing any
// entry in `datedPricing`: it catches the half-landed pair (timeline
// updated but defaultPricing not, or vice-versa) that would leave
// today's costs wrong while history looked fine.
func TestDatedSeedIsSelfConsistent(t *testing.T) {
	tbl := NewTable()
	if w := tbl.ValidateDated(); len(w) != 0 {
		t.Fatalf("baked-in datedPricing is inconsistent with defaultPricing:\n  %v", w)
	}
	for model, entries := range datedPricing {
		if len(entries) < 2 {
			t.Errorf("model %q has a %d-entry timeline: a rate CHANGE needs BOTH the historical period and the current one, or usage before the first entry silently falls back to the (new) flat rate — see datedPricing's doc comment",
				model, len(entries))
		}
		if _, ok := defaultPricing[model]; !ok {
			t.Errorf("model %q has a dated timeline but no defaultPricing row; add the current-rate row too", model)
		}
	}
}

// TestDated_GPT56TerraLunaPriceCut pins the REAL 2026-07-30 OpenAI price
// cut (developers.openai.com/api/docs/changelog: "Starting July 30,
// GPT-5.6 Luna costs 80% less, while GPT-5.6 Terra costs 20% less")
// against the baked-in datedPricing seed (not a synthetic fixture).
// Boundary is INCLUSIVE: usage timestamped exactly at
// 2026-07-30T00:00:00Z bills at the NEW rate. Sol has no timeline and
// is unaffected.
func TestDated_GPT56TerraLunaPriceCut(t *testing.T) {
	tbl := NewTable()
	cutover := time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC)

	oldTerra := Pricing{Input: 2.50, Output: 15, CacheRead: 0.25, CacheCreation: 3.125, CacheCreation1h: 3.125, WebSearchPerRequest: 0.01}
	newTerra := Pricing{
		Input: 2.00, Output: 12.00, CacheRead: 0.20, CacheCreation: 2.50, CacheCreation1h: 2.50, WebSearchPerRequest: 0.01,
		LongContextThreshold: 272_000, LongContextInput: 4.00, LongContextOutput: 18.00, LongContextCacheRead: 0.40,
		LongContextCacheCreation: 5.00, LongContextCacheCreation1h: 5.00, FastMultiplier: 2,
	}
	oldLuna := Pricing{Input: 1, Output: 6, CacheRead: 0.10, CacheCreation: 1.25, CacheCreation1h: 1.25, WebSearchPerRequest: 0.01}
	newLuna := Pricing{
		Input: 0.20, Output: 1.20, CacheRead: 0.02, CacheCreation: 0.25, CacheCreation1h: 0.25, WebSearchPerRequest: 0.01,
		LongContextThreshold: 272_000, LongContextInput: 0.40, LongContextOutput: 1.80, LongContextCacheRead: 0.04,
		LongContextCacheCreation: 0.50, LongContextCacheCreation1h: 0.50, FastMultiplier: 2,
	}

	for _, tc := range []struct {
		name  string
		model string
		at    time.Time
		want  Pricing
	}{
		{"terra long before the cut", "gpt-5.6-terra", cutover.Add(-365 * 24 * time.Hour), oldTerra},
		{"terra one nanosecond before", "gpt-5.6-terra", cutover.Add(-time.Nanosecond), oldTerra},
		{"terra EXACTLY at cutover -> new (inclusive)", "gpt-5.6-terra", cutover, newTerra},
		{"terra after the cut", "gpt-5.6-terra", cutover.Add(24 * time.Hour), newTerra},
		{"terra zero time -> current flat rate", "gpt-5.6-terra", time.Time{}, newTerra},
		{"luna long before the cut", "gpt-5.6-luna", cutover.Add(-365 * 24 * time.Hour), oldLuna},
		{"luna one nanosecond before", "gpt-5.6-luna", cutover.Add(-time.Nanosecond), oldLuna},
		{"luna EXACTLY at cutover -> new (inclusive)", "gpt-5.6-luna", cutover, newLuna},
		{"luna after the cut", "gpt-5.6-luna", cutover.Add(24 * time.Hour), newLuna},
		{"luna zero time -> current flat rate", "gpt-5.6-luna", time.Time{}, newLuna},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := tbl.LookupAt(tc.model, tc.at)
			if !ok {
				t.Fatalf("LookupAt(%q, %s): ok=false", tc.model, tc.at)
			}
			if want := fillDefaults(tc.want); got != want {
				t.Fatalf("LookupAt(%q, %s) = %+v, want %+v", tc.model, tc.at, got, want)
			}
		})
	}

	// Sol has NO timeline: unaffected by the cut at every instant.
	solWant := fillDefaults(Pricing{
		Input: 5, Output: 30, CacheRead: 0.50, CacheCreation: 6.25, CacheCreation1h: 6.25, WebSearchPerRequest: 0.01,
		LongContextThreshold: 272_000, LongContextInput: 10.00, LongContextOutput: 45.00, LongContextCacheRead: 1.00,
		LongContextCacheCreation: 12.50, LongContextCacheCreation1h: 12.50, FastMultiplier: 2,
	})
	for _, at := range []time.Time{{}, cutover.Add(-time.Hour), cutover, cutover.Add(time.Hour)} {
		got, ok := tbl.LookupAt("gpt-5.6-sol", at)
		if !ok || got != solWant {
			t.Fatalf("gpt-5.6-sol at %s = %+v (ok=%v), want %+v unaffected by the Terra/Luna cut", at, got, ok, solWant)
		}
	}

	// The "gpt-5.6" family row and the un-changed defaultPricing rate
	// (LookupAt at "now") must both mirror the NEW rate — the flat table
	// is by contract current, and TestDatedSeedIsSelfConsistent already
	// enforces this via ValidateDated; this pins the USER-VISIBLE value.
	if flat, ok := tbl.Lookup("gpt-5.6-terra"); !ok || flat != fillDefaults(newTerra) {
		t.Fatalf("undated Lookup(gpt-5.6-terra) = %+v (ok=%v), want the NEW rate %+v", flat, ok, fillDefaults(newTerra))
	}
	if flat, ok := tbl.Lookup("gpt-5.6-luna"); !ok || flat != fillDefaults(newLuna) {
		t.Fatalf("undated Lookup(gpt-5.6-luna) = %+v (ok=%v), want the NEW rate %+v", flat, ok, fillDefaults(newLuna))
	}
}

// TestDated_DeepSeekPeakOffPeakOverhaul pins the REAL 2026-08-16T16:00Z
// DeepSeek V4 peak/off-peak overhaul (api-docs.deepseek.com, confirmed
// live 2026-09-07) against the baked-in datedPricing seed. Boundary is
// INCLUSIVE: usage timestamped exactly at the cutover bills at the NEW
// (off-peak-representative) rate. Covers all six affected keys —
// deepseek-v4-flash, deepseek-chat, deepseek-reasoner, deepseek-v4,
// deepseek, and deepseek-v4-pro — since a dated timeline is per exact
// table key, not inherited across aliases.
func TestDated_DeepSeekPeakOffPeakOverhaul(t *testing.T) {
	tbl := NewTable()
	cutover := time.Date(2026, 8, 16, 16, 0, 0, 0, time.UTC)

	// Flash has TWO cutovers: 2026-08-16 (off-peak base bump, no peak) and
	// 2026-09-10 (V4.1-Flash rename → reduced base + a peak variant).
	flashCut2 := time.Date(2026, 9, 10, 16, 0, 0, 0, time.UTC)
	oldFlash := Pricing{Input: 0.14, Output: 0.28, CacheRead: 0.0028}
	midFlash := Pricing{Input: 0.22, Output: 0.66, CacheRead: 0.007}
	newestFlash := Pricing{Input: 0.15, Output: 0.60, CacheRead: 0.003, Peak: deepseekFlashPeak}
	oldPro := Pricing{Input: 0.435, Output: 0.87, CacheRead: 0.003625}
	// The post-overhaul (and current flat) v4-pro Pricing carries the peak
	// variant, preserved through resolution for display surfaces; the
	// pre-overhaul entry stays peak-free (the scheme didn't exist yet).
	newPro := Pricing{Input: 0.66, Output: 1.98, CacheRead: 0.022, Peak: deepseekV4ProPeak}

	flashAliases := []string{"deepseek-v4-flash", "deepseek-chat", "deepseek-reasoner", "deepseek-v4", "deepseek"}
	for _, model := range flashAliases {
		t.Run(model, func(t *testing.T) {
			for _, tc := range []struct {
				name string
				at   time.Time
				want Pricing
			}{
				{"long before the cut", cutover.Add(-365 * 24 * time.Hour), oldFlash},
				{"one nanosecond before 2026-08-16", cutover.Add(-time.Nanosecond), oldFlash},
				{"EXACTLY at 2026-08-16 -> mid (inclusive)", cutover, midFlash},
				{"between the two cuts", cutover.Add(24 * time.Hour), midFlash},
				{"one nanosecond before 2026-09-10", flashCut2.Add(-time.Nanosecond), midFlash},
				{"EXACTLY at 2026-09-10 -> newest (inclusive)", flashCut2, newestFlash},
				{"after 2026-09-10", flashCut2.Add(24 * time.Hour), newestFlash},
				{"zero time -> current flat rate", time.Time{}, newestFlash},
			} {
				t.Run(tc.name, func(t *testing.T) {
					got, ok := tbl.LookupAt(model, tc.at)
					if !ok {
						t.Fatalf("LookupAt(%q, %s): ok=false", model, tc.at)
					}
					if want := fillDefaults(tc.want); got != want {
						t.Fatalf("LookupAt(%q, %s) = %+v, want %+v", model, tc.at, got, want)
					}
				})
			}
		})
	}

	for _, tc := range []struct {
		name string
		at   time.Time
		want Pricing
	}{
		{"long before the cut", cutover.Add(-365 * 24 * time.Hour), oldPro},
		{"one nanosecond before", cutover.Add(-time.Nanosecond), oldPro},
		{"EXACTLY at cutover -> new (inclusive)", cutover, newPro},
		{"after the cut", cutover.Add(24 * time.Hour), newPro},
		{"zero time -> current flat rate", time.Time{}, newPro},
	} {
		t.Run("deepseek-v4-pro/"+tc.name, func(t *testing.T) {
			got, ok := tbl.LookupAt("deepseek-v4-pro", tc.at)
			if !ok {
				t.Fatalf("LookupAt(deepseek-v4-pro, %s): ok=false", tc.at)
			}
			if want := fillDefaults(tc.want); got != want {
				t.Fatalf("LookupAt(deepseek-v4-pro, %s) = %+v, want %+v", tc.at, got, want)
			}
		})
	}

	// deepseek-v4-flash-vision-exp has NO dated timeline (a new SKU, no
	// history to preserve) — it must resolve to the current rate at every
	// instant, including long before the DeepSeek cutover.
	visionWant := fillDefaults(newestFlash)
	for _, at := range []time.Time{{}, cutover.Add(-365 * 24 * time.Hour), cutover, cutover.Add(time.Hour)} {
		got, ok := tbl.LookupAt("deepseek-v4-flash-vision-exp", at)
		if !ok || got != visionWant {
			t.Fatalf("deepseek-v4-flash-vision-exp at %s = %+v (ok=%v), want %+v (no timeline, always current)", at, got, ok, visionWant)
		}
	}

	// deepseek-flash / deepseek-v4.1-flash are NEW keys (flat row only, no
	// dated timeline): they resolve to the current flash rate at every
	// instant, including long before either DeepSeek cutover.
	for _, model := range []string{"deepseek-flash", "deepseek-v4.1-flash"} {
		for _, at := range []time.Time{{}, cutover.Add(-365 * 24 * time.Hour), cutover, flashCut2, flashCut2.Add(time.Hour)} {
			got, ok := tbl.LookupAt(model, at)
			if !ok || got != fillDefaults(newestFlash) {
				t.Fatalf("%s at %s = %+v (ok=%v), want %+v (no timeline, always current)", model, at, got, ok, fillDefaults(newestFlash))
			}
		}
	}

	// Flash PEAK: a turn INSIDE a peak window (Mon 02:00 UTC, in the
	// 01:00-04:00 window) after 2026-09-10 bills EXACTLY 2× — $0.30 in /
	// $1.20 out / $0.006 cache-read. A turn in that same window BEFORE
	// 2026-09-10 has no flash peak variant, so it bills the mid off-peak
	// base ($0.22/$0.66/$0.007), i.e. the pre-Task-2 under-billing.
	mondayPeak := time.Date(2026, 9, 14, 2, 0, 0, 0, time.UTC) // Monday 02:00 UTC, post-cut
	if wd := mondayPeak.Weekday(); wd != time.Monday {
		t.Fatalf("test setup: %s is %s, want Monday", mondayPeak, wd)
	}
	peakFlash := fillDefaults(Pricing{Input: 0.30, Output: 1.20, CacheRead: 0.006, Peak: deepseekFlashPeak})
	for _, model := range []string{"deepseek-v4-flash", "deepseek-flash", "deepseek-v4.1-flash", "deepseek-chat", "deepseek-reasoner", "deepseek-v4", "deepseek", "deepseek-v4-flash-vision-exp"} {
		got, ok := tbl.LookupAt(model, mondayPeak)
		if !ok || got != peakFlash {
			t.Fatalf("LookupAt(%q, Mon 02:00 UTC peak) = %+v (ok=%v), want %+v (2x flash peak)", model, got, ok, peakFlash)
		}
	}
	// Same window, before 2026-09-10: flash has no peak variant yet.
	mondayPeakPre := time.Date(2026, 8, 31, 2, 0, 0, 0, time.UTC) // Monday 02:00 UTC, between the two cuts
	if wd := mondayPeakPre.Weekday(); wd != time.Monday {
		t.Fatalf("test setup: %s is %s, want Monday", mondayPeakPre, wd)
	}
	for _, model := range []string{"deepseek-v4-flash", "deepseek-chat", "deepseek-reasoner", "deepseek-v4", "deepseek"} {
		got, ok := tbl.LookupAt(model, mondayPeakPre)
		if !ok || got != fillDefaults(midFlash) {
			t.Fatalf("LookupAt(%q, Mon 02:00 UTC pre-2026-09-10) = %+v (ok=%v), want %+v (no flash peak yet)", model, got, ok, fillDefaults(midFlash))
		}
	}
}

// ─────────────────────────────────────────────────────────────────────
// 8. Engine-level Compute*At parity
// ─────────────────────────────────────────────────────────────────────

func TestDated_EngineComputeAtParity(t *testing.T) {
	e := NewEngine(config.IntelligenceConfig{})
	bundle := TokenBundle{Input: 10_000, Output: 2_000, CacheRead: 90_000, WebSearchRequests: 2}
	for _, m := range []string{"claude-opus-5", "gpt-5.6-sol", "unknown-xyz"} {
		wantBD, wantOK := e.ComputeBreakdown(m, bundle)
		wantC, _ := e.Compute(m, bundle)
		for _, at := range []time.Time{{}, boundary, time.Now().UTC()} {
			gotBD, gotOK := e.ComputeBreakdownAt(m, bundle, at)
			if gotOK != wantOK || gotBD != wantBD {
				t.Fatalf("%s at %s: (%+v,%v) want (%+v,%v)", m, at, gotBD, gotOK, wantBD, wantOK)
			}
			if gotC, _ := e.ComputeAt(m, bundle, at); gotC != wantC {
				t.Fatalf("%s at %s: ComputeAt=%v want %v", m, at, gotC, wantC)
			}
		}
	}
}

func TestDated_NilEngineAndTableAreSafe(t *testing.T) {
	var e *Engine
	if _, ok := e.LookupAt("claude-opus-5", boundary); ok {
		t.Fatal("nil engine returned ok=true")
	}
	if e.HasDatedPricing() {
		t.Fatal("nil engine reported dated pricing")
	}
	if w := e.PricingWarnings(); w != nil {
		t.Fatalf("nil engine warnings = %v", w)
	}
	var tbl *Table
	if _, ok := tbl.LookupAt("x", boundary); ok {
		t.Fatal("nil table returned ok=true")
	}
	if tbl.HasDated() || tbl.DatedFor("x") != nil || tbl.DatedModels() != nil || tbl.ValidateDated() != nil {
		t.Fatal("nil table accessors misbehaved")
	}
}

// ─────────────────────────────────────────────────────────────────────
// 9. End-to-end: the CANONICAL rollup (Engine.Summary — `observer cost`,
//    MCP get_cost_summary, the dashboard Cost tab) must split a window
//    that straddles a rate boundary, with no SQL-side bucketing.
// ─────────────────────────────────────────────────────────────────────

func TestDated_SummarySplitsAcrossTheBoundary(t *testing.T) {
	database := openTestDB(t)
	f := seedSession(t, database, t.TempDir(), "dated-sess", "claude-code")

	// Anchor the window on "now" so the Days filter includes everything,
	// and place the boundary in the middle of it.
	now := time.Now().UTC()
	bound := now.Add(-5 * 24 * time.Hour)

	// Two rows before the boundary, two at/after it. Same shape on each
	// side so the arithmetic is easy to state.
	const in, out = int64(1_000_000), int64(1_000_000)
	insertTokenUsageWithEventID(t, database, f, bound.Add(-48*time.Hour), "claude-code", synthDated, in, out, "high", "d-1")
	insertTokenUsageWithEventID(t, database, f, bound.Add(-time.Second), "claude-code", synthDated, in, out, "high", "d-2")
	insertTokenUsageWithEventID(t, database, f, bound, "claude-code", synthDated, in, out, "high", "d-3")
	insertTokenUsageWithEventID(t, database, f, bound.Add(48*time.Hour), "claude-code", synthDated, in, out, "high", "d-4")

	opts := Options{Days: 30, GroupBy: GroupByModel, Source: SourceJSONL, Limit: 10}

	// (a) UNDATED engine: flat table only → every row at the current rate.
	flatEngine := NewEngine(config.IntelligenceConfig{
		Pricing: config.PricingConfig{Models: map[string]config.ModelPricing{
			synthDated: {Input: newRates.Input, Output: newRates.Output, CacheRead: newRates.CacheRead},
		}},
	})
	flatSum, err := flatEngine.Summary(context.Background(), database, opts)
	if err != nil {
		t.Fatalf("flat Summary: %v", err)
	}
	wantFlat := 4 * (float64(in)*newRates.Input/1e6 + float64(out)*newRates.Output/1e6)
	approx(t, flatSum.TotalCost, wantFlat, "undated rollup total")

	// (b) DATED engine: same rows, timeline added.
	datedEngine := NewEngine(config.IntelligenceConfig{
		Pricing: config.PricingConfig{
			Models: map[string]config.ModelPricing{
				synthDated: {Input: newRates.Input, Output: newRates.Output, CacheRead: newRates.CacheRead},
			},
			Dated: map[string][]config.DatedModelPricing{
				synthDated: {
					{EffectiveFrom: "", ModelPricing: config.ModelPricing{Input: oldRates.Input, Output: oldRates.Output, CacheRead: oldRates.CacheRead}},
					{EffectiveFrom: bound.Format(time.RFC3339Nano), ModelPricing: config.ModelPricing{Input: newRates.Input, Output: newRates.Output, CacheRead: newRates.CacheRead}},
				},
			},
		},
	})
	if w := datedEngine.PricingWarnings(); len(w) != 0 {
		t.Fatalf("dated engine warnings: %v", w)
	}
	datedSum, err := datedEngine.Summary(context.Background(), database, opts)
	if err != nil {
		t.Fatalf("dated Summary: %v", err)
	}

	perRowOld := float64(in)*oldRates.Input/1e6 + float64(out)*oldRates.Output/1e6
	perRowNew := float64(in)*newRates.Input/1e6 + float64(out)*newRates.Output/1e6
	want := 2*perRowOld + 2*perRowNew
	approx(t, datedSum.TotalCost, want, "dated rollup total")

	// The two halves genuinely differ, so the split was exercised.
	if datedSum.TotalCost <= flatSum.TotalCost {
		t.Fatalf("dated total %.6f <= flat total %.6f — the boundary had no effect", datedSum.TotalCost, flatSum.TotalCost)
	}
	// Token sums are identical either way: only the pricing split, not
	// the aggregation shape, changed.
	if datedSum.TotalTokens != flatSum.TotalTokens {
		t.Fatalf("token totals diverged: %+v vs %+v", datedSum.TotalTokens, flatSum.TotalTokens)
	}
	if datedSum.TurnCount != 4 || flatSum.TurnCount != 4 {
		t.Fatalf("turn counts = %d / %d, want 4", datedSum.TurnCount, flatSum.TurnCount)
	}
}

// TestDated_SummaryUndatedInstallIsGolden pins the parity claim at the
// rollup level: with zero dated entries, the summary is byte-identical
// to what the pre-dated code produced.
func TestDated_SummaryUndatedInstallIsGolden(t *testing.T) {
	database := openTestDB(t)
	f := seedSession(t, database, t.TempDir(), "golden-sess", "claude-code")
	now := time.Now().UTC()
	for i := 0; i < 6; i++ {
		insertTokenUsageWithEventID(t, database, f, now.Add(-time.Duration(i)*36*time.Hour),
			"claude-code", "claude-opus-5", int64(1000*(i+1)), int64(500*(i+1)), "high",
			fmt.Sprintf("g-%d", i))
	}
	e := NewEngine(config.IntelligenceConfig{})
	// The golden claim is scoped to "claude-opus-5", the model actually
	// exercised below — it carries no dated timeline of its own, so its
	// rollup is byte-identical to the pre-dated code path, regardless of
	// the baked-in datedPricing seed covering OTHER models (the GPT-5.6
	// Terra/Luna 2026-07-30 price cut).
	if tl := e.Table().DatedFor("claude-opus-5"); len(tl) != 0 {
		t.Fatalf("claude-opus-5 unexpectedly carries a dated timeline: %v", tl)
	}
	sum, err := e.Summary(context.Background(), database, Options{Days: 30, GroupBy: GroupByModel, Source: SourceJSONL, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	// Recompute the expected total the old way: current rates, per row.
	p, ok := e.Lookup("claude-opus-5")
	if !ok {
		t.Fatal("claude-opus-5 unpriced")
	}
	var want float64
	for i := 0; i < 6; i++ {
		want += Compute(p, TokenBundle{Input: int64(1000 * (i + 1)), Output: int64(500 * (i + 1))})
	}
	approx(t, sum.TotalCost, want, "undated golden rollup")
}

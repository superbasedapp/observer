package cost

import (
	"os"
	"reflect"
	"sort"
	"testing"
	"time"
)

// historySnapshotFile is the snapshot tools/pricing-snapshotgen writes from the
// HISTORY-bearing signed feed that Tokenomics migration 0028 produces (the
// chain: 0028's rows -> observer_price_feed -> signed envelope ->
// internal/pricingfeed/testdata/golden-envelope-history-v1.json -> generator ->
// this file). Each link has its own byte-pinning test; this file tests the last
// one: that the engine prices from it exactly as from the hand-written table.
const historySnapshotFile = "../../../tools/pricing-snapshotgen/testdata/history-snapshot.json"

// historyNow is the instant the golden envelope was resolved at.
var historyNow = time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)

func loadHistorySnapshot(t *testing.T) map[string][]snapshotPrice {
	t.Helper()
	raw, err := os.ReadFile(historySnapshotFile)
	if err != nil {
		t.Fatalf("read %s: %v", historySnapshotFile, err)
	}
	meta, rows, _ := parseSnapshot(raw)
	if meta.Err != nil || len(meta.Skipped) != 0 {
		t.Fatalf("parseSnapshot: err=%v skipped=%v", meta.Err, meta.Skipped)
	}
	return rows
}

// probeInstants is every boundary of both timelines, a nanosecond either side
// of it, a Monday inside a DeepSeek peak window after each, and the far past
// and future.
func probeInstants(a, b []DatedPricing) []time.Time {
	var out []time.Time
	add := func(ts time.Time) {
		out = append(out, ts.Add(-time.Nanosecond), ts, ts.Add(time.Nanosecond))
		// The first Monday 02:00 UTC at or after ts (inside 01:00-04:00).
		d := time.Date(ts.Year(), ts.Month(), ts.Day(), 2, 0, 0, 0, time.UTC)
		for d.Weekday() != time.Monday || d.Before(ts) {
			d = d.Add(24 * time.Hour)
		}
		out = append(out, d)
	}
	for _, e := range append(append([]DatedPricing(nil), a...), b...) {
		if !e.EffectiveFrom.IsZero() {
			add(e.EffectiveFrom)
		}
	}
	out = append(out,
		time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2029, 6, 1, 0, 0, 0, 0, time.UTC))
	sort.Slice(out, func(i, j int) bool { return out[i].Before(out[j]) })
	return out
}

// samePricing compares two rates by VALUE (a *PeakRates from the snapshot is
// never the same pointer as the hand table's).
func samePricing(a, b Pricing) bool {
	ap, bp := a.Peak, b.Peak
	a.Peak, b.Peak = nil, nil
	if a != b {
		return false
	}
	return reflect.DeepEqual(ap, bp)
}

// TestHandTimelinesMatchSnapshot is the DATABASE-AUTHORITY proof for the date
// dimension (lane R2-PRICING-2): every timeline hand-written in dated.go is
// present in the price database's history, and a table built from that
// history prices EVERY instant exactly as the hand table does - each
// boundary, a nanosecond either side, inside a peak window after each, and far
// before and after. That is what makes the hand table deletable the moment a
// generated snapshot carries the history (TestHandTimelinesRetiredOnce...).
func TestHandTimelinesMatchSnapshot(t *testing.T) {
	rows := loadHistorySnapshot(t)
	hand := newLiteralTableAt(historyNow)
	db := newLiteralTableAt(historyNow)
	applySnapshotRows(db, rows)

	for key, handTL := range datedPricing {
		if len(rows[key]) < 2 {
			t.Errorf("%s: dated.go carries a timeline the price database does not (add it to observer_price_history)", key)
			continue
		}
		for _, at := range probeInstants(handTL, db.DatedFor(key)) {
			hp, hok := hand.LookupAt(key, at)
			dp, dok := db.LookupAt(key, at)
			if hok != dok || !samePricing(hp, dp) {
				t.Errorf("%s at %s: hand %+v (ok=%v) != database %+v (ok=%v)", key, at.Format(time.RFC3339Nano), hp, hok, dp, dok)
			}
		}
		hf, _ := hand.Lookup(key)
		df, _ := db.Lookup(key)
		if !samePricing(hf, df) {
			t.Errorf("%s current rate: hand %+v != database %+v", key, hf, df)
		}
	}
	if w := db.ValidateDatedAt(historyNow); len(w) != 0 {
		t.Fatalf("database-built table fails ValidateDatedAt: %v", w)
	}
}

// TestSnapshotHistoryBeyondTheHandTable pins the dated changes that exist ONLY
// in the price database: GLM-5.3-Flash's launch promotion, Gemini 3.6 Flash's
// launch card and cut, and the 3.6 / 3.7 / 3.8 Flash card Google states from
// 2027-01-01 - including that a table built BEFORE that date keeps the
// introductory card as the current rate while a timestamped lookup already
// prices a 2027 turn at the standard card, and that a table built after it has
// moved the current rate forward.
func TestSnapshotHistoryBeyondTheHandTable(t *testing.T) {
	rows := loadHistorySnapshot(t)
	intro := Pricing{Input: 0.75, Output: 3.75, CacheRead: 0.075}
	standard := Pricing{Input: 1.50, Output: 7.50, CacheRead: 0.15}
	glmList := Pricing{Input: 0.15, Output: 0.50, CacheRead: 0.03}
	glmPromo := Pricing{Input: 0.075, Output: 0.25, CacheRead: 0.015}
	promoFrom := time.Date(2026, 9, 7, 15, 0, 0, 0, time.UTC)
	promoTo := time.Date(2026, 9, 9, 16, 0, 0, 0, time.UTC)
	cut36 := time.Date(2026, 8, 15, 0, 0, 0, 0, time.UTC)
	jan27 := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	ns := time.Nanosecond

	before := newLiteralTableAt(historyNow)
	applySnapshotRows(before, rows)
	after := newLiteralTableAt(jan27.Add(24 * time.Hour))
	applySnapshotRows(after, rows)

	cases := []struct {
		name  string
		tbl   *Table
		model string
		at    time.Time // zero = the current (flat) rate
		want  Pricing
	}{
		{"glm list before the promo", before, "glm-5.3-flash", promoFrom.Add(-ns), glmList},
		{"glm promo at its start", before, "glm-5.3-flash", promoFrom, glmPromo},
		{"glm promo just before its end", before, "glm-5.3-flash", promoTo.Add(-ns), glmPromo},
		{"glm list again at the end", before, "glm-5.3-flash", promoTo, glmList},
		{"glm current", before, "glm-5.3-flash", time.Time{}, glmList},
		{"3.6 launch card before the cut", before, "gemini-3.6-flash", cut36.Add(-ns), standard},
		{"3.6 intro at the cut", before, "gemini-3.6-flash", cut36, intro},
		{"3.6 intro just before 2027", before, "gemini-3.6-flash", jan27.Add(-ns), intro},
		{"3.6 standard from 2027 (built before)", before, "gemini-3.6-flash", jan27, standard},
		{"3.6 current before 2027 is intro", before, "gemini-3.6-flash", time.Time{}, intro},
		{"3.7 intro from launch", before, "gemini-3.7-flash", time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC), intro},
		{"3.7 standard from 2027 (built before)", before, "gemini-3.7-flash", jan27, standard},
		{"3.8 current before 2027 is intro", before, "gemini-3.8-flash", time.Time{}, intro},
		{"3.8 current after 2027 is standard", after, "gemini-3.8-flash", time.Time{}, standard},
		{"3.7 an old turn after 2027 still intro", after, "gemini-3.7-flash", time.Date(2026, 12, 31, 23, 0, 0, 0, time.UTC), intro},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got Pricing
			var ok bool
			if tc.at.IsZero() {
				got, ok = tc.tbl.Lookup(tc.model)
			} else {
				got, ok = tc.tbl.LookupAt(tc.model, tc.at)
			}
			if want := applyCacheWriteRule(tc.model, fillDefaultsFor(tc.model, tc.want)); !ok || !samePricing(got, want) {
				t.Fatalf("%s = %+v (ok=%v), want %+v", tc.model, got, ok, tc.want)
			}
		})
	}
	for _, tbl := range []*Table{before, after} {
		if w := tbl.ValidateDatedAt(tbl.clockNow()); len(w) != 0 {
			t.Fatalf("ValidateDatedAt(%s) = %v", tbl.clockNow(), w)
		}
	}
}

// TestHandTimelinesRetiredOnceSnapshotCovers is the retirement gate for
// dated.go's DATA (its lookup code stays): once the EMBEDDED, generated
// snapshot carries a model's price history, the database is the authority for
// it (setSnapshotHistory already replaces the hand timeline at build), so the
// hand copy must be deleted in the same commit as `make pricing-snapshot`. The
// committed zero snapshot carries no history, so this passes until then.
func TestHandTimelinesRetiredOnceSnapshotCovers(t *testing.T) {
	loadSnapshot()
	var stale []string
	for key := range datedPricing {
		if len(snapshotRows[key]) >= 2 {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	if len(stale) != 0 {
		t.Fatalf("the generated snapshot now carries the price history of %v; delete these entries from datedPricing in dated.go (TestHandTimelinesMatchSnapshot proved them equal)", stale)
	}
}

// TestSetSnapshotHistory pins the history rule directly: every period stands
// alone (a rate it does not quote is absent, never inherited from the literal
// or the previous period), a restatement is not a new period, a history that
// starts later keeps the literal before it, and the flat rate is the period in
// force at the table's clock even when a later period is already known.
func TestSetSnapshotHistory(t *testing.T) {
	d := func(y int, m time.Month, day int) time.Time { return time.Date(y, m, day, 0, 0, 0, 0, time.UTC) }
	price := func(from time.Time, in, out float64) snapshotPrice {
		return snapshotPrice{from: from, rates: OrgPrice{
			Pricing: Pricing{Input: in, Output: out},
			Set:     OrgPriceSet{Input: true, Output: true},
		}}
	}
	literal := Pricing{Input: 9, Output: 9, CacheRead: 1, LongContextThreshold: 200_000, LongContextInput: 18}

	cases := []struct {
		name     string
		now      time.Time
		rows     []snapshotPrice
		wantTL   []DatedPricing
		wantFlat Pricing
	}{
		{
			name: "since-forever history ignores the literal's other dimensions",
			now:  d(2026, 9, 1),
			rows: []snapshotPrice{price(time.Time{}, 1, 2), price(d(2026, 7, 30), 3, 4)},
			wantTL: []DatedPricing{
				{EffectiveFrom: time.Time{}, Pricing: Pricing{Input: 1, Output: 2}},
				{EffectiveFrom: d(2026, 7, 30), Pricing: Pricing{Input: 3, Output: 4}},
			},
			wantFlat: Pricing{Input: 3, Output: 4},
		},
		{
			// The database states no rate before its first period: nothing
			// is in force then (deepseek-chat before 2025-09-05), never the
			// literal's current rate.
			name: "a later-starting history is unpriced before it",
			now:  d(2026, 9, 1),
			rows: []snapshotPrice{price(d(2026, 7, 1), 1, 2), price(d(2026, 8, 1), 3, 4)},
			wantTL: []DatedPricing{
				{EffectiveFrom: time.Time{}, Unpriced: true},
				{EffectiveFrom: d(2026, 7, 1), Pricing: Pricing{Input: 1, Output: 2}},
				{EffectiveFrom: d(2026, 8, 1), Pricing: Pricing{Input: 3, Output: 4}},
			},
			wantFlat: Pricing{Input: 3, Output: 4},
		},
		{
			name: "a known future period is not yet the flat rate",
			now:  d(2026, 9, 1),
			rows: []snapshotPrice{price(time.Time{}, 1, 2), price(d(2027, 1, 1), 3, 4)},
			wantTL: []DatedPricing{
				{EffectiveFrom: time.Time{}, Pricing: Pricing{Input: 1, Output: 2}},
				{EffectiveFrom: d(2027, 1, 1), Pricing: Pricing{Input: 3, Output: 4}},
			},
			wantFlat: Pricing{Input: 1, Output: 2},
		},
		{
			name:     "a restatement collapses into one period",
			now:      d(2026, 9, 1),
			rows:     []snapshotPrice{price(time.Time{}, 1, 2), price(d(2026, 7, 1), 1, 2)},
			wantTL:   nil,
			wantFlat: Pricing{Input: 1, Output: 2},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tbl := &Table{
				exact:   map[string]Pricing{"m": literal},
				builtAt: tc.now,
				dated:   map[string][]DatedPricing{"m": {{EffectiveFrom: time.Time{}, Pricing: Pricing{Input: 5}}}},
			}
			tbl.setSnapshotHistory("m", tc.rows)
			if got := tbl.dated["m"]; !reflect.DeepEqual(got, tc.wantTL) {
				t.Fatalf("timeline = %+v, want %+v", got, tc.wantTL)
			}
			if got := tbl.exact["m"]; got != tc.wantFlat {
				t.Fatalf("flat = %+v, want %+v", got, tc.wantFlat)
			}
		})
	}
}

// TestOpus46LongContextPremiumEndsAt20260313 pins migration 0029's
// two-period claude-opus-4-6 history as the compiled seed carries it. From
// launch Anthropic charged a >200K premium ("Premium pricing applies for
// prompts exceeding 200k tokens ($10/$37.50 per million input/output
// tokens)", anthropic.com/news/claude-opus-4-6, Feb 5 2026; the cache rates
// under it are DERIVED with the standard multipliers); from 2026-03-13 the 1M
// window is "at standard pricing" (Claude release notes, Mar 13 2026).
func TestOpus46LongContextPremiumEndsAt20260313(t *testing.T) {
	tb := NewTable()
	end := time.Date(2026, 3, 13, 0, 0, 0, 0, time.UTC)
	before, ok := tb.LookupAt("claude-opus-4-6", end.Add(-time.Nanosecond))
	if !ok {
		t.Fatal("claude-opus-4-6 unpriced before 2026-03-13")
	}
	if before.Input != 5 || before.Output != 25 || before.LongContextThreshold != 200_000 ||
		before.LongContextInput != 10 || before.LongContextOutput != 37.50 ||
		before.LongContextCacheRead != 1 || before.LongContextCacheCreation != 12.50 || before.LongContextCacheCreation1h != 20 {
		t.Errorf("claude-opus-4-6 before 2026-03-13 = %+v, want 5/25 with the >200K 10/37.50 (cache 1/12.50/20) tier", before)
	}
	for _, at := range []time.Time{end, {}} {
		p, _ := tb.LookupAt("claude-opus-4-6", at)
		if p.Input != 5 || p.Output != 25 || p.LongContextThreshold != 0 || p.LongContextInput != 0 {
			t.Errorf("claude-opus-4-6 at %s = %+v, want the standard card with no long-context tier", at, p)
		}
	}
	// A 300K-input request inside the premium window bills the premium.
	big := TokenBundle{Input: 300_000, Output: 1_000}
	if got := ComputeBreakdown(before, big).AICost; got <= ComputeBreakdown(mustLookupAt(t, tb, "claude-opus-4-6", end), big).AICost {
		t.Errorf("a >200K request before 2026-03-13 costs %v, not more than the same request after", got)
	}
}

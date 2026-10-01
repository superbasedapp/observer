package cost

import (
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// THE 2026-09-30 PRICING-CHAIN CONTRACT, consumer side (lane CHAIN): a quoted
// reasoning rate bills the separately-tracked reasoning tokens, the carried
// dimensions change no bill, and a present long-context threshold of 0 is a
// FLAT row on every path.

// TestReasoningRateApplied is one case per reasoning-billing rule.
func TestReasoningRateApplied(t *testing.T) {
	cases := []struct {
		name string
		p    Pricing
		want float64 // OutputCost for 1M reasoning tokens
	}{
		{"unquoted reasoning bills at the output rate", Pricing{Output: 10}, 10},
		{"a quoted reasoning rate replaces the output rate", Pricing{Output: 10, Reasoning: 2}, 2},
		{"the carried dimensions change nothing", Pricing{Output: 10, RequestFee: 1, ImageInput: 5, AudioOutput: 7, CacheCreationOther: 3, ImageOutputPerImage: 0.04, AudioInput: 4}, 10},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := ComputeBreakdown(tc.p, TokenBundle{Reasoning: 1_000_000})
			if b.OutputCost != tc.want || b.AICost != tc.want || b.Total != tc.want {
				t.Fatalf("breakdown = %+v, want output/ai/total %v", b, tc.want)
			}
		})
	}
}

// TestExtendedRatesOverlayWithPresence: an org / feed row's extended
// dimensions and fast multiplier overlay with the migration-135 rule - a
// quoted value wins (0 included), an unquoted one keeps the base's.
func TestExtendedRatesOverlayWithPresence(t *testing.T) {
	base := Pricing{Input: 1, Output: 2, FastMultiplier: 2, Reasoning: 9, RequestFee: 0.5}
	row := OrgPrice{
		Model:   "m",
		Pricing: Pricing{Input: 3, Output: 4, FastMultiplier: 0, Reasoning: 1.5, AudioInput: 40},
		Set:     OrgPriceSet{Input: true, Output: true, FastMultiplier: true, Reasoning: true, AudioInput: true},
	}
	got := row.overlay(base)
	want := Pricing{Input: 3, Output: 4, FastMultiplier: 0, Reasoning: 1.5, RequestFee: 0.5, AudioInput: 40}
	if got != want {
		t.Fatalf("overlay = %+v, want %+v", got, want)
	}
	neg := row
	neg.RequestFee, neg.Set.RequestFee = -1, true
	if !neg.negativeQuotedRate() {
		t.Fatal("a negative quoted request fee is not refused")
	}
}

// TestFlatLongContextSnapshotAndFeedAgree proves the compiled snapshot and the
// live feed price a curated NO-TIER period identically: the feed states it as
// long_context_threshold 0 (present = FLAT, the 2026-09-30 ruling), the
// generator carries that 0 onto the snapshot row, and both paths - the
// snapshot's history fold and the live feed's overlay on the seed - end with
// no long-context tier (threshold 0 AND no dormant long-context rate), so a
// prompt above the seed's old threshold bills at the base rates on both. A
// later period that does publish a tier prices it identically too.
func TestFlatLongContextSnapshotAndFeedAgree(t *testing.T) {
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	seed := newTableAt(now)
	keys := seed.Known()
	sort.Strings(keys)
	model := ""
	for _, k := range keys {
		if p, ok := seed.Lookup(k); ok && p.LongContextThreshold > 0 && p.LongContextInput > 0 {
			model = k
			break
		}
	}
	if model == "" {
		t.Skip("no seed model carries a long-context tier")
	}

	// The snapshot path: two dated rows, as tools/pricing-snapshotgen writes
	// a feed row's history (the flat period states its 0 threshold).
	doc := fmt.Sprintf(`{"schema_version":%d,"feed_version":%d,"rows":[
	 {"model":%q,"effective_from":"2026-01-01","input_per_mtok":3,"output_per_mtok":15,"long_context_threshold":0},
	 {"model":%q,"effective_from":"2026-06-01","input_per_mtok":3,"output_per_mtok":15,"long_context_threshold":200000,"long_context_input_per_mtok":6,"long_context_output_per_mtok":22.5}]}`,
		SnapshotSchemaVersion, SnapshotMinFeedVersion, model, model)
	meta, rows, _ := parseSnapshot([]byte(doc))
	if meta.Err != nil || len(meta.Skipped) != 0 {
		t.Fatalf("parseSnapshot: err=%v skipped=%v", meta.Err, meta.Skipped)
	}
	snap := newTableAt(now)
	applySnapshotRows(snap, rows)

	// The live-feed path: the same history projected the way
	// pricewire.FeedPriceRows projects it (a present threshold is quoted, 0
	// included), composed through the real engine rebuild.
	period := func(from string, lcThreshold int64, lcIn, lcOut float64) OrgPrice {
		p := OrgPrice{
			Model:         model,
			EffectiveFrom: from,
			Pricing: Pricing{
				Input: 3, Output: 15, LongContextThreshold: lcThreshold,
				LongContextInput: lcIn, LongContextOutput: lcOut,
			},
			Set: OrgPriceSet{Input: true, Output: true, LongContextThreshold: true},
		}
		p.Set.LongContextInput, p.Set.LongContextOutput = lcIn > 0, lcOut > 0
		return p
	}
	flat := period("2026-01-01", 0, 0, 0)
	tiered := period("2026-06-01", 200000, 6, 22.5)
	top := tiered
	top.History = []OrgPrice{flat, tiered}
	e := NewEngine(config.IntelligenceConfig{}, withClock(func() time.Time { return now }))
	e.SetOrgRows([]OrgPrice{top}, 1, false)
	feed := e.Table()

	long := TokenBundle{Input: 300_000, Output: 1_000}
	for i, at := range []time.Time{
		time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), // the curated no-tier period
		time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), // the tiered period
	} {
		flatPeriod := i == 0
		sp, sok := snap.LookupAt(model, at)
		fp, fok := feed.LookupAt(model, at)
		if !sok || !fok {
			t.Fatalf("%s at %s: snapshot ok=%v feed ok=%v", model, at, sok, fok)
		}
		lc := func(p Pricing) [6]float64 {
			return [6]float64{
				float64(p.LongContextThreshold), p.LongContextInput, p.LongContextOutput,
				p.LongContextCacheRead, p.LongContextCacheCreation, p.LongContextCacheCreation1h,
			}
		}
		// The whole tier must agree on the flat period. On the tiered one a
		// long-context CACHE rate the period does not quote still differs by
		// design (a snapshot history period is a complete statement, a feed
		// period overlays the seed), so only the billed prompt is compared.
		if flatPeriod && lc(sp) != lc(fp) {
			t.Errorf("%s at %s: long-context tier differs: snapshot %v, feed %v", model, at, lc(sp), lc(fp))
		}
		if s, f := Compute(sp, long), Compute(fp, long); s != f {
			t.Errorf("%s at %s: a 300k prompt costs %v on the snapshot path, %v on the feed path", model, at, s, f)
		}
	}
	if p, _ := feed.LookupAt(model, time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)); p.LongContextThreshold != 0 || p.LongContextInput != 0 {
		t.Fatalf("the flat period kept a long-context tier: %+v", p)
	}
}

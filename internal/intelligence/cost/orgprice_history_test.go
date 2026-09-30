package cost

import (
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// PRICE HISTORY ON THE ORG / FEED RAILS (lane R2-PRICING-2).
//
// A row that carries a History builds the key's DATED timeline; a row that
// does not keeps the F13 behaviour (one flat rate for all of history). These
// pin both, through the real engine rebuild.

func datedRow(model, from string, in, out float64) OrgPrice {
	r := orgRow(model, in, out)
	r.EffectiveFrom = from
	return r
}

func withHistory(top OrgPrice, periods ...OrgPrice) OrgPrice {
	top.History = periods
	return top
}

func TestOrgHistoryBuildsTimeline(t *testing.T) {
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	d := func(s string) time.Time {
		ts, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatal(err)
		}
		return ts
	}
	ns := time.Nanosecond
	// "zz-hist" is priced by NOTHING in the seed: every instant is the
	// history's statement alone (before the first period there is no rate).
	p0 := datedRow("zz-hist", "2026-01-01T00:00:00Z", 1, 2)
	p1 := datedRow("zz-hist", "2026-06-01T00:00:00Z", 3, 4)
	p2 := datedRow("zz-hist", "2027-01-01T00:00:00Z", 5, 6) // stated in advance
	top := withHistory(p1, p0, p1, p2)

	e := NewEngine(config.IntelligenceConfig{}, withClock(func() time.Time { return now }))
	e.SetOrgRows([]OrgPrice{top}, 1, false)

	cases := []struct {
		name   string
		at     time.Time // zero = current
		wantIn float64
		wantOK bool
	}{
		{"before the first period nothing prices it", d("2026-01-01T00:00:00Z").Add(-ns), 0, false},
		{"first period at its start", d("2026-01-01T00:00:00Z"), 1, true},
		{"first period just before the second", d("2026-06-01T00:00:00Z").Add(-ns), 1, true},
		{"second period at its start", d("2026-06-01T00:00:00Z"), 3, true},
		{"current is the period in force now, not the future one", time.Time{}, 3, true},
		{"the future period prices a turn at its instant", d("2027-01-01T00:00:00Z"), 5, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got Pricing
			var ok bool
			if tc.at.IsZero() {
				got, ok = e.Table().Lookup("zz-hist")
			} else {
				got, ok = e.Table().LookupAt("zz-hist", tc.at)
			}
			if tc.wantOK != (ok && got.Input != 0) || (tc.wantOK && got.Input != tc.wantIn) {
				t.Fatalf("zz-hist at %v = %+v (ok=%v), want input %v (priced=%v)", tc.at, got, ok, tc.wantIn, tc.wantOK)
			}
		})
	}
	if w := e.PricingWarnings(); len(w) != 0 {
		t.Fatalf("warnings = %v", w)
	}
	if src := e.Table().sourceFor("zz-hist", PricingSourceExact); src != PricingSourceOrg {
		t.Fatalf("a history key is not reported as org-owned: %s", src)
	}
}

// A period that does not quote a dimension keeps the SEED's value for it at
// that instant - here the seed's own dated.go timeline - so a partial org
// history over gpt-5.6-terra keeps the pre-cut cache-write rate before the cut
// and the post-cut one after it.
func TestOrgHistoryOverlaysTheSeedAtEachInstant(t *testing.T) {
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	cut := time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC)
	e := NewEngine(config.IntelligenceConfig{}, withClock(func() time.Time { return now }))
	top := withHistory(datedRow("gpt-5.6-terra", "2026-09-01T00:00:00Z", 7, 70),
		datedRow("gpt-5.6-terra", "", 8, 80),
		datedRow("gpt-5.6-terra", "2026-09-01T00:00:00Z", 7, 70))
	e.SetOrgRows([]OrgPrice{top}, 1, false)
	tbl := e.Table()

	before, _ := tbl.LookupAt("gpt-5.6-terra", cut.Add(-time.Hour))
	if before.Input != 8 || before.CacheCreation != 3.125 {
		t.Fatalf("pre-cut = %+v, want the org's 8 over the seed's pre-cut 3.125 write", before)
	}
	between, _ := tbl.LookupAt("gpt-5.6-terra", cut.Add(time.Hour))
	if between.Input != 8 || between.CacheCreation != 2.50 || between.LongContextThreshold != 272_000 {
		t.Fatalf("post-cut = %+v, want the org's 8 over the seed's post-cut card", between)
	}
	cur, _ := tbl.Lookup("gpt-5.6-terra")
	if cur.Input != 7 || cur.CacheCreation != 2.50 {
		t.Fatalf("current = %+v, want the org's 7 over the seed's current card", cur)
	}
}

func TestOrgHistoryFallsBackAndWarns(t *testing.T) {
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name         string
		row          OrgPrice
		wantTimeline bool
		wantWarn     string
	}{
		{
			name:         "an undated row with no history keeps the flat F13 behaviour",
			row:          datedRow("zz-flat", "", 3, 4),
			wantTimeline: false,
		},
		{
			// PRICE-REPRICE-1 review finding 1: a single DATED row is its own
			// one-period history - nothing before its date, its rate after.
			name:         "a dated row with no history is dated from its start",
			row:          datedRow("zz-flat", "2026-06-01T00:00:00Z", 3, 4),
			wantTimeline: true,
		},
		{
			name: "a negative period is ignored; the one left still dates the key",
			row: withHistory(datedRow("zz-flat", "2026-06-01T00:00:00Z", 3, 4),
				datedRow("zz-flat", "", -1, 2),
				datedRow("zz-flat", "2026-06-01T00:00:00Z", 3, 4)),
			wantTimeline: true,
			wantWarn:     "period 0 ignored: a rate is negative",
		},
		{
			name: "a negative period is ignored; an undated one left is flat",
			row: withHistory(datedRow("zz-flat", "", 3, 4),
				datedRow("zz-flat", "", 3, 4),
				datedRow("zz-flat", "2026-06-01T00:00:00Z", -3, 4)),
			wantTimeline: false,
			wantWarn:     "period 1 ignored: a rate is negative",
		},
		{
			name: "an unreadable start is ignored and reported",
			row: withHistory(datedRow("zz-flat", "2026-06-01T00:00:00Z", 3, 4),
				datedRow("zz-flat", "June", 1, 2),
				datedRow("zz-flat", "", 2, 3),
				datedRow("zz-flat", "2026-06-01T00:00:00Z", 3, 4)),
			wantTimeline: true,
			wantWarn:     "is not a date this node understands",
		},
		{
			name: "two periods at one instant keep the later one",
			row: withHistory(datedRow("zz-flat", "2026-06-01T00:00:00Z", 3, 4),
				datedRow("zz-flat", "", 1, 2),
				datedRow("zz-flat", "2026-06-01", 9, 9),
				datedRow("zz-flat", "2026-06-01T00:00:00Z", 3, 4)),
			wantTimeline: true,
			wantWarn:     "two periods start at",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := NewEngine(config.IntelligenceConfig{}, withClock(func() time.Time { return now }))
			e.SetOrgRows([]OrgPrice{tc.row}, 1, false)
			if got := e.Table().DatedFor("zz-flat") != nil; got != tc.wantTimeline {
				t.Fatalf("timeline present = %v, want %v (%+v)", got, tc.wantTimeline, e.Table().DatedFor("zz-flat"))
			}
			if cur, _ := e.Table().Lookup("zz-flat"); cur.Input != 3 {
				t.Fatalf("current input = %v, want the in-force 3", cur.Input)
			}
			joined := strings.Join(e.PricingWarnings(), "\n")
			if tc.wantWarn != "" && !strings.Contains(joined, tc.wantWarn) {
				t.Fatalf("warnings %q do not mention %q", joined, tc.wantWarn)
			}
		})
	}
}

// On an INDIVIDUAL node a developer's own override still wins over an org
// history row: the key is neither org-owned nor dated by the org.
func TestOrgHistoryYieldsToLocalOverrideOnIndividualNode(t *testing.T) {
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	cfg := config.IntelligenceConfig{Pricing: config.PricingConfig{Models: map[string]config.ModelPricing{
		"zz-hist": {Input: 42, Output: 84},
	}}}
	e := NewEngine(cfg, withClock(func() time.Time { return now }))
	e.SetOrgRows([]OrgPrice{withHistory(datedRow("zz-hist", "2026-06-01T00:00:00Z", 3, 4),
		datedRow("zz-hist", "", 1, 2), datedRow("zz-hist", "2026-06-01T00:00:00Z", 3, 4))}, 1, false)
	got, _ := e.Table().LookupAt("zz-hist", time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC))
	if got.Input != 42 || e.Table().DatedFor("zz-hist") != nil {
		t.Fatalf("local override lost to an org history: %+v, timeline %+v", got, e.Table().DatedFor("zz-hist"))
	}
}

// A seed period with NO rate in force (deepseek-chat before 2025-09-05,
// dated.go) stays a MISS under an org/feed history that says nothing about
// that time, and becomes priced only where a history period states a rate -
// the feed never turns "unknown" into the seed's current rate.
func TestOrgHistoryKeepsTheSeedsUnpricedPeriod(t *testing.T) {
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	preV4 := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	postV4 := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	// A history that starts after the V4 launch: before it the seed applies,
	// and the seed is unpriced before 2026-04-24.
	late := withHistory(datedRow("deepseek-chat", "2026-09-10T04:00:00Z", 7, 8),
		datedRow("deepseek-chat", "2026-08-16T16:00:00Z", 5, 6),
		datedRow("deepseek-chat", "2026-09-10T04:00:00Z", 7, 8))
	e := NewEngine(config.IntelligenceConfig{}, withClock(func() time.Time { return now }))
	e.SetOrgRows([]OrgPrice{late}, 1, false)
	if p, src, ok := e.Table().LookupWithSourceAt("deepseek-chat", preV4); ok || src != PricingSourceMiss {
		t.Fatalf("pre-V4 = %+v %s (ok=%v), want a miss (the seed states no rate then)", p, src, ok)
	}
	if p, ok := e.Table().LookupAt("deepseek-chat", postV4); !ok || p.Input != 0.14 {
		t.Fatalf("post-V4, before the org history = %+v (ok=%v), want the seed's V4 card", p, ok)
	}

	// A history that states a rate since forever prices the whole past.
	forever := withHistory(datedRow("deepseek-chat", "2026-09-10T04:00:00Z", 7, 8),
		datedRow("deepseek-chat", "", 3, 4),
		datedRow("deepseek-chat", "2026-09-10T04:00:00Z", 7, 8))
	e2 := NewEngine(config.IntelligenceConfig{}, withClock(func() time.Time { return now }))
	e2.SetOrgRows([]OrgPrice{forever}, 1, false)
	if p, ok := e2.Table().LookupAt("deepseek-chat", preV4); !ok || p.Input != 3 {
		t.Fatalf("pre-V4 under a since-forever history = %+v (ok=%v), want the history's 3", p, ok)
	}
}

package cost

import (
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// PRICE-REPRICE-1 review finding 1: a SINGLE dated org row (the shape the
// Pricing page's authoring form and the assistant's executor produce - both
// stamp a date) must price only from its own effective_from on. Before it, the
// key prices at whatever would apply WITHOUT the row: the seed's own dated
// history or flat rate, else nothing (a miss, never $0). Only an undated row
// is flat across all of history. The rule lives in composeOrgRows, so the
// capture-time stamp (Lookup at now), the read path and a re-price (LookupAt
// at a row's timestamp) all follow it, on a node and on the org alike.
func TestSingleDatedOrgRowPricesFromItsDate(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	date := time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)
	before := date.Add(-24 * time.Hour)
	after := date.Add(24 * time.Hour)
	terraCut := time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC)

	seedAt := func(model string, at time.Time) (Pricing, bool) {
		e := NewEngine(config.IntelligenceConfig{}, withClock(func() time.Time { return now }))
		return e.Table().LookupAt(model, at)
	}
	opusSeed, ok := seedAt("claude-opus-4-1", before)
	if !ok || opusSeed.Input == 0 {
		t.Fatalf("fixture: the seed prices claude-opus-4-1 (%+v ok=%v)", opusSeed, ok)
	}
	terraPre, _ := seedAt("gpt-5.6-terra", terraCut.Add(-time.Hour))
	terraPost, _ := seedAt("gpt-5.6-terra", terraCut.Add(time.Hour))
	if terraPre == terraPost {
		t.Fatalf("fixture: gpt-5.6-terra must carry a seed timeline across %s", terraCut)
	}

	type probe struct {
		at      time.Time
		wantOK  bool
		wantIn  float64 // checked when wantOK
		wantRef *Pricing
	}
	cases := []struct {
		name          string
		rows          []OrgPrice
		authoritative bool
		model         string
		probes        []probe
	}{
		{
			name:  "single dated row over a seeded model: seed before, org from the date",
			rows:  []OrgPrice{datedRow("claude-opus-4-1", "2026-09-16", 5, 25)},
			model: "claude-opus-4-1",
			probes: []probe{
				{at: before, wantOK: true, wantIn: opusSeed.Input},
				{at: date, wantOK: true, wantIn: 5},
				{at: after, wantOK: true, wantIn: 5},
			},
		},
		{
			name:          "the same on an authoritative (managed) node",
			rows:          []OrgPrice{datedRow("claude-opus-4-1", "2026-09-16", 5, 25)},
			authoritative: true,
			model:         "claude-opus-4-1",
			probes: []probe{
				{at: before, wantOK: true, wantIn: opusSeed.Input},
				{at: after, wantOK: true, wantIn: 5},
			},
		},
		{
			name:  "single dated row for a model the seed never priced: no price before",
			rows:  []OrgPrice{datedRow("zz-new-model", "2026-09-16", 3, 0)},
			model: "zz-new-model",
			probes: []probe{
				{at: before, wantOK: false},
				{at: date, wantOK: true, wantIn: 3},
			},
		},
		{
			name:  "the seed's own dated history holds before the org's first date",
			rows:  []OrgPrice{datedRow("gpt-5.6-terra", "2026-09-01", 7, 70)},
			model: "gpt-5.6-terra",
			probes: []probe{
				{at: terraCut.Add(-time.Hour), wantOK: true, wantRef: &terraPre},
				{at: terraCut.Add(time.Hour), wantOK: true, wantRef: &terraPost},
				{at: time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC), wantOK: true, wantIn: 7},
			},
		},
		{
			name: "two dated rows: each prices its own period, the seed before both",
			rows: []OrgPrice{
				datedRow("claude-opus-4-1", "2026-08-01", 4, 20),
				datedRow("claude-opus-4-1", "2026-09-16", 5, 25),
			},
			model: "claude-opus-4-1",
			probes: []probe{
				{at: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), wantOK: true, wantIn: opusSeed.Input},
				{at: before, wantOK: true, wantIn: 4},
				{at: after, wantOK: true, wantIn: 5},
			},
		},
		{
			name:  "an undated row is flat across all of history, as before",
			rows:  []OrgPrice{datedRow("claude-opus-4-1", "", 5, 25)},
			model: "claude-opus-4-1",
			probes: []probe{
				{at: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC), wantOK: true, wantIn: 5},
				{at: after, wantOK: true, wantIn: 5},
			},
		},
		{
			name:  "an undated row for an unseeded model prices all of history",
			rows:  []OrgPrice{datedRow("zz-new-model", "", 3, 0)},
			model: "zz-new-model",
			probes: []probe{
				{at: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC), wantOK: true, wantIn: 3},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := NewEngine(config.IntelligenceConfig{}, withClock(func() time.Time { return now }))
			e.SetOrgRows(tc.rows, 1, tc.authoritative)
			for _, p := range tc.probes {
				got, _, ok := e.Table().LookupWithSourceAt(tc.model, p.at)
				if ok != p.wantOK {
					t.Fatalf("%s at %s: ok=%v (%+v), want ok=%v", tc.model, p.at.Format(time.RFC3339), ok, got, p.wantOK)
				}
				if !ok {
					continue
				}
				if p.wantRef != nil {
					if got.Input != p.wantRef.Input || got.CacheCreation != p.wantRef.CacheCreation {
						t.Fatalf("%s at %s = %+v, want the seed's own period %+v", tc.model, p.at.Format(time.RFC3339), got, *p.wantRef)
					}
					continue
				}
				if got.Input != p.wantIn {
					t.Fatalf("%s at %s: input %v, want %v", tc.model, p.at.Format(time.RFC3339), got.Input, p.wantIn)
				}
			}
			// Capture-time: the flat (current) rate is the org's in-force row,
			// and it agrees with LookupAt(now).
			flat, _ := e.Table().Lookup(tc.model)
			atNow, _ := e.Table().LookupAt(tc.model, now)
			if flat.Input != atNow.Input {
				t.Fatalf("Lookup %v != LookupAt(now) %v", flat.Input, atNow.Input)
			}
			if w := e.PricingWarnings(); len(w) != 0 {
				t.Fatalf("warnings = %v", w)
			}
		})
	}
}

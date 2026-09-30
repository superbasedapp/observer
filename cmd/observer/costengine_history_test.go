package main

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/pricingfeed"
)

// THE NODE HALF OF THE PRICE-HISTORY CHAIN (lane R2-PRICING-2, directive (e)).
//
// The signed, history-bearing feed Tokenomics migration 0028 produces
// (internal/pricingfeed/testdata/golden-envelope-history-v1.json, byte-pinned
// against the publisher in both modules) is verified, projected through the
// SAME functions the daemon uses (feedRowsOf / orgPriceRowsOf), composed into a
// real engine, and priced before, at and after every boundary.

func loadHistoryGolden(t *testing.T) pricingfeed.Envelope {
	t.Helper()
	raw, err := os.ReadFile("../../internal/pricingfeed/testdata/golden-envelope-history-v1.json")
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var env pricingfeed.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("decode golden: %v", err)
	}
	pub, err := os.ReadFile("../../internal/pricingfeed/testdata/golden-envelope-history-v1.pub")
	if err != nil {
		t.Fatalf("read pub: %v", err)
	}
	keys, err := pricingfeed.NewKeySet(map[string]string{env.KeyID: strings.TrimSpace(string(pub))})
	if err != nil {
		t.Fatal(err)
	}
	if err := pricingfeed.Verify(env, keys); err != nil {
		t.Fatalf("Verify(golden history) = %v", err)
	}
	return env
}

// probes: every boundary of a timeline, a nanosecond either side, a weekday
// peak-window instant after it, and the far past.
func historyProbes(tl []cost.DatedPricing) []time.Time {
	out := []time.Time{time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)}
	for _, e := range tl {
		if e.EffectiveFrom.IsZero() {
			continue
		}
		b := e.EffectiveFrom
		out = append(out, b.Add(-time.Nanosecond), b, b.Add(time.Nanosecond))
		d := time.Date(b.Year(), b.Month(), b.Day(), 2, 0, 0, 0, time.UTC)
		for d.Weekday() != time.Monday || d.Before(b) {
			d = d.Add(24 * time.Hour)
		}
		out = append(out, d)
	}
	return out
}

func sameRate(a, b cost.Pricing) bool {
	ap, bp := a.Peak, b.Peak
	a.Peak, b.Peak = nil, nil
	return a == b && reflect.DeepEqual(ap, bp)
}

// asOrgRail re-expresses the feed as the ORG server would hand it on after
// importing it (one org_model_prices row per period, source=imported, each
// projected with the org rail's encoders): the top-level row plus its History
// of plain policy rows. It mirrors internal/orgserver's feedRowPricings ->
// pricingPolicyRowOf for exactly the fields a feed period carries; the org
// server's own tests pin that path against its store.
func asOrgRail(env pricingfeed.Envelope) []orgcontract.PricingPolicyRow {
	wire := func(r pricingfeed.Row) orgcontract.PricingPolicyRow {
		w := r.PricingPolicyRow
		w.History = nil
		w.Source = "imported"
		// Imported rows store NULL where the feed quoted nothing; the org rail
		// spells a NULL threshold / peak with its "unquoted" markers.
		w.SetOrgThreshold(r.LongContextThreshold)
		if r.Peak == nil {
			w.SetOrgPeak(nil)
		}
		return w
	}
	var out []orgcontract.PricingPolicyRow
	for _, r := range env.Rows {
		top := wire(r)
		if len(r.History) >= 2 {
			for _, h := range r.History {
				top.History = append(top.History, wire(h))
			}
		}
		out = append(out, top)
	}
	return out
}

// TestHistoryFeedPricesLikeTheHandTable: a standalone node taking the
// history-bearing feed prices EVERY dated.go model at every probe exactly as
// the hand-written table does (the feed now carries that history, so a feed
// row no longer erases it), on BOTH rails. Before this lane a feed or org row
// for deepseek-v4-flash deleted its timeline and repriced all of history at
// today's rate.
func TestHistoryFeedPricesLikeTheHandTable(t *testing.T) {
	env := loadHistoryGolden(t)
	seed := cost.NewEngine(config.IntelligenceConfig{})
	feed := cost.NewEngine(config.IntelligenceConfig{})
	feed.SetOrgRows(feedRowsOf(env.Rows), env.FeedVersion, false)
	org := cost.NewEngine(config.IntelligenceConfig{})
	org.SetOrgRows(orgPriceRowsOf(asOrgRail(env)), 1, true)

	for name, e := range map[string]*cost.Engine{"feed": feed, "org": org} {
		if w := e.PricingWarnings(); len(w) != 0 {
			t.Fatalf("%s rail warnings: %v", name, w)
		}
	}
	dated := cost.BakedInDatedDefaults()
	if len(dated) == 0 {
		t.Fatal("no hand timelines to compare against")
	}
	for key, tl := range dated {
		for _, at := range historyProbes(tl) {
			want, wok := seed.LookupAt(key, at)
			for name, e := range map[string]*cost.Engine{"feed": feed, "org": org} {
				got, ok := e.LookupAt(key, at)
				if ok != wok || !sameRate(got, want) {
					t.Errorf("%s rail %s at %s = %+v, hand table %+v", name, key, at.Format(time.RFC3339Nano), got, want)
				}
			}
		}
	}
}

// TestHistoryFeedDatedChangesBeyondTheHandTable: the dated changes that live
// only in the price database reach the engine through the feed.
func TestHistoryFeedDatedChangesBeyondTheHandTable(t *testing.T) {
	env := loadHistoryGolden(t)
	e := cost.NewEngine(config.IntelligenceConfig{})
	e.SetOrgRows(feedRowsOf(env.Rows), env.FeedVersion, false)
	ns := time.Nanosecond
	promo := time.Date(2026, 9, 7, 15, 0, 0, 0, time.UTC)
	promoEnd := time.Date(2026, 9, 9, 16, 0, 0, 0, time.UTC)
	cut36 := time.Date(2026, 8, 15, 0, 0, 0, 0, time.UTC)
	jan27 := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		model  string
		at     time.Time
		wantIn float64
	}{
		{"glm-5.3-flash", promo.Add(-ns), 0.15},
		{"glm-5.3-flash", promo, 0.075},
		{"glm-5.3-flash", promoEnd.Add(-ns), 0.075},
		{"glm-5.3-flash", promoEnd, 0.15},
		{"gemini-3.6-flash", cut36.Add(-ns), 1.50},
		{"gemini-3.6-flash", cut36, 0.75},
		{"gemini-3.6-flash", jan27.Add(-ns), 0.75},
		{"gemini-3.6-flash", jan27, 1.50},
		{"gemini-3.7-flash", jan27.Add(-ns), 0.75},
		{"gemini-3.7-flash", jan27, 1.50},
		{"gemini-3.8-flash", jan27, 1.50},
	}
	for _, tc := range cases {
		got, ok := e.LookupAt(tc.model, tc.at)
		if !ok || got.Input != tc.wantIn {
			t.Errorf("%s at %s: input %v (ok=%v), want %v", tc.model, tc.at.Format(time.RFC3339Nano), got.Input, ok, tc.wantIn)
		}
	}
}

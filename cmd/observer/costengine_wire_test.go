package main

import (
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestOrgPriceRowsOfPeak pins the wire -> node engine leg of the Phase 2 peak
// translation (peak-off-peak plan §R2/P2-B): orgPriceRowsOf must carry a
// wire row's Peak field across as a plain field copy, base rates AND
// schedule windows both, with nil translating to nil.
func TestOrgPriceRowsOfPeak(t *testing.T) {
	t.Parallel()

	wireRow := orgcontract.PricingPolicyRow{
		Model:         "deepseek-v4-pro",
		InputPerMTok:  orgcontract.Rate(4),
		OutputPerMTok: orgcontract.Rate(8),
		EffectiveFrom: "2026-01-01",
		Peak: &orgcontract.PeakRates{
			RateSet: orgcontract.RateSet{
				Input:                8,
				Output:               16,
				CacheRead:            1,
				CacheCreation:        2,
				CacheCreation1h:      3,
				LongContextThreshold: 128000,
				LongContextInput:     12,
				LongContextOutput:    24,
			},
			Schedule: orgcontract.PeakSchedule{Windows: []orgcontract.PeakWindow{
				{Days: []time.Weekday{time.Monday, time.Wednesday, time.Friday}, StartUTC: "13:00", EndUTC: "21:00"},
			}},
		},
	}
	noPeakRow := orgcontract.PricingPolicyRow{Model: "no-peak-model", InputPerMTok: orgcontract.Rate(1), OutputPerMTok: orgcontract.Rate(2)}

	out := orgPriceRowsOf([]orgcontract.PricingPolicyRow{wireRow, noPeakRow})
	if len(out) != 2 {
		t.Fatalf("orgPriceRowsOf returned %d rows, want 2", len(out))
	}

	got := out[0]
	if got.Model != "deepseek-v4-pro" {
		t.Fatalf("row order changed: got model %q first", got.Model)
	}
	if got.Peak == nil {
		t.Fatal("Peak was dropped by orgPriceRowsOf")
	}
	if got.Peak.Input != 8 || got.Peak.Output != 16 || got.Peak.CacheRead != 1 ||
		got.Peak.CacheCreation != 2 || got.Peak.CacheCreation1h != 3 {
		t.Errorf("peak base rates = %+v, want the wire's exact values", got.Peak.RateSet)
	}
	if got.Peak.LongContextThreshold != 128000 || got.Peak.LongContextInput != 12 || got.Peak.LongContextOutput != 24 {
		t.Errorf("peak long-context rates = %+v", got.Peak.RateSet)
	}
	if len(got.Peak.Schedule.Windows) != 1 {
		t.Fatalf("schedule windows = %d, want 1", len(got.Peak.Schedule.Windows))
	}
	w := got.Peak.Schedule.Windows[0]
	if w.StartUTC != "13:00" || w.EndUTC != "21:00" || len(w.Days) != 3 {
		t.Errorf("schedule window = %+v", w)
	}
	if w.Days[0] != time.Monday || w.Days[1] != time.Wednesday || w.Days[2] != time.Friday {
		t.Errorf("schedule days = %v, want Mon/Wed/Fri in order", w.Days)
	}

	if out[1].Peak != nil {
		t.Errorf("a wire row with no Peak produced a non-nil cost.OrgPrice.Peak: %+v", out[1].Peak)
	}
}

// TestOrgPriceRowsOfPeakWireRoundTrip pins the full wire -> node round trip
// end to end: composing the translated OrgPrice onto a seed-priced model via
// SetOrgRows must yield a Table lookup whose Peak carries the same rates and
// schedule the wire document named.
func TestOrgPriceRowsOfPeakWireRoundTrip(t *testing.T) {
	t.Parallel()
	const model = "acme-peak-model"
	wireRow := orgcontract.PricingPolicyRow{
		Model:         model,
		InputPerMTok:  orgcontract.Rate(1),
		OutputPerMTok: orgcontract.Rate(2),
		Peak: &orgcontract.PeakRates{
			RateSet: orgcontract.RateSet{Input: 2, Output: 4},
			Schedule: orgcontract.PeakSchedule{Windows: []orgcontract.PeakWindow{
				{Days: []time.Weekday{time.Sunday}, StartUTC: "00:00", EndUTC: "23:59"},
			}},
		},
	}

	e := cost.NewEngine(config.IntelligenceConfig{})
	e.SetOrgRows(orgPriceRowsOf([]orgcontract.PricingPolicyRow{wireRow}), 1, false)

	p, ok := e.Lookup(model)
	if !ok {
		t.Fatal("lookup missed the org-priced model")
	}
	if p.Peak == nil {
		t.Fatal("the composed table lost the peak variant")
	}
	if p.Peak.Input != 2 || p.Peak.Output != 4 {
		t.Errorf("composed peak rates = %+v, want input 2 output 4", p.Peak.RateSet)
	}
	if len(p.Peak.Schedule.Windows) != 1 || p.Peak.Schedule.Windows[0].StartUTC != "00:00" {
		t.Errorf("composed peak schedule = %+v", p.Peak.Schedule)
	}
}

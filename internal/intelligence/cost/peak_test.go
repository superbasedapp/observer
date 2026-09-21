package cost

import (
	"math"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// approxEqUSD reports whether two USD amounts are equal within a tight
// float epsilon — the pricing math is exact rational arithmetic, so the
// only slack needed is IEEE-754 rounding.
func approxEqUSD(a, b float64) bool {
	return math.Abs(a-b) < 1e-9
}

// Reference instants. 2026-08-17 is a Monday (a peak weekday) and is
// after the DeepSeek 2026-08-16T16:00Z off-peak/peak cutover, so the v4-pro
// timeline resolves to the current (off-peak base) period at both.
var (
	// 02:00 UTC Monday → inside the 01:00-04:00 peak window.
	peakInstant = time.Date(2026, 8, 17, 2, 0, 0, 0, time.UTC)
	// 05:00 UTC Monday → the gap between the two peak windows → off-peak.
	offPeakInstant = time.Date(2026, 8, 17, 5, 0, 0, 0, time.UTC)
)

// TestPeakScheduleContains walks the DeepSeek schedule boundary matrix
// (half-open windows, weekday gating) plus the empty-schedule and
// malformed-window edge cases.
func TestPeakScheduleContains(t *testing.T) {
	// 2026-08-17 = Monday (peak weekday), 2026-08-15 = Saturday, 2026-08-16 = Sunday.
	mon := func(h, m, s int) time.Time { return time.Date(2026, 8, 17, h, m, s, 0, time.UTC) }
	sat := func(h, m int) time.Time { return time.Date(2026, 8, 15, h, m, 0, 0, time.UTC) }
	sun := func(h, m int) time.Time { return time.Date(2026, 8, 16, h, m, 0, 0, time.UTC) }

	for _, tc := range []struct {
		name string
		at   time.Time
		want bool
	}{
		{"Mon 00:59:59 before window1", mon(0, 59, 59), false},
		{"Mon 01:00:00 window1 start inclusive", mon(1, 0, 0), true},
		{"Mon 03:59:59 window1 last second", mon(3, 59, 59), true},
		{"Mon 04:00:00 window1 end exclusive", mon(4, 0, 0), false},
		{"Mon 05:00:00 gap between windows", mon(5, 0, 0), false},
		{"Mon 06:00:00 window2 start inclusive", mon(6, 0, 0), true},
		{"Mon 10:00:00 window2 end exclusive", mon(10, 0, 0), false},
		{"Sat 02:00 weekend not a peak day", sat(2, 0), false},
		{"Sun 07:00 weekend not a peak day", sun(7, 0), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := deepseekPeakSchedule.Contains(tc.at); got != tc.want {
				t.Fatalf("Contains(%s) = %v, want %v", tc.at.Format(time.RFC3339), got, tc.want)
			}
		})
	}

	// Empty schedule is never peak.
	if (PeakSchedule{}).Contains(peakInstant) {
		t.Fatalf("empty PeakSchedule.Contains should be false")
	}

	// A malformed window (bad HH:MM or Start>=End) is SKIPPED, never a
	// panic, and never a match — pricing does not fail closed.
	malformedOnly := PeakSchedule{Windows: []PeakWindow{
		{Days: []time.Weekday{time.Monday}, StartUTC: "nope", EndUTC: "04:00"},
		{Days: []time.Weekday{time.Monday}, StartUTC: "05:00", EndUTC: "03:00"}, // Start >= End
		{Days: []time.Weekday{time.Monday}, StartUTC: "25:99", EndUTC: "04:00"}, // out of range
	}}
	if malformedOnly.Contains(time.Date(2026, 8, 17, 2, 0, 0, 0, time.UTC)) {
		t.Fatalf("a schedule of only malformed windows must never match")
	}

	// A valid window alongside malformed ones still matches — one bad row
	// does not disable the rest.
	mixed := PeakSchedule{Windows: []PeakWindow{
		{Days: []time.Weekday{time.Monday}, StartUTC: "bad", EndUTC: "bad"},
		{Days: []time.Weekday{time.Monday}, StartUTC: "01:00", EndUTC: "04:00"},
	}}
	if !mixed.Contains(time.Date(2026, 8, 17, 2, 0, 0, 0, time.UTC)) {
		t.Fatalf("a valid window must still match when a malformed one precedes it")
	}
}

// TestPeakAdjustedV4Pro asserts that deepseek-v4-pro resolves to the
// off-peak base rate outside a peak window and to EXACTLY 2× inside one,
// and that a computed cost at peak is exactly 2× the same bundle off-peak.
func TestPeakAdjustedV4Pro(t *testing.T) {
	e := NewEngine(config.IntelligenceConfig{})

	off, ok := e.LookupAt("deepseek-v4-pro", offPeakInstant)
	if !ok {
		t.Fatalf("LookupAt(deepseek-v4-pro, off-peak): ok=false")
	}
	if off.Input != 0.66 || off.Output != 1.98 || off.CacheRead != 0.022 {
		t.Fatalf("off-peak rates = %+v, want input=0.66 output=1.98 cacheRead=0.022", off)
	}

	peak, ok := e.LookupAt("deepseek-v4-pro", peakInstant)
	if !ok {
		t.Fatalf("LookupAt(deepseek-v4-pro, peak): ok=false")
	}
	if peak.Input != 1.32 || peak.Output != 3.96 || peak.CacheRead != 0.044 {
		t.Fatalf("peak rates = %+v, want input=1.32 output=3.96 cacheRead=0.044 (2x off-peak)", peak)
	}

	// A concrete bundle: 1M each of input/output/cache-read so the per-1M
	// rates read straight through as dollars.
	bundle := TokenBundle{Input: 1_000_000, Output: 1_000_000, CacheRead: 1_000_000}
	offCost, ok := e.ComputeAt("deepseek-v4-pro", bundle, offPeakInstant)
	if !ok {
		t.Fatalf("ComputeAt off-peak: ok=false")
	}
	peakCost, ok := e.ComputeAt("deepseek-v4-pro", bundle, peakInstant)
	if !ok {
		t.Fatalf("ComputeAt peak: ok=false")
	}
	if want := 0.66 + 1.98 + 0.022; !approxEqUSD(offCost, want) {
		t.Fatalf("off-peak cost = %v, want %v", offCost, want)
	}
	if !approxEqUSD(peakCost, 2*offCost) {
		t.Fatalf("peak cost = %v, want exactly 2x off-peak (%v)", peakCost, 2*offCost)
	}
}

// TestPeakBlindOnZeroAt pins the display invariant: a non-At (zero-`at`)
// lookup returns the OFF-PEAK base rate AND still exposes .Peak, so a
// surface can render the peak variant without re-pricing at an instant.
func TestPeakBlindOnZeroAt(t *testing.T) {
	e := NewEngine(config.IntelligenceConfig{})
	p, ok := e.Lookup("deepseek-v4-pro")
	if !ok {
		t.Fatalf("Lookup(deepseek-v4-pro): ok=false")
	}
	if p.Input != 0.66 || p.Output != 1.98 || p.CacheRead != 0.022 {
		t.Fatalf("non-At lookup = %+v, want the OFF-PEAK base rate", p)
	}
	if p.Peak == nil {
		t.Fatalf("non-At lookup dropped .Peak — display surfaces read the peak variant off a plain lookup")
	}
	if p.Peak.Input != 1.32 || p.Peak.Output != 3.96 || p.Peak.CacheRead != 0.044 {
		t.Fatalf(".Peak rate set = %+v, want input=1.32 output=3.96 cacheRead=0.044", p.Peak.RateSet)
	}
}

// TestPeakComposesWithLCAndFast drives the full peak × long-context × fast
// selector matrix over a synthetic model whose peak variant carries its
// OWN distinct long-context sub-tier, and confirms the flat web-search fee
// is scaled by neither peak nor fast.
func TestPeakComposesWithLCAndFast(t *testing.T) {
	const model = "synth-peak-model"

	synthPeak := &PeakRates{
		RateSet: RateSet{
			Input: 100, Output: 400, CacheRead: 10,
			LongContextThreshold: 1000,
			LongContextInput:     200, LongContextOutput: 800, LongContextCacheRead: 20,
		},
		Schedule: PeakSchedule{Windows: []PeakWindow{
			{Days: []time.Weekday{time.Monday}, StartUTC: "01:00", EndUTC: "04:00"},
		}},
	}
	base := Pricing{
		Input: 10, Output: 40, CacheRead: 1,
		LongContextThreshold: 1000,
		LongContextInput:     20, LongContextOutput: 80, LongContextCacheRead: 2,
		WebSearchPerRequest: 0.5,
		FastMultiplier:      3,
		Peak:                synthPeak,
	}

	tbl := NewTable()
	tbl.Merge(map[string]Pricing{model: base})

	// prompt window = Input + CacheRead + CacheCreation. Small stays below
	// the 1000 LC threshold; large exceeds it. Both carry 2 web-search
	// calls so the flat fee ($0.50 each = $1.00) is visible in every case.
	small := TokenBundle{Input: 100, Output: 50, WebSearchRequests: 2}
	large := TokenBundle{Input: 2000, Output: 50, WebSearchRequests: 2}
	const toolFee = 1.0 // 2 × 0.50, never scaled

	for _, tc := range []struct {
		name    string
		at      time.Time
		bundle  TokenBundle
		fast    bool
		wantAI  float64
		wantTot float64
	}{
		// Off-peak, base tier: input 100×10, output 50×40.
		{"offpeak/base", offPeakInstant, small, false, 0.001 + 0.002, 0.001 + 0.002 + toolFee},
		{"offpeak/base/fast", offPeakInstant, small, true, 3 * (0.001 + 0.002), 3*(0.001+0.002) + toolFee},
		// Off-peak, LC tier: input 2000×20, output 50×80.
		{"offpeak/lc", offPeakInstant, large, false, 0.04 + 0.004, 0.04 + 0.004 + toolFee},
		{"offpeak/lc/fast", offPeakInstant, large, true, 3 * (0.04 + 0.004), 3*(0.04+0.004) + toolFee},
		// Peak, base tier: input 100×100, output 50×400.
		{"peak/base", peakInstant, small, false, 0.01 + 0.02, 0.01 + 0.02 + toolFee},
		{"peak/base/fast", peakInstant, small, true, 3 * (0.01 + 0.02), 3*(0.01+0.02) + toolFee},
		// Peak, LC tier: input 2000×200, output 50×800 (peak's own LC tier).
		{"peak/lc", peakInstant, large, false, 0.4 + 0.04, 0.4 + 0.04 + toolFee},
		{"peak/lc/fast", peakInstant, large, true, 3 * (0.4 + 0.04), 3*(0.4+0.04) + toolFee},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, ok := tbl.LookupAt(model, tc.at)
			if !ok {
				t.Fatalf("LookupAt(%q, %s): ok=false", model, tc.at.Format(time.RFC3339))
			}
			b := tc.bundle
			b.Fast = tc.fast
			bd := ComputeBreakdown(p, b)
			if !approxEqUSD(bd.AICost, tc.wantAI) {
				t.Fatalf("AICost = %v, want %v", bd.AICost, tc.wantAI)
			}
			if !approxEqUSD(bd.Total, tc.wantTot) {
				t.Fatalf("Total = %v, want %v", bd.Total, tc.wantTot)
			}
			// The flat web-search fee is never scaled by peak OR fast.
			if !approxEqUSD(bd.ToolCost, toolFee) {
				t.Fatalf("ToolCost = %v, want %v (web-search fee is flat)", bd.ToolCost, toolFee)
			}
		})
	}
}

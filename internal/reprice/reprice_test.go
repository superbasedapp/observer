package reprice

import (
	"math"
	"testing"
	"time"
)

func f(v float64) *float64 { return &v }

// boundary is a dated price change: $1 per 1M input tokens before it, $3 from
// it on. Model "fast-model" carries a fast tier; "free-model" is quoted free;
// "nan-model" is a misbehaving pricer; any other model has no price.
var boundary = time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)

func testPrice(model string, at time.Time, t Tokens) Quote {
	rate := 1.0
	if !at.Before(boundary) {
		rate = 3.0
	}
	switch model {
	case "m":
		return Quote{USD: float64(t.Input) * rate / 1e6, OK: true, Source: "feed"}
	case "fast-model":
		mult := 1.0
		if t.Fast {
			mult = 2
		}
		return Quote{USD: float64(t.Input) * rate * mult / 1e6, OK: true, FastTier: true, Source: "org"}
	case "free-model":
		return Quote{USD: 0, OK: true, Source: "org"}
	case "nan-model":
		return Quote{USD: math.NaN(), OK: true}
	case "neg-model":
		return Quote{USD: -1, OK: true}
	}
	return Quote{}
}

// TestSkipRules is the rule table, one case per row of skipRules plus the two
// update outcomes. Adding a rule adds a case here.
func TestSkipRules(t *testing.T) {
	before := "2026-09-10T12:00:00Z"
	after := "2026-09-20T12:00:00.123456789Z"
	mil := Tokens{Input: 1_000_000}
	cases := []struct {
		name   string
		row    Row
		action Action
		reason Reason
		newUSD *float64
	}{
		{"source reported is never overwritten", Row{Model: "m", Timestamp: after, Tokens: mil, Stored: f(9), SourceReported: true}, ActionSkip, ReasonSourceReported, nil},
		{"source reported wins even over a missing model", Row{Model: "", Timestamp: after, Stored: f(9), SourceReported: true}, ActionSkip, ReasonSourceReported, nil},
		{"no model", Row{Model: "  ", Timestamp: after, Tokens: mil, Stored: f(1)}, ActionSkip, ReasonNoModel, nil},
		{"unparseable timestamp is never priced at today's rate", Row{Model: "m", Timestamp: "yesterday", Tokens: mil, Stored: f(1)}, ActionSkip, ReasonNoTimestamp, nil},
		{"no price keeps a captured price", Row{Model: "unknown", Timestamp: after, Tokens: mil, Stored: f(1)}, ActionSkip, ReasonNoPrice, nil},
		{"no price keeps an unpriced row unknown (never $0)", Row{Model: "unknown", Timestamp: after, Tokens: mil}, ActionSkip, ReasonNoPrice, nil},
		{"NaN price is discarded", Row{Model: "nan-model", Timestamp: after, Tokens: mil, Stored: f(1)}, ActionSkip, ReasonInvalidPrice, nil},
		{"negative price is discarded", Row{Model: "neg-model", Timestamp: after, Tokens: mil, Stored: f(1)}, ActionSkip, ReasonInvalidPrice, nil},
		{"fast tier unknown on a fast-tier model", Row{Model: "fast-model", Timestamp: after, Tokens: mil, Stored: f(6), FastUnknown: true}, ActionSkip, ReasonFastUnknown, nil},
		{"unchanged", Row{Model: "m", Timestamp: after, Tokens: mil, Stored: f(3)}, ActionSkip, ReasonUnchanged, nil},
		{"repriced at the rate in force after the boundary", Row{Model: "m", Timestamp: after, Tokens: mil, Stored: f(1)}, ActionUpdate, ReasonRepriced, f(3)},
		{"repriced at the rate in force before the boundary", Row{Model: "m", Timestamp: before, Tokens: mil, Stored: f(3)}, ActionUpdate, ReasonRepriced, f(1)},
		{"unpriced row filled", Row{Model: "m", Timestamp: before, Tokens: mil}, ActionUpdate, ReasonFilled, f(1)},
		{"known fast flag prices the premium", Row{Model: "fast-model", Timestamp: after, Tokens: Tokens{Input: 1_000_000, Fast: true}, Stored: f(3)}, ActionUpdate, ReasonRepriced, f(6)},
		{"fast-unknown row of a model with no fast tier is priced", Row{Model: "m", Timestamp: after, Tokens: mil, Stored: f(1), FastUnknown: true}, ActionUpdate, ReasonRepriced, f(3)},
		{"a quoted free rate is a price, not a miss", Row{Model: "free-model", Timestamp: after, Tokens: mil, Stored: f(2)}, ActionUpdate, ReasonRepriced, f(0)},
		{"sqlite datetime form parses", Row{Model: "m", Timestamp: "2026-09-10 12:00:00", Tokens: mil, Stored: f(3)}, ActionUpdate, ReasonRepriced, f(1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := Evaluate(tc.row, testPrice)
			if d.Action != tc.action || d.Reason != tc.reason {
				t.Fatalf("got %s/%s, want %s/%s", d.Action, d.Reason, tc.action, tc.reason)
			}
			if tc.newUSD == nil {
				if d.New != nil {
					t.Fatalf("skip carried New=%v", *d.New)
				}
				return
			}
			if d.New == nil || math.Abs(*d.New-*tc.newUSD) > 1e-12 {
				t.Fatalf("New=%v, want %v", d.New, *tc.newUSD)
			}
		})
	}
}

// TestEverySkipRuleHasACase keeps the table test honest: a rule added to
// skipRules without a case in TestSkipRules fails here.
func TestEverySkipRuleHasACase(t *testing.T) {
	covered := map[Reason]bool{
		ReasonSourceReported: true, ReasonNoModel: true, ReasonNoTimestamp: true, ReasonNoPrice: true,
		ReasonInvalidPrice: true, ReasonFastUnknown: true, ReasonUnchanged: true,
	}
	for _, r := range skipRules {
		if !covered[r.reason] {
			t.Errorf("skip rule %q has no TestSkipRules case", r.reason)
		}
	}
	if len(skipRules) != len(covered) {
		t.Errorf("skipRules has %d rules, the case set %d", len(skipRules), len(covered))
	}
}

// TestSourceReportedCostsNoLookup: a source-reported row must not even consult
// the pricer (the rule order puts it first).
func TestSourceReportedCostsNoLookup(t *testing.T) {
	called := false
	price := func(string, time.Time, Tokens) Quote { called = true; return Quote{OK: true} }
	Evaluate(Row{Model: "m", Timestamp: "2026-09-20T00:00:00Z", SourceReported: true}, price)
	if called {
		t.Fatal("pricer consulted for a source-reported row")
	}
}

func TestPlannerSummary(t *testing.T) {
	p := NewPlanner(testPrice)
	mil := Tokens{Input: 1_000_000}
	p.Add(Row{Table: "api_turns", ID: 1, Model: "m", Timestamp: "2026-09-20T00:00:00Z", Tokens: mil, Stored: f(1)}) // +2
	p.Add(Row{Table: "api_turns", ID: 2, Model: "m", Timestamp: "2026-09-10T00:00:00Z", Tokens: mil})               // filled +1
	p.Add(Row{Table: "api_turns", ID: 3, Model: "m", Timestamp: "2026-09-20T00:00:00Z", Tokens: mil, Stored: f(3)}) // unchanged
	p.Add(Row{Table: "summary_calls", ID: 9, Model: "x", Timestamp: "2026-09-20T00:00:00Z", Tokens: mil})           // no price
	s := p.Summary()
	if s.Scanned != 4 || s.Changed != 2 || s.Filled != 1 {
		t.Fatalf("scanned/changed/filled = %d/%d/%d", s.Scanned, s.Changed, s.Filled)
	}
	if math.Abs(s.DeltaUSD()-3) > 1e-12 || math.Abs(s.OldUSD-1) > 1e-12 || math.Abs(s.NewUSD-4) > 1e-12 {
		t.Fatalf("old/new/delta = %v/%v/%v", s.OldUSD, s.NewUSD, s.DeltaUSD())
	}
	if s.Skipped[ReasonUnchanged] != 1 || s.Skipped[ReasonNoPrice] != 1 {
		t.Fatalf("skipped = %v", s.Skipped)
	}
	if len(s.Tables) != 2 || s.Tables[0].Table != "api_turns" || s.Tables[0].Changed != 2 || s.Tables[1].Scanned != 1 {
		t.Fatalf("tables = %+v", s.Tables)
	}
	if len(s.Models) != 1 || s.Models[0].Model != "m" || s.Models[0].Changed != 2 {
		t.Fatalf("models = %+v", s.Models)
	}
	if got := len(p.Updates()); got != 2 {
		t.Fatalf("updates = %d", got)
	}
}

func TestRevertRules(t *testing.T) {
	const run = 7
	ch := Change{Table: "api_turns", ID: 1, Old: f(1), New: f(3), PrevRun: 0}
	cases := []struct {
		name    string
		change  Change
		cur     Current
		action  Action
		reason  Reason
		restore *float64
		prevRun int64
	}{
		{"row gone", ch, Current{Found: false}, ActionSkip, ReasonRowGone, nil, 0},
		{"a later run re-priced it", ch, Current{Found: true, Cost: f(4), Run: 8}, ActionSkip, ReasonLaterRun, nil, 0},
		{"a capture path rewrote it", ch, Current{Found: true, Cost: f(5), Run: run}, ActionSkip, ReasonChangedSince, nil, 0},
		{"a re-send rewrote it and cleared the marker", ch, Current{Found: true, Cost: f(5)}, ActionSkip, ReasonChangedSince, nil, 0},
		{"a re-send cleared the marker at the same cost", ch, Current{Found: true, Cost: f(3)}, ActionSkip, ReasonChangedSince, nil, 0},
		{"restored to the captured cost", ch, Current{Found: true, Cost: f(3), Run: run}, ActionUpdate, ReasonRestored, f(1), 0},
		{"restored to an earlier run's cost", Change{Table: "api_turns", ID: 1, Old: f(2), New: f(3), PrevRun: 5}, Current{Found: true, Cost: f(3), Run: run}, ActionUpdate, ReasonRestored, f(2), 5},
		{"restored to unpriced", Change{Table: "api_turns", ID: 1, Old: nil, New: f(3)}, Current{Found: true, Cost: f(3), Run: run}, ActionUpdate, ReasonRestored, nil, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := EvaluateRevert(tc.change, tc.cur, run)
			if d.Action != tc.action || d.Reason != tc.reason {
				t.Fatalf("got %s/%s, want %s/%s", d.Action, d.Reason, tc.action, tc.reason)
			}
			if d.Action != ActionUpdate {
				return
			}
			if (d.Restore == nil) != (tc.restore == nil) || (d.Restore != nil && *d.Restore != *tc.restore) {
				t.Fatalf("restore = %v, want %v", d.Restore, tc.restore)
			}
			if d.Run != tc.prevRun {
				t.Fatalf("run = %d, want %d", d.Run, tc.prevRun)
			}
		})
	}
	if len(revertRules) != 3 {
		t.Fatalf("revertRules grew to %d: add a TestRevertRules case", len(revertRules))
	}
}

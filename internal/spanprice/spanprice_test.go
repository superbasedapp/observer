package spanprice

import (
	"testing"
	"time"
)

func i64(v int64) *int64     { return &v }
func f64(v float64) *float64 { return &v }

// book prices "m-priced" at $1/1M input, $2/1M output, $0.1/1M cache read.
func book(model string, b Bundle, _ time.Time) (Breakdown, bool) {
	if model != "m-priced" {
		return Breakdown{}, false
	}
	in := float64(b.Input) * 1 / 1e6
	out := float64(b.Output) * 2 / 1e6
	cr := float64(b.CacheRead) * 0.1 / 1e6
	return Breakdown{Total: in + out + cr, Input: in, Output: out, CacheRead: cr}, true
}

// TestRulesD24 has one case per rule-table row (and its edges).
func TestRulesD24(t *testing.T) {
	cases := []struct {
		name       string
		f          Facts
		wantSource Source
		wantCost   *float64
		wantRep    *float64
		wantComp   *float64
	}{
		{"priced, no report", Facts{Model: "m-priced", InputTokens: i64(1_000_000)}, SourceComputed, f64(1), nil, f64(1)},
		{"priced beats a higher report", Facts{Model: "m-priced", InputTokens: i64(1_000_000), Reported: f64(5)}, SourceComputed, f64(1), f64(5), f64(1)},
		{"priced beats a lower report", Facts{Model: "m-priced", InputTokens: i64(1_000_000), Reported: f64(0.2)}, SourceComputed, f64(1), f64(0.2), f64(1)},
		{"unpriced model: reported", Facts{Model: "m-unknown", InputTokens: i64(10), Reported: f64(0.3)}, SourceReported, f64(0.3), f64(0.3), nil},
		{"priced model without tokens: reported", Facts{Model: "m-priced", Reported: f64(0.3)}, SourceReported, f64(0.3), f64(0.3), nil},
		{"nothing", Facts{Model: "m-unknown", InputTokens: i64(10)}, SourceNone, nil, nil, nil},
		{"no model", Facts{InputTokens: i64(10)}, SourceNone, nil, nil, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Price(book, c.f)
			if got.Source != c.wantSource {
				t.Fatalf("source = %q, want %q", got.Source, c.wantSource)
			}
			eq := func(what string, a, b *float64) {
				if (a == nil) != (b == nil) || (a != nil && *a != *b) {
					t.Fatalf("%s = %v, want %v", what, val(a), val(b))
				}
			}
			eq("cost", got.CostUSD, c.wantCost)
			eq("reported", got.Detail.Reported, c.wantRep)
			eq("computed", got.Detail.Computed, c.wantComp)
		})
	}
	if got := Price(nil, Facts{Model: "m-priced", InputTokens: i64(1), Reported: f64(2)}); got.Source != SourceReported {
		t.Fatalf("nil lookup: source = %q, want reported", got.Source)
	}
}

func val(p *float64) any {
	if p == nil {
		return nil
	}
	return *p
}

func TestNetInput(t *testing.T) {
	cases := []struct {
		provider     string
		in, cr, want int64
	}{
		{"anthropic", 100, 40, 100},
		{"claude", 100, 40, 100},
		{"openai", 100, 40, 60},
		{"OpenAI", 30, 40, 0},
		{"", 100, 40, 100},
	}
	for _, c := range cases {
		if got := NetInput(c.provider, c.in, c.cr); got != c.want {
			t.Errorf("NetInput(%q,%d,%d) = %d, want %d", c.provider, c.in, c.cr, got, c.want)
		}
	}
	// A gross input's cached part is billed once, at the cache rate.
	got := Price(book, Facts{Model: "m-priced", InputTokens: i64(1_000_000), CacheReadTokens: i64(1_000_000)})
	if got.CostUSD == nil || *got.CostUSD != 0.1 {
		t.Fatalf("gross cached call cost = %v, want 0.1", val(got.CostUSD))
	}
}

// TestBundleOfShapes pins E-18: the bundle follows the mapped shape, never a
// provider name. The counts are the C5/C6 instrument fixtures'.
func TestBundleOfShapes(t *testing.T) {
	cases := []struct {
		name string
		f    Facts
		want Bundle
	}{
		{
			"OpenInference anthropic reports gross input under provider anthropic: cache billed once",
			Facts{InputTokens: i64(2130), OutputTokens: i64(5), CacheReadTokens: i64(2000), CacheWriteTokens: i64(100)},
			Bundle{Input: 30, Output: 5, CacheRead: 2000, CacheWrite: 100},
		},
		{
			"Bedrock (provider aws / aws.bedrock) reports net input: kept",
			Facts{InputTokens: i64(30), OutputTokens: i64(5), CacheReadTokens: i64(2000), CacheWriteTokens: i64(100), InputNet: true},
			Bundle{Input: 30, Output: 5, CacheRead: 2000, CacheWrite: 100},
		},
		{
			"OpenAI gross input with cache read",
			Facts{InputTokens: i64(1200), OutputTokens: i64(40), CacheReadTokens: i64(1024), ReasoningTokens: i64(16)},
			Bundle{Input: 176, Output: 40, CacheRead: 1024},
		},
		{
			"Gemini output net of thinking: reasoning added",
			Facts{InputTokens: i64(1200), OutputTokens: i64(24), CacheReadTokens: i64(1024), ReasoningTokens: i64(16), OutputNet: true},
			Bundle{Input: 176, Output: 40, CacheRead: 1024},
		},
		{
			"gross input smaller than its cache: floored",
			Facts{InputTokens: i64(10), CacheReadTokens: i64(40)},
			Bundle{Input: 0, CacheRead: 40},
		},
	}
	for _, c := range cases {
		if got := BundleOf(c.f); got != c.want {
			t.Errorf("%s: bundle = %+v, want %+v", c.name, got, c.want)
		}
	}
}

// TestGrossOfShapes pins FR-M04: GrossOf turns a net-reported count into the
// vocabulary's gross one and keeps a gross or absent count, and the gross
// counts give the same bundle (BundleOf, zero shape) and the same budget
// tokens (BudgetTokens) as the reported counts with their shape, so a store
// that keeps the gross counts prices and budgets both shapes alike. The
// counts are TestBundleOfShapes' fixtures.
func TestGrossOfShapes(t *testing.T) {
	cases := []struct {
		name      string
		f         Facts
		wantIn    *int64
		wantOut   *int64
		wantSpend int64 // BudgetTokens over the gross counts: uncached input + output
	}{
		{
			"gross input and output: kept",
			Facts{InputTokens: i64(2130), OutputTokens: i64(5), CacheReadTokens: i64(2000), CacheWriteTokens: i64(100)},
			i64(2130), i64(5), 35,
		},
		{
			"Bedrock net input: both cache buckets added back",
			Facts{InputTokens: i64(30), OutputTokens: i64(5), CacheReadTokens: i64(2000), CacheWriteTokens: i64(100), InputNet: true},
			i64(2130), i64(5), 35,
		},
		{
			"Gemini output net of thinking: reasoning added",
			Facts{InputTokens: i64(1200), OutputTokens: i64(24), CacheReadTokens: i64(1024), ReasoningTokens: i64(16), OutputNet: true},
			i64(1200), i64(40), 216,
		},
		{
			"both net",
			Facts{InputTokens: i64(176), OutputTokens: i64(24), CacheReadTokens: i64(1024), ReasoningTokens: i64(16), InputNet: true, OutputNet: true},
			i64(1200), i64(40), 216,
		},
		{
			"net input with no cache count: unchanged",
			Facts{InputTokens: i64(30), OutputTokens: i64(5), InputNet: true},
			i64(30), i64(5), 35,
		},
		{
			"absent counts stay absent",
			Facts{InputNet: true, OutputNet: true},
			nil, nil, 0,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in, out := GrossOf(c.f)
			if !sameCount(in, c.wantIn) || !sameCount(out, c.wantOut) {
				t.Fatalf("gross = %v/%v, want %v/%v", show(in), show(out), show(c.wantIn), show(c.wantOut))
			}
			stored := c.f
			stored.InputTokens, stored.OutputTokens, stored.InputNet, stored.OutputNet = in, out, false, false
			if got, want := BundleOf(stored), BundleOf(c.f); got != want {
				t.Fatalf("bundle of the gross counts = %+v, of the reported ones = %+v", got, want)
			}
			if got := BudgetTokens("llm", deref(in), deref(out), deref(c.f.CacheReadTokens), deref(c.f.CacheWriteTokens)); got != c.wantSpend {
				t.Fatalf("budget tokens = %d, want %d", got, c.wantSpend)
			}
		})
	}
	// GrossOf never aliases the caller's counts when it changes one.
	f := Facts{InputTokens: i64(30), CacheReadTokens: i64(2000), InputNet: true}
	in, _ := GrossOf(f)
	if *f.InputTokens != 30 || *in != 2030 {
		t.Fatalf("GrossOf changed the reported count: %d / %d", *f.InputTokens, *in)
	}
}

func sameCount(a, b *int64) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func show(p *int64) any {
	if p == nil {
		return "nil"
	}
	return *p
}

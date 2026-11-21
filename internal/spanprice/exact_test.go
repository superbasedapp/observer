package spanprice

import (
	"encoding/json"
	"testing"
)

func eqPtr(a, b *float64) bool {
	if a == nil || b == nil {
		return a == b
	}
	d := *a - *b
	return d < 1e-12 && d > -1e-12
}

// TestExactRules has one case per contract section 2 row.
func TestExactRules(t *testing.T) {
	computed := Price(book, Facts{Model: "m-priced", InputTokens: i64(1_000_000), Reported: f64(0.5)})
	reported := Price(book, Facts{Model: "m-unknown", InputTokens: i64(10), Reported: f64(0.3)})
	none := Price(book, Facts{Model: "m-unknown", InputTokens: i64(10)})
	gw := &Exact{Source: SourceGatewayExact, USD: 1.2, RequestIDs: []string{"gw-1"}, Requests: 1, RateCardVersion: "v7", JoinRule: "request_id"}
	cases := []struct {
		name       string
		base       Result
		exact      *Exact
		wantSource Source
		wantCost   *float64
		wantDelta  *float64
	}{
		{"row 1: exact beats computed, delta vs reported", computed, gw, SourceGatewayExact, f64(1.2), f64(0.7)},
		{"row 1: exact beats reported", reported, gw, SourceGatewayExact, f64(1.2), f64(0.9)},
		{"row 1: exact on an unpriced span, no delta", none, gw, SourceGatewayExact, f64(1.2), nil},
		{"row 1: proxy exact", computed, &Exact{Source: SourceProxyExact, USD: 1}, SourceProxyExact, f64(1), f64(0.5)},
		{"row 2: no exact, computed stays", computed, nil, SourceComputed, f64(1), nil},
		{"row 3: no exact, reported stays", reported, nil, SourceReported, f64(0.3), nil},
		{"row 4: nothing", none, nil, SourceNone, nil, nil},
		{"a non-exact source is ignored", computed, &Exact{Source: SourceComputed, USD: 9}, SourceComputed, f64(1), nil},
		{"row 1b (D27): an unpriced exact keeps computed", computed, &Exact{Source: SourceGatewayExact, Unpriced: true, USD: 0}, SourceComputed, f64(1), nil},
		{"row 1b (D27): an unpriced exact keeps reported", reported, &Exact{Source: SourceGatewayExact, Unpriced: true}, SourceReported, f64(0.3), nil},
		{"row 1b (D27): an unpriced exact on an unpriced span stays unpriced", none, &Exact{Source: SourceGatewayExact, Unpriced: true}, SourceNone, nil, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := WithExact(c.base, c.exact)
			if got.Source != c.wantSource {
				t.Fatalf("source = %q, want %q", got.Source, c.wantSource)
			}
			if !eqPtr(got.CostUSD, c.wantCost) {
				t.Fatalf("cost = %v, want %v", got.CostUSD, c.wantCost)
			}
			if !eqPtr(got.DeltaUSD, c.wantDelta) {
				t.Fatalf("delta = %v, want %v", got.DeltaUSD, c.wantDelta)
			}
		})
	}
}

// TestDelta checks the detail keeps every number and both deltas.
func TestDelta(t *testing.T) {
	base := Price(book, Facts{Model: "m-priced", InputTokens: i64(1_000_000), Reported: f64(0.5)})
	got := WithExact(base, &Exact{Source: SourceGatewayExact, USD: 1.1, RequestIDs: []string{"a", "b"}, Requests: 2, RateCardVersion: "v3", JoinRule: "traceparent"})
	d := got.Detail
	if !eqPtr(d.Reported, f64(0.5)) || !eqPtr(d.Computed, f64(1)) || !eqPtr(d.GatewayExact, f64(1.1)) {
		t.Fatalf("numbers lost: %+v", d)
	}
	if !eqPtr(d.DeltaReported, f64(0.6)) || !eqPtr(d.DeltaComputed, f64(0.1)) {
		t.Fatalf("deltas: %v %v", d.DeltaReported, d.DeltaComputed)
	}
	if d.BaseSource == nil || *d.BaseSource != SourceComputed || d.GatewayRequests != 2 || d.JoinRule != "traceparent" {
		t.Fatalf("detail: %+v", d)
	}
	raw, _ := json.Marshal(d)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	for _, k := range []string{"reported", "computed", "gateway_exact", "base_source", "delta_reported", "delta_computed", "gateway_request_ids", "gateway_requests", "rate_card_version", "join_rule"} {
		if _, ok := m[k]; !ok {
			t.Errorf("cost_detail lacks %q: %s", k, raw)
		}
	}
	// Request ids are capped.
	many := make([]string, MaxRequestIDs+5)
	for i := range many {
		many[i] = "r"
	}
	if got := WithExact(base, &Exact{Source: SourceGatewayExact, USD: 1, RequestIDs: many, Requests: len(many)}); len(got.Detail.GatewayRequestIDs) != MaxRequestIDs || got.Detail.GatewayRequests != len(many) {
		t.Fatalf("cap: %d ids, %d requests", len(got.Detail.GatewayRequestIDs), got.Detail.GatewayRequests)
	}
}

// TestBaseFromStored rebuilds the D24 result of stored rows.
func TestBaseFromStored(t *testing.T) {
	bs := SourceReported
	cases := []struct {
		name     string
		source   Source
		cost     *float64
		detail   Detail
		base     *Source
		want     Source
		wantCost *float64
	}{
		{"push computed row without detail", SourceComputed, f64(0.4), Detail{}, nil, SourceComputed, f64(0.4)},
		{"push reported row without detail", SourceReported, f64(0.2), Detail{}, nil, SourceReported, f64(0.2)},
		{"gateway computed row with detail", SourceComputed, f64(0.4), Detail{Computed: f64(0.4), Reported: f64(0.1)}, nil, SourceComputed, f64(0.4)},
		{"a joined row: back to its base", SourceGatewayExact, f64(9), Detail{Reported: f64(0.2)}, &bs, SourceReported, f64(0.2)},
		{"a joined row with no base", SourceGatewayExact, f64(9), Detail{}, nil, SourceNone, nil},
		{"unpriced", SourceNone, f64(0), Detail{}, nil, SourceNone, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := BaseFromStored(c.source, c.cost, c.detail, c.base)
			if got.Source != c.want || !eqPtr(got.CostUSD, c.wantCost) {
				t.Fatalf("got %q %v, want %q %v", got.Source, got.CostUSD, c.want, c.wantCost)
			}
		})
	}
}

// TestProvenanceLabel has one case per contract section 5 label row.
func TestProvenanceLabel(t *testing.T) {
	build := func(srcs ...Source) Provenance {
		p := NewProvenance()
		for _, s := range srcs {
			p.Add(s)
		}
		p.Finish()
		return p
	}
	cases := []struct {
		name         string
		p            Provenance
		label        string
		wantComplete bool
	}{
		{"no span at all: no model call", build(), ProvenanceNoModelCalls, true},
		{"no priced span", build(SourceNone, SourceNone), ProvenanceUnpriced, false},
		{"one source", build(SourceGatewayExact, SourceGatewayExact), "gateway_exact", true},
		{"one source and an unpriced span: partial", build(SourceComputed, SourceNone), "computed", false},
		{"several sources", build(SourceGatewayExact, SourceComputed), ProvenanceMixed, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.p.Label != c.label || c.p.Complete != c.wantComplete {
				t.Fatalf("got %q complete=%v, want %q complete=%v", c.p.Label, c.p.Complete, c.label, c.wantComplete)
			}
			for _, s := range Sources {
				if _, ok := c.p.Sources[sourceKey(s)]; !ok {
					t.Fatalf("sources lacks %q", sourceKey(s))
				}
			}
		})
	}
}

// TestLabels pins the display labels of contract section 1.
func TestLabels(t *testing.T) {
	want := map[Source]string{
		SourceGatewayExact: "Gateway exact", SourceProxyExact: "Proxy exact",
		SourceComputed: "Computed", SourceReported: "Reported", SourceNone: "Unpriced",
	}
	for s, l := range want {
		if Label(s) != l {
			t.Errorf("Label(%q) = %q, want %q", s, Label(s), l)
		}
	}
	if !IsExact(SourceGatewayExact) || !IsExact(SourceProxyExact) || IsExact(SourceComputed) {
		t.Fatal("IsExact")
	}
	one := 1.0
	for _, c := range []struct {
		kind   string
		tokens int64
		cost   *float64
		src    Source
		want   bool
	}{
		{"llm", 3, nil, SourceNone, true},           // usage, unpriced
		{"llm", 0, &one, SourceComputed, true},      // a cost
		{"llm", 0, nil, SourceNone, false},          // L-07: a model and nothing else
		{"embedding", 5, nil, SourceNone, true},     // embedding stays a cost kind (E-17 open)
		{"agent", 300, &one, SourceComputed, false}, // L-03: restates its children
		{"chain", 300, nil, SourceNone, false},      // L-03
		{"retriever", 3, nil, SourceNone, false},    // container kind
		{"", 3, nil, SourceNone, true},              // unstated kind: the old rule
		{"", 0, nil, SourceNone, false},
	} {
		if got := CostBearing(c.kind, c.tokens, c.cost, c.src); got != c.want {
			t.Errorf("CostBearing(%q, %d, %v, %q) = %v, want %v", c.kind, c.tokens, c.cost, c.src, got, c.want)
		}
	}
}

// TestExactD27Facts: the gateway's exact tokens and its rate card estimate
// ride in cost_detail for reference, priced or not, and the estimate is never
// the cost (ruling D27).
func TestExactD27Facts(t *testing.T) {
	base := Price(book, Facts{Model: "m-priced", InputTokens: i64(1_000_000)})
	card := 7.5
	toks := &ExactTokens{Input: 900, Output: 10}
	priced := WithExact(base, &Exact{Source: SourceGatewayExact, USD: 1.1, Tokens: toks, RateCardUSD: &card})
	if !eqPtr(priced.CostUSD, f64(1.1)) || !eqPtr(priced.Detail.GatewayRateCardUSD, &card) || priced.Detail.GatewayTokens != toks || priced.Detail.GatewayUnpriced {
		t.Fatalf("priced: %+v", priced.Detail)
	}
	unpriced := WithExact(base, &Exact{Source: SourceGatewayExact, Unpriced: true, Tokens: toks, RateCardUSD: &card, RequestIDs: []string{"gw"}, Requests: 1})
	if unpriced.Source != SourceComputed || !eqPtr(unpriced.CostUSD, f64(1)) || unpriced.DeltaUSD != nil {
		t.Fatalf("unpriced cost: %+v", unpriced)
	}
	d := unpriced.Detail
	if !d.GatewayUnpriced || d.GatewayExact != nil || d.GatewayTokens != toks || !eqPtr(d.GatewayRateCardUSD, &card) || len(d.GatewayRequestIDs) != 1 {
		t.Fatalf("unpriced facts: %+v", d)
	}
}

package spanprice

import (
	"encoding/json"
	"strings"
)

// tracecost.go - the SDK-visible cost shape of one trace (plan W4-2,
// contracts/cost-source.md section 6), shared by the org
// (internal/orgserver/gwcostjoin, GET /v1/sdk/traces/{trace_id}/cost) and the
// machine (internal/obs/httpapi, GET /api/obs/trace/{id} "cost"), so both
// answer the same fields by the same rule.

// SpanCost is one cost-bearing span of a TraceCost (contract section 6).
type SpanCost struct {
	SpanID       string   `json:"span_id"`
	Model        string   `json:"model"`
	CostUSD      *float64 `json:"cost_usd"`
	CostSource   string   `json:"cost_source"`
	ReportedUSD  *float64 `json:"reported_usd"`
	ComputedUSD  *float64 `json:"computed_usd"`
	ExactUSD     *float64 `json:"exact_usd"`
	CostDeltaUSD *float64 `json:"cost_delta_usd"`
	// GatewayRequestID is null unless the gateway served the span.
	GatewayRequestID *string `json:"gateway_request_id"`
}

// TraceCost is the SDK-visible cost of one trace (contract section 6).
type TraceCost struct {
	APIVersion     string     `json:"api_version,omitempty"`
	TraceID        string     `json:"trace_id"`
	CostUSD        *float64   `json:"cost_usd"`
	CostProvenance Provenance `json:"cost_provenance"`
	Spans          []SpanCost `json:"spans"`
}

// CostFacts are one stored span's cost columns, the input of BuildSpanCost.
type CostFacts struct {
	// Kind is the span's normalized kind (obs_spans.kind); only a
	// model-call kind is cost-bearing (CostKind). Empty keeps the old,
	// kind-blind rule.
	Kind                                            string
	SpanID, Model, Source, Detail, GatewayRequestID string
	CostUSD                                         *float64
	Delta                                           *float64
	Tokens                                          int64
}

// BuildSpanCost turns stored cost columns into a SpanCost; ok is false for a
// span that is not cost-bearing. The rule is shared by the org and the
// machine (internal/obs/httpapi), so both answer the same shape.
func BuildSpanCost(f CostFacts) (SpanCost, bool) {
	src := Source(f.Source)
	if !CostBearing(f.Kind, f.Tokens, f.CostUSD, src) {
		return SpanCost{}, false
	}
	d := DecodeDetail(f.Detail)
	sc := SpanCost{
		SpanID: f.SpanID, Model: f.Model, CostSource: f.Source,
		ReportedUSD: d.Reported, ComputedUSD: d.Computed, CostDeltaUSD: f.Delta,
	}
	if f.GatewayRequestID != "" {
		id := f.GatewayRequestID
		sc.GatewayRequestID = &id
	}
	if src != SourceNone {
		sc.CostUSD = f.CostUSD
	}
	switch src {
	case SourceGatewayExact:
		sc.ExactUSD = firstNonNil(d.GatewayExact, f.CostUSD)
	case SourceProxyExact:
		sc.ExactUSD = firstNonNil(d.ProxyExact, f.CostUSD)
	case SourceComputed:
		sc.ComputedUSD = firstNonNil(d.Computed, f.CostUSD)
	case SourceReported:
		sc.ReportedUSD = firstNonNil(d.Reported, f.CostUSD)
	}
	return sc, true
}

// Summarize fills a TraceCost's total and provenance from its spans. It
// cannot tell a trace with no model call from one whose calls reported no
// usage; SummarizeFacts can, and is what a reader with the span list uses.
func Summarize(tc *TraceCost) {
	summarize(tc, 1)
}

// SummarizeFacts builds a TraceCost's spans from every stored span of the
// trace (cost-bearing or not) and fills its total and provenance: a trace
// with no cost-bearing span and no ModelSpan reads ProvenanceNoModelCalls.
func SummarizeFacts(tc *TraceCost, facts []CostFacts) {
	models := 0
	for _, f := range facts {
		if ModelSpan(f.Kind, f.Model) {
			models++
		}
		if sc, ok := BuildSpanCost(f); ok {
			tc.Spans = append(tc.Spans, sc)
		}
	}
	summarize(tc, models)
}

func summarize(tc *TraceCost, modelSpans int) {
	p := NewProvenance()
	for range modelSpans {
		p.AddModelSpan()
	}
	var total float64
	priced := false
	for _, s := range tc.Spans {
		p.Add(Source(s.CostSource))
		if s.CostUSD != nil && s.CostSource != "" {
			total += *s.CostUSD
			priced = true
		}
	}
	p.Finish()
	tc.CostProvenance = p
	tc.CostUSD = nil
	if priced {
		tc.CostUSD = &total
	}
	if tc.Spans == nil {
		tc.Spans = []SpanCost{}
	}
}

// SpanProvenance is the provenance of an already-loaded span list (a trace
// detail): no query.
func SpanProvenance(facts []CostFacts) Provenance {
	tc := TraceCost{}
	SummarizeFacts(&tc, facts)
	return tc.CostProvenance
}

// DecodeDetail decodes a stored cost_detail (empty or invalid JSON: none).
func DecodeDetail(raw string) ExactDetail {
	var d ExactDetail
	if strings.TrimSpace(raw) != "" {
		_ = json.Unmarshal([]byte(raw), &d)
	}
	return d
}

func firstNonNil(a, b *float64) *float64 {
	if a != nil {
		return a
	}
	return b
}

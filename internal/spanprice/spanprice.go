package spanprice

import (
	"strings"
	"time"
)

// Bundle is the token bundle a Lookup prices. Input is NET of cache reads.
type Bundle struct {
	Input, Output, CacheRead, CacheWrite int64
}

// Breakdown is a priced bundle in USD.
type Breakdown struct {
	Total, Input, Output, CacheRead, CacheWrite float64
}

// Lookup prices b for model at the rate in force at at. ok is false when the
// model is not in the price book.
type Lookup func(model string, b Bundle, at time.Time) (Breakdown, bool)

// Facts are the pricing inputs of one span. A nil count is "not reported".
//
// The counts follow the span vocabulary's bucket definition
// (internal/genaiattr: Input includes the cache read and cache write tokens,
// Output includes the reasoning tokens) unless InputNet / OutputNet say the
// emitter reported them net. The shape is a mapped FACT the mapper resolves
// (genaiattr.Usage.InputShape / OutputShape), never a provider name (review
// finding E-18): a Claude model reports net input on one rail and gross on
// another, so a name says nothing about the count.
type Facts struct {
	Model string
	// InputTokens is the reported input count; OutputTokens the reported
	// output count; ReasoningTokens the reasoning count (a subset of a gross
	// output, added to a net one).
	InputTokens, OutputTokens, CacheReadTokens, CacheWriteTokens, ReasoningTokens *int64
	// InputNet is true when InputTokens excludes the cache tokens.
	InputNet bool
	// OutputNet is true when OutputTokens excludes the reasoning tokens.
	OutputNet bool
	// Reported is the instrumentor's reported total cost, nil when none.
	Reported *float64
	// At is the span's start (dated prices); zero means now's rate.
	At time.Time
}

// Source is the provenance of a span's recorded cost (obs_spans.cost_source).
type Source string

// The cost sources.
const (
	SourceNone     Source = ""
	SourceComputed Source = "computed"
	SourceReported Source = "reported"
)

// Detail keeps both costs and the computed components (obs_spans.cost_detail).
type Detail struct {
	Reported   *float64 `json:"reported,omitempty"`
	Computed   *float64 `json:"computed,omitempty"`
	Input      *float64 `json:"input,omitempty"`
	Output     *float64 `json:"output,omitempty"`
	CacheRead  *float64 `json:"cache_read,omitempty"`
	CacheWrite *float64 `json:"cache_write,omitempty"`
}

// Empty reports whether no cost is kept.
func (d Detail) Empty() bool { return d.Reported == nil && d.Computed == nil }

// Result is a span's recorded cost.
type Result struct {
	// CostUSD is the winning cost; nil when the span is unpriced.
	CostUSD *float64
	Source  Source
	Detail  Detail
}

// Rule is one row of the D24 rule table: When matches, Pick chooses.
type Rule struct {
	Name string
	When func(priced, reported bool) bool
	Pick Source
}

// Rules is D24, walked top-down; the first match wins.
var Rules = []Rule{
	{Name: "priced model: computed wins, reported kept", When: func(p, _ bool) bool { return p }, Pick: SourceComputed},
	{Name: "unpriced model: reported cost", When: func(p, r bool) bool { return !p && r }, Pick: SourceReported},
	{Name: "nothing to price", When: func(bool, bool) bool { return true }, Pick: SourceNone},
}

// Price applies the rule table to one span. A nil lookup prices nothing (the
// reported cost, if any, is then used).
func Price(lookup Lookup, f Facts) Result {
	var res Result
	var computed Breakdown
	priced := false
	if lookup != nil && f.Model != "" && hasTokens(f) {
		computed, priced = lookup(f.Model, BundleOf(f), f.At)
	}
	reported := f.Reported != nil
	if reported {
		v := *f.Reported
		res.Detail.Reported = &v
	}
	if priced {
		total := computed.Total
		res.Detail.Computed = &total
		res.Detail.Input = nonZero(computed.Input)
		res.Detail.Output = nonZero(computed.Output)
		res.Detail.CacheRead = nonZero(computed.CacheRead)
		res.Detail.CacheWrite = nonZero(computed.CacheWrite)
	}
	for _, r := range Rules {
		if !r.When(priced, reported) {
			continue
		}
		res.Source = r.Pick
		switch r.Pick {
		case SourceComputed:
			res.CostUSD = res.Detail.Computed
		case SourceReported:
			res.CostUSD = res.Detail.Reported
		}
		return res
	}
	return res
}

// BundleOf resolves a span's counts to the bundle the price book bills: the
// input NET of both cache buckets (floored at 0) unless it was reported net,
// the output INCLUDING the reasoning tokens (added when it was reported net
// of them; reasoning is never added to a gross output, which already holds
// it). The org gateway and the machine both price through Price, so one span
// is priced one way on both rails (E-18).
func BundleOf(f Facts) Bundle {
	cr, cw := deref(f.CacheReadTokens), deref(f.CacheWriteTokens)
	in := deref(f.InputTokens)
	if !f.InputNet {
		if in -= cr + cw; in < 0 {
			in = 0
		}
	}
	out := deref(f.OutputTokens)
	if f.OutputNet {
		out += deref(f.ReasoningTokens)
	}
	return Bundle{Input: in, Output: out, CacheRead: cr, CacheWrite: cw}
}

// GrossOf resolves a span's reported input and output counts to the span
// vocabulary's bucket definition (internal/genaiattr "Token buckets": the
// input includes the cache read and cache write tokens, the output the
// reasoning tokens). An input reported net of the cache tokens (InputNet)
// gets them added back, an output reported net of the reasoning tokens
// (OutputNet) gets those added; a gross count, and an absent (nil) one, is
// kept as it is. It is the other half of BundleOf: counts stored gross price
// through BundleOf with the zero shape to the same bundle as the reported
// counts with their shape, and BudgetTokens, which reads a stored input as
// gross, then counts both shapes alike (review FR-M04).
func GrossOf(f Facts) (input, output *int64) {
	input, output = f.InputTokens, f.OutputTokens
	if f.InputNet && input != nil {
		v := *input + deref(f.CacheReadTokens) + deref(f.CacheWriteTokens)
		input = &v
	}
	if f.OutputNet && output != nil {
		v := *output + deref(f.ReasoningTokens)
		output = &v
	}
	return input, output
}

// NetInput resolves a reported input count by the provider kind's name. It
// is the LEGACY fallback of the exact-cost join for a gw_audit row written
// before the AI gateway recorded the wire shape (aigateway.Usage.InputGross,
// R-C05) and must not be used for a span: a span carries its shape as a
// mapped fact (Facts.InputNet, E-18). Anthropic-family kinds are net, the
// rest gross (netted against the cache reads, floored at 0), an empty kind
// net.
func NetInput(provider string, input, cacheRead int64) int64 {
	return NetInputOf(inputIsGross(provider), input, cacheRead)
}

// NetInputOf resolves an input count whose wire shape is known: gross counts
// are netted against the cache reads, floored at 0; net counts are kept. The
// AI gateway records the shape per request (aigateway.Usage.InputGross), so
// the exact-cost join nets by it rather than by a provider name (review
// finding R-C05).
func NetInputOf(gross bool, input, cacheRead int64) int64 {
	if !gross {
		return input
	}
	if n := input - cacheRead; n > 0 {
		return n
	}
	return 0
}

func inputIsGross(provider string) bool {
	p := strings.ToLower(strings.TrimSpace(provider))
	switch {
	case p == "":
		return false
	case strings.Contains(p, "anthropic"), strings.Contains(p, "claude"):
		return false
	default:
		return true
	}
}

func hasTokens(f Facts) bool {
	return f.InputTokens != nil || f.OutputTokens != nil || f.CacheReadTokens != nil || f.CacheWriteTokens != nil
}

func deref(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

func nonZero(v float64) *float64 {
	if v == 0 {
		return nil
	}
	return &v
}

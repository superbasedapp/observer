package sessionmsg

import (
	"sort"
	"time"
)

// Headline is the session-headline token figure for a bundle: net input +
// output + cache read + cache write. Reasoning and web-search requests are
// separate reported dimensions and are deliberately NOT added in (a twinned
// proxy row's Output is already net of the reasoning its JSONL twin
// reported; an untwinned proxy row's Output is the provider's gross figure).
// This is the ONE definition of "tokens" both the node session header
// (web/src/components/sessiondetail/KpiBand.tsx sums the same four fields of
// the node's /api/session/<id> tokens map) and the org drawer
// (rollup.SessionDetail's Tokens) render.
func (b TokenBundle) Headline() int64 {
	return b.Input + b.Output + b.CacheRead + b.CacheCreation
}

// ModelTotals is one model's slice of Totals.
type ModelTotals struct {
	// Model is the contribution's own model, else the defaultModel passed to
	// SumContributions, else "" (the caller decides how to label a model
	// that no row carried).
	Model           string
	Bundle          TokenBundle
	RecordedCostUSD float64
	// Turns counts every contribution (proxy + token rows that survived the
	// twin fold); ProxyTurns counts only the proxy-row contributions.
	Turns      int64
	ProxyTurns int64
}

// Totals is a session's spend summed over Derive's rows: the headline token
// bundle, the recorded cost, the turn counts and the per-model split, all
// from the SAME contributions, so a per-model sum always equals the
// headline.
type Totals struct {
	Bundle          TokenBundle
	RecordedCostUSD float64
	Turns           int64
	ProxyTurns      int64
	// ByModel is ordered by Headline() descending, then model ascending.
	ByModel []ModelTotals
	// Points is every contribution, ordered by timestamp ascending (a stable
	// sort over Derive's own row order, so equal timestamps keep that
	// order). It is the substrate for a per-turn cost series.
	Points []Contribution
}

// SumContributions totals Derive's output. It is the ONE owner of "what does
// this session add up to" for both engines: the node's session-detail handler
// and the org's rollup.SessionDetail both call Derive over their own loaded
// rows and then this, so the two headers can only differ when the rows they
// were handed differ (for the org: rows the node has not pushed yet, or rows
// the node changed after pushing them).
//
// Only Contributions are summed. A row Derive synthesized from actions alone
// carries none, so it adds nothing — exactly like the SQL substrates this
// replaces, which never read the actions table for spend.
func SumContributions(rows []*Row, defaultModel string) Totals {
	var out Totals
	byModel := map[string]*ModelTotals{}
	var order []string
	for _, r := range rows {
		for _, c := range r.Contributions {
			model := c.Model
			if model == "" {
				model = defaultModel
			}
			mt, ok := byModel[model]
			if !ok {
				mt = &ModelTotals{Model: model}
				byModel[model] = mt
				order = append(order, model)
			}
			addBundle(&out.Bundle, c.Bundle)
			addBundle(&mt.Bundle, c.Bundle)
			out.RecordedCostUSD += c.RecordedCostUSD
			mt.RecordedCostUSD += c.RecordedCostUSD
			out.Turns++
			mt.Turns++
			if c.Proxy {
				out.ProxyTurns++
				mt.ProxyTurns++
			}
			out.Points = append(out.Points, c)
		}
	}
	out.ByModel = make([]ModelTotals, 0, len(order))
	for _, m := range order {
		out.ByModel = append(out.ByModel, *byModel[m])
	}
	sort.SliceStable(out.ByModel, func(i, j int) bool {
		hi, hj := out.ByModel[i].Bundle.Headline(), out.ByModel[j].Bundle.Headline()
		if hi != hj {
			return hi > hj
		}
		return out.ByModel[i].Model < out.ByModel[j].Model
	})
	sort.SliceStable(out.Points, func(i, j int) bool {
		return timestampLess(out.Points[i].Timestamp, out.Points[j].Timestamp)
	})
	return out
}

// addBundle accumulates src into dst (Fast is sticky: any fast contribution
// marks the sum fast).
func addBundle(dst *TokenBundle, src TokenBundle) {
	dst.Input += src.Input
	dst.Output += src.Output
	dst.CacheRead += src.CacheRead
	dst.CacheCreation += src.CacheCreation
	dst.CacheCreation1h += src.CacheCreation1h
	dst.Reasoning += src.Reasoning
	dst.WebSearchRequests += src.WebSearchRequests
	dst.Fast = dst.Fast || src.Fast
}

// timestampLess orders two RFC3339(Nano) stamps chronologically. A plain
// string compare is wrong across differing fractional-second widths
// ("10:00:00Z" sorts after "10:00:00.5Z"), so both are parsed; a stamp that
// does not parse falls back to the string compare, and sorts after every
// parseable one.
func timestampLess(a, b string) bool {
	ta, errA := time.Parse(time.RFC3339Nano, a)
	tb, errB := time.Parse(time.RFC3339Nano, b)
	switch {
	case errA == nil && errB == nil:
		return ta.Before(tb)
	case errA == nil:
		return true
	case errB == nil:
		return false
	default:
		return a < b
	}
}

package pricewire

import (
	"time"

	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// OrgPriceRows projects the ORG rail's wire rows onto the engine's input type.
//
// It is a plain field copy and stays that way: the two field sets are
// deliberately identical (orgcontract.PricingPolicyRow is authored in
// cost.Pricing's vocabulary), so anything clever here would be arithmetic
// nobody asked for on a number an org negotiated.
//
// The one thing it MUST carry across is which rates the org actually QUOTED
// (server migration 135): a nil wire rate is "the org quotes nothing here" and
// the engine falls through to the seed or the developer's own override for it,
// while a rate SET to zero is a negotiated FREE rate. Collapsing the two here
// would put the whole cut-over back where it started, silently.
//
// Its two STRUCTURAL dimensions are read through the org rail's own rule
// (PricingPolicyRow.OrgThreshold / OrgPeak): an ABSENT threshold or peak keeps
// the LEGACY meaning every pre-175 node gave it - "quoted flat", overlaid over
// the seed - so a document from an org server that predates the nullable
// threshold bills exactly as it did on the node it shipped with; only the
// explicit `*_unquoted` markers a post-175 server writes for a NULL column
// mean "not quoted, keep the seed's" (review finding F1, 2026-09-26). The
// public feed has the opposite absence rule and goes through [FeedPriceRows].
//
// A row that carries the org's dated HISTORY (two or more rows for the model in
// the org's price book) has each period projected by the same rule, so the
// engine can price an old row at the org rate in force when it was captured.
func OrgPriceRows(rows []orgcontract.PricingPolicyRow) []cost.OrgPrice {
	out := make([]cost.OrgPrice, 0, len(rows))
	for _, r := range rows {
		p := QuotedRates(r)
		p.LongContextThreshold, p.Set.LongContextThreshold = r.OrgThreshold()
		peak, quoted := r.OrgPeak()
		p.Peak, p.Set.Peak = PeakRatesToCost(peak), quoted
		if len(r.History) >= 2 {
			p.History = OrgPriceRows(r.History)
		}
		out = append(out, p)
	}
	return out
}

// FeedPriceRows is the STANDALONE PUBLIC FEED's projection. The feed never
// had the org rail's legacy: its generator omits the threshold for every row
// whose tier it does not know and never wrote a peak it did not have, so on
// this rail absence has always meant "not quoted" - the seed's tier and peak
// are kept - and a present value (0 included) is quoted.
func FeedPriceRows(rows []orgcontract.PricingPolicyRow) []cost.OrgPrice {
	out := make([]cost.OrgPrice, 0, len(rows))
	for _, r := range rows {
		p := QuotedRates(r)
		if r.LongContextThreshold != nil {
			p.LongContextThreshold, p.Set.LongContextThreshold = *r.LongContextThreshold, true
		}
		p.Peak, p.Set.Peak = PeakRatesToCost(r.Peak), r.Peak != nil
		out = append(out, p)
	}
	return out
}

// QuotedRates copies a wire row's identity and its eleven nullable rates
// (server migration 135: nil = not quoted, a set 0 = negotiated free) onto a
// cost.OrgPrice. It is the part of the projection the org rail and the feed
// share; the structural dimensions differ per rail and are left to the caller.
func QuotedRates(r orgcontract.PricingPolicyRow) cost.OrgPrice {
	p := cost.OrgPrice{
		Model:         r.Model,
		EffectiveFrom: r.EffectiveFrom,
	}
	for _, f := range []struct {
		src *float64
		dst *float64
		set *bool
	}{
		{r.InputPerMTok, &p.Input, &p.Set.Input},
		{r.OutputPerMTok, &p.Output, &p.Set.Output},
		{r.CacheReadPerMTok, &p.CacheRead, &p.Set.CacheRead},
		{r.CacheWritePerMTok, &p.CacheCreation, &p.Set.CacheCreation},
		{r.CacheWrite1hPerMTok, &p.CacheCreation1h, &p.Set.CacheCreation1h},
		{r.LongContextInputPerMTok, &p.LongContextInput, &p.Set.LongContextInput},
		{r.LongContextOutputPerMTok, &p.LongContextOutput, &p.Set.LongContextOutput},
		{r.LongContextCacheReadPerMTok, &p.LongContextCacheRead, &p.Set.LongContextCacheRead},
		{r.LongContextCacheWritePerMTok, &p.LongContextCacheCreation, &p.Set.LongContextCacheCreation},
		{r.LongContextCacheWrite1hPerMTok, &p.LongContextCacheCreation1h, &p.Set.LongContextCacheCreation1h},
		{r.WebSearchPerRequest, &p.WebSearchPerRequest, &p.Set.WebSearchPerRequest},
	} {
		if f.src != nil {
			*f.dst, *f.set = *f.src, true
		}
	}
	return p
}

// PeakRatesToCost translates the wire's peak variant into the engine's own
// vocabulary (a plain field copy, mirroring [OrgPriceRows]' own rule - the two
// shapes are deliberately identical, see orgcontract.RateSet's doc). nil in,
// nil out. Whether a nil peak is "quoted flat" or "not quoted" is the RAIL's
// rule and is decided by the caller ([OrgPriceRows] / [FeedPriceRows]), never
// here.
func PeakRatesToCost(pr *orgcontract.PeakRates) *cost.PeakRates {
	if pr == nil {
		return nil
	}
	out := &cost.PeakRates{
		RateSet: cost.RateSet{
			Input:           pr.Input,
			Output:          pr.Output,
			CacheRead:       pr.CacheRead,
			CacheCreation:   pr.CacheCreation,
			CacheCreation1h: pr.CacheCreation1h,

			LongContextThreshold:       pr.LongContextThreshold,
			LongContextInput:           pr.LongContextInput,
			LongContextOutput:          pr.LongContextOutput,
			LongContextCacheRead:       pr.LongContextCacheRead,
			LongContextCacheCreation:   pr.LongContextCacheCreation,
			LongContextCacheCreation1h: pr.LongContextCacheCreation1h,
		},
	}
	for _, w := range pr.Schedule.Windows {
		out.Schedule.Windows = append(out.Schedule.Windows, cost.PeakWindow{
			Days:     append([]time.Weekday(nil), w.Days...),
			StartUTC: w.StartUTC,
			EndUTC:   w.EndUTC,
		})
	}
	return out
}

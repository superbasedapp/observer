package pricewire

import (
	"time"

	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/reprice"
)

// RepricePriceFunc adapts a cost engine to the stored-cost re-price planner's
// price seam (internal/reprice.PriceFunc). It is the ONE adapter: the node's
// `observer reprice` (over its process engine) and the org server's re-price
// (over an engine built from the seed plus the org's price book) both price
// through it, so the two can never disagree about what a row costs at an
// instant.
//
// One date-aware lookup per row (the same LookupWithSourceAt the read path
// uses), the row's full bundle (fast tier and web-search requests included),
// whether the model carries a fast / priority premium at that time, and the
// rate's provenance for display. A rate set that quotes nothing at all
// ([QuotesNoRate]) is answered as "no price", never as $0.
func RepricePriceFunc(e *cost.Engine) reprice.PriceFunc {
	return func(model string, at time.Time, t reprice.Tokens) reprice.Quote {
		if e == nil {
			return reprice.Quote{}
		}
		p, src, ok := e.LookupWithSourceAt(model, at)
		if !ok || QuotesNoRate(p) {
			return reprice.Quote{}
		}
		usd := cost.Compute(p, cost.TokenBundle{
			Input:             t.Input,
			Output:            t.Output,
			CacheRead:         t.CacheRead,
			CacheCreation:     t.CacheCreation,
			CacheCreation1h:   t.CacheCreation1h,
			Reasoning:         t.Reasoning,
			WebSearchRequests: t.WebSearchRequests,
			Fast:              t.Fast,
		})
		return reprice.Quote{USD: usd, OK: true, FastTier: p.FastMultiplier > 0, Source: string(src)}
	}
}

// QuotesNoRate reports a rate set with every billed dimension at zero. The
// engine answers a model its seed never priced, at an instant BEFORE the first
// period of an org / feed price history, with a MISS (an Unpriced period; see
// internal/intelligence/cost orgTimeline's seedAt) since the PRICE-REPRICE-1
// review; an all-zero set can still reach here from any other source, and a
// re-price would otherwise write it as $0 over a captured figure. A re-price
// treats it as "no rate at that time": the row is left as it was. The cost of the guard is that
// a model priced fully free is never re-priced DOWN to $0 (its rows keep their
// captured figure): the safe direction, and the one the "never written as $0"
// rule asks for.
func QuotesNoRate(p cost.Pricing) bool {
	return p.Input == 0 && p.Output == 0 && p.CacheRead == 0 && p.CacheCreation == 0 &&
		p.CacheCreation1h == 0 && p.WebSearchPerRequest == 0 &&
		p.LongContextInput == 0 && p.LongContextOutput == 0 && p.LongContextCacheRead == 0 &&
		p.LongContextCacheCreation == 0 && p.LongContextCacheCreation1h == 0 && p.Peak == nil
}

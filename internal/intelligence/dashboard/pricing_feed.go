package dashboard

import (
	"context"
	"time"

	"github.com/marmutapp/superbased-observer/internal/store"
)

// pricing_feed.go is the dashboard's READ of the standalone-node public pricing
// feed (docs/plans/pricing-sync-tokenomics-to-platform-plan-2026-09-11.md §G).
//
// It exists because the cost engine composes a synced feed through the SAME
// org-rows input as an org's signed rates (cost.PricingSourceOrg), so the
// engine alone cannot say whether a composed "org" rate is really the org's or
// the public feed's. The disambiguator is node-local and cheap: an ENROLLED
// node ignores the public feed entirely (§C.3/D8), so a composed "org" rate on
// a STANDALONE node that has a synced feed IS the feed. This helper reads that
// fact once per /api/config and /api/governance render (not a hot path) and the
// two surfaces relabel `org` -> `feed` from it.

// dashboardFeedEconomics is the per-model economics the feed carried, surfaced
// as a hint beside the rate (cache mode / reasoning billing, §K).
type dashboardFeedEconomics struct {
	CacheMode        string `json:"cache_mode,omitempty"`
	ReasoningBilling string `json:"reasoning_billing,omitempty"`
}

// dashboardFeedPosture is the resolved standalone-feed state for a render.
// Active is false on an enrolled node, on a node that never synced, and when
// no DB is wired — in every one of those the engine's "org" rows (if any) are a
// real org's, not the public feed's, so no relabel happens.
type dashboardFeedPosture struct {
	Active    bool
	Version   int64
	FetchedAt string
	State     string
	Economics map[string]dashboardFeedEconomics
}

// feedPosture resolves whether the public pricing feed is the active
// org-shaped price source on this node, and the feed metadata to display.
func (s *Server) feedPosture(ctx context.Context) dashboardFeedPosture {
	if s.opts.DB == nil {
		return dashboardFeedPosture{}
	}
	st := store.New(s.opts.DB)
	// An enrolled node (or one whose enrolment cannot be read) is never on the
	// public feed — the org rail is the authority (§C.3/D8).
	if enr, err := st.LoadEnrolment(ctx); err != nil || enr != nil {
		return dashboardFeedPosture{}
	}
	cache, err := st.LoadPricingFeed(ctx)
	if err != nil || !cache.Have {
		return dashboardFeedPosture{}
	}
	out := dashboardFeedPosture{
		Active:    true,
		Version:   cache.Envelope.FeedVersion,
		State:     cache.State,
		Economics: map[string]dashboardFeedEconomics{},
	}
	if !cache.FetchedAt.IsZero() {
		out.FetchedAt = cache.FetchedAt.UTC().Format(time.RFC3339)
	}
	for _, r := range cache.Envelope.Rows {
		if r.Economics == nil {
			continue
		}
		out.Economics[r.Model] = dashboardFeedEconomics{
			CacheMode:        r.Economics.CacheMode,
			ReasoningBilling: r.Economics.ReasoningBilling,
		}
	}
	return out
}

package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/pricingfeed"
	"github.com/marmutapp/superbased-observer/internal/sessiongauge"
)

// LoadModelContextWindows is the node's ONE composition of the per-model
// context-window table, every rung of it Tokenomics data (operator ruling
// 2026-09-30: no hand-coded context windows). Precedence, highest first,
// composed per lookup by sessiongauge.MergeWindows:
//
//  1. the ORG's windows, the unsigned context_windows sibling of the org's
//     pricing document this node persisted (orgcontract.PricingPolicyDoc
//     .ContextWindows, agent migration 106) - an enrolled node's org rail is
//     its one pricing authority and outranks the public feed;
//  2. economics.context_window_tokens of the node's own persisted public
//     pricing feed (agent migration 113), which a standalone node applies;
//  3. the compiled seed: the embedded Tokenomics snapshot's per-model windows
//     (cost.SnapshotContextWindows).
//
// This is the pricing ladder's seed -> feed/org order applied to a
// model-level fact; there is no local-override rung because a context window
// is not a rate the developer authors. A model no rung names is absent, so
// every consumer reads it as UNKNOWN, never as a default size.
//
// Each runtime rung's load error degrades that rung to empty. The error is
// non-nil only when BOTH runtime rungs failed to load (the returned table
// then holds the seed rung alone), so a caller that keeps a last-good table
// can prefer it.
//
// Consumers: the session context gauge (internal/intelligence/dashboard) and
// the routing capability filter (RoutingRefresher, `observer routing
// simulate`, the dashboard's simulate endpoint).
func (s *Store) LoadModelContextWindows(ctx context.Context) (sessiongauge.Windows, error) {
	var orgWindows, feedWindows sessiongauge.Windows
	orgPricing, orgErr := s.LoadOrgPricing(ctx)
	if orgErr == nil {
		orgWindows = sessiongauge.DocWindows(orgPricing.Document.ContextWindows)
	}
	feed, feedErr := s.LoadPricingFeed(ctx)
	if feedErr == nil {
		econ := map[string]*pricingfeed.Economics{}
		for _, row := range feed.Envelope.Rows {
			if row.Economics != nil {
				econ[row.Model] = row.Economics
			}
		}
		feedWindows = sessiongauge.ModelWindows(econ)
	}
	seedWindows := sessiongauge.Windows(cost.SnapshotContextWindows())
	merged := sessiongauge.MergeWindows(orgWindows, feedWindows, seedWindows)
	if orgErr != nil && feedErr != nil {
		return merged, fmt.Errorf("store.LoadModelContextWindows: %w", errors.Join(orgErr, feedErr))
	}
	return merged, nil
}

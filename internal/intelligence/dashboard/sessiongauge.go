package dashboard

import (
	"context"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/pricingfeed"
	"github.com/marmutapp/superbased-observer/internal/sessiongauge"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// sessiongauge.go wires the node's session detail onto the shared pure
// context-gauge derivation (internal/sessiongauge). The org session drawer
// (internal/orgserver/rollup) feeds the same derivation from its own copy of
// the rows, so the two dashboards report the same numbers (lane F-WIRE).

// windowCacheTTL bounds how stale the node's model context-window table may
// be. The table comes from the persisted pricing feed, which changes at most
// once per (opt-in) feed poll, while the session detail is polled every few
// seconds; re-decoding the stored feed envelope on every poll would be waste.
const windowCacheTTL = 5 * time.Minute

// windowCache is the Server's one owner of the cached model-window table.
type windowCache struct {
	mu       sync.Mutex
	loadedAt time.Time
	windows  sessiongauge.Windows
}

// modelWindows returns the node's model context-window table, composed in
// precedence order (sessiongauge.MergeWindows, highest first):
//
//  1. the ORG's windows, carried on the org's pricing document the node
//     persisted (org_pricing_cache, agent migration 106) as the UNSIGNED
//     context_windows sibling of the signed body
//     (orgcontract.PricingPolicyDoc.ContextWindows). The org lists every
//     model its feed economics names - the same table its own session
//     drawer reads - so an enrolled node's gauge reports the org's ratio,
//     including for a model the org's price book does not carry;
//  2. the economics.context_window_tokens of the node's own persisted
//     pricing feed (store.LoadPricingFeed, agent migration 113), which a
//     STANDALONE node accepts (an enrolled node ignores the public feed,
//     orgpricing.FeedApplies, so its stored feed is at most stale).
//
// This mirrors the pricing precedence: an enrolled node's org rail is its
// one authority and outranks the public feed. A node with neither has an
// empty table, and every model's window reads as unknown. Each source's load
// error degrades that source to empty; both failing keeps the last good
// table (or empty), never an error.
func (s *Server) modelWindows(ctx context.Context) sessiongauge.Windows {
	s.windows.mu.Lock()
	defer s.windows.mu.Unlock()
	now := time.Now()
	if !s.windows.loadedAt.IsZero() && now.Sub(s.windows.loadedAt) < windowCacheTTL {
		return s.windows.windows
	}
	s.windows.loadedAt = now
	st := store.New(s.db())
	var orgWindows, feedWindows sessiongauge.Windows
	orgPricing, orgErr := st.LoadOrgPricing(ctx)
	if orgErr == nil {
		orgWindows = sessiongauge.DocWindows(orgPricing.Document.ContextWindows)
	}
	feed, feedErr := st.LoadPricingFeed(ctx)
	if feedErr == nil {
		econ := map[string]*pricingfeed.Economics{}
		for _, row := range feed.Envelope.Rows {
			if row.Economics != nil {
				econ[row.Model] = row.Economics
			}
		}
		feedWindows = sessiongauge.ModelWindows(econ)
	}
	if orgErr != nil && feedErr != nil {
		return s.windows.windows
	}
	s.windows.windows = sessiongauge.MergeWindows(orgWindows, feedWindows)
	return s.windows.windows
}

// sessionContextGauge derives one session's context-window gauge from its
// counted turn rows, its reported prompt-context budget and the model window
// table. sessionModel is the raw sessions.model (the derivation applies the
// dominant-turn-model fallback itself, exactly as the org does). A load error
// degrades to an empty gauge (unknown), never a failed detail page.
func (s *Server) sessionContextGauge(ctx context.Context, sessionID, sessionModel string) sessiongauge.ContextGauge {
	turns, err := store.New(s.db()).LoadSessionGaugeTurns(ctx, sessionID)
	if err != nil {
		turns = nil
	}
	return sessiongauge.Context(sessiongauge.ContextInput{
		Turns:          turns,
		SessionModel:   sessionModel,
		ReportedBudget: s.sessionContextBudget(ctx, sessionID),
		Windows:        s.modelWindows(ctx),
	})
}

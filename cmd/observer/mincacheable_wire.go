package main

import (
	"context"
	"log/slog"

	"github.com/marmutapp/superbased-observer/internal/cachetrack"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// COMPOSITION SITE for the min-cacheable registry.
//
// internal/cachetrack owns the registry; this file decides WHICH published
// sources feed it and in what order. That split is deliberate: cachetrack is a
// pure package and must not learn about embedded files, SQLite or enrolment,
// and the ordering question ("does a run-time feed beat a build-time
// snapshot?") is a composition decision, which belongs where the daemon is
// assembled — the same shape as orgPricingLoader next door.
//
// The ladder, lowest first:
//
//  1. the generated build-time snapshot embedded in the cost package
//     (internal/intelligence/cost.SnapshotMinCacheable) — a projection of the
//     Tokenomics model_economics curation as of the build;
//  2. the node-local VERIFIED pricing-feed envelope, when this node has one —
//     newer than the snapshot by construction, so it wins per model.
//
// Anything neither source names keeps the compiled cachetrack table. That is
// why this is additive and why a node with no feed and a zero snapshot behaves
// exactly as it did before the seam existed.
//
// TWO CALL SITES, ONE COMPOSITION. wireCacheTrack calls this at startup, before
// the engine observes its first turn, and pricingAutoSyncOnce calls it again
// after every successfully persisted feed sync (review finding 8) so a running
// daemon picks up a newly published minimum without a restart. Both go through
// this function, so the snapshot-then-feed order cannot drift between them.
//
// The ORG rail is deliberately absent from this ladder. orgcontract's
// PricingPolicyRow carries rates only — it has no economics field — so an
// enrolled node has no org-supplied min-cacheable to compose. Pretending
// otherwise would mean inventing the number, which is the one thing this whole
// lane exists to stop.
func applyMinCacheableOverrides(ctx context.Context, st *store.Store, logger *slog.Logger) {
	merged := cost.SnapshotMinCacheable()
	snapshotCount := len(merged)

	feedCount := 0
	if st != nil {
		// LoadPricingFeed returns the node-local cache of an envelope this node
		// already fetched AND verified (the standalone lane). Reading it costs
		// no egress; a node that never opted in simply has nothing stored.
		if cache, err := st.LoadPricingFeed(ctx); err != nil {
			if logger != nil {
				logger.Warn("cachetrack: pricing feed cache unreadable; min-cacheable stays on the compiled table plus snapshot", "err", err)
			}
		} else if why := cost.FeedVersionRefusal(cache.Envelope.FeedVersion, cache.Envelope.Digest, false, 0, ""); cache.Have && why != "" {
			// Same compiled floor as the price rail (round-2 finding 1): a
			// cached body below it contributes nothing.
			if logger != nil {
				logger.Warn("cachetrack: cached pricing feed refused; min-cacheable stays on the compiled table plus snapshot", "reason", why)
			}
		} else if cache.Have {
			for _, r := range cache.Envelope.Rows {
				if r.Economics == nil || r.Economics.MinCacheableTokens == nil {
					continue
				}
				if v := *r.Economics.MinCacheableTokens; v > 0 {
					merged[r.Model] = int(v)
					feedCount++
				}
			}
		}
	}

	if len(merged) == 0 {
		// Explicit, not implicit: clearing restores the compiled table exactly,
		// which matters when a previously-applied feed is withdrawn.
		cachetrack.SetMinCacheableOverrides(nil)
		return
	}
	cachetrack.SetMinCacheableOverrides(merged)
	if logger != nil {
		logger.Info("cachetrack: published min-cacheable prefixes applied",
			"from_snapshot", snapshotCount, "from_feed", feedCount,
			"in_force", cachetrack.MinCacheableOverrideCount())
	}
}

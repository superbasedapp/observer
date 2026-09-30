package cachetrack

import (
	"sort"
	"strings"
	"sync/atomic"
)

// THE MIN-CACHEABLE REGISTRY, AS DATA.
//
// THE PROBLEM. Registering a new model has historically meant editing THREE
// hand-maintained Go tables, not one: the cost pricing table, this package's
// [minCacheableTable], and the routing tier seed. A miss in the first prices a
// turn at $0.00 silently; a wrong value here is quieter but not harmless - a
// prefix the provider really cached gets labelled kind='below_min' /
// cause='below_min_cacheable', or a predicted write that never happens
// self-grades as a mispredict, and the engine's own accuracy metric drifts.
//
// THE FIX. The Tokenomics publisher already carries this fact as DATA:
// pricingfeed.Economics.MinCacheableTokens, curated per model in the catalog's
// model_economics table (docs playbook section 10.2). It reaches a node two
// ways - baked into the generated price snapshot at build time
// (internal/intelligence/cost.SnapshotMinCacheable), and over the wire in the
// verified feed envelope at run time. This file is the ONE seam that lets
// either of them SUPERSEDE the compiled table without a release.
//
// PRECEDENCE, and why the compiled table is never deleted:
//
//	override (published data, when it names the model) -> minCacheableTable -> defaultMinCacheable
//
// The override wins where it SPEAKS and is silent everywhere else. The compiled
// table stays as the permanent floor because the publisher's coverage is
// partial by construction (it names models it has curated; it has never heard
// of a vendor-decorated Bedrock id), and because an override that cleared the
// table would turn a gap in curation into a silently wrong 1,024 default.
//
// ONE OWNER. This package owns the registry; the composition (which sources,
// in which order) is the caller's job and happens once at wiring time in
// cmd/observer. Nothing here reads a database, a file or the network - the
// package stays pure, and the values arrive as a plain map.

// minCacheableOverrides holds the published per-model minimums, or nil.
//
// It is an atomic.Pointer for the same reason routing's TierTable is: readers
// are on the hot observe path and must never take a lock, while the writer is a
// once-at-wiring-time (and, for a standalone node that re-syncs its feed,
// occasionally-again) whole-map replacement. A reader that captured the old map
// keeps a consistent view for the rest of its call.
var minCacheableOverrides atomic.Pointer[minCacheableOverrideSet]

// minCacheableOverrideSet is the published data, pre-ordered for a
// deterministic walk.
type minCacheableOverrideSet struct {
	// keys are the override model ids, lowercased, sorted LONGEST FIRST so the
	// walk is deterministic and the most specific id wins. Two override ids can
	// legitimately be substrings of one another (`claude-opus-5` and
	// `claude-opus-5-5`); without an order the answer would depend on map
	// iteration, which is randomized.
	keys []string
	byID map[string]int
}

// SetMinCacheableOverrides installs the published per-model minimum cacheable
// prefix lengths, replacing any previous set.
//
// Keys are model ids as the publisher states them; they are lowercased here so
// a caller never has to know that the lookup is case-insensitive. A
// non-positive value is DROPPED rather than stored: zero is how "the publisher
// said nothing" arrives after a JSON round-trip, and storing it would claim
// every prefix is cacheable.
//
// Passing nil or an empty map clears the overrides and restores the compiled
// table exactly. That is the honest reset - a node whose feed was withdrawn
// falls back to what it shipped with, never to "no minimum".
func SetMinCacheableOverrides(m map[string]int) {
	if len(m) == 0 {
		minCacheableOverrides.Store(nil)
		return
	}
	set := &minCacheableOverrideSet{byID: make(map[string]int, len(m))}
	for k, v := range m {
		key := strings.ToLower(strings.TrimSpace(k))
		if key == "" || v <= 0 {
			continue
		}
		set.byID[key] = v
	}
	if len(set.byID) == 0 {
		minCacheableOverrides.Store(nil)
		return
	}
	set.keys = make([]string, 0, len(set.byID))
	for k := range set.byID {
		set.keys = append(set.keys, k)
	}
	sort.Slice(set.keys, func(i, j int) bool {
		if len(set.keys[i]) != len(set.keys[j]) {
			return len(set.keys[i]) > len(set.keys[j])
		}
		return set.keys[i] < set.keys[j]
	})
	minCacheableOverrides.Store(set)
}

// MinCacheableOverrideCount reports how many published minimums are in force.
// Surfaces use it to say whether this node's cache thresholds are the compiled
// ones or the published ones; it is also what a test asserts against without
// reaching into package state.
func MinCacheableOverrideCount() int {
	set := minCacheableOverrides.Load()
	if set == nil {
		return 0
	}
	return len(set.byID)
}

// lookupMinCacheableOverride resolves model against the published set.
//
// The match is a SUBSTRING scan over the lowercased id, exactly like
// [minCacheableTable]'s, and for the same reason: a live model string carries
// SKU decorations the publisher's canonical id does not
// (`claude-opus-5-5-20260922`, `us.anthropic.claude-opus-5-5-v1:0`). Walking
// longest-key-first makes the most specific published id win, so an override
// for `claude-opus-5-5` is never shadowed by one for `claude-opus-5`.
func lookupMinCacheableOverride(lowered string) (int, bool) {
	set := minCacheableOverrides.Load()
	if set == nil {
		return 0, false
	}
	if v, ok := set.byID[lowered]; ok {
		return v, true
	}
	for _, k := range set.keys {
		if strings.Contains(lowered, k) {
			return set.byID[k], true
		}
	}
	return 0, false
}

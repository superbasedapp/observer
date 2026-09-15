// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package orgcontract

import "github.com/marmutapp/superbased-observer/internal/cachetrack"

// cacheeventsession.go carries the PER-EVENT cache timeline to the org
// (operator directive item 6; server migration 142).
//
// WHY, GIVEN cachesession.go ALREADY EXISTS. SessionCacheRow is a BUCKET —
// counts and token sums per (session, model, tier, kind, cause, zero_usage).
// The node's Cache tab does not render buckets: it renders a chronological
// timeline (internal/cachetrack.BuildTimeline) that collapses contiguous runs
// of baseline events into one roll-up row and itemizes every anomaly, in
// order. A bucket cannot be un-bucketed, so the org tab has been rendering a
// synthesized approximation next to a disclaimer that the raw event log "never
// crosses to the org". This row is that stance being removed: it carries every
// field cachetrack.TimelineEvent needs, so the org runs the SAME pure builder
// over the SAME events and the two surfaces cannot drift.
//
// THE POSTURE IS ENTERPRISE-RAW, NOT THE cache_detail TEAMS TIER. This wire
// ships under ShareOptions.shipsRawContent() (FullContent || AdminManaged ||
// EnterpriseGranted) — the SessionCacheRow posture, deliberately NOT the
// `cache_detail` flag. cache_detail gates the CONTENT-FREE FLEET day-aggregate
// (CacheSummaryRow) and stays orthogonal in both directions: a
// cache_detail-only node ships day buckets and NOT this log, and a
// full_content node ships this log without ever enabling cache_detail.
// Session-scoped per-event telemetry is per-developer detail the enterprise
// posture treats as admin-visible-by-default, which is a different decision
// from a fleet aggregate's opt-in.
//
// THE PRIVACY SENTINEL IS UNCHANGED, ON PURPOSE. `cache_events` REMAINS in
// tests/invariant/privacy_test.go's forbiddenCacheTables set. That sentinel is
// a SOURCE-LEVEL rule about internal/store/orgpush.go — the table name may not
// appear there — and it still holds: the read lives in
// internal/store/cacheeventorgrows.go, its own seam file, exactly as
// SelectCacheSummaries and SelectSessionCacheSummaries already do. The DATA
// posture is pinned instead by the named test
// TestSessionCacheEventsShipOnlyUnderRawContent.
//
// WHAT IS DELIBERATELY EXCLUDED:
//
//   - cache_events.`detail`, the engine's bounded diagnostic JSON. It has no
//     stable schema, no org reader and no honest retention story; there is no
//     field for it here and the seam does not SELECT it. This is a policy
//     exclusion, pinned by the privacy test's `detail`-sentinel case.
//   - The cache SCOPE and PREFIX hashes (cache_entries.cache_scope /
//     prefix_hash, cache_segments.prefix_hash) — the auth-identity and
//     prompt-prefix chain hashes. They live in tables this wire does not read
//     at all, and no timeline field needs them.
//   - api_turn_id / token_usage_id — node-local row ids with no org-side
//     referent. MessageID ships instead, because that is what the node's own
//     TimelineEvent carries and what a drawer joins a message on.
//
// HONESTY OF NULLS. Cause, DivergedSeq, DivergedLevel, CostDeltaUSD,
// PredictedKind and MessageID are all optional at the source. The two NUMERIC
// ones are pointers rather than zero-valued scalars because zero is a REAL
// reading for both: DivergedSeq == 0 means the FIRST block diverged, and
// CostDeltaUSD == 0 means a genuinely zero delta. Collapsing "not computed"
// onto 0 would make the org timeline claim something the node never said.
//
// ZeroUsage IS NOT A FIELD. cachetrack.IsZeroUsage is THE one rule — a
// KindMispredict whose token pair is both zero — and ZeroUsageOf below simply
// delegates to it. Shipping a zero_usage field as well would create a second
// source of truth that could disagree with the Kind and tokens beside it, so
// every reader spells the rule through the one predicate instead.

// SessionCacheEventRow is ONE node cache_events row on the wire — the
// per-event substrate for the org's session cache timeline.
//
// Its natural key is (org_id, pushed_by_user_id, node_event_id): NodeEventID
// is the node's own autoincrement id, unique per NODE and not per org, so the
// PUSHER is part of the identity. Two developers in one org both have a
// cache_events row #1; collapsing them would silently destroy one developer's
// timeline. Because the node recomputes a bounded trailing window, the same id
// re-arrives on later ticks and upserts in place.
type SessionCacheEventRow struct {
	// OrgID / UserEmail are the agent-stamped attribution (the server
	// re-stamps both from the authenticated pusher).
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`

	// SessionID is the session the event belongs to.
	SessionID string `json:"session_id"`

	// NodeEventID is the node's own cache_events.id — the idempotency key,
	// scoped by the pusher. It is NOT a stable org-wide identifier and no
	// surface should render it.
	NodeEventID int64 `json:"node_event_id"`

	// Tier is the cache-observation tier: "proxy" | "transcript" | "counts".
	// Carried PER EVENT rather than collapsed at the node, so
	// cachetrack.CollapseTier produces the same proxy/transcript/mixed/none
	// badge the node shows.
	Tier string `json:"tier"`

	// Timestamp is the event time (the timeline's ordering key).
	Timestamp string `json:"timestamp"`

	// Model is the model the event was observed against.
	Model string `json:"model"`

	// Kind is the event class: hit | write | expiry_rewrite |
	// invalidation_rewrite | model_switch_rewrite | compaction_reset |
	// reanchor | mispredict | below_min.
	Kind string `json:"kind"`

	// Cause is the §7 cause vocabulary; empty when the engine attributed none.
	// BuildTimeline's baseline/anomaly split reads it (baseline is
	// hit-or-write with cause=suffix_growth), and its Flagged pill keys off
	// the known-limitation causes, so it must ship verbatim.
	Cause string `json:"cause,omitempty"`

	// DivergedSeq is the first differing block index vs the prior turn and
	// DivergedLevel the level it diverged at (tools|system|message|unknown).
	// DivergedSeq is a POINTER: nil = the engine did not compute it, whereas 0
	// means the FIRST block diverged.
	DivergedSeq   *int64 `json:"diverged_seq,omitempty"`
	DivergedLevel string `json:"diverged_level,omitempty"`

	// TokensRead / TokensWritten are the event's cache token movement, and
	// TokensWritten1H the 1h-tier share of the write. Together with the two
	// above they are what the efficiency tile and the mispredict-rate
	// denominator are computed from.
	TokensRead      int64 `json:"tokens_read"`
	TokensWritten   int64 `json:"tokens_written"`
	TokensWritten1H int64 `json:"tokens_written_1h,omitempty"`

	// CostDeltaUSD is the write paid minus the hypothetical read price. A
	// POINTER for the same reason as DivergedSeq: nil = not computed, 0 = a
	// genuinely zero delta. cachetrack.BuildEfficiency's AvoidableUSD is fed
	// from this once the reconciliation engine populates it.
	CostDeltaUSD *float64 `json:"cost_delta_usd,omitempty"`

	// PredictedKind is what the engine EXPECTED. A row where it differs from
	// Kind is exactly what the mispredict rate grades, so it ships rather than
	// being collapsed server-side into a boolean.
	PredictedKind string `json:"predicted_kind,omitempty"`

	// MessageID is the provider message id, so a drawer can join a cache event
	// to the message it belongs to. Empty on pre-037 node rows and on tiers
	// with no message id.
	MessageID string `json:"message_id,omitempty"`
}

// ZeroUsageOf reports whether an event is observationally vacant — a
// KindMispredict whose provider envelope carried no token data at all (read
// and written both zero). It delegates to cachetrack.IsZeroUsage, THE one
// rule, so the org spelling cannot drift from the node's: a 0/0 hit or write
// is NOT vacant. It is DERIVED, never shipped as its own field, so the flag
// and the Kind/tokens beside it cannot disagree. cachetrack
// (MispredictRateGraded) excludes these from mispredict-rate grading and
// surfaces them as "[zero-usage, excluded from rate]".
func (r SessionCacheEventRow) ZeroUsageOf() bool {
	return cachetrack.IsZeroUsage(r.Kind, r.TokensRead, r.TokensWritten)
}

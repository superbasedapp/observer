package cachetrack

// This file is the ONE OWNER of the cache-events → session timeline
// builder. It was extracted from internal/intelligence/dashboard/cache.go
// (the node dashboard's Cache tab) so the same pure logic can be reused by
// the org server, which will build the identical timeline over per-event
// rows that arrive on the wire. The dashboard package keeps its existing
// exported names as type aliases + thin delegating functions so the
// /api/session/<id>/cache JSON shape is unchanged.

// TimelineEvent mirrors a cache_events row for the diagnostic dump
// alongside the timeline. ZeroUsage is [IsZeroUsage] over (Kind,
// TokensRead, TokensWritten) — a mispredict whose provider envelope
// carried no token data at all; callers render these neutrally and the
// graded rate excludes them per the C12 follow-up (MispredictRateGraded).
//
// CostDeltaUSD is a POINTER: nil = the reconciliation engine did not
// compute a cost delta for this event, 0 = a genuinely zero delta. This
// is the same nil-vs-zero convention the wire row carries
// (orgcontract.SessionCacheEventRow.CostDeltaUSD), and it is what
// [BuildEfficiency] sums into AvoidableUSD — a nil delta contributes
// nothing, never a fabricated zero.
type TimelineEvent struct {
	Timestamp     string   `json:"timestamp"`
	Tier          string   `json:"tier"`
	Model         string   `json:"model"`
	Kind          string   `json:"kind"`
	Cause         string   `json:"cause"`
	PredictedKind string   `json:"predicted_kind,omitempty"`
	TokensRead    int64    `json:"tokens_read"`
	TokensWritten int64    `json:"tokens_written"`
	MessageID     string   `json:"message_id,omitempty"`
	ZeroUsage     bool     `json:"zero_usage,omitempty"`
	CostDeltaUSD  *float64 `json:"cost_delta_usd,omitempty"`
}

// IsZeroUsage is THE one rule for "observationally vacant" cache events,
// spelled the same way at every surface: the node dashboard's per-event
// fill and its annotation counts, the org rollup's per-event fill and its
// anomaly bucket, and orgcontract.SessionCacheEventRow.ZeroUsageOf. An
// event is zero-usage iff it is a KindMispredict AND its provider envelope
// carried no token data at all (tokensRead == 0 AND tokensWritten == 0).
// Such a turn predicted SOMETHING but the provider returned nothing to
// grade against, so counting it as a mispredict is metric distortion —
// [MispredictRateGraded] drops it from the denominator and surfaces it as
// "[zero-usage, excluded from rate]".
//
// A NON-mispredict event with a zero token pair is NOT zero-usage: a hit or
// a write can legitimately move zero cache tokens (a below-threshold turn,
// a suffix-growth write of nothing new), and marking those "vacant" would
// hide real, correctly-graded events behind the neutral marker.
func IsZeroUsage(kind string, tokensRead, tokensWritten int64) bool {
	return kind == string(KindMispredict) && tokensRead == 0 && tokensWritten == 0
}

// TimelineItem is one row of the session cache timeline. The operator UI
// steer: a long warm session produces 100+ baseline events (suffix_growth
// / hit) that the user doesn't need to scroll through one-by-one. Two
// kinds:
//
//   - Kind="baseline" — a single roll-up entry per contiguous run of
//     baseline events. Count + first/last timestamps + summed token
//     movement. Anomalies break runs.
//   - Kind="anomaly" — a fully itemized event. One row per non-baseline
//     event (rewrites, mispredicts, model_changed, reanchor, etc.) plus a
//     Flagged bool the caller uses to render a neutral "flagged" pill
//     (not alarm-red) for known-limitation causes like tools_changed
//     where the reading is correct but the alert level is reduced.
//
// The two are interleaved in chronological order.
type TimelineItem struct {
	Kind string `json:"kind"` // "baseline" | "anomaly"

	// Baseline-only fields.
	Count            int    `json:"count,omitempty"`
	BaselineReadSum  int64  `json:"baseline_read_sum,omitempty"`
	BaselineWriteSum int64  `json:"baseline_write_sum,omitempty"`
	FirstAt          string `json:"first_at,omitempty"`
	LastAt           string `json:"last_at,omitempty"`

	// Anomaly-only fields.
	Event   *TimelineEvent `json:"event,omitempty"`
	Flagged bool           `json:"flagged,omitempty"`
}

// Efficiency is the rollup tile summarizing a set of events. Ratio is
// read/write — the cache-payback signal (higher = more cache benefit).
// AvoidableUSD is the sum of the per-event cost_delta_usd over the
// avoidable, non-baseline events (see [BuildEfficiency] for the exact
// rule). It stays 0 while the reconciliation engine has not populated any
// event's cost_delta_usd — a NULL column contributes nothing, so the tile
// reads "not yet computed" rather than a fabricated $0.00.
type Efficiency struct {
	ReadTokens    int64   `json:"read_tokens"`
	WrittenTokens int64   `json:"written_tokens"`
	Ratio         float64 `json:"ratio"`
	AvoidableUSD  float64 `json:"avoidable_usd"`
}

// CollapseTier returns the single-string tier label for a set of events.
// "proxy" or "transcript" when all events share one tier; "mixed" when
// both appear; "none" on empty.
func CollapseTier(events []TimelineEvent) string {
	if len(events) == 0 {
		return "none"
	}
	seen := map[string]bool{}
	for _, ev := range events {
		if ev.Tier != "" {
			seen[ev.Tier] = true
		}
	}
	if len(seen) == 0 {
		return "none"
	}
	if len(seen) > 1 {
		return "mixed"
	}
	for t := range seen {
		return t
	}
	return "none"
}

// BuildEfficiency rolls per-event tokens into an efficiency tile. Ratio is
// read/write; division-by-zero falls through to 0 (no writes = no cache
// yet = no payback signal).
//
// AvoidableUSD is the sum of cost_delta_usd over the events that are NOT
// baseline ([IsBaselineEvent]) AND whose delta is non-nil AND > 0. The
// three conditions are each load-bearing:
//
//   - A nil cost_delta_usd means the reconciliation engine did not compute
//     one; it contributes nothing, so a session whose events all carry NULL
//     deltas keeps AvoidableUSD == 0 and the tile stays honestly blank.
//   - Baseline suffix-growth writes are unavoidable by definition — every
//     turn writes some new suffix — so their delta is never "avoidable"
//     spend and is excluded even when populated.
//   - A negative delta is a SAVING (the write cost less than the read it
//     replaced), not avoidable spend, so only positive deltas are summed.
func BuildEfficiency(events []TimelineEvent) Efficiency {
	var eff Efficiency
	for _, ev := range events {
		eff.ReadTokens += ev.TokensRead
		eff.WrittenTokens += ev.TokensWritten
		if ev.CostDeltaUSD != nil && *ev.CostDeltaUSD > 0 && !IsBaselineEvent(ev) {
			eff.AvoidableUSD += *ev.CostDeltaUSD
		}
	}
	if eff.WrittenTokens > 0 {
		eff.Ratio = float64(eff.ReadTokens) / float64(eff.WrittenTokens)
	}
	return eff
}

// BuildTimeline produces the interleaved baseline-roll-up + anomaly-
// itemized timeline. Operator UI steer #1: a long warm session produces
// 100+ suffix_growth events that the user does NOT want itemized —
// collapse them into a single roll-up row per CONTIGUOUS RUN of baseline
// events. Anomalies break runs + land as their own rows.
//
// "Baseline" = (kind=hit OR kind=write) AND cause=suffix_growth. Every
// other event is an anomaly.
//
// Operator UI steer #2: causes that may legitimately fire on a real
// toggle (`tools_changed` after MCP server connect / disconnect —
// documented as known limitation in docs/cache-tracking.md) get
// Flagged=true. Callers render these with a neutral "flagged" pill, not
// alarm-red. The existing per-event diagnostic stays the same — only the
// pill styling differs.
func BuildTimeline(events []TimelineEvent) []TimelineItem {
	out := []TimelineItem{}
	var runStart, runEnd string
	var runCount int
	var runRead, runWrite int64

	flushBaseline := func() {
		if runCount == 0 {
			return
		}
		out = append(out, TimelineItem{
			Kind:             "baseline",
			Count:            runCount,
			BaselineReadSum:  runRead,
			BaselineWriteSum: runWrite,
			FirstAt:          runStart,
			LastAt:           runEnd,
		})
		runCount, runRead, runWrite = 0, 0, 0
		runStart, runEnd = "", ""
	}

	for i := range events {
		ev := events[i]
		if IsBaselineEvent(ev) {
			if runCount == 0 {
				runStart = ev.Timestamp
			}
			runEnd = ev.Timestamp
			runCount++
			runRead += ev.TokensRead
			runWrite += ev.TokensWritten
			continue
		}
		flushBaseline()
		evCopy := ev
		out = append(out, TimelineItem{
			Kind:    "anomaly",
			Event:   &evCopy,
			Flagged: IsFlaggedCause(ev.Cause),
		})
	}
	flushBaseline()
	return out
}

// IsBaselineEvent reports whether an event is part of the healthy
// warm-growth baseline (collapsed into the timeline's baseline roll-up
// rows). hit+suffix_growth is a cache hit on the predicted prefix;
// write+suffix_growth is the normal per-turn incremental write (every
// turn writes SOME new suffix; that's not pathological).
//
// reanchor is NOT baseline — it's the first turn for a session and rates
// the visibility on a session-detail page. Per the existing rate-skipped
// list it's denominator-excluded, but callers still itemize it.
//
// Zero-usage mispredict events are also itemized (callers render them
// with the [zero-usage, excluded from rate] marker per the C12
// follow-up).
func IsBaselineEvent(ev TimelineEvent) bool {
	if ev.Cause != "suffix_growth" {
		return false
	}
	return ev.Kind == "hit" || ev.Kind == "write"
}

// flaggedCauses lists causes that may legitimately fire on a real
// operator toggle. Callers render these neutrally (a "flagged" pill, not
// "alarm").
//
// tools_changed: MCP server connect/disconnect legitimately changes the
// tools array; the prior-prefix warm read combined with the new-tail
// rewrite trips the read:write WARN at the 3.0× default threshold even
// though the cause attribution is correct
// (docs/cache-tracking.md#mcp-tools_changed-readwrite-over-flag).
var flaggedCauses = map[string]bool{
	"tools_changed": true,
}

// IsFlaggedCause reports whether cause is a known-limitation cause that
// should render as a neutral "flagged" pill rather than alarm-red.
func IsFlaggedCause(cause string) bool {
	return flaggedCauses[cause]
}

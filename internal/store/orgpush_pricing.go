package store

import (
	"math"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// PushTokenSplit is the content-free token split of ONE token_usage row,
// handed to the injected OrgPushPricer. It mirrors the dashboard's
// cost.TokenBundle field-for-field (input / output / cache_read /
// cache_creation (+1h subset) / reasoning / web_search / fast) WITHOUT
// importing the cost package into the push seam — the seam stays a pure
// row reader and the pricing math stays in ONE place
// (cost.ComputeBreakdown, reached through the injected func).
//
// Fast is the node-local token_usage.fast flag (migration 035). It is an
// INPUT to pricing only — it never becomes a wire field (the wire ships
// the priced dollar amount, exactly as the migration's header promises).
type PushTokenSplit struct {
	Input             int64
	Output            int64
	CacheRead         int64
	CacheCreation     int64
	CacheCreation1h   int64
	Reasoning         int64
	WebSearchRequests int64
	Fast              bool
}

// OrgPushPricer prices one token_usage row at push time. `at` is the
// row's own timestamp (zero when unparseable — the pricer's date-aware
// lookup then falls back to current rates, the same contract the node
// dashboard's cost.Summary applies). ok=false means "model unknown to the
// pricing table": the wire keeps the stored $0 rather than inventing a
// number. Pure by contract — no SQL, no I/O; the ONE implementation is
// assembled in cmd/observer from the same cost.Engine the dashboard
// prices with (one engine, one pricing truth).
//
// Why it exists (G1-COST(b)): most adapters store
// token_usage.estimated_cost_usd = 0 and the NODE prices read-side, but
// the org rollup (internal/orgserver/rollup/cost.go::spendCTE) SUMS the
// shipped column, so every hook-only / non-proxied row landed as $0 on
// the org dashboard. Pricing the row here — and only here, the single
// wire seam — closes that gap without a wire-shape change: the existing
// estimated_cost_usd field is filled, so v1.7 servers keep working.
type OrgPushPricer func(model string, at time.Time, split PushTokenSplit) (usd float64, ok bool)

// SetOrgPushPricer wires the push-time token_usage pricer. Same pattern as
// SetCacheEngine / SetObsOrgProviders: idempotent, set once at
// composition (cmd/observer/org.go::buildOrgBundle); nil disables the
// seam, which is the pre-G1-COST(b) behaviour (rows ship with whatever
// cost the adapter stored).
func (s *Store) SetOrgPushPricer(p OrgPushPricer) {
	s.pushPricer = p
}

// priceTokenUsageRow fills r.EstimatedCostUSD for a token_usage wire row
// whose STORED cost is zero. Rules (all deliberate, all tested in
// orgpush_pricing_test.go):
//
//   - a non-zero stored cost is NEVER overwritten — that number is either
//     provider/client-reported (OpenCode, Pi, commandcode's costUsd) or
//     the proxy's own insert-time pricing, and both outrank a re-price;
//   - api_turns rows are never touched (they are proxy-priced at insert
//     and live in a different loop entirely — this helper is only called
//     from the token_usage arm);
//   - an unknown model (ok=false) leaves $0 — never NaN, never a guess;
//   - a NaN / ±Inf / negative result from a misbehaving pricer is
//     discarded (the wire carries $0), so a pricing-table bug can never
//     poison the org rollup's SUM.
func (s *Store) priceTokenUsageRow(r *orgcontract.TokenUsageRow, fast bool) {
	if s.pushPricer == nil || r == nil || r.EstimatedCostUSD != 0 {
		return
	}
	at, _ := time.Parse(time.RFC3339Nano, r.Timestamp)
	usd, ok := s.pushPricer(r.Model, at, PushTokenSplit{
		Input:             r.InputTokens,
		Output:            r.OutputTokens,
		CacheRead:         r.CacheReadTokens,
		CacheCreation:     r.CacheCreationTokens,
		CacheCreation1h:   r.CacheCreation1hTokens,
		Reasoning:         r.ReasoningTokens,
		WebSearchRequests: r.WebSearchRequests,
		Fast:              fast,
	})
	if !ok || math.IsNaN(usd) || math.IsInf(usd, 0) || usd < 0 {
		return
	}
	r.EstimatedCostUSD = usd
}

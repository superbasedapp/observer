package sessionmsg

import "strings"

// sessionCumulativePrefix is the source_event_id prefix a session-cumulative
// adapter gives its ONE running-total token row ("tokens:<session-id>" /
// "tokens:session:<id>": droid, goose, crush, mistral-code). The prefix alone
// is not enough - aider keys its PER-EXCHANGE rows "tokens:<chat>:<seq>" too -
// so a row is cumulative only when the session's tool also declares
// TokenTier.SessionCumulative (DeriveInput.SessionCumulative).
const sessionCumulativePrefix = "tokens:"

// isCumulativeRow reports whether t is a session-cumulative running total.
func isCumulativeRow(t TokenRow, sessionCumulative bool) bool {
	return sessionCumulative && strings.HasPrefix(t.SourceEventID, sessionCumulativePrefix)
}

// billableToken is every token dimension a token row bills: net input,
// output plus reasoning, both cache tiers and web-search requests. It is the
// coverage measure of the session-cumulative reconciliation: a capture thin
// on input/output but heavy on cache reads (the dominant cost of a long
// session) must not lose a comparison because those columns were left out.
func billableToken(t TokenRow) int64 {
	return t.Input + t.Output + t.Reasoning + t.CacheRead + t.CacheCreation + t.CacheCreation1h + t.WebSearchRequests
}

// billableProxy is billableToken for a proxy row, whose output is already
// gross (visible + reasoning) and which carries no reasoning of its own.
func billableProxy(p ProxyRow) int64 {
	return p.Input + p.Output + p.CacheRead + p.CacheCreation + p.CacheCreation1h + p.WebSearchRequests
}

// reconcileCumulative resolves a session that carries session-cumulative
// token rows, and reports whether it did (false: the session has none, and
// planDedup runs the ordinary per-turn pairing over every row).
//
// A cumulative row is a running total for the WHOLE session, so it can never
// pair with one proxy turn by shape or id: left to the per-turn pairing it
// would count on top of every token the proxy (and any per-turn transcript
// row) already captured. So the session's capture is split into two
// COVERAGE SETS - the cumulative rows, and everything else (proxy rows plus
// per-turn token rows, deduplicated against each other by the ordinary
// per-turn pairing so a turn both captured counts once) - and the set with
// the larger billable total wins WHOLESALE:
//
//   - the other set captured nothing billable: nothing to reconcile; every
//     row goes through the ordinary per-turn pairing;
//   - the cumulative rows captured more: they count, and every proxy row and
//     per-turn token row is dropped (the proxy rows keep their message rows,
//     without spend - see foldProxyRows);
//   - otherwise: the cumulative rows are dropped and the rest is paired as
//     usual.
//
// Never both sets, and never a partial merge. This was the node cost engine's
// reconcileSessionAggregates, which ran BEFORE its per-turn pass and so held
// a second copy of the pairing rule for its coverage tally; it lives here so
// the session header, both Messages tabs, the stored verdicts and every
// windowed surface apply it identically.
func reconcileCumulative(plan *dedupPlan, in DeriveInput) bool {
	var agg, rest []int
	for i, t := range plan.tokens {
		if isCumulativeRow(t, in.SessionCumulative) {
			agg = append(agg, i)
		} else {
			rest = append(rest, i)
		}
	}
	if len(agg) == 0 {
		return false
	}
	// The per-turn side's coverage, deduplicated by the ordinary pairing.
	plan.pair(true, rest, in.ShadowCapable)
	var other int64
	for _, p := range plan.proxies {
		other += billableProxy(p)
	}
	for _, i := range rest {
		if !plan.tokenDropped(i) {
			other += billableToken(plan.tokens[i])
		}
	}
	var cumulative int64
	for _, i := range agg {
		cumulative += billableToken(plan.tokens[i])
	}
	switch {
	case other == 0:
		plan.pair(true, identityIndex(len(plan.tokens)), in.ShadowCapable)
	case cumulative > other:
		for i := range plan.proxyDropped {
			plan.proxyDropped[i] = true
		}
		for _, i := range rest {
			plan.tokenReconciled[i] = true
		}
		plan.pair(false, agg, in.ShadowCapable)
	default:
		for _, i := range agg {
			plan.tokenReconciled[i] = true
		}
		// plan already holds the pairing over the per-turn side.
	}
	return true
}

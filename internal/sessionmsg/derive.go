package sessionmsg

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Derive is the one shared message-bucketing algorithm. It takes the raw,
// already-loaded rows for a single session and returns the ordered message
// rows: token/proxy rows bucketed by group key (with proxy/JSONL twin
// folding and Copilot-family shadow-row pairing), actions bucketed onto
// those rows (synthesizing a bare row for any action whose key matches
// none), and a final deterministic chronological sort with Seq assigned.
//
// A proxy/token row with NO real identity field (empty request_id /
// message_id / source_event_id / turn_id — a legacy pre-fallback capture)
// is never dropped: it gets a synthesized keylessKey and Row.Keyless=true
// instead of being silently skipped (review round 5 finding #7 — every
// caller of Derive, including the org's SessionMessageMetrics, now sees the
// SAME row for the SAME legacy data, closing the divergence where only the
// node's Session Detail endpoint counted it via its own now-removed local
// synthesis). The synthesized key is derived from the row's own CONTENT
// (a fingerprint over its stable fields), never its position in whatever
// order the caller's SQL scan happened to hand rows to Derive in (round 6
// finding F3 — two equal-timestamp keyless rows have no engine-portable
// scan-order guarantee, so an ordinal-position key could name a different
// physical row on SQLite vs PostgreSQL). See resolveKeylessProxyKeys /
// resolveKeylessTokenKeys.
//
// Derive re-sorts its inputs defensively (a caller relying on that instead
// of an explicit ORDER BY in its own SQL is a smell the review's finding #6
// called out — order it explicitly at the query site).
//
// The body is a straight-line pipeline over named stages, each mirroring
// one rule of the documented algorithm:
//
//  1. planDedup            — load ordered proxy/token/action rows.
//  2. PairShadowRows       — shadow pairing on OutputOnlyShadow.
//  3. buildRequestIDIndex  — index proxy request ids for the token-fold's
//     direct-id-match short-circuit.
//  4. assignTwins          — twin assignment (shape-based proxy/JSONL fold).
//  5. foldProxyRows        — key resolution (turn_id > message_id, off the
//     twin) + row build/merge for proxy-sourced rows.
//  6. foldTokenRows        — key resolution (turn_id > message_id >
//     source_event_id) + keyless synthesis + row build/merge for the
//     token rows the twin fold didn't already claim.
//  7. foldActions          — user-row keying + bare-row synthesis for any
//     action whose join key matched no token/proxy bucket. Status kinds
//     (status.go: rate_limit) never become rows or tool calls — they fold
//     onto the message they follow (attachStatusActions, stage 7b), with
//     their changed readings marked.
//  8. finalizeOrder        — tie-ordered sort + Seq assignment.
func Derive(in DeriveInput) []*Row {
	plan := planDedup(in)
	proxies, tokens := plan.proxies, plan.tokens
	actions := orderedActions(in.ActionRows)
	twinOf := plan.twinOf

	// Keyless-key pre-pass (round 6 finding F3): resolved BEFORE either
	// fold loop, over the FULL row set, so a keyless row's synthesized key
	// is a function of every keyless row's content — never of the loop's
	// own iteration position — and therefore identical regardless of the
	// order the caller's SQL handed rows to Derive in.
	proxyKeylessKeys := resolveKeylessProxyKeys(proxies, tokens, twinOf, in.Mode)
	tokenKeylessKeys := resolveKeylessTokenKeys(tokens, in.Mode)

	state := newDeriveState()
	foldProxyRows(state, proxies, tokens, twinOf, plan.proxyDropped, in.Mode, proxyKeylessKeys)
	foldTokenRows(state, plan, in.Mode, tokenKeylessKeys, in.ReasoningDisjoint)
	foldActions(state, actions, in.DefaultModel)

	out := finalizeOrder(state)
	stampGapToNext(out)
	return out
}

// dedupPlan is stages 1-4 of Derive: the canonically ordered proxy and token
// rows (with each one's index in the caller's input), and every decision
// about which token rows are a second capture of a turn already counted.
// Derive folds from it, and DeriveVerdicts (verdicts.go) reports it back per
// input row, so the rule has ONE implementation whichever way it is read.
type dedupPlan struct {
	proxies []ProxyRow
	tokens  []TokenRow
	// proxyIn / tokenIn map a canonical position to its caller input index.
	proxyIn []int
	tokenIn []int

	shadowExcluded []bool
	requestIDs     map[string]bool
	twinOf         []int
	twinClaimed    []bool

	// proxyDropped / tokenReconciled are the session-cumulative
	// reconciliation's decisions (cumulative.go): a proxy row, or a token
	// row, dropped WHOLESALE because the other side of a session-cumulative
	// session captured more of it. Both are all-false for every session
	// without a session-cumulative token row.
	proxyDropped    []bool
	tokenReconciled []bool
}

// planDedup builds the dedupPlan for in.
//
// A session whose tool writes ONE session-cumulative token row (a running
// total for the whole session, DeriveInput.SessionCumulative) is first
// reconciled wholesale against its per-turn capture (reconcileCumulative);
// every other session goes straight to the per-turn pairing below, exactly
// as before.
func planDedup(in DeriveInput) dedupPlan {
	var plan dedupPlan
	plan.proxyIn = orderedProxyIndex(in.ProxyRows)
	plan.tokenIn = orderedTokenIndex(in.TokenRows)
	plan.proxies = make([]ProxyRow, len(plan.proxyIn))
	for i, src := range plan.proxyIn {
		plan.proxies[i] = in.ProxyRows[src]
	}
	plan.tokens = make([]TokenRow, len(plan.tokenIn))
	for i, src := range plan.tokenIn {
		plan.tokens[i] = in.TokenRows[src]
	}
	plan.proxyDropped = make([]bool, len(plan.proxies))
	plan.tokenReconciled = make([]bool, len(plan.tokens))
	if reconcileCumulative(&plan, in) {
		return plan
	}
	plan.pair(true, identityIndex(len(plan.tokens)), in.ShadowCapable)
	return plan
}

// pair runs the per-turn pairing over the proxy rows (all of them when
// withProxies, none otherwise) and the canonical token rows named by
// tokenIdx, and records its decisions against the canonical indexes. Rows
// outside tokenIdx are never paired, excluded or claimed.
func (plan *dedupPlan) pair(withProxies bool, tokenIdx []int, shadowCapable bool) {
	plan.shadowExcluded = make([]bool, len(plan.tokens))
	plan.twinClaimed = make([]bool, len(plan.tokens))
	plan.twinOf = make([]int, len(plan.proxies))
	for i := range plan.twinOf {
		plan.twinOf[i] = -1
	}
	sub := make([]TokenRow, len(tokenIdx))
	for i, c := range tokenIdx {
		sub[i] = plan.tokens[c]
	}
	var proxies []ProxyRow
	if withProxies {
		proxies = plan.proxies
	}

	// Copilot-family (or any future adapter carrying the same capability)
	// output-only shadow-row pairing, dispatched on the caller-supplied
	// capability flag alone — never a tool literal. One-to-one by session +
	// output count (finding #7): a shadow row is only ever excluded when a
	// specific, unused full-usage sibling claims it, so N legitimate turns
	// sharing an output count never lose more than the true number of
	// shadow siblings.
	for i, ex := range PairShadowRows(sub, shadowCapable) {
		plan.shadowExcluded[tokenIdx[i]] = ex
	}

	plan.requestIDs = buildRequestIDIndex(proxies)

	// One-to-one twin assignment (the same closest-match, claim-once
	// discipline as PairShadowRows): each proxy row claims at most one
	// UNCLAIMED shape-matching token row, closest in time. A token row a
	// later proxy row might also shape-match is no longer a candidate once
	// claimed — this is what keeps two GENUINELY DISTINCT token rows that
	// happen to share an identical token-bundle shape (same model/input/
	// output/cache — "effectively impossible" per the original SQL's own
	// comment, since cache_read grows monotonically in real data) from
	// BOTH being discarded just because at least one proxy row's shape
	// matches; only the row actually claimed as a twin is excluded.
	twinOf, claimed := assignTwins(proxies, sub)
	for pi, ti := range twinOf {
		if ti >= 0 {
			plan.twinOf[pi] = tokenIdx[ti]
		}
	}
	for i, c := range claimed {
		plan.twinClaimed[tokenIdx[i]] = c
	}
}

// tokenDropped reports whether canonical token row i contributes nothing
// because it is a second capture of spend already counted: a row the
// session-cumulative reconciliation dropped wholesale, a paired output-only
// shadow row, a row whose source_event_id names one of the session's proxy
// request ids, or a proxy row's claimed shape twin. It is the ONE predicate
// foldTokenRows and DeriveVerdicts both consult.
func (p dedupPlan) tokenDropped(i int) bool {
	t := p.tokens[i]
	return p.tokenReconciled[i] || p.shadowExcluded[i] ||
		(t.SourceEventID != "" && p.requestIDs[t.SourceEventID]) ||
		p.twinClaimed[i]
}

// orderedProxyIndex / orderedTokenIndex / orderedActions are Derive's stage
// 1: they order the caller's row slices (never mutating the caller's own
// backing arrays), re-sorting them
// defensively — actions by timestamp then SourceEventID for a stable
// tie-break. A caller relying on this defensive sort instead of an
// explicit ORDER BY in its own SQL is a smell (review round 5 finding #6)
// — order it explicitly at the query site; this stage exists only as a
// backstop.
//
// proxies and tokens sort by (timestamp, content fingerprint) rather than
// timestamp alone — round 7 finding F4: a tie-break on arrival order (what
// a bare timestamp-only stable sort falls back to) is exactly what let
// PairShadowRows and assignTwins pick a DIFFERENT physical row on the
// node vs the org for two equal-timestamp candidates, since neither
// engine's SQL scan order for an equal-(timestamp, secondary-key) tie is
// portable (the same class of bug canonicalizeKeyless's keyless-key
// synthesis already had to solve). Sorting the FULL input by the same
// wire-stable fingerprint (fingerprintProxyRow / fingerprintTokenRow, now
// that round 7 finding F3 has made them wire-stable) before pairing ever
// runs means every downstream stage — PairShadowRows, assignTwins, the
// fold loops, the keyless pre-pass — walks an order that depends only on
// the rows' own content, never on the caller's scan order.
//
// A third tier, localTiebreak(Fast, CostUSD), breaks the RESIDUAL tie left
// when two rows also share an identical wire fingerprint (round 8 finding
// F4): Fast/CostUSD are real fields on the physical row even though they
// are deliberately excluded from the wire-stable fingerprint (round 7
// finding F3's "ships verbatim" rule), so without this tier the base order
// this function hands downstream would still fall back to arrival order
// for that residual tie — exactly the scan-order sensitivity this whole
// function exists to remove.
//
// The org runs this exact same tier, over its own loaded rows — Derive is
// one shared function, not two independent implementations. But (round 9
// finding F2, docs/security.md) the org's own ProxyRow.Fast is always the
// zero value and its TokenRow.CostUSD can be independently repriced at
// push time, so this tier is deterministic WITHIN each engine but not
// guaranteed to agree BETWEEN them for a wire-identical duplicate group —
// see localTiebreak's doc comment for the full accounting and
// tests/crossengine's compareKeylessGroup for how the oracle asserts this
// documented, inherent limit rather than a false exact-match guarantee.
//
// The proxy and token orders are computed as index permutations over the
// caller's slices (orderedProxyIndex / orderedTokenIndex) rather than by
// sorting copies, so DeriveVerdicts can report each decision against the
// caller's own row index. A stable sort's result is fully determined by
// its comparator and its input order, so the permutation is the exact
// order the copy-sort produced.
func orderedProxyIndex(rows []ProxyRow) []int {
	idx := identityIndex(len(rows))
	sort.SliceStable(idx, func(a, b int) bool {
		pa, pb := rows[idx[a]], rows[idx[b]]
		if pa.Timestamp != pb.Timestamp {
			return pa.Timestamp < pb.Timestamp
		}
		if fa, fb := fingerprintProxyRow(pa), fingerprintProxyRow(pb); fa != fb {
			return fa < fb
		}
		return localTiebreak(pa.Fast, pa.CostUSD) < localTiebreak(pb.Fast, pb.CostUSD)
	})
	return idx
}

// orderedTokenIndex is orderedProxyIndex's token-row twin.
func orderedTokenIndex(rows []TokenRow) []int {
	idx := identityIndex(len(rows))
	sort.SliceStable(idx, func(a, b int) bool {
		ta, tb := rows[idx[a]], rows[idx[b]]
		if ta.Timestamp != tb.Timestamp {
			return ta.Timestamp < tb.Timestamp
		}
		if fa, fb := fingerprintTokenRow(ta), fingerprintTokenRow(tb); fa != fb {
			return fa < fb
		}
		return localTiebreak(ta.Fast, ta.CostUSD) < localTiebreak(tb.Fast, tb.CostUSD)
	})
	return idx
}

// orderedActions copies and sorts the caller's actions (timestamp, then
// SourceEventID), never mutating the caller's backing array.
func orderedActions(in []ActionRow) []ActionRow {
	actions := append([]ActionRow(nil), in...)
	sort.SliceStable(actions, func(i, j int) bool {
		if actions[i].Timestamp != actions[j].Timestamp {
			return actions[i].Timestamp < actions[j].Timestamp
		}
		return actions[i].SourceEventID < actions[j].SourceEventID
	})
	return actions
}

// identityIndex returns [0, 1, ..., n-1].
func identityIndex(n int) []int {
	idx := make([]int, n)
	for i := range idx {
		idx[i] = i
	}
	return idx
}

// buildRequestIDIndex indexes every proxy row's non-empty RequestID, so
// foldTokenRows can recognize — without a second pass over proxies — a
// token_usage row whose SourceEventID directly names an already-folded
// proxy row (ids already agree, e.g. claude-code).
func buildRequestIDIndex(proxies []ProxyRow) map[string]bool {
	requestIDs := make(map[string]bool, len(proxies))
	for _, p := range proxies {
		if p.RequestID != "" {
			requestIDs[p.RequestID] = true
		}
	}
	return requestIDs
}

// deriveState accumulates the rows Derive is building across the fold
// stages: byKey resolves a group key to its row for merge lookups, out
// preserves creation order (re-sorted into final chronological order by
// finalizeOrder), and turnBuckets collects every row sharing one turn_id in
// chronological arrival order, for foldActions' per-inference bucket
// resolution (PickInferenceBucket).
type deriveState struct {
	byKey       map[string]*Row
	out         []*Row
	turnBuckets map[string][]*Row
}

// newDeriveState returns an empty deriveState ready for the fold stages.
func newDeriveState() *deriveState {
	return &deriveState{byKey: map[string]*Row{}, turnBuckets: map[string][]*Row{}}
}

// newRow is the one place a Row is constructed: it registers the row under
// key (for merge lookups) and appends it to the build-order slice (re-
// sorted later by finalizeOrder).
func (s *deriveState) newRow(key, ts, model, role, source string) *Row {
	row := &Row{Key: key, Timestamp: ts, Role: role, Model: model, Source: source}
	s.byKey[key] = row
	s.out = append(s.out, row)
	return row
}

// resolveProxyRowKey resolves a proxy row's own group key BEFORE any
// keyless fallback — its own RequestID, else (when it has a shape-matched
// JSONL twin, per assignTwins) the twin's turn_id/message_id via
// groupKeyForTwin — plus the reasoning/output split and twin-fast flag the
// caller needs regardless of which key it resolved to. An empty returned
// key means the row is keyless. Factored out of foldProxyRows so the
// keyless pre-pass (resolveKeylessProxyKeys, which must know for EVERY
// proxy row whether it resolves to a real key or none) and the actual fold
// share one source of truth for this resolution instead of two copies that
// could drift.
func resolveProxyRowKey(p ProxyRow, tokens []TokenRow, twinOf []int, pi int, mode GroupMode) (key, turnID string, reasoning, output int64, twinFast bool) {
	key = p.RequestID
	output = p.Output
	if idx := twinOf[pi]; idx >= 0 {
		t := tokens[idx]
		turnID = t.TurnID
		if k := groupKeyForTwin(mode, t); k != "" {
			key = k
		}
		// The twin's reasoning, capped at the proxy's gross output: a
		// provider can report more reasoning than the completion count it
		// bills (outputConsistent's clamp case), and the proxy's gross
		// figure is what was billed.
		reasoning = min(t.Reasoning, p.Output)
		output = p.Output - reasoning
		twinFast = t.Fast
	}
	return key, turnID, reasoning, output, twinFast
}

// foldProxyRows is Derive's stage 5: each proxy row, enriched by its
// shape-matched JSONL twin (the same turn captured a second time by the
// transcript/file adapter, assigned by assignTwins). The twin supplies what
// the wire capture alone can't know: the transcript's turn_id/message_id
// (so the proxy row lands in the SAME bucket its sibling action rows key
// to — the turn_id > message_id precedence), the reasoning split (the
// proxy stores gross output = visible + reasoning; the JSONL side already
// nets reasoning out), and the twin's own fast flag.
//
// A legacy pre-fallback capture can carry neither a request_id nor a
// twin-supplied turn_id/message_id (review round 5 finding #7). Rather
// than dropping the row (the pre-fix behavior — silently invisible in
// Messages/org while Detail's own since-removed local hack counted it, the
// exact cross-surface divergence this fixes), it adopts the content-derived
// key the keylessKeys pre-pass (resolveKeylessProxyKeys) already resolved
// for it — see that function's doc comment for why this makes the same
// session's node and org calls agree on the identical synthetic key
// regardless of scan order.
//
// A proxy row the session-cumulative reconciliation dropped (dropped[pi]:
// the session's cumulative token row captured more than the proxy did)
// keeps its message row - it is still a real turn with its own timing - but
// adds no spend to it: no bundle, no recorded cost, no Contribution.
func foldProxyRows(state *deriveState, proxies []ProxyRow, tokens []TokenRow, twinOf []int, dropped []bool, mode GroupMode, keylessKeys []string) {
	for pi, p := range proxies {
		key, turnID, reasoning, output, twinFast := resolveProxyRowKey(p, tokens, twinOf, pi, mode)
		rowKeyless := key == ""
		if rowKeyless {
			key = keylessKeys[pi]
		}
		row, ok := state.byKey[key]
		if !ok {
			row = state.newRow(key, p.Timestamp, p.Model, "assistant", "proxy")
			row.IsProxy = true
			row.Keyless = rowKeyless
		}
		if row.Model == "" && p.Model != "" {
			row.Model = p.Model
		}
		row.TTFBMs += p.TTFBMs
		row.TotalMs += p.TotalMs
		// Speed: the proxy's own output count is GROSS (visible +
		// reasoning) whatever the twin says, and TotalMs is the capture's
		// request duration for exactly this call - so this contribution's
		// generated tokens are p.Output, independent of ReasoningDisjoint.
		// A twin token row adds NO duration (it is the same call).
		row.Speed.add(p.Output, p.TotalMs, BasisMeasured)
		if row.StopReason == "" && p.StopReason != "" {
			row.StopReason = p.StopReason
		}
		row.alias(p.RequestID)
		if turnID != "" {
			row.TurnRollup = true
			row.alias(turnID)
			state.turnBuckets[turnID] = appendRowOnce(state.turnBuckets[turnID], row)
		}
		if dropped[pi] {
			continue
		}
		row.Bundle.Input += p.Input
		row.Bundle.Output += output
		row.Bundle.CacheRead += p.CacheRead
		row.Bundle.CacheCreation += p.CacheCreation
		row.Bundle.CacheCreation1h += p.CacheCreation1h
		row.Bundle.Reasoning += reasoning
		row.Bundle.WebSearchRequests += p.WebSearchRequests
		row.Bundle.Fast = row.Bundle.Fast || p.Fast || twinFast
		row.RecordedCostUSD += p.CostUSD
		row.Contributions = append(row.Contributions, Contribution{
			Timestamp: p.Timestamp,
			Model:     p.Model,
			Bundle: TokenBundle{
				Input: p.Input, Output: output, CacheRead: p.CacheRead,
				CacheCreation: p.CacheCreation, CacheCreation1h: p.CacheCreation1h,
				Reasoning: reasoning, WebSearchRequests: p.WebSearchRequests,
				Fast: p.Fast || twinFast,
			},
			RecordedCostUSD: p.CostUSD,
			OwnFast:         p.Fast,
			InheritedFast:   twinFast,
			Proxy:           true,
		})
	}
}

// foldTokenRows is Derive's stage 6: every token_usage row not already
// folded into a proxy row by foldProxyRows — either because its
// SOURCE_EVENT_ID directly matches a proxy request_id (ids already agree,
// e.g. claude-code), or because its token-bundle SHAPE duplicated some
// proxy row's and assignTwins already claimed it (ids differ, e.g. codex
// tk:… vs resp_…) — and not already excluded as a paired Copilot shadow
// row. Its own key resolves via the turn_id > message_id > source_event_id
// precedence (groupKeyForToken), falling back to the same content-derived
// keyless synthesis as foldProxyRows for a legacy id-less row (see
// resolveKeylessTokenKeys).
func foldTokenRows(state *deriveState, plan dedupPlan, mode GroupMode, keylessKeys []string, reasoningDisjoint bool) {
	for i, t := range plan.tokens {
		if plan.tokenDropped(i) {
			continue
		}
		key := groupKeyForToken(mode, t)
		// Same legacy id-less case as foldProxyRows, content-fingerprint
		// keyed (a separate "jsonl" kind namespace, so a proxy-side and a
		// token-side keyless row never collide even on an identical
		// fingerprint).
		rowKeyless := key == ""
		if rowKeyless {
			key = keylessKeys[i]
		}
		row, ok := state.byKey[key]
		if !ok {
			row = state.newRow(key, t.Timestamp, t.Model, "assistant", "jsonl")
			row.Keyless = rowKeyless
		}
		if row.Model == "" && t.Model != "" {
			row.Model = t.Model
		}
		row.Bundle.Input += t.Input
		row.Bundle.Output += t.Output
		row.Bundle.CacheRead += t.CacheRead
		row.Bundle.CacheCreation += t.CacheCreation
		row.Bundle.CacheCreation1h += t.CacheCreation1h
		row.Bundle.Reasoning += t.Reasoning
		row.Bundle.WebSearchRequests += t.WebSearchRequests
		row.Bundle.Fast = row.Bundle.Fast || t.Fast
		row.RecordedCostUSD += t.CostUSD
		row.Contributions = append(row.Contributions, Contribution{
			Timestamp: t.Timestamp,
			Model:     t.Model,
			Bundle: TokenBundle{
				Input: t.Input, Output: t.Output, CacheRead: t.CacheRead,
				CacheCreation: t.CacheCreation, CacheCreation1h: t.CacheCreation1h,
				Reasoning: t.Reasoning, WebSearchRequests: t.WebSearchRequests,
				Fast: t.Fast,
			},
			RecordedCostUSD: t.CostUSD,
			OwnFast:         t.Fast,
		})
		row.alias(t.MessageID)
		row.alias(t.SourceEventID)
		if t.TurnID != "" {
			row.TurnRollup = true
			row.alias(t.TurnID)
			state.turnBuckets[t.TurnID] = appendRowOnce(state.turnBuckets[t.TurnID], row)
		}
		row.Speed.add(tokenGenTokens(t, reasoningDisjoint), t.GenMs, t.GenBasis)
	}
}

// foldActions is Derive's stage 7: attribute each action to its message's
// bucket (matching by key, else — when the bucket grain is finer than the
// action's own join key, e.g. ?detail=inference — by which per-inference
// bucket timestamp-window contains it, via PickInferenceBucket), or
// synthesize a bare row when no bucket claims it (a user_prompt, or any
// action whose tokens were captured at a coarser grain than the individual
// turn — goose's session-level accumulated usage is the grounding case).
// This is also where a synthesized user row is keyed exactly like every
// other action (via joinKey) and, when its own key names a peer
// "assistant:" bucket, inherits that peer's model.
func foldActions(state *deriveState, actions []ActionRow, defaultModel string) {
	var status []ActionRow
	for _, a := range actions {
		if IsStatusAction(a.ActionType) {
			status = append(status, a)
			continue
		}
		foldOneAction(state, a, defaultModel)
	}
	attachStatusActions(state, status, defaultModel)
}

// foldOneAction attributes one (non-status) action to its message row,
// synthesizing a bare row when its join key matches none.
func foldOneAction(state *deriveState, a ActionRow, defaultModel string) {
	joinKey := firstNonEmpty(a.MessageID, a.SourceEventID)
	row, ok := state.byKey[joinKey]
	if !ok && a.ActionType != "user_prompt" {
		if list := state.turnBuckets[joinKey]; len(list) > 0 {
			stamps := make([]string, len(list))
			proxyFlags := make([]bool, len(list))
			for i, b := range list {
				stamps[i], proxyFlags[i] = b.Timestamp, b.IsProxy
			}
			if idx := PickInferenceBucket(stamps, proxyFlags, a.Timestamp); idx >= 0 {
				row, ok = list[idx], true
			}
		}
	}
	if !ok {
		role, model := "assistant", defaultModel
		if a.ActionType == "user_prompt" {
			role = "user"
			if strings.HasPrefix(joinKey, "user:") {
				peerKey := "assistant:" + strings.TrimPrefix(joinKey, "user:")
				if peer, pok := state.byKey[peerKey]; pok && peer.Model != "" {
					model = peer.Model
				}
			}
		}
		row = state.newRow(joinKey, a.Timestamp, model, role, "actions")
	}
	row.Actions = append(row.Actions, a)
	row.alias(a.MessageID)
	row.alias(a.SourceEventID)
	if row.EffortLevel == "" && a.EffortLevel != "" {
		row.EffortLevel = a.EffortLevel
	}
	if row.ServiceTier == "" && a.ServiceTier != "" {
		row.ServiceTier = a.ServiceTier
	}
	if row.StopReason == "" && a.StopReason != "" {
		row.StopReason = a.StopReason
	}
}

// finalizeOrder is Derive's stage 8: the final deterministic order (finding
// #6) — timestamp ascending, ties broken user-before-assistant (a
// synthesized user_prompt often shares its triggering assistant turn's
// wall-clock, and "user said X → assistant did Y" reads naturally),
// remaining ties broken on Key so SQLite and PostgreSQL — which give no
// scan-order guarantee on an equal-timestamp set — always agree. Seq is
// assigned once, after this sort, so it means the same thing under any
// later display reordering; AccountKey is stamped here too, once the row's
// final Key is settled.
func finalizeOrder(state *deriveState) []*Row {
	out := state.out
	sort.SliceStable(out, func(i, j int) bool { return Less(out[i], out[j]) })
	for i, row := range out {
		row.Seq = i + 1
		row.alias(row.Key)
		row.AccountKey = row.Role + ":" + row.Key
	}
	return out
}

// Less is the ONE shared ordering predicate (finding #6): timestamp
// ascending, user-before-assistant tie-break, then Key ascending as the
// final deterministic tie-break. Exported so a caller that must sort a
// caller-decorated row slice (the node's richer messageRow, the org's
// content-free MessageMetricRow) can key its own comparator on the same
// (Timestamp, Role, Key) triple and get an IDENTICAL order to Derive's
// internal sort, without needing sessionmsg.Row itself.
func Less(a, b TimestampRoleKey) bool {
	if a.OrderTimestamp() != b.OrderTimestamp() {
		return a.OrderTimestamp() < b.OrderTimestamp()
	}
	ar, br := a.OrderRole() == "user", b.OrderRole() == "user"
	if ar != br {
		return ar
	}
	return a.OrderKey() < b.OrderKey()
}

// TimestampRoleKey is the minimal projection Less needs. sessionmsg.Row
// implements it directly; a caller sorting its own decorated row type
// implements the three accessor methods (each one line) instead of
// reimplementing the tie-break policy.
type TimestampRoleKey interface {
	OrderTimestamp() string
	OrderRole() string
	OrderKey() string
}

// OrderTimestamp, OrderRole, OrderKey implement TimestampRoleKey for *Row.
func (r *Row) OrderTimestamp() string { return r.Timestamp }
func (r *Row) OrderRole() string      { return r.Role }
func (r *Row) OrderKey() string       { return r.Key }

// alias records another identity key this row answers to (a proxy
// request_id, a token row's message_id/turn_id/source_event_id, an
// action's message_id/source_event_id). Deduped, empty keys ignored. This
// is what lets a caller resolve per-message vendor-login evidence
// (session_tool_accounts.binding_id) bound to ANY of a merged row's
// constituent ids, not just its final group Key — the generalization of
// the org's pre-existing bucketIndex/messageRowKeys mechanism.
func (r *Row) alias(key string) {
	if key == "" {
		return
	}
	for _, k := range r.AliasKeys {
		if k == key {
			return
		}
	}
	r.AliasKeys = append(r.AliasKeys, key)
}

// AliasIndex maps every identity key any derived row answers to
// (Row.AliasKeys) to that row's position in `rows`. The FIRST row to claim
// a key wins — deterministic regardless of iteration order, since `rows`
// is already Derive's own final, sorted output. This is the ONE shared
// lookup structure BOTH engines' vendor-login account-resolution pass
// build (S7, 2026-09-22 review round 3: the node previously indexed only
// Role+":"+finalKey while the org indexed every alias — building this map
// from the identical field via the identical function closes that gap by
// construction rather than by convention). See RowKeysByIndex for the
// inverse a resolver actually walks.
func AliasIndex(rows []*Row) map[string]int {
	idx := make(map[string]int, len(rows))
	for i, row := range rows {
		for _, k := range row.AliasKeys {
			if _, exists := idx[k]; !exists {
				idx[k] = i
			}
		}
	}
	return idx
}

// RowKeysByIndex inverts an AliasIndex (as built by AliasIndex over the
// SAME `n`-length rows slice) into row index → its identity keys, sorted
// for deterministic first-hit resolution when a caller walks them looking
// for the first key an accounts/evidence map recognizes. Indices outside
// [0,n) are dropped defensively rather than panicking — an AliasIndex
// built from a mismatched slice is a caller bug, not a runtime fault here.
func RowKeysByIndex(aliasIdx map[string]int, n int) map[int][]string {
	out := make(map[int][]string, len(aliasIdx))
	for key, idx := range aliasIdx {
		if key == "" || idx < 0 || idx >= n {
			continue
		}
		out[idx] = append(out[idx], key)
	}
	for i := range out {
		sort.Strings(out[i])
	}
	return out
}

// keylessOrdinalPrefix marks a Derive-synthesized group key for a proxy or
// token row that carries none of its real identity fields. No live capture
// path ever emits an id starting with this literal (internal/proxy's
// newRequestID doc comment: always a real upstream id or a generated
// "sbo-…" fallback; every JSONL adapter stamps at least one of message_id/
// source_event_id/turn_id), so this can never collide with a genuine key —
// it only ever fires for a legacy pre-fallback row.
const keylessOrdinalPrefix = "keyless:"

// keylessKey synthesizes the internal key Derive assigns a legacy id-less
// proxy/token row (review round 5 finding #7), so it still surfaces as its
// own message row instead of being silently dropped. kind ("proxy" or
// "jsonl") keeps the two namespaces from colliding with each other;
// fingerprint is a short content hash (fingerprintProxyRow /
// fingerprintTokenRow) over the row's own stable fields, and dup is the
// row's ordinal WITHIN its fingerprint group, assigned by
// resolveKeylessProxyKeys/resolveKeylessTokenKeys in a canonical
// (timestamp, fingerprint) order that never depends on the order rows
// arrived in (round 6 finding F3 — the ordinal-position predecessor of
// this function could resolve to a DIFFERENT physical row on SQLite vs
// PostgreSQL for two equal-timestamp keyless rows, since neither engine
// guarantees a scan-order tie-break). This determinism is exactly what
// lets the node and the org — which each load the identical underlying
// rows via their own ordered SQL and pass them through this SAME shared
// function — resolve the SAME synthetic key for the SAME legacy row, so
// Detail, Messages, and the org's SessionMessageMetrics all agree
// (tests/crossengine's oracle asserts this by comparing message_id
// literally). A keyless row is never folded with another keyless row
// (each fingerprint+dup pair is unique so byKey never already holds the
// key), and is paired with another row as a twin/shadow ONLY when
// assignTwins/PairShadowRows' own shape/id rules — which never consult
// this key, only the raw ProxyRow/TokenRow fields — already say so.
func keylessKey(kind, fingerprint string, dup int) string {
	return fmt.Sprintf("%s%s:%s:%d", keylessOrdinalPrefix, kind, fingerprint, dup)
}

// canonicalizeKeyless assigns each keyless row (identified by its own
// index into the caller's row slice) a deterministic key, in a strict
// (timestamp, fingerprint, tiebreak) order that depends on nothing but the
// rows' own content — never on the order the caller handed them to Derive
// in. A run of rows sharing one fingerprint gets consecutive dup ordinals
// in that same canonical order.
//
// Round 8 finding F4: a shared fingerprint no longer means the two rows
// are byte-identical, because round 7 finding F3 deliberately excluded
// Fast/CostUSD from the fingerprint (neither is wire-stable — see
// fingerprintProxyRow's doc comment). Two DISTINCT keyless rows can
// therefore tie on (timestamp, fingerprint) while still differing in
// Fast/CostUSD; without a further tiebreak, sort.SliceStable would fall
// back to the two rows' relative position in the caller-supplied slice —
// i.e. scan order — to decide which one gets dup ordinal 0 vs 1, and
// which physical Fast/CostUSD content that ordinal's row then carries.
// tiebreak (localTiebreak's output) is that further, content-derived
// disambiguator: when it too ties, the two physical rows really are
// indistinguishable in every field this package or its callers ever look
// at, and which one lands on which ordinal is immaterial, exactly as the
// pre-F4 comment already established for a true byte-identical pair.
//
// ts/fingerprint/tiebreak are parallel slices, one entry per keyless row,
// in whatever order the caller happened to collect them in; the returned
// slice is in that SAME order (position-for-position), for the caller to
// scatter back onto its own original-index space.
func canonicalizeKeyless(kind string, ts, fingerprint, tiebreak []string) []string {
	order := make([]int, len(ts))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool {
		ia, ib := order[a], order[b]
		if ts[ia] != ts[ib] {
			return ts[ia] < ts[ib]
		}
		if fingerprint[ia] != fingerprint[ib] {
			return fingerprint[ia] < fingerprint[ib]
		}
		return tiebreak[ia] < tiebreak[ib]
	})
	out := make([]string, len(ts))
	dup := map[string]int{}
	for _, i := range order {
		n := dup[fingerprint[i]]
		dup[fingerprint[i]] = n + 1
		out[i] = keylessKey(kind, fingerprint[i], n)
	}
	return out
}

// resolveKeylessProxyKeys computes the content-derived key
// (resolveProxyRowKey returning "") every keyless proxy row will use,
// BEFORE foldProxyRows runs — see canonicalizeKeyless for why this must
// happen over the full row set rather than inline in the fold loop. The
// returned slice is indexed exactly like `proxies`; a non-keyless index is
// left as the empty string (foldProxyRows never reads it for those rows).
func resolveKeylessProxyKeys(proxies []ProxyRow, tokens []TokenRow, twinOf []int, mode GroupMode) []string {
	out := make([]string, len(proxies))
	var idxs []int
	var ts, fp, tb []string
	for pi, p := range proxies {
		key, _, _, _, _ := resolveProxyRowKey(p, tokens, twinOf, pi, mode)
		if key != "" {
			continue
		}
		idxs = append(idxs, pi)
		ts = append(ts, p.Timestamp)
		fp = append(fp, fingerprintProxyRow(p))
		tb = append(tb, localTiebreak(p.Fast, p.CostUSD))
	}
	if len(idxs) == 0 {
		return out
	}
	keys := canonicalizeKeyless("proxy", ts, fp, tb)
	for i, pi := range idxs {
		out[pi] = keys[i]
	}
	return out
}

// resolveKeylessTokenKeys is resolveKeylessProxyKeys' token-row twin — see
// its doc comment. The returned slice is indexed exactly like `tokens`.
func resolveKeylessTokenKeys(tokens []TokenRow, mode GroupMode) []string {
	out := make([]string, len(tokens))
	var idxs []int
	var ts, fp, tb []string
	for i, t := range tokens {
		if groupKeyForToken(mode, t) != "" {
			continue
		}
		idxs = append(idxs, i)
		ts = append(ts, t.Timestamp)
		fp = append(fp, fingerprintTokenRow(t))
		tb = append(tb, localTiebreak(t.Fast, t.CostUSD))
	}
	if len(idxs) == 0 {
		return out
	}
	keys := canonicalizeKeyless("jsonl", ts, fp, tb)
	for i, ti := range idxs {
		out[ti] = keys[i]
	}
	return out
}

// fingerprintProxyRow returns a short, deterministic content fingerprint
// for a keyless proxy row: its timestamp plus every OTHER field that ships
// to the org VERBATIM and UNCHANGED by the push/ingest seam — NEVER a
// content body (ProxyRow carries none). Two keyless proxy rows with the
// same fingerprint are, for every purpose this package cares about,
// interchangeable (see canonicalizeKeyless).
//
// Round 7 finding F3: this used to also hash CostUSD and Fast, both of
// which fail the "ships verbatim" test:
//
//   - Fast is NOT a wire field at all. orgcontract.APITurnRow (internal/
//     orgcontract/types.go) has no Fast/fast column; api_turns.fast lives
//     only on the node (read by internal/intelligence/dashboard/
//     dashboard.go's loadMessageProxyRows) and orgpush.go's api_turns
//     SELECT never selects it. The org's own ProxyRow loader
//     (internal/orgserver/rollup/messagemetrics.go) therefore leaves
//     ProxyRow.Fast at its zero value, always false — a keyless proxy row
//     with fast=true would fingerprint differently node-side (Fast=true)
//     vs org-side (Fast=false), naming a DIFFERENT synthetic key for the
//     identical row.
//   - CostUSD, while api_turns rows are never re-priced by the push seam
//     (internal/store/orgpush_pricing.go::priceTokenUsageRow is only
//     called from the token_usage arm of SelectUnpushedSince — see
//     orgpush.go's "api_turns rows are never touched" comment there), is
//     dropped anyway for the same defense-in-depth reason as
//     fingerprintTokenRow's CostUSD: a dollar figure is a derived/priced
//     value, not identity, and every other field below already gives a
//     keyless row plenty of fingerprint entropy (model, full token
//     bundle, latency, stop reason).
//
// Fields kept and their wire evidence (internal/store/orgpush.go's
// api_turns SELECT + internal/orgserver/ingest/ingest.go's api_turns
// INSERT, both field-for-field, no transform): Timestamp, Model, Input,
// Output, CacheRead, CacheCreation, CacheCreation1h, WebSearchRequests,
// TTFBMs (time_to_first_token_ms), TotalMs (total_response_ms),
// StopReason — every one selected unconditionally (never gated by
// ShareOptions.shipsRawContent, unlike ProjectRoot) and inserted verbatim.
func fingerprintProxyRow(p ProxyRow) string {
	return contentFingerprint(strings.Join([]string{
		p.Timestamp, p.Model,
		strconv.FormatInt(p.Input, 10), strconv.FormatInt(p.Output, 10),
		strconv.FormatInt(p.CacheRead, 10), strconv.FormatInt(p.CacheCreation, 10),
		strconv.FormatInt(p.CacheCreation1h, 10), strconv.FormatInt(p.WebSearchRequests, 10),
		strconv.FormatInt(p.TTFBMs, 10), strconv.FormatInt(p.TotalMs, 10), p.StopReason,
	}, "|"))
}

// fingerprintTokenRow is fingerprintProxyRow's token-row twin — see that
// function's doc comment for the "ships verbatim" test every field here
// must pass, and round 7 finding F3 for why CostUSD and Fast fail it.
//
// TurnID/MessageID/SourceEventID are always empty (or, in RollupInference
// mode, carry a TurnID Derive doesn't consult) for a row classified
// keyless by groupKeyForToken, but are included anyway for defensive
// completeness.
//
// CostUSD (token_usage.estimated_cost_usd) is dropped: G1-COST(b)
// (internal/store/orgpush_pricing.go::priceTokenUsageRow, called from
// SelectUnpushedSince's token_usage arm in orgpush.go) REPRICES a stored
// $0 at push time using the org's own pricing table — so a keyless row
// the node stored at $0 can land on the org with a non-zero
// EstimatedCostUSD. Fast is dropped for the same reason as the proxy row:
// orgcontract.TokenUsageRow carries no Fast field (internal/store/
// orgpush_pricing.go's own doc comment: "the node-local fast flag is a
// pricing input only, never a wire field"); token_usage.fast lives only
// on the node (dashboard.go's loadMessageTokenRows), and the org's own
// TokenRow loader (messagemetrics.go) never scans it, leaving it at its
// zero value.
//
// Fields kept and their wire evidence (orgpush.go's token_usage SELECT +
// ingest.go's token_usage INSERT, field-for-field, no transform):
// Timestamp, Model, Tool (stamped from the session's own tool by BOTH
// engines' loaders — never a per-row DB column, so it agrees by
// construction even though it isn't literally a wire column), TurnID,
// MessageID, SourceEventID, Input, Output, CacheRead, CacheCreation,
// CacheCreation1h, Reasoning, WebSearchRequests — every one selected
// unconditionally and inserted verbatim.
//
// SourceFileHash (round 10 finding F4, docs/security.md) is appended AFTER
// all of the above: it too ships verbatim and unconditionally (see
// TokenRow.SourceFileHash's doc comment), and — unlike every other field
// here — it is exactly the discriminator a prior version of this function
// was missing. Two keyless rows can otherwise tie on every field above
// (same timestamp/model/tool/token bundle, both id-less) while genuinely
// originating from two DIFFERENT capture files; before this field was
// added such a pair fingerprinted identically and was treated as one
// indistinguishable duplicate group even though a real, wire-shipped
// discriminator existed to tell them apart. Two rows sharing the SAME
// source file (and therefore the same SourceFileHash) remain a genuine
// duplicate group — the multiset comparison in tests/crossengine's
// compareKeylessGroup is still correct for that case.
func fingerprintTokenRow(t TokenRow) string {
	return contentFingerprint(strings.Join([]string{
		t.Timestamp, t.Model, t.Tool, t.TurnID, t.MessageID, t.SourceEventID,
		strconv.FormatInt(t.Input, 10), strconv.FormatInt(t.Output, 10),
		strconv.FormatInt(t.CacheRead, 10), strconv.FormatInt(t.CacheCreation, 10),
		strconv.FormatInt(t.CacheCreation1h, 10), strconv.FormatInt(t.Reasoning, 10),
		strconv.FormatInt(t.WebSearchRequests, 10),
		t.SourceFileHash,
	}, "|"))
}

// contentFingerprint hashes a canonical, pipe-joined field tuple down to a
// short (12 hex char / 48 bit) identifier — collision-safe at the scale of
// one session's keyless rows, and short enough to stay readable where a
// caller renders Key to an operator (the node's Messages tab).
func contentFingerprint(canonical string) string {
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:6])
}

// localTiebreak formats a row's LOCAL-ONLY Fast/CostUSD pair into a
// canonical string used solely as a tertiary, content-derived
// disambiguator (round 8 finding F4) — never as part of an emitted key or
// folded into a wire-stable fingerprint (fingerprintProxyRow /
// fingerprintTokenRow deliberately exclude both, per those functions' own
// "ships verbatim" rule). Fast and CostUSD are the ONLY fields either
// ProxyRow or TokenRow carries beyond what the two fingerprint functions
// already hash (a keyless row's RequestID is always empty by definition,
// so it adds nothing), so once two candidates tie on the wire fingerprint
// this is the entire remaining local signal available to break the tie
// deterministically — a pure function of the row's own content, never of
// scan order.
//
// Round 9 finding F2 (docs/security.md), correcting this comment's earlier,
// false claim that the two engines' resulting buckets are interchangeable:
// the org runs this SAME function over its OWN loaded rows, so its ordinal
// assignment for a wire-identical duplicate group is likewise a
// deterministic, scan-order-free function of ITS OWN data — but it is not
// the same function OF THE SAME DATA as the node's, and the two mappings
// are NOT guaranteed to agree. The org's own ProxyRow.Fast is always the
// zero value (no fast column ever crosses the wire — internal/store/
// orgpush.go's api_turns SELECT never selects it) and its TokenRow.CostUSD
// can be independently repriced at push time (G1-COST(b), internal/store/
// orgpush_pricing.go) even where a proxy row's CostUSD survives verbatim.
// So a node-side pair like {fast:true,cost:$1} vs {fast:false,cost:$100}
// sorts as [{fast:false,cost:$100}, {fast:true,cost:$1}] on the node
// ("false" precedes "true" lexically once Fast is the only thing that
// differs) but as [{cost:$1}, {cost:$100}] on the org (Fast is false on
// both there, so the tie falls straight to cost) — the identical synthetic
// key "keyless:<kind>:<fp>:0" names a DIFFERENT physical bundle, with a
// DIFFERENT recorded cost, on each engine.
//
// This is an INHERENT LIMIT of the wire shape, not a gap left open by this
// fix — no fingerprint change can close it without either fabricating a
// wire-stable disambiguator that doesn't exist or merging the two rows
// (which would conflate two distinct billable calls into one, a worse
// dishonesty than an engine-specific ordinal). What DOES still hold: the
// SET of keys a duplicate group resolves to is identical on both engines
// (canonicalizeKeyless assigns dup ordinals 0..N-1 within a fingerprint
// group regardless of which physical row lands on which), and the group's
// aggregate content (its multiset of bundles/costs, and therefore any
// per-session sum or count over it) agrees — only the per-ordinal
// attribution within the group is undefined across engines. A caller that
// needs per-message cost/fast attribution must not treat ordinal identity
// as portable across the node/org boundary for a keyless duplicate group.
// tests/crossengine's oracle (compareKeylessGroup) asserts exactly this:
// group membership and aggregate content must match, per-ordinal payload
// need not.
func localTiebreak(fast bool, cost float64) string {
	return strconv.FormatBool(fast) + "|" + strconv.FormatFloat(cost, 'g', -1, 64)
}

// lessTokenCandidate is the deterministic "which of two token-row
// candidates wins a tie" comparator shared by assignTwins' twin pick and
// pickShadowPartner's partner pick (round 8 finding F4): primary on the
// wire-stable fingerprintTokenRow — exactly what both call sites already
// compared pre-fix — falling through to the LOCAL-ONLY localTiebreak only
// when the wire fingerprint ALSO ties, i.e. the two candidates are
// byte-identical in every field that ships to the org. Two
// fingerprint-identical candidates can still be genuinely distinct
// PHYSICAL rows differing only in Fast/CostUSD (round 7 finding F3
// excluded both from the fingerprint precisely because neither survives
// the wire unchanged); without this second tier, a caller's
// `delta == bestDelta && fingerprintTokenRow(t) < fingerprintTokenRow(best)`
// check evaluates false for BOTH orderings of such a pair, so the running
// "best" pick keeps whichever candidate the (scan-order-dependent) loop
// happened to reach first. This comparator makes that pick a pure
// function of the candidate's own full content instead.
func lessTokenCandidate(a, b TokenRow) bool {
	if fa, fb := fingerprintTokenRow(a), fingerprintTokenRow(b); fa != fb {
		return fa < fb
	}
	return localTiebreak(a.Fast, a.CostUSD) < localTiebreak(b.Fast, b.CostUSD)
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// groupKeyForToken resolves a token_usage row's own bucket key.
func groupKeyForToken(mode GroupMode, t TokenRow) string {
	if mode == RollupTurn && t.TurnID != "" {
		return t.TurnID
	}
	return firstNonEmpty(t.MessageID, t.SourceEventID)
}

// groupKeyForTwin resolves the key a PROXY row adopts from its JSONL twin —
// turn_id/message_id only, per the node's proxyKeyExpr; a twin's bare
// source_event_id is deliberately never adopted (the proxy row's own
// request_id is the fallback the caller applies when this returns "").
func groupKeyForTwin(mode GroupMode, t TokenRow) string {
	if mode == RollupTurn && t.TurnID != "" {
		return t.TurnID
	}
	return t.MessageID
}

// shapeMatches is the token-bundle-shape equality a proxy row and a
// token_usage row must share to be the SAME captured turn: same model,
// same net input, same cache figures (twinShape), and an output the
// transcript could have derived from the proxy's (outputConsistent).
// Timestamp is deliberately excluded — closeness is used only to pick AMONG
// shape-matching candidates, in assignTwins.
func shapeMatches(p ProxyRow, t TokenRow) bool {
	return proxyTwinShape(&p) == tokenTwinShape(&t) && outputConsistent(p, t)
}

// outputConsistent reports whether a transcript row's visible output is the
// one its adapter derives from the proxy row's gross output: the provider's
// completion count minus the reasoning count it reports, CLAMPED AT ZERO -
// t.Output == max(0, p.Output - t.Reasoning).
//
// Above zero this is the exact equality p.Output == t.Output + t.Reasoning
// (the proxy stores gross output; the transcript nets reasoning out). The
// clamp is the one other shape a real twin takes: some providers report a
// reasoning count LARGER than the completion count they bill (live, an
// OpenRouter free model under OpenCode: completion 59, reasoning 65), and
// the transcript adapter floors the visible output at zero instead of
// storing a negative - so that twin read output 0 + reasoning 65 against
// the proxy's 59, never summed to it, and both copies of the turn counted
// (lane R2-ONERULE, defect D2).
//
// Nothing else is tolerated: output still has to be explained exactly, so
// two turns that share a prompt shape but produced different output never
// fold. A zero-visible-output row folds only onto a proxy row whose gross
// output its reasoning covers.
func outputConsistent(p ProxyRow, t TokenRow) bool {
	if t.Output > 0 || p.Output >= t.Reasoning {
		return p.Output == t.Output+t.Reasoning
	}
	return t.Output == 0
}

// assignTwins resolves each proxy row's own JSONL twin via one-to-one
// closest-timestamp shape matching. Proxy rows are matched in the order
// given (callers pass the canonically-sorted slice — see
// orderedProxyIndex), each claiming at most one UNCLAIMED shape-matching
// token row; a token row already claimed by an earlier proxy row is no
// longer a candidate for a later one. Returns, per proxy row index, the
// claimed token row index (-1 if none matched), and a per-token-row
// "claimed" mask — the set to exclude from separate emission.
//
// Round 7 finding F4: when two candidate token rows are EQUIDISTANT from
// the proxy row's timestamp (including the degenerate case where both
// share the proxy row's own timestamp exactly), the smaller
// fingerprintTokenRow wins — a deterministic, content-derived tie-break
// that never depends on which candidate `tokens` happened to present
// first. This matters even with the canonical presort:
// two token rows can shape-match the SAME proxy row (equal net input,
// equal output+reasoning SUM) while disagreeing on the output/reasoning
// SPLIT — genuinely different content, and therefore a genuinely
// different fingerprint — so relying on presort order alone (which only
// fixes the ARRIVAL-order half of the bug) would still leave the actual
// pick order-sensitive whenever the two candidates' deltas tie exactly.
//
// Round 8 finding F4: a fingerprintTokenRow tie no longer settles it —
// two candidates can also share an identical wire fingerprint while still
// being distinct physical rows that differ only in Fast/CostUSD (round 7
// finding F3 excluded both from the fingerprint). lessTokenCandidate
// (below) is what supplies the further, content-derived tier for that
// residual tie; see its doc comment.
//
// Candidates are looked up by shape (twinShape) rather than by scanning every
// token row for every proxy row: shapeMatches is exactly twinShape equality,
// and each shape's candidate list keeps the token rows' own order, so the
// scan visits the same candidates in the same relative order and picks the
// same row - in time linear in the session's rows instead of quadratic.
func assignTwins(proxies []ProxyRow, tokens []TokenRow) (twinOf []int, claimed []bool) {
	twinOf = make([]int, len(proxies))
	for i := range twinOf {
		twinOf[i] = -1
	}
	claimed = make([]bool, len(tokens))
	if len(proxies) == 0 || len(tokens) == 0 {
		return twinOf, claimed
	}
	byShape := make(map[twinShape][]int, len(tokens))
	stamps := make([]time.Time, len(tokens))
	stampOK := make([]bool, len(tokens))
	for ti := range tokens {
		t := &tokens[ti]
		k := tokenTwinShape(t)
		byShape[k] = append(byShape[k], ti)
		if tt, err := time.Parse(time.RFC3339Nano, t.Timestamp); err == nil {
			stamps[ti], stampOK[ti] = tt, true
		}
	}
	for pi := range proxies {
		p := &proxies[pi]
		candidates := byShape[proxyTwinShape(p)]
		if len(candidates) == 0 {
			continue
		}
		best := -1
		var bestDelta time.Duration
		pt, pErr := time.Parse(time.RFC3339Nano, p.Timestamp)
		for _, ti := range candidates {
			if claimed[ti] || !outputConsistent(*p, tokens[ti]) {
				continue
			}
			var delta time.Duration
			if pErr == nil && stampOK[ti] {
				delta = absDuration(pt.Sub(stamps[ti]))
			}
			switch {
			case best == -1, delta < bestDelta:
				best, bestDelta = ti, delta
			case delta == bestDelta && lessTokenCandidate(tokens[ti], tokens[best]):
				best, bestDelta = ti, delta
			}
		}
		if best >= 0 {
			twinOf[pi] = best
			claimed[best] = true
		}
	}
	return twinOf, claimed
}

// twinShape is the input side of shapeMatches: two rows can be twins only
// when their twinShape values are equal (proxyTwinShape / tokenTwinShape);
// outputConsistent then decides between the candidates of one shape.
type twinShape struct {
	model                    string
	input                    int64
	cacheRead, cacheCreation int64
}

// proxyTwinShape is a proxy row's twinShape.
func proxyTwinShape(p *ProxyRow) twinShape {
	return twinShape{model: p.Model, input: p.Input, cacheRead: p.CacheRead, cacheCreation: p.CacheCreation}
}

// tokenTwinShape is a token row's twinShape.
func tokenTwinShape(t *TokenRow) twinShape {
	return twinShape{model: t.Model, input: t.Input, cacheRead: t.CacheRead, cacheCreation: t.CacheCreation}
}

// shadowPairMaxDelta bounds PairShadowRows' adjacency fallback (S4,
// 2026-09-22 review round 3, tightening finding #7's round-2 fix): when
// neither side of a candidate pair carries a comparable stable id, a
// shadow row may only pair with a full-usage row within this many seconds
// of it — never "nearest in the bucket regardless of distance", which is
// exactly the round-2 bug (an id-less shadow at 09:00 paired with an
// unrelated equal-output full turn at 17:00, 8 hours away). A Copilot-
// family adapter's shadow/full pair for ONE turn are both written by the
// same request handler moments apart (sub-second in every observed
// fixture); 30s leaves generous headroom for adapter batching/flush
// jitter without risking a false pair across two genuinely different
// turns in a rapid-fire session.
const shadowPairMaxDelta = 30 * time.Second

// PairShadowRows implements S4 (2026-09-22 review round 3): pair each
// output-only "shadow" token_usage row with exactly one full-usage
// sibling sharing the same output count (the initial bucketing — two rows
// with different output counts were never the same turn's pair regardless
// of id or timing), subject to:
//
//   - (a) STABLE ID MATCH — when the shadow row and a candidate full row
//     BOTH carry a non-empty message_id, or (absent that) BOTH carry a
//     non-empty turn_id, equality on that field is a definitive pairing —
//     no distance bound applies. A MISMATCH on a field both sides carry
//     rules that candidate out entirely; it never falls through to (b),
//     because two rows that explicitly disagree on their own stable id
//     are never adjacency-paired just because they happen to be close in
//     time.
//   - (b) BOUNDED ADJACENCY — only for a candidate pair where neither side
//     offers a comparable stable id (or the field is empty on at least
//     one side): |shadow.Timestamp − full.Timestamp| <= shadowPairMaxDelta,
//     nearest wins among eligible candidates. Symmetric: the full row may
//     land before OR after the shadow, as long as the gap stays inside
//     the bound in either direction.
//   - (c) ZERO-ELSEWHERE — a "shadow" row must be zero on EVERY OTHER
//     billable field, not just input/cache_read/cache_creation: also
//     cache_creation_1h, reasoning, and web_search_requests. A row
//     carrying real reasoning or 1h-cache tokens is never classified as a
//     shadow — collapsing it would silently drop billed usage.
//
// Returns a per-index exclusion mask; a shadow row with no eligible
// partner is left UNEXCLUDED (surfaced as its own real, separately
// visible turn — never silently dropped).
func PairShadowRows(tokens []TokenRow, capable bool) []bool {
	excluded := make([]bool, len(tokens))
	if !capable {
		return excluded
	}
	isShadow := func(t TokenRow) bool {
		return t.Output > 0 &&
			t.Input == 0 && t.CacheRead == 0 && t.CacheCreation == 0 &&
			t.CacheCreation1h == 0 && t.Reasoning == 0 && t.WebSearchRequests == 0
	}
	isFull := func(t TokenRow) bool {
		return t.Input > 0 || t.CacheRead > 0 || t.CacheCreation > 0
	}
	byOutput := map[int64][]int{}
	for i, t := range tokens {
		byOutput[t.Output] = append(byOutput[t.Output], i)
	}
	for _, idxs := range byOutput {
		var shadows, fulls []int
		for _, i := range idxs {
			switch {
			case isShadow(tokens[i]):
				shadows = append(shadows, i)
			case isFull(tokens[i]):
				fulls = append(fulls, i)
			}
		}
		if len(shadows) == 0 || len(fulls) == 0 {
			continue
		}
		used := map[int]bool{}
		for _, s := range shadows {
			if pick := pickShadowPartner(tokens, s, fulls, used); pick != -1 {
				used[pick] = true
				excluded[s] = true
			}
		}
	}
	return excluded
}

// pickShadowPartner resolves ONE full-row candidate for shadow index s out
// of fulls (skipping any already in used), implementing PairShadowRows'
// (a)/(b) precedence. Returns -1 when no candidate is eligible.
func pickShadowPartner(tokens []TokenRow, s int, fulls []int, used map[int]bool) int {
	shadow := tokens[s]
	idEligible := func(full TokenRow) (eligible, mismatch bool) {
		if shadow.MessageID != "" && full.MessageID != "" {
			return true, shadow.MessageID != full.MessageID
		}
		if shadow.TurnID != "" && full.TurnID != "" {
			return true, shadow.TurnID != full.TurnID
		}
		return false, false
	}
	// (a) stable id match — first candidate (fulls is timestamp-ordered,
	// same as the caller's already-sorted tokens slice) whose comparable
	// id field equals the shadow's wins outright, regardless of distance.
	for _, f := range fulls {
		if used[f] {
			continue
		}
		if eligible, mismatch := idEligible(tokens[f]); eligible && !mismatch {
			return f
		}
	}
	// (b) bounded adjacency — only a candidate offering no comparable id at
	// all reaches the distance check below. A candidate whose id field IS
	// comparable is resolved entirely by pass (a): either it matched (and
	// pass (a) already returned it above) or it explicitly mismatched (a
	// stronger "not this one" signal than mere proximity) — either way it
	// is excluded here unconditionally, without needing to re-inspect which
	// of those two cases applied.
	//
	// Round 7 finding F4: an exact delta tie between two eligible
	// candidates breaks on the smaller fingerprintTokenRow, the same
	// deterministic, content-derived rule assignTwins uses — never on
	// which candidate `fulls` happened to present first, which is exactly
	// the scan-order sensitivity this fix removes.
	//
	// Round 8 finding F4: when the wire fingerprint ALSO ties (two
	// distinct physical rows differing only in Fast/CostUSD),
	// lessTokenCandidate falls through to that further local tier instead
	// of leaving the pick to whichever candidate `fulls` presents first —
	// see lessTokenCandidate's doc comment.
	st, sErr := time.Parse(time.RFC3339Nano, shadow.Timestamp)
	if sErr != nil {
		return -1
	}
	pick := -1
	var bestDelta time.Duration
	for _, f := range fulls {
		if used[f] {
			continue
		}
		full := tokens[f]
		if eligible, _ := idEligible(full); eligible {
			continue
		}
		ft, fErr := time.Parse(time.RFC3339Nano, full.Timestamp)
		if fErr != nil {
			continue
		}
		delta := absDuration(st.Sub(ft))
		if delta > shadowPairMaxDelta {
			continue
		}
		switch {
		case pick == -1, delta < bestDelta:
			pick, bestDelta = f, delta
		case delta == bestDelta && lessTokenCandidate(full, tokens[pick]):
			pick, bestDelta = f, delta
		}
	}
	return pick
}

// PickInferenceBucket picks which of a turn's chronologically-ordered
// per-inference buckets owns an action stamped actionTS. Boundary semantics
// differ by capture source: a proxy bucket is stamped at request START, so
// it owns actions from its own timestamp until the next bucket begins; a
// transcript bucket is stamped at inference END, so it owns actions since
// the PREVIOUS bucket's end (the first transcript bucket is unbounded
// below). Moved verbatim from the node's dashboard.go (the only caller
// before this package existed).
func PickInferenceBucket(stamps []string, isProxy []bool, actionTS string) int {
	if len(stamps) == 0 || len(stamps) != len(isProxy) {
		return -1
	}
	at, err := time.Parse(time.RFC3339Nano, actionTS)
	if err != nil {
		return 0
	}
	pick := 0
	for i := range stamps {
		var boundStamp string
		switch {
		case isProxy[i]:
			boundStamp = stamps[i]
		case i == 0:
			continue // unbounded below — the default pick already covers it
		default:
			boundStamp = stamps[i-1]
		}
		bound, err := time.Parse(time.RFC3339Nano, boundStamp)
		if err != nil {
			continue
		}
		if bound.Before(at) {
			pick = i
		}
	}
	return pick
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

func appendRowOnce(list []*Row, row *Row) []*Row {
	for _, r := range list {
		if r == row {
			return list
		}
	}
	return append(list, row)
}

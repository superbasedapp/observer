package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/turnmerge"
)

// Turn-provenance source tags persisted in api_turns.source (migration 047).
// They map to a turnmerge.Fidelity via fidelityForSource — the ONE place a
// source string becomes a fidelity rank, so the merge core
// (internal/turnmerge) stays blind to source identity (CLAUDE.md module
// rule #3).
const (
	// SourceProxy is a proxy intercept (exact tokens, cache-tier split, 1h
	// surcharge). Also the implicit value of a legacy NULL source — every
	// api_turns row written before migration 047 came from the proxy.
	SourceProxy = "proxy"
	// SourceCCOTel is Claude Code's native OTel (exact tokens, no proxy-only
	// fields). Written by the native-console ingest receiver.
	SourceCCOTel = "cc_otel"
	// SourceNativeOTel is any other AI tool's own native OTel export, mapped
	// by the vendor-agnostic table in internal/otlpvendor (T-475). Exact
	// tokens from the tool itself, so it ranks like Claude Code's.
	SourceNativeOTel = "native_otel"
	// SourceJSONL is a JSONL usage envelope (approximate). api_turns is not
	// written from the JSONL path today; reserved for completeness.
	SourceJSONL = "jsonl"
	// SourceObsSDK / SourceObsOTLP are the generalized-observability
	// subsystem's LLM-span sources (internal/obs; plan §5). SDK- and
	// instrumentor-reported token counts are estimates, so both rank
	// Approx — a proxy or native-OTel turn for the same request_id always
	// wins. These string values mirror internal/obs/span.Source. When obs
	// is removed they are simply unused strings; no edit is needed.
	SourceObsSDK  = "sdk_otlp"
	SourceObsOTLP = "otlp_trace"
	// SourceAgentOTel is a developer's own agent's span turn (PT-55,
	// internal/otlpvendor's own-agent row, docs/own-agents.md). The counts
	// are what the developer's own instrumentation reported from the
	// provider response, never computed by Observer, but they are not the
	// provider's bytes as the proxy sees them, so they rank Approx: a proxy
	// row for the same request id always wins, and a proxy insert for that
	// id replaces the span row outright (supersededByProxyInsert).
	SourceAgentOTel = "agent_otel"
	// SourceProxyTurn mirrors internal/obs/span.SourceProxyTurn (the gateway
	// rail, cmd/observer/obs_wire.go): a chat.completions span synthesized
	// FROM an already-priced api_turns row. obsTurnSink.ReconcileLLMSpan
	// gates on this source and never reconciles it back into api_turns (the
	// row already exists — reconciling would be the span writing back into
	// itself), so this value should never actually appear in api_turns.source
	// today. The row exists as defense-in-depth per CLAUDE.md module rule
	// #3/#5 (table-driven, not an implicit default): if that guard is ever
	// removed or a new path writes this source, it must rank Exact — a
	// proxy-priced turn is exact, not an SDK estimate — never silently fall
	// through to Approx via `default`.
	SourceProxyTurn = "proxy_turn"
)

// fidelityForSource maps a persisted source tag to its merge fidelity. An
// empty/unknown source is treated as proxy (the historical sole writer of
// api_turns), so legacy rows keep top rank without a backfill.
func fidelityForSource(source string) turnmerge.Fidelity {
	switch source {
	case SourceCCOTel, SourceNativeOTel:
		return turnmerge.FidelityNativeExact
	case SourceJSONL, SourceObsSDK, SourceObsOTLP, SourceAgentOTel:
		return turnmerge.FidelityApprox
	case SourceProxyTurn:
		return turnmerge.FidelityProxyExact
	default: // "" (legacy) and SourceProxy
		return turnmerge.FidelityProxyExact
	}
}

// mergeTurnRow holds the existing api_turns columns that participate in
// cross-source merge, plus its id and source for the precedence decision.
type mergeTurnRow struct {
	id     int64
	source string
	turn   turnmerge.Turn
	// upstreamLane is the row's /up/<id> lane, "" when it is not a
	// gateway-rail turn (migration 260).
	upstreamLane string
}

// UpsertTurnByRequestID records a turn observation, deduping against any
// existing api_turns row for the same request_id by source-derived fidelity
// (the native-console dedup core, Phase 2). It returns the action taken and the
// id of the affected row.
//
//   - No existing row (or t.RequestID == "", which has no dedup key) → the turn
//     is inserted via InsertAPITurn; action is turnmerge.ActionInsert. A
//     native-only turn (no proxy) lands here at full fidelity — the no-proxy
//     coverage-gap fill.
//   - An existing row → the observation is merged per turnmerge precedence:
//     authoritative token/cost fields take the higher fidelity (equal → MAX);
//     enrichment fields (ttft, total_response_ms, stop_reason) fill only if
//     absent. action is ActionUpdate when something changed, else
//     ActionNoChange.
//
// NOTE (Phase-3 hardening): the read-modify-write is not yet wrapped in a
// transaction, so two sources inserting the same request_id in the same instant
// could briefly produce two rows. Today the proxy is the only writer of
// api_turns; the native receiver (Phase 2b) is the first concurrent writer, and
// turn telemetry is at-least-once. Phase 3 adds a guarded unique index once
// legacy duplicate/empty request_ids are confirmed handled.
func (s *Store) UpsertTurnByRequestID(ctx context.Context, t models.APITurn) (turnmerge.Action, int64, error) {
	if t.RequestID == "" {
		id, err := s.InsertAPITurn(ctx, t)
		if err != nil {
			return turnmerge.ActionInsert, 0, fmt.Errorf("store.UpsertTurnByRequestID: %w", err)
		}
		return turnmerge.ActionInsert, id, nil
	}

	existing, err := s.loadMergeTurn(ctx, t.RequestID)
	if err != nil {
		return turnmerge.ActionNoChange, 0, fmt.Errorf("store.UpsertTurnByRequestID: %w", err)
	}

	incoming := turnFromAPITurn(t)
	var existingTurn *turnmerge.Turn
	if existing != nil {
		existingTurn = &existing.turn
	}

	res := turnmerge.Merge(existingTurn, incoming)
	switch res.Action {
	case turnmerge.ActionInsert:
		id, err := s.InsertAPITurn(ctx, t)
		if err != nil {
			return res.Action, 0, fmt.Errorf("store.UpsertTurnByRequestID: %w", err)
		}
		return res.Action, id, nil
	case turnmerge.ActionUpdate:
		if err := s.updateMergeTurnSource(ctx, existing.id, res.Turn, mergedSource(res.Turn.Fidelity, existing.source, t.Source)); err != nil {
			return res.Action, existing.id, fmt.Errorf("store.UpsertTurnByRequestID: %w", err)
		}
		return res.Action, existing.id, nil
	default: // ActionNoChange
		return res.Action, existing.id, nil
	}
}

// planeATurnSources are the Plane A (hosted-app observability) source tags
// (internal/obs; D6, F10). A hosted app's spend is not the developer's coding
// spend, so these sources never CREATE an api_turns row
// (MergeTurnByRequestID); the rows older nodes wrote were relocated by agent
// migration 256, and a row that still carries one never ships on the Plane B
// org push (PlaneATurnSourceSQL in orgpush.go). Data table, one row per
// source; migration 256 names the same two values.
var planeATurnSources = []string{SourceObsSDK, SourceObsOTLP}

// IsPlaneATurnSource reports whether an api_turns source tag is a Plane A
// (hosted-app observability) source.
func IsPlaneATurnSource(source string) bool {
	for _, s := range planeATurnSources {
		if s == source {
			return true
		}
	}
	return false
}

// PlaneATurnSourceSQL is the SQL predicate "this api_turns row (alias) was
// written by a Plane A source". Plane B reads that must not count a hosted
// app's spend as coding spend exclude rows matching it. The values are the
// in-package constants above, never user input.
func PlaneATurnSourceSQL(alias string) string {
	col := "source"
	if alias != "" {
		col = alias + ".source"
	}
	quoted := make([]string, len(planeATurnSources))
	for i, s := range planeATurnSources {
		quoted[i] = "'" + s + "'"
	}
	return "COALESCE(" + col + ",'') IN (" + strings.Join(quoted, ",") + ")"
}

// MergeTurnByRequestID is the MERGE-ONLY sibling of UpsertTurnByRequestID,
// the seam Plane A LLM spans reconcile through (D6, F10). It enriches an
// existing api_turns row for t.RequestID (a proxy, gateway, native-OTel or
// own-agent turn) by the same turnmerge precedence, and NEVER inserts:
//
//   - t.RequestID == "" or no row for it: nothing happens (ActionNoChange,
//     id 0). A hosted app's span must not create a Plane B row.
//   - The existing row is itself a Plane A row (IsPlaneATurnSource, written
//     before this rule): left untouched, so a re-merge can never relabel it
//     through sourceForFidelity into a source the Plane B push would ship.
//   - The existing row is not a gateway-rail turn (no upstream_lane: a
//     coding agent's default-lane proxy turn, a transcript, native-OTel or
//     own-agent row): left untouched (review E-23, plan principle 5). The
//     loopback receiver takes spans from any local process without a token,
//     and an app-chosen request id must not reach a coding agent's row.
//   - Otherwise: the span may only ENRICH the row (time to first token,
//     total response time, stop reason, each fill-if-absent). Its tokens and
//     cost never replace or raise the row's, whatever the two ranks are
//     (mergeOnlyRules, review R-A14): a hosted app's span carrying a
//     developer's request id must not inflate that developer's Plane B
//     spend, and at equal rank turnmerge would otherwise take the MAX.
func (s *Store) MergeTurnByRequestID(ctx context.Context, t models.APITurn) (turnmerge.Action, int64, error) {
	if t.RequestID == "" {
		return turnmerge.ActionNoChange, 0, nil
	}
	existing, err := s.loadMergeTurn(ctx, t.RequestID)
	if err != nil {
		return turnmerge.ActionNoChange, 0, fmt.Errorf("store.MergeTurnByRequestID: %w", err)
	}
	if existing == nil {
		return turnmerge.ActionNoChange, 0, nil
	}
	if IsPlaneATurnSource(existing.source) || existing.upstreamLane == "" {
		return turnmerge.ActionNoChange, existing.id, nil
	}
	res := turnmerge.Merge(&existing.turn, mergeOnlyIncoming(existing.turn, turnFromAPITurn(t)))
	if res.Action != turnmerge.ActionUpdate {
		return turnmerge.ActionNoChange, existing.id, nil
	}
	// The row keeps its own rank and source tag: only enrichment changed.
	res.Turn.Fidelity = existing.turn.Fidelity
	if err := s.updateMergeTurnSource(ctx, existing.id, res.Turn, mergedSource(res.Turn.Fidelity, existing.source, existing.source)); err != nil {
		return res.Action, existing.id, fmt.Errorf("store.MergeTurnByRequestID: %w", err)
	}
	return res.Action, existing.id, nil
}

// mergeOnlyRule is one row of the merge-only seam's decision table: for a
// relation between the existing row's rank and the incoming span's, whether
// the span may write the authoritative block (tokens, cost). Enrichment is
// always fill-if-absent (turnmerge).
type mergeOnlyRule struct {
	relation      string
	match         func(existing, incoming turnmerge.Fidelity) bool
	authoritative bool
}

// mergeOnlyRules is walked top-down; the first matching row decides. No row
// lets a Plane A span author Plane B tokens or cost: above it the row is
// more exact already, at its rank turnmerge would take the MAX (raising an
// own-agent or JSONL row from a hosted app's numbers, R-A14), and below it
// the span would replace a Plane B observation with a hosted app's.
var mergeOnlyRules = []mergeOnlyRule{
	{"existing ranks higher", func(e, i turnmerge.Fidelity) bool { return e > i }, false},
	{"equal rank", func(e, i turnmerge.Fidelity) bool { return e == i }, false},
	{"existing ranks lower", func(e, i turnmerge.Fidelity) bool { return e < i }, false},
}

// mergeOnlyIncoming returns the incoming observation as the merge-only seam
// may apply it: when the matching mergeOnlyRules row forbids the
// authoritative block, the block is replaced by the existing row's values
// and the rank by the existing rank, so turnmerge changes enrichment only.
func mergeOnlyIncoming(existing, incoming turnmerge.Turn) turnmerge.Turn {
	for _, r := range mergeOnlyRules {
		if !r.match(existing.Fidelity, incoming.Fidelity) {
			continue
		}
		if r.authoritative {
			return incoming
		}
		out := incoming
		out.Fidelity = existing.Fidelity
		out.InputTokens = existing.InputTokens
		out.OutputTokens = existing.OutputTokens
		out.CacheReadTokens = existing.CacheReadTokens
		out.CacheCreationTokens = existing.CacheCreationTokens
		out.CacheCreation1hTokens = existing.CacheCreation1hTokens
		out.WebSearchRequests = existing.WebSearchRequests
		out.CostUSD = existing.CostUSD
		return out
	}
	return incoming
}

// turnFromAPITurn projects a full models.APITurn into the merge view, assigning
// fidelity from its source tag at the boundary.
func turnFromAPITurn(t models.APITurn) turnmerge.Turn {
	return turnmerge.Turn{
		RequestID:             t.RequestID,
		Fidelity:              fidelityForSource(t.Source),
		InputTokens:           t.InputTokens,
		OutputTokens:          t.OutputTokens,
		CacheReadTokens:       t.CacheReadTokens,
		CacheCreationTokens:   t.CacheCreationTokens,
		CacheCreation1hTokens: t.CacheCreation1hTokens,
		WebSearchRequests:     t.WebSearchRequests,
		CostUSD:               t.CostUSD,
		TimeToFirstTokenMS:    t.TimeToFirstTokenMS,
		TotalResponseMS:       t.TotalResponseMS,
		StopReason:            t.StopReason,
	}
}

// loadMergeTurn reads the oldest api_turns row for request_id (lowest id, the
// canonical one when legacy duplicates exist) into the merge view. Returns nil
// when no row exists.
func (s *Store) loadMergeTurn(ctx context.Context, requestID string) (*mergeTurnRow, error) {
	var (
		r   mergeTurnRow
		src sql.NullString
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT id, COALESCE(source,''),
		        input_tokens, output_tokens,
		        COALESCE(cache_read_tokens,0), COALESCE(cache_creation_tokens,0),
		        COALESCE(cache_creation_1h_tokens,0), COALESCE(web_search_requests,0),
		        COALESCE(cost_usd,0),
		        COALESCE(time_to_first_token_ms,0), COALESCE(total_response_ms,0),
		        COALESCE(stop_reason,''), COALESCE(upstream_lane,'')
		   FROM api_turns
		  WHERE request_id = ? ORDER BY id ASC LIMIT 1`, requestID).Scan(
		&r.id, &src,
		&r.turn.InputTokens, &r.turn.OutputTokens,
		&r.turn.CacheReadTokens, &r.turn.CacheCreationTokens,
		&r.turn.CacheCreation1hTokens, &r.turn.WebSearchRequests,
		&r.turn.CostUSD,
		&r.turn.TimeToFirstTokenMS, &r.turn.TotalResponseMS,
		&r.turn.StopReason, &r.upstreamLane,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("loadMergeTurn: %w", err)
	}
	r.source = src.String
	r.turn.RequestID = requestID
	r.turn.Fidelity = fidelityForSource(r.source)
	return &r, nil
}

// updateMergeTurn writes the merged authoritative + enrichment columns back to
// the existing row, stamping the source that corresponds to the merged
// fidelity so a later read resolves the same rank.
func (s *Store) updateMergeTurn(ctx context.Context, id int64, merged turnmerge.Turn) error {
	return s.updateMergeTurnSource(ctx, id, merged, sourceForFidelity(merged.Fidelity))
}

// updateMergeTurnSource is updateMergeTurn persisting an explicit source tag
// (mergedSource), so a merged native_otel row keeps its own tag.
func (s *Store) updateMergeTurnSource(ctx context.Context, id int64, merged turnmerge.Turn, source string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE api_turns SET
		    input_tokens = ?, output_tokens = ?,
		    cache_read_tokens = ?, cache_creation_tokens = ?,
		    cache_creation_1h_tokens = ?, web_search_requests = ?,
		    cost_usd = ?,
		    time_to_first_token_ms = ?, total_response_ms = ?,
		    stop_reason = ?, source = ?
		  WHERE id = ?`,
		merged.InputTokens, merged.OutputTokens,
		merged.CacheReadTokens, merged.CacheCreationTokens,
		merged.CacheCreation1hTokens, merged.WebSearchRequests,
		merged.CostUSD,
		merged.TimeToFirstTokenMS, merged.TotalResponseMS,
		nullableString(merged.StopReason), source,
		id)
	if err != nil {
		return fmt.Errorf("updateMergeTurn: %w", err)
	}
	return nil
}

// preservedSources are the source tags a merged row keeps verbatim when the
// merge kept that tag's fidelity. Every other tag maps through
// sourceForFidelity exactly as before T-475. native_otel needs it because it
// shares the native-exact fidelity with cc_otel: mapping it back would
// relabel any other tool's native turn as Claude Code's.
// SourceAgentOTel needs it for the same reason: mapping Approx back would
// relabel an own agent's span turn as a JSONL envelope.
var preservedSources = map[string]bool{SourceNativeOTel: true, SourceAgentOTel: true}

// supersededByProxyInsert lists the sources whose row a PROXY insert for the
// same request id replaces instead of standing beside. The proxy writes its
// rows with InsertAPITurn, not the request-id merge, so a lower-fidelity
// row that landed first (an own agent's span exported before the proxy
// finished writing the same call) would otherwise count the call twice. A
// replaced row is deleted through the normal path, so the org push records
// the deletion (org_push_delete_api_turns). Data table, one row per source.
var supersededByProxyInsert = map[string]bool{SourceAgentOTel: true}

// mergedSource names the source a merged row persists with.
func mergedSource(merged turnmerge.Fidelity, existing, incoming string) string {
	for _, src := range []string{existing, incoming} {
		if preservedSources[src] && fidelityForSource(src) == merged {
			return src
		}
	}
	return sourceForFidelity(merged)
}

// sourceForFidelity is the inverse of fidelityForSource for persisting a merged
// row's rank. ProxyExact persists as the explicit "proxy" tag (never empty) so
// a merged row's provenance is unambiguous after an update.
func sourceForFidelity(f turnmerge.Fidelity) string {
	switch f {
	case turnmerge.FidelityNativeExact:
		return SourceCCOTel
	case turnmerge.FidelityApprox:
		return SourceJSONL
	default:
		return SourceProxy
	}
}

// supersedeForProxyInsert deletes the rows the proxy's just-inserted row
// (id) replaces (supersededByProxyInsert): rows with t's request id whose
// source the table lists. It runs only for a proxy-fidelity insert that
// carries a request id, so every other writer's insert is unchanged.
func (s *Store) supersedeForProxyInsert(ctx context.Context, t models.APITurn, id int64) error {
	if t.RequestID == "" || fidelityForSource(t.Source) != turnmerge.FidelityProxyExact {
		return nil
	}
	for src := range supersededByProxyInsert {
		if _, err := s.db.ExecContext(ctx,
			`DELETE FROM api_turns WHERE request_id = ? AND source = ? AND id <> ?`, t.RequestID, src, id); err != nil {
			return fmt.Errorf("store.InsertAPITurn: supersede %s row: %w", src, err)
		}
	}
	return nil
}

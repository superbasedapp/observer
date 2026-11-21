package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// RequestEnrichment is the pull-only bundle the host hands the observability
// subsystem for one request_id: proxy-exact tokens + cache-tier split + cost
// from api_turns, plus the routing rationale joined through the api_turn id.
// It is the host-side substrate behind obs.Enrichment (the wedge made visible
// on an arbitrary agent's trajectory); obs never reads api_turns / routing
// directly — it asks through the ProxyEnricher interface, and this struct is
// what the host returns. GuardVerdict is the inline guard decision the proxy
// recorded for this turn's response (§8.3), joined through the api_turn id —
// the proxy response-inspection path now anchors guard_events.api_turn_id, so
// a verdict can be honestly surfaced on the span; empty when the guard flagged
// nothing for this turn.
type RequestEnrichment struct {
	Found               bool
	Provider            string
	Model               string
	InputTokens         int64
	OutputTokens        int64
	CacheReadTokens     int64
	CacheCreationTokens int64
	CostUSD             float64
	// CostUnpriced: the cost engine did not price the turn (a local or
	// unknown model). api_turns stores that as NULL on insert
	// (nullableFloat64) and as 0 after a merge update, so both read unpriced;
	// a model the book prices at exactly $0 is indistinguishable and reads
	// unpriced too, the honest side. CostUSD is then 0 and means nothing; a
	// reader must show the turn unpriced, never $0 (review finding R-C06).
	CostUnpriced  bool
	RoutingReason string // human-readable: "→ <selected_model> (<codes>)", empty when no decision logged
	GuardVerdict  string // human-readable: "<decision> <rule> (<category>)", empty when no verdict anchored
}

// EnrichmentByRequestID returns the proxy-observed facts for one request_id, or
// found=false when no GENUINELY proxy/native turn carries it. It reads only the
// host's own tables (api_turns, router_decisions) — the single read seam behind
// the obs ProxyEnricher, keeping api_turns' owner inside internal/store
// (CLAUDE.md rule #4). The canonical (lowest-id) api_turn wins when legacy
// duplicates share a request_id, matching loadMergeTurn.
//
// Honesty gate: obs-reported turns (the TurnSink reconciliation writes an
// api_turn with source otlp_trace / sdk_otlp from the OTLP span itself) are
// EXCLUDED — enrichment means "the proxy/native telemetry ALSO observed this
// request," not "the span reconciled itself." A merged proxy turn has its
// source rewritten to the proxy/native source by updateMergeTurn
// (sourceForFidelity of the winning fidelity), so a real proxy observation
// still matches; a pure self-reconcile does not. Without this gate every OTLP
// span with a request_id would falsely render "Proxy-verified" (§9).
func (s *Store) EnrichmentByRequestID(ctx context.Context, requestID string) (RequestEnrichment, bool, error) {
	if requestID == "" {
		return RequestEnrichment{}, false, nil
	}
	var (
		e         RequestEnrichment
		apiTurnID int64
	)
	err := s.db.QueryRowContext(ctx, `
SELECT id, provider, model, input_tokens, output_tokens,
       COALESCE(cache_read_tokens,0), COALESCE(cache_creation_tokens,0),
       COALESCE(cost_usd,0), CASE WHEN COALESCE(cost_usd,0) = 0 THEN 1 ELSE 0 END
  FROM api_turns
 WHERE request_id = ?
   AND COALESCE(source,'') NOT IN (?, ?)
 ORDER BY id ASC LIMIT 1`, requestID, SourceObsOTLP, SourceObsSDK).Scan(
		&apiTurnID, &e.Provider, &e.Model, &e.InputTokens, &e.OutputTokens,
		&e.CacheReadTokens, &e.CacheCreationTokens, &e.CostUSD, &e.CostUnpriced,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return RequestEnrichment{}, false, nil
	}
	if err != nil {
		return RequestEnrichment{}, false, fmt.Errorf("store.EnrichmentByRequestID: %w", err)
	}
	e.Found = true
	e.RoutingReason = s.routingReasonForTurn(ctx, apiTurnID)
	e.GuardVerdict = s.guardVerdictForTurn(ctx, apiTurnID)
	return e, true, nil
}

// guardVerdictForTurn returns a human-readable guard verdict for an api_turn
// id, or "" when no guard_event was anchored to it (the common case — the
// guard flagged nothing, or this turn predates the proxy api_turn_id anchor).
// The most severe / most recent verdict wins (highest id among the turn's
// events). Best-effort: a query failure yields "", never an error — enrichment
// is additive and must never fail the trace read.
func (s *Store) guardVerdictForTurn(ctx context.Context, apiTurnID int64) string {
	var (
		decision string
		ruleID   string
		category string
	)
	err := s.db.QueryRowContext(ctx, `
SELECT COALESCE(decision,''), COALESCE(rule_id,''), COALESCE(category,'')
  FROM guard_events
 WHERE api_turn_id = ? ORDER BY id DESC LIMIT 1`, apiTurnID).Scan(&decision, &ruleID, &category)
	if err != nil || decision == "" {
		return ""
	}
	v := decision
	if ruleID != "" {
		v += " " + ruleID
	}
	if category != "" {
		v += " (" + category + ")"
	}
	return v
}

// routingReasonForTurn returns a human-readable routing rationale for an
// api_turn id, or "" when no decision was logged for it (routing off, or a
// turn the router never saw). Best-effort: a decode/query failure yields "",
// never an error — enrichment is additive and must never fail the trace read.
func (s *Store) routingReasonForTurn(ctx context.Context, apiTurnID int64) string {
	var (
		selected string
		codesRaw string
	)
	err := s.db.QueryRowContext(ctx, `
SELECT selected_model, reason_codes
  FROM router_decisions
 WHERE api_turn_id = ? ORDER BY id DESC LIMIT 1`, apiTurnID).Scan(&selected, &codesRaw)
	if err != nil {
		return ""
	}
	var codes []string
	if codesRaw != "" {
		_ = json.Unmarshal([]byte(codesRaw), &codes)
	}
	reason := "→ " + selected
	if len(codes) > 0 {
		reason += " (" + strings.Join(codes, ", ") + ")"
	}
	return reason
}

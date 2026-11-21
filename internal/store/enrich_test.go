package store

import (
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestEnrichmentByRequestID_JoinsTurnAndRouting pins the P6 read seam: facts
// come from api_turns by request_id and the routing rationale joins through
// the api_turn id.
func TestEnrichmentByRequestID_JoinsTurnAndRouting(t *testing.T) {
	t.Parallel()
	st, ctx := openRoutingTestStore(t)

	_, id, err := st.UpsertTurnByRequestID(ctx, models.APITurn{
		Provider: "openai", Model: "gpt-4o", RequestID: "chatcmpl-x",
		InputTokens: 100, OutputTokens: 20,
		CacheReadTokens: 64, CacheCreationTokens: 16,
		CostUSD: 0.0123, Source: SourceProxy, Timestamp: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("UpsertTurnByRequestID: %v", err)
	}
	if err := st.InsertRouterDecisions(ctx, []RouterDecisionRow{{
		APITurnID: &id, Timestamp: time.Now().UTC(), Mode: "advise", Channel: "proxy",
		OriginalModel: "gpt-4o", SelectedModel: "gpt-4o-mini", TurnKind: "edit",
		PolicyHash: "h1", ReasonCodes: []string{"downshift", "budget"},
	}}); err != nil {
		t.Fatalf("InsertRouterDecisions: %v", err)
	}

	e, found, err := st.EnrichmentByRequestID(ctx, "chatcmpl-x")
	if err != nil || !found {
		t.Fatalf("EnrichmentByRequestID: found=%v err=%v", found, err)
	}
	if e.Provider != "openai" || e.Model != "gpt-4o" || e.InputTokens != 100 || e.OutputTokens != 20 {
		t.Errorf("turn facts = %+v", e)
	}
	if e.CacheReadTokens != 64 || e.CacheCreationTokens != 16 || e.CostUSD != 0.0123 {
		t.Errorf("cost/cache = %+v", e)
	}
	if e.RoutingReason != "→ gpt-4o-mini (downshift, budget)" {
		t.Errorf("RoutingReason = %q", e.RoutingReason)
	}
}

// TestEnrichmentByRequestID_NoTurnAndNoRouting covers the honest-empty paths:
// an unknown request_id is not-found, and a turn with no routing decision
// yields an empty RoutingReason (not an error).
func TestEnrichmentByRequestID_NoTurnAndNoRouting(t *testing.T) {
	t.Parallel()
	st, ctx := openRoutingTestStore(t)

	if _, found, err := st.EnrichmentByRequestID(ctx, "nope"); err != nil || found {
		t.Errorf("unknown req: found=%v err=%v, want false nil", found, err)
	}
	if _, found, err := st.EnrichmentByRequestID(ctx, ""); err != nil || found {
		t.Errorf("empty req: found=%v err=%v, want false nil", found, err)
	}

	if _, _, err := st.UpsertTurnByRequestID(ctx, models.APITurn{
		Provider: "openai", Model: "gpt-4o", RequestID: "no-route",
		InputTokens: 10, OutputTokens: 2, Source: SourceProxy, Timestamp: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("UpsertTurnByRequestID: %v", err)
	}
	e, found, err := st.EnrichmentByRequestID(ctx, "no-route")
	if err != nil || !found {
		t.Fatalf("EnrichmentByRequestID: found=%v err=%v", found, err)
	}
	if e.RoutingReason != "" {
		t.Errorf("RoutingReason = %q, want empty (no decision logged)", e.RoutingReason)
	}
	if e.GuardVerdict != "" {
		t.Errorf("GuardVerdict = %q, want empty (no verdict anchored)", e.GuardVerdict)
	}
}

// TestEnrichmentByRequestID_ExcludesObsSelfReconcile pins the honesty gate: a
// turn whose only source is the obs OTLP/SDK self-reconcile (the TurnSink
// writing an api_turn from the OTLP span itself) must NOT enrich — otherwise
// every OTLP span with a request_id would falsely read "Proxy-verified". A
// genuine proxy turn for the same id DOES enrich.
func TestEnrichmentByRequestID_ExcludesObsSelfReconcile(t *testing.T) {
	t.Parallel()
	st, ctx := openRoutingTestStore(t)

	// obs OTLP self-reconcile only → not proxy-observed → not found.
	if _, _, err := st.UpsertTurnByRequestID(ctx, models.APITurn{
		Provider: "openai", Model: "gpt-4o", RequestID: "otlp-only",
		InputTokens: 100, OutputTokens: 20, Source: SourceObsOTLP, Timestamp: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("UpsertTurnByRequestID otlp: %v", err)
	}
	if _, found, err := st.EnrichmentByRequestID(ctx, "otlp-only"); err != nil || found {
		t.Errorf("obs-self-reconcile: found=%v err=%v, want false (not proxy-observed)", found, err)
	}

	// A genuine proxy turn merges in (fidelity upgrades the source) → found.
	if _, _, err := st.UpsertTurnByRequestID(ctx, models.APITurn{
		Provider: "openai", Model: "gpt-4o", RequestID: "otlp-only",
		InputTokens: 100, OutputTokens: 20, CostUSD: 0.02, Source: SourceProxy, Timestamp: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("UpsertTurnByRequestID proxy: %v", err)
	}
	e, found, err := st.EnrichmentByRequestID(ctx, "otlp-only")
	if err != nil || !found {
		t.Fatalf("after proxy merge: found=%v err=%v, want found", found, err)
	}
	if e.CostUSD != 0.02 {
		t.Errorf("proxy cost = %v, want 0.02", e.CostUSD)
	}
}

// TestEnrichmentByRequestID_GuardVerdict pins the P6 GuardVerdict follow-up:
// a guard_event anchored to the turn's api_turn_id (the proxy response-
// inspection anchor) surfaces as a human-readable verdict on the enrichment.
func TestEnrichmentByRequestID_GuardVerdict(t *testing.T) {
	t.Parallel()
	st, ctx := openRoutingTestStore(t)

	_, id, err := st.UpsertTurnByRequestID(ctx, models.APITurn{
		Provider: "anthropic", Model: "claude-opus-4-8", RequestID: "req-guard",
		InputTokens: 10, OutputTokens: 5, Source: SourceProxy, Timestamp: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("UpsertTurnByRequestID: %v", err)
	}
	if _, err := st.InsertGuardEvents(ctx, []GuardEventRow{{
		TS: time.Now().UTC(), SessionID: "s1", APITurnID: &id,
		RuleID: "R-172", Category: "destructive", Severity: "high", Decision: "flag",
		Source: "proxy", Reason: "rm -rf ~",
	}}); err != nil {
		t.Fatalf("InsertGuardEvents: %v", err)
	}

	e, found, err := st.EnrichmentByRequestID(ctx, "req-guard")
	if err != nil || !found {
		t.Fatalf("EnrichmentByRequestID: found=%v err=%v", found, err)
	}
	if e.GuardVerdict != "flag R-172 (destructive)" {
		t.Errorf("GuardVerdict = %q, want %q", e.GuardVerdict, "flag R-172 (destructive)")
	}
}

// TestEnrichmentByRequestID_UnpricedTurn pins review finding R-C06: a proxy
// turn with tokens the cost engine could not price reads unpriced, never a
// priced $0.
func TestEnrichmentByRequestID_UnpricedTurn(t *testing.T) {
	t.Parallel()
	st, ctx := openRoutingTestStore(t)
	for _, tc := range []struct {
		req      string
		cost     float64
		unpriced bool
	}{{"unpriced", 0, true}, {"priced", 0.01, false}} {
		if _, _, err := st.UpsertTurnByRequestID(ctx, models.APITurn{
			Provider: "openai", Model: "local-model", RequestID: tc.req,
			InputTokens: 10, OutputTokens: 2, CostUSD: tc.cost, Source: SourceProxy, Timestamp: time.Now().UTC(),
		}); err != nil {
			t.Fatalf("UpsertTurnByRequestID: %v", err)
		}
		e, found, err := st.EnrichmentByRequestID(ctx, tc.req)
		if err != nil || !found {
			t.Fatalf("EnrichmentByRequestID(%s): found=%v err=%v", tc.req, found, err)
		}
		if e.CostUnpriced != tc.unpriced {
			t.Errorf("%s: CostUnpriced = %v, want %v", tc.req, e.CostUnpriced, tc.unpriced)
		}
	}
}

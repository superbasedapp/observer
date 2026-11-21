package store

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/turnmerge"
)

// TestMergeOnlyRulesNeverWriteAuthoritative is one case per mergeOnlyRules
// row (review R-A14): whatever the rank relation, the incoming span's tokens
// and cost are replaced by the existing row's, its rank by the existing
// rank, and its enrichment fields survive for turnmerge to fill.
func TestMergeOnlyRulesNeverWriteAuthoritative(t *testing.T) {
	t.Parallel()
	existing := func(f turnmerge.Fidelity) turnmerge.Turn {
		return turnmerge.Turn{RequestID: "r", Fidelity: f, InputTokens: 10, OutputTokens: 1, CacheReadTokens: 2, CostUSD: 0.01}
	}
	incoming := turnmerge.Turn{
		RequestID: "r", Fidelity: turnmerge.FidelityApprox, InputTokens: 500, OutputTokens: 50,
		CacheReadTokens: 99, CacheCreationTokens: 7, WebSearchRequests: 3, CostUSD: 9.99,
		TimeToFirstTokenMS: 120, TotalResponseMS: 900, StopReason: "end_turn",
	}
	for _, tc := range []struct {
		relation string
		exist    turnmerge.Fidelity
	}{
		{"existing ranks higher", turnmerge.FidelityProxyExact},
		{"equal rank", turnmerge.FidelityApprox},
		{"existing ranks lower", turnmerge.FidelityUnknown},
	} {
		t.Run(tc.relation, func(t *testing.T) {
			e := existing(tc.exist)
			got := mergeOnlyIncoming(e, incoming)
			if got.Fidelity != e.Fidelity || got.InputTokens != e.InputTokens || got.OutputTokens != e.OutputTokens ||
				got.CacheReadTokens != e.CacheReadTokens || got.CacheCreationTokens != e.CacheCreationTokens ||
				got.WebSearchRequests != e.WebSearchRequests || got.CostUSD != e.CostUSD {
				t.Errorf("authoritative block leaked: %+v", got)
			}
			if got.TimeToFirstTokenMS != 120 || got.TotalResponseMS != 900 || got.StopReason != "end_turn" {
				t.Errorf("enrichment lost: %+v", got)
			}
			res := turnmerge.Merge(&e, got)
			if res.Turn.InputTokens != 10 || res.Turn.CostUSD != 0.01 {
				t.Errorf("merge raised the row: %+v", res.Turn)
			}
			if res.Turn.TimeToFirstTokenMS != 120 || res.Turn.StopReason != "end_turn" {
				t.Errorf("merge did not enrich: %+v", res.Turn)
			}
		})
	}
	// Every relation is covered by exactly one row.
	for _, pair := range [][2]turnmerge.Fidelity{
		{turnmerge.FidelityProxyExact, turnmerge.FidelityApprox},
		{turnmerge.FidelityApprox, turnmerge.FidelityApprox},
		{turnmerge.FidelityUnknown, turnmerge.FidelityApprox},
	} {
		n := 0
		for _, r := range mergeOnlyRules {
			if r.match(pair[0], pair[1]) {
				n++
			}
		}
		if n != 1 {
			t.Errorf("relation %v: %d rules match, want exactly 1", pair, n)
		}
	}
}

// TestMergeTurnByRequestIDEnrichesOnly drives the store seam against one
// existing row per Plane B source, each once as a gateway-rail turn (an
// /up/<id> lane) and once not. Only a gateway-rail turn is enriched (review
// E-23, principle 5): a missing time to first token is filled, tokens and
// cost never change and the source tag is kept. A row with no lane (a coding
// agent's default-lane proxy turn, a transcript or native-OTel row) is never
// altered by an app's span.
func TestMergeTurnByRequestIDEnrichesOnly(t *testing.T) {
	t.Parallel()
	s, db := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	sources := []string{SourceProxy, SourceCCOTel, SourceNativeOTel, SourceAgentOTel, SourceJSONL}
	for _, src := range sources {
		for _, lane := range []string{"", "openrouter"} {
			if _, err := s.InsertAPITurn(ctx, models.APITurn{
				RequestID: "req-" + src + "-" + lane, Source: src, Provider: "anthropic", Model: "m",
				InputTokens: 10, OutputTokens: 1, CostUSD: 0.01, Timestamp: now, UpstreamLane: lane,
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, src := range sources {
		for _, lane := range []string{"", "openrouter"} {
			t.Run(src+"/lane="+lane, func(t *testing.T) {
				rid := "req-" + src + "-" + lane
				act, _, err := s.MergeTurnByRequestID(ctx, models.APITurn{
					RequestID: rid, Source: SourceObsOTLP, Provider: "anthropic", Model: "m",
					InputTokens: 5000, OutputTokens: 500, CostUSD: 4.2, TimeToFirstTokenMS: 77,
				})
				if err != nil {
					t.Fatal(err)
				}
				wantAct, wantTTFT := turnmerge.ActionUpdate, int64(77)
				if lane == "" {
					wantAct, wantTTFT = turnmerge.ActionNoChange, 0
				}
				if act != wantAct {
					t.Errorf("action = %v, want %v", act, wantAct)
				}
				var (
					gotSrc  string
					in, out int64
					cost    float64
					ttft    int64
				)
				if err := db.QueryRowContext(ctx, `SELECT COALESCE(source,''), input_tokens, output_tokens, COALESCE(cost_usd,0),
					COALESCE(time_to_first_token_ms,0) FROM api_turns WHERE request_id = ?`, rid).Scan(&gotSrc, &in, &out, &cost, &ttft); err != nil {
					t.Fatal(err)
				}
				if gotSrc != src || in != 10 || out != 1 || cost != 0.01 {
					t.Errorf("row = (%q, %d, %d, %v), want (%q, 10, 1, 0.01)", gotSrc, in, out, cost, src)
				}
				if ttft != wantTTFT {
					t.Errorf("ttft = %d, want %d", ttft, wantTTFT)
				}
			})
		}
	}
}

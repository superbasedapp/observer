package store

import (
	"context"
	"database/sql"
	"math"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// seedPricingRows inserts one project/session, one api_turns row with a
// stored cost, and three token_usage rows: stored $0 (to be priced),
// stored $1.23 (must survive untouched) and an unknown model at $0.
func seedPricingRows(t *testing.T, s *Store, db *sql.DB) {
	t.Helper()
	ctx := context.Background()
	pid, err := s.UpsertProject(ctx, "/tmp/proj", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	if err := s.UpsertSession(ctx, models.Session{
		ID: "s1", ProjectID: pid, Tool: models.ToolClaudeCode, Model: "m-known",
		StartedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("UpsertSession: %v", err)
	}
	ts := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	if _, err := db.ExecContext(ctx,
		`INSERT INTO api_turns(session_id, project_id, timestamp, provider, model, request_id,
		    input_tokens, output_tokens, cost_usd) VALUES('s1', ?, ?, 'anthropic', 'm-known', 'req1', 100, 50, 0)`,
		pid, ts); err != nil {
		t.Fatalf("insert api_turn: %v", err)
	}
	for _, r := range []struct {
		model string
		cost  float64
		fast  int
		eid   string
	}{
		{"m-known", 0, 0, "tu-zero"},
		{"m-known", 1.23, 0, "tu-stored"},
		{"m-unknown", 0, 0, "tu-unknown"},
		{"m-known", 0, 1, "tu-fast"},
	} {
		if _, err := db.ExecContext(ctx,
			`INSERT INTO token_usage(session_id, timestamp, tool, model, input_tokens, output_tokens,
			    cache_read_tokens, cache_creation_tokens, cache_creation_1h_tokens, reasoning_tokens,
			    web_search_requests, estimated_cost_usd, fast, source, source_file, source_event_id)
			 VALUES('s1', ?, 'claude-code', ?, 1000, 200, 3000, 400, 100, 50, 2, ?, ?, 'jsonl', 'f.jsonl', ?)`,
			ts, r.model, r.cost, r.fast, r.eid); err != nil {
			t.Fatalf("insert token_usage %s: %v", r.eid, err)
		}
	}
}

// fakePricer is a deterministic stand-in for the cost.Engine adapter:
// it prices every field with a distinct weight so a test can verify the
// full split (incl. the 1h subset, reasoning and the fast flag) reached
// the pricer, and reports ok=false for "m-unknown".
func fakePricer(t *testing.T, calls *[]PushTokenSplit) OrgPushPricer {
	t.Helper()
	return func(model string, at time.Time, s PushTokenSplit) (float64, bool) {
		*calls = append(*calls, s)
		if model != "m-known" {
			return 0, false
		}
		if at.IsZero() {
			t.Errorf("pricer got zero `at` for a parseable RFC3339 timestamp")
		}
		usd := float64(s.Input)*1 + float64(s.Output)*10 + float64(s.CacheRead)*100 +
			float64(s.CacheCreation)*1000 + float64(s.CacheCreation1h)*10000 +
			float64(s.Reasoning)*100000 + float64(s.WebSearchRequests)*1000000
		if s.Fast {
			usd *= 2
		}
		return usd, true
	}
}

func TestSelectUnpushedSince_PricesZeroCostTokenUsageOnly(t *testing.T) {
	s, db := newTestStore(t)
	seedPricingRows(t, s, db)
	var calls []PushTokenSplit
	s.SetOrgPushPricer(fakePricer(t, &calls))

	batch, err := s.SelectUnpushedSince(context.Background(), PushCursor{}, 1<<20, "org-1", "dev@acme.example", ShareOptions{}, ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince: %v", err)
	}
	byEID := map[string]float64{}
	for _, r := range batch.TokenUsage {
		byEID[r.SourceEventID] = r.EstimatedCostUSD
	}
	// 1000*1 + 200*10 + 3000*100 + 400*1000 + 100*10000 + 50*100000 + 2*1000000
	const want = 1000 + 2000 + 300000 + 400000 + 1000000 + 5000000 + 2000000
	if got := byEID["tu-zero"]; got != want {
		t.Errorf("tu-zero: stored $0 row should be priced to %v, got %v", float64(want), got)
	}
	if got := byEID["tu-fast"]; got != 2*want {
		t.Errorf("tu-fast: fast flag must reach the pricer (want %v), got %v", 2.0*want, got)
	}
	if got := byEID["tu-stored"]; got != 1.23 {
		t.Errorf("tu-stored: non-zero stored cost must be shipped unchanged (1.23), got %v", got)
	}
	if got := byEID["tu-unknown"]; got != 0 || math.IsNaN(got) {
		t.Errorf("tu-unknown: unknown model must push 0 (never NaN), got %v", got)
	}
	// api_turns rows are proxy-priced and never re-priced here.
	if len(batch.APITurns) != 1 || batch.APITurns[0].CostUSD != 0 {
		t.Errorf("api_turns must be untouched by the pricer: %+v", batch.APITurns)
	}
	// The pricer is consulted only for the $0 rows (3 of 4).
	if len(calls) != 3 {
		t.Errorf("pricer calls = %d, want 3 (the three $0 rows)", len(calls))
	}
}

func TestSelectUnpushedSince_NoPricerLeavesStoredCost(t *testing.T) {
	s, db := newTestStore(t)
	seedPricingRows(t, s, db)
	batch, err := s.SelectUnpushedSince(context.Background(), PushCursor{}, 1<<20, "org-1", "dev@acme.example", ShareOptions{}, ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince: %v", err)
	}
	for _, r := range batch.TokenUsage {
		want := 0.0
		if r.SourceEventID == "tu-stored" {
			want = 1.23
		}
		if r.EstimatedCostUSD != want {
			t.Errorf("%s: nil pricer must be the pre-existing behaviour (want %v), got %v", r.SourceEventID, want, r.EstimatedCostUSD)
		}
	}
}

func TestPriceTokenUsageRow_RejectsNonFinite(t *testing.T) {
	s := &Store{}
	for _, bad := range []float64{math.NaN(), math.Inf(1), math.Inf(-1), -0.5} {
		s.SetOrgPushPricer(func(string, time.Time, PushTokenSplit) (float64, bool) { return bad, true })
		r := tokenUsageRowFixture()
		s.priceTokenUsageRow(&r, false)
		if r.EstimatedCostUSD != 0 {
			t.Errorf("pricer returning %v must leave $0 on the wire, got %v", bad, r.EstimatedCostUSD)
		}
	}
}

func tokenUsageRowFixture() (r orgcontract.TokenUsageRow) {
	r.Model = "m-known"
	r.Timestamp = "2026-09-02T12:00:00Z"
	r.InputTokens = 10
	return r
}

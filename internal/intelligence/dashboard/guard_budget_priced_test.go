package dashboard

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestAPIGuardBudget_PricesTranscriptRows pins demo bug #6: the Budget
// guardrails card summed only RECORDED costs, so a transcript row (priced at
// read time, no recorded cost: every non-proxied Claude Code turn) was $0 to
// it - "$0.00 today", "p95 from n=3 days" - while the Cost page priced it.
// The card now reads the guard budget rules' own priced substrate.
func TestAPIGuardBudget_PricesTranscriptRows(t *testing.T) {
	t.Parallel()
	s, _ := newTestServer(t)
	st := store.New(s.opts.DB)
	ctx := context.Background()
	now := time.Now().UTC()
	seedTS := now.Add(-time.Hour)
	if dayStart := now.Truncate(24 * time.Hour); seedTS.Before(dayStart) {
		seedTS = dayStart.Add(time.Minute)
	}
	pid, err := st.UpsertProject(ctx, t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSession(ctx, models.Session{ID: "cc1", ProjectID: pid, Tool: models.ToolClaudeCode, StartedAt: seedTS}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertTokenEvents(ctx, []models.TokenEvent{{
		SessionID: "cc1", SourceFile: "fixture.jsonl", SourceEventID: "msg_1", Timestamp: seedTS,
		Tool: models.ToolClaudeCode, Model: "claude-sonnet-4-5",
		InputTokens: 200_000, OutputTokens: 20_000,
		Source: models.TokenSourceJSONL, Reliability: models.ReliabilityUnreliable,
	}}); err != nil {
		t.Fatal(err)
	}
	// The recorded read the card used to make sees nothing.
	recorded, err := st.GuardBudgetSpend(ctx, "", now.Truncate(24*time.Hour), now.Add(-7*24*time.Hour), now.Add(-30*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if recorded.DailyUSD != 0 {
		t.Fatalf("fixture premise: the recorded read already priced the row (%.4f)", recorded.DailyUSD)
	}

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/api/guard/budget", nil))
	if rec.Code != 200 {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		SpendToday float64 `json:"spend_today_usd"`
		Days       int     `json:"days"`
		Sessions   int     `json:"sessions"`
		DailyP95   float64 `json:"daily_p95_usd"`
		Substrate  string  `json:"spend_substrate"`
		Unpriced   int     `json:"unpriced_rows"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Substrate != "priced" {
		t.Fatalf("spend_substrate = %q, want priced", resp.Substrate)
	}
	if resp.SpendToday <= 0 || resp.Days != 1 || resp.Sessions != 1 || resp.DailyP95 <= 0 {
		t.Fatalf("the transcript row is still invisible to the card: %s", rec.Body.String())
	}
	if resp.Unpriced != 0 {
		t.Fatalf("unpriced_rows = %d for a priced model", resp.Unpriced)
	}
}

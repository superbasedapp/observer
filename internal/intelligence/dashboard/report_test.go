package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestReportMonthly pins the P6.6 statement data: month windowing,
// project scoping, by-model/tool/project rollups with session counts,
// proxy-dedup, savings totals, and the bad-month 400. Fixtures are
// built from a pinned mid-month instant: offsets from the wall clock
// (now-3h) land in the prior month during the first hours of the 1st
// (the v1.37.0 tag-run flake, FU-231).
func TestReportMonthly(t *testing.T) {
	server, _ := wizardTestServer(t)
	now := pinServerClock(server, midMonthTestNow)
	month := now.Format("2006-01")

	// Two sessions in two projects this month; one last month.
	seedLiveSession(t, server, "rep-a", "claude-code", now.Add(-3*time.Hour), now.Add(-2*time.Hour), 1)
	if _, err := server.opts.DB.Exec(
		`INSERT INTO projects (root_path, name, created_at) VALUES ('/rep-b', 'b', ?)`,
		now.Format(time.RFC3339Nano),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := server.opts.DB.Exec(
		`INSERT INTO sessions (id, project_id, tool, started_at)
		 VALUES ('rep-b-s', (SELECT id FROM projects WHERE root_path='/rep-b'), 'codex', ?)`,
		now.Format(time.RFC3339Nano),
	); err != nil {
		t.Fatal(err)
	}
	turn := func(sid, model string, ts time.Time, usd float64, comp int64) {
		t.Helper()
		if _, err := server.opts.DB.Exec(
			`INSERT INTO api_turns (session_id, timestamp, provider, model, input_tokens, output_tokens,
			    cache_read_tokens, cache_creation_tokens, cost_usd,
			    compression_original_bytes, compression_compressed_bytes)
			 VALUES (?, ?, 'anthropic', ?, 100, 10, 400, 20, ?, ?, 0)`,
			sid, ts.Format(time.RFC3339Nano), model, usd, comp,
		); err != nil {
			t.Fatal(err)
		}
	}
	turn("rep-a", "claude-opus-4-8", now.Add(-2*time.Hour), 3.0, 4000)
	turn("rep-a", "claude-haiku-4-5", now.Add(-90*time.Minute), 1.0, 0)
	turn("rep-b-s", "gpt-5.4", now.Add(-time.Hour), 2.0, 0)
	// Prior month — must not appear. Use a fixed long offset so the
	// row is always outside the current calendar month.
	turn("rep-a", "claude-opus-4-8", now.AddDate(0, -1, 0).Add(-72*time.Hour), 50, 0)

	rr := httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/report/monthly?month="+month, nil))
	if rr.Code != 200 {
		t.Fatalf("status %d body=%s", rr.Code, rr.Body.String())
	}
	var got struct {
		Totals struct {
			CostUSD  float64 `json:"cost_usd"`
			Sessions int     `json:"sessions"`
			Turns    int64   `json:"turns"`
		} `json:"totals"`
		ByModel   []reportRow     `json:"by_model"`
		ByTool    []reportRow     `json:"by_tool"`
		ByProject []reportRow     `json:"by_project"`
		Top       []reportSession `json:"top_sessions"`
		Savings   struct {
			CompressionBytes int64 `json:"compression_bytes"`
		} `json:"savings"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Totals.CostUSD < 5.99 || got.Totals.CostUSD > 6.01 {
		t.Errorf("total: got %f want 6 (prior month leaked?)", got.Totals.CostUSD)
	}
	if got.Totals.Sessions != 2 || got.Totals.Turns != 3 {
		t.Errorf("totals: %+v", got.Totals)
	}
	if len(got.ByModel) != 3 || got.ByModel[0].Key != "claude-opus-4-8" {
		t.Errorf("by_model: %+v", got.ByModel)
	}
	if len(got.ByTool) != 2 || got.ByTool[0].Key != "claude-code" || got.ByTool[0].Sessions != 1 {
		t.Errorf("by_tool: %+v", got.ByTool)
	}
	if len(got.ByProject) != 2 {
		t.Errorf("by_project: %+v", got.ByProject)
	}
	if len(got.Top) != 2 || got.Top[0].ID != "rep-a" || got.Top[0].CostUSD != 4.0 {
		t.Errorf("top_sessions: %+v", got.Top)
	}
	if got.Savings.CompressionBytes != 4000 {
		t.Errorf("savings: %+v", got.Savings)
	}

	// Project scoping.
	rr = httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet,
		"/api/report/monthly?month="+month+"&project=%2Frep-b", nil))
	var scoped struct {
		Totals struct {
			CostUSD float64 `json:"cost_usd"`
		} `json:"totals"`
		ByProject []reportRow `json:"by_project"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&scoped); err != nil {
		t.Fatal(err)
	}
	if scoped.Totals.CostUSD != 2.0 {
		t.Errorf("scoped total: got %f want 2", scoped.Totals.CostUSD)
	}
	if scoped.ByProject != nil {
		t.Error("by_project should be omitted when scoped to one project")
	}

	// Bad month + method guard.
	rr = httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/report/monthly?month=junk", nil))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("bad month: got %d want 400", rr.Code)
	}
	rr = httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/report/monthly", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: got %d want 405", rr.Code)
	}
}

// TestReportMonthly_DatedPricingLadder pins the recorded-cost →
// dated-rate → undated-fallback ladder in handleReportMonthly's
// per-row pricing (report.go:183-ish). Three rows in one session, one
// month: a recorded row (must win verbatim over any computed price), an
// unrecorded row before the synthetic rate-change boundary (must price
// at the OLD/dated rate, not current), and an unrecorded row after the
// boundary (must price at the NEW/current rate) — proving both rungs of
// the fallback AND the mixed-aggregation case in one totals sum.
func TestReportMonthly_DatedPricingLadder(t *testing.T) {
	server, _ := wizardTestServer(t)
	now := pinServerClock(server, midMonthTestNow)
	month := now.Format("2006-01")
	boundary := now.Add(-2 * time.Hour)
	server.opts.CostEngine = newLadderTestEngine(t, boundary)

	seedLiveSession(t, server, "ladder-rep", "claude-code", now.Add(-5*time.Hour), now.Add(-30*time.Minute), 1)
	insertTurn := func(ts time.Time, usd float64) {
		t.Helper()
		if _, err := server.opts.DB.Exec(
			`INSERT INTO api_turns (session_id, timestamp, provider, model, input_tokens, output_tokens, cost_usd)
			 VALUES ('ladder-rep', ?, 'anthropic', ?, ?, ?, ?)`,
			ts.Format(time.RFC3339Nano), ladderModel, ladderBundle.Input, ladderBundle.Output, usd,
		); err != nil {
			t.Fatal(err)
		}
	}
	insertTurn(now.Add(-4*time.Hour), 9.99) // recorded — must win verbatim
	insertTurn(now.Add(-3*time.Hour), 0)    // unrecorded, before boundary — OLD dated rate
	insertTurn(now.Add(-1*time.Hour), 0)    // unrecorded, after boundary — NEW/current rate

	rr := httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/report/monthly?month="+month, nil))
	if rr.Code != 200 {
		t.Fatalf("status %d body=%s", rr.Code, rr.Body.String())
	}
	var got struct {
		Totals struct {
			CostUSD float64 `json:"cost_usd"`
			Turns   int64   `json:"turns"`
		} `json:"totals"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	want := 9.99 + ladderOldCost + ladderNewCost
	if got.Totals.Turns != 3 {
		t.Fatalf("turns: got %d want 3", got.Totals.Turns)
	}
	if diff := got.Totals.CostUSD - want; diff > 0.001 || diff < -0.001 {
		t.Errorf("cost_usd: got %f want %f (recorded=9.99 old=%.2f new=%.2f)",
			got.Totals.CostUSD, want, ladderOldCost, ladderNewCost)
	}
}

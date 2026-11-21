package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// writeBudgetConfig writes a config.toml with budget keys to the
// server's configured path.
func writeBudgetConfig(t *testing.T, server *Server, global float64, projects map[string]float64) {
	t.Helper()
	body := "[intelligence]\nmonthly_budget_usd = " + jsonNum(global) + "\n"
	if len(projects) > 0 {
		body += "[intelligence.project_budgets_usd]\n"
		for root, usd := range projects {
			body += "\"" + root + "\" = " + jsonNum(usd) + "\n"
		}
	}
	if err := os.WriteFile(server.opts.ConfigPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func jsonNum(f float64) string {
	b, _ := json.Marshal(f)
	return string(b)
}

// TestHandleBudget pins the P6.3 surface: unconfigured short-circuit,
// global + per-project month-to-date rollups, linear forecast,
// threshold levels, and the method guard. Spend is seeded as recorded
// api_turns cost inside the current month. The server clock is pinned
// mid-month so the fixtures (built from the same instant) can never fall
// into the prior month when the wall clock sits just after midnight UTC
// on the 1st (the v1.37.0 tag-run flake, FU-231).
func TestHandleBudget(t *testing.T) {
	server, _ := wizardTestServer(t)
	now := pinServerClock(server, midMonthTestNow)

	// Unconfigured: no DB work, configured=false.
	rr := httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/budget", nil))
	if rr.Code != 200 {
		t.Fatalf("status %d", rr.Code)
	}
	var probe struct {
		Configured bool `json:"configured"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&probe); err != nil {
		t.Fatal(err)
	}
	if probe.Configured {
		t.Fatal("unconfigured install reported configured=true")
	}

	// Seed: two projects, spend this month attributed via sessions.
	seedLiveSession(t, server, "bud-a", "claude-code", now.Add(-2*time.Hour), now.Add(-time.Hour), 1)
	if _, err := server.opts.DB.Exec(
		`INSERT INTO projects (root_path, name, created_at) VALUES ('/bud-b', 'b', ?)`,
		now.Format(time.RFC3339Nano),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := server.opts.DB.Exec(
		`INSERT INTO sessions (id, project_id, tool, started_at)
		 VALUES ('bud-b-s', (SELECT id FROM projects WHERE root_path = '/bud-b'), 'codex', ?)`,
		now.Format(time.RFC3339Nano),
	); err != nil {
		t.Fatal(err)
	}
	turn := func(session string, usd float64) {
		t.Helper()
		if _, err := server.opts.DB.Exec(
			`INSERT INTO api_turns (session_id, timestamp, provider, model, input_tokens, output_tokens, cost_usd)
			 VALUES (?, ?, 'anthropic', 'claude-opus-4-8', 100, 10, ?)`,
			session, now.Add(-time.Hour).Format(time.RFC3339Nano), usd,
		); err != nil {
			t.Fatal(err)
		}
	}
	turn("bud-a", 9.0) // project /live-p (seedLiveSession's root)
	turn("bud-b-s", 2.0)

	writeBudgetConfig(t, server, 100, map[string]float64{
		"/live-p": 10, // 9/10 = 90% → warn80
		"/bud-b":  1,  // 2/1 = 200% → over100
	})

	rr = httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/budget", nil))
	if rr.Code != 200 {
		t.Fatalf("status %d body=%s", rr.Code, rr.Body.String())
	}
	var got struct {
		Configured  bool   `json:"configured"`
		Month       string `json:"month"`
		DaysElapsed int    `json:"days_elapsed"`
		DaysInMonth int    `json:"days_in_month"`
		Global      *struct {
			BudgetUSD   float64 `json:"budget_usd"`
			MTDUSD      float64 `json:"mtd_usd"`
			Pct         float64 `json:"pct"`
			ForecastUSD float64 `json:"forecast_usd"`
			Threshold   string  `json:"threshold"`
		} `json:"global"`
		Projects []struct {
			Root      string  `json:"root"`
			Pct       float64 `json:"pct"`
			Threshold string  `json:"threshold"`
		} `json:"projects"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if !got.Configured || got.Global == nil {
		t.Fatalf("configured/global: %+v", got)
	}
	if got.Global.MTDUSD < 10.9 || got.Global.MTDUSD > 11.1 {
		t.Errorf("global mtd: got %f want 11", got.Global.MTDUSD)
	}
	if got.Global.Threshold != "" {
		t.Errorf("global threshold: got %q want none (11%%)", got.Global.Threshold)
	}
	wantForecast := got.Global.MTDUSD * float64(got.DaysInMonth) / float64(got.DaysElapsed)
	if diff := got.Global.ForecastUSD - wantForecast; diff > 0.001 || diff < -0.001 {
		t.Errorf("forecast: got %f want %f", got.Global.ForecastUSD, wantForecast)
	}
	if len(got.Projects) != 2 {
		t.Fatalf("projects: %+v", got.Projects)
	}
	// Sorted by pct descending: /bud-b (200%) first.
	if got.Projects[0].Root != "/bud-b" || got.Projects[0].Threshold != "over100" {
		t.Errorf("projects[0]: %+v", got.Projects[0])
	}
	if got.Projects[1].Root != "/live-p" || got.Projects[1].Threshold != "warn80" {
		t.Errorf("projects[1]: %+v", got.Projects[1])
	}

	// Method guard.
	rr = httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/budget", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: got %d want 405", rr.Code)
	}
}

// TestHandleBudget_DatedPricingLadder pins the same recorded → dated →
// undated ladder in monthToDateCostByProject: a recorded row wins
// verbatim, an unrecorded row before the synthetic boundary prices at
// the OLD dated rate, and one after prices at the NEW/current rate —
// all three folding into one project's month-to-date total.
func TestHandleBudget_DatedPricingLadder(t *testing.T) {
	server, _ := wizardTestServer(t)
	now := pinServerClock(server, midMonthTestNow)
	boundary := now.Add(-2 * time.Hour)
	server.opts.CostEngine = newLadderTestEngine(t, boundary)

	seedLiveSession(t, server, "ladder-bud", "claude-code", now.Add(-5*time.Hour), now.Add(-30*time.Minute), 1)
	writeBudgetConfig(t, server, 100, map[string]float64{"/live-p": 1000})
	insertTurn := func(ts time.Time, usd float64) {
		t.Helper()
		if _, err := server.opts.DB.Exec(
			`INSERT INTO api_turns (session_id, timestamp, provider, model, input_tokens, output_tokens, cost_usd)
			 VALUES ('ladder-bud', ?, 'anthropic', ?, ?, ?, ?)`,
			ts.Format(time.RFC3339Nano), ladderModel, ladderBundle.Input, ladderBundle.Output, usd,
		); err != nil {
			t.Fatal(err)
		}
	}
	insertTurn(now.Add(-4*time.Hour), 9.99) // recorded — must win verbatim
	insertTurn(now.Add(-3*time.Hour), 0)    // unrecorded, before boundary — OLD dated rate
	insertTurn(now.Add(-1*time.Hour), 0)    // unrecorded, after boundary — NEW/current rate

	rr := httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/budget", nil))
	if rr.Code != 200 {
		t.Fatalf("status %d body=%s", rr.Code, rr.Body.String())
	}
	var got struct {
		Projects []struct {
			Root   string  `json:"root"`
			MTDUSD float64 `json:"mtd_usd"`
		} `json:"projects"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	var mtd float64
	found := false
	for _, p := range got.Projects {
		if p.Root == "/live-p" {
			mtd = p.MTDUSD
			found = true
		}
	}
	if !found {
		t.Fatalf("no /live-p project in response: %+v", got.Projects)
	}
	want := 9.99 + ladderOldCost + ladderNewCost
	if diff := mtd - want; diff > 0.001 || diff < -0.001 {
		t.Errorf("mtd_usd: got %f want %f (recorded=9.99 old=%.2f new=%.2f)",
			mtd, want, ladderOldCost, ladderNewCost)
	}
}

// TestHandleConfigSection_IntelligencePreservesBudgets pins the D14-
// class guard: a Settings intelligence save that does NOT carry the
// ProjectBudgetsUSD field must preserve stored budgets, while an
// explicit field replaces them.
func TestHandleConfigSection_IntelligencePreservesBudgets(t *testing.T) {
	server, _ := wizardTestServer(t)
	writeBudgetConfig(t, server, 50, map[string]float64{"/p1": 5})

	put := func(body string) int {
		t.Helper()
		req := httptest.NewRequest(http.MethodPut, "/api/config/section/intelligence",
			strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		server.Handler().ServeHTTP(rr, req)
		return rr.Code
	}

	// Save WITHOUT the field (the Settings form shape).
	if code := put(`{"MonthlyBudgetUSD": 75, "APIKeyEnv": "", "SummaryModel": ""}`); code != 200 {
		t.Fatalf("save without field: %d", code)
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: server.opts.ConfigPath})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Intelligence.MonthlyBudgetUSD != 75 {
		t.Errorf("monthly budget: got %v want 75", cfg.Intelligence.MonthlyBudgetUSD)
	}
	if cfg.Intelligence.ProjectBudgetsUSD["/p1"] != 5 {
		t.Errorf("project budgets clobbered by field-less save: %+v", cfg.Intelligence.ProjectBudgetsUSD)
	}

	// Save WITH the field replaces (explicit empty clears).
	if code := put(`{"MonthlyBudgetUSD": 75, "ProjectBudgetsUSD": {"/p2": 9}}`); code != 200 {
		t.Fatalf("save with field: %d", code)
	}
	cfg, err = config.Load(config.LoadOptions{GlobalPath: server.opts.ConfigPath})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Intelligence.ProjectBudgetsUSD["/p2"] != 9 || len(cfg.Intelligence.ProjectBudgetsUSD) != 1 {
		t.Errorf("explicit field not applied: %+v", cfg.Intelligence.ProjectBudgetsUSD)
	}
}

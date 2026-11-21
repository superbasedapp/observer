package dashboard

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/budgetwarnfile"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/predict"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// seedRecentUsage adds token rows inside the current week: two sessions of
// claude-code (the session under test and another), so the projection has
// usage to divide.
func seedRecentUsage(t *testing.T, database *sql.DB, sessionID string, now time.Time) {
	t.Helper()
	ctx := context.Background()
	var projectID int64
	if err := database.QueryRowContext(ctx, `SELECT project_id FROM sessions WHERE id = ?`, sessionID).Scan(&projectID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, tool, project_id, model, started_at) VALUES (?, 'claude-code', ?, 'claude-opus-4-8', ?)`,
		sessionID+"-other", projectID, now.Add(-48*time.Hour).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		sid string
		ago time.Duration
		in  int64
		out int64
		usd float64
	}{
		{sessionID, 50 * time.Hour, 1000, 500, 1.0},
		{sessionID, 30 * time.Hour, 1000, 500, 1.0},
		{sessionID + "-other", 20 * time.Hour, 3000, 1500, 3.0},
		{sessionID + "-other", 2 * time.Hour, 3000, 1500, 3.0},
	}
	for i, r := range rows {
		if _, err := database.ExecContext(ctx,
			`INSERT INTO token_usage (session_id, timestamp, tool, model, input_tokens, output_tokens, cache_read_tokens,
			   estimated_cost_usd, source, reliability, source_file, source_event_id)
			 VALUES (?, ?, 'claude-code', 'claude-opus-4-8', ?, ?, 0, ?, 'jsonl', 'high', 'f', ?)`,
			r.sid, now.Add(-r.ago).Format(time.RFC3339Nano), r.in, r.out, r.usd, "recent-"+sessionID+itoa(i)); err != nil {
			t.Fatal(err)
		}
	}
}

func insertWeeklySnapshot(t *testing.T, database *sql.DB, sessionID string, util float64, reset, observed time.Time) {
	t.Helper()
	r := reset.Unix()
	if err := store.New(database).InsertLimitSnapshot(context.Background(), models.LimitSnapshot{
		ScopeHash: "default", Provider: "anthropic", SessionID: sessionID, ObservedAt: observed,
		Window7dUtil: &util, Window7dReset: &r,
	}); err != nil {
		t.Fatal(err)
	}
}

func getPredict(t *testing.T, srv *Server, sessionID string) (PredictResponse, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	srv.handleSessionDetail(rec, httptest.NewRequest(http.MethodGet, "/api/session/"+sessionID+"/predict", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var resp PredictResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	var raw map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &raw)
	return resp, raw
}

// TestHandleSessionPredict_ProjectionLive pins the response shape of a live
// weekly reading: the projection rides beside the unchanged gauge.
func TestHandleSessionPredict_ProjectionLive(t *testing.T) {
	t.Parallel()
	database, cleanup := openForecastTestDB(t)
	defer cleanup()
	seedPredictSession(t, database, "sPL", "claude-opus-4-8")
	now := time.Now().UTC()
	seedRecentUsage(t, database, "sPL", now)
	insertWeeklySnapshot(t, database, "sPL", 0.4, now.Add(4*24*time.Hour), now)

	srv := &Server{opts: Options{DB: database, CostEngine: newForecastTestEngine(t)}}
	resp, raw := getPredict(t, srv, "sPL")
	if !resp.Limit.Available || resp.Limit.Window7dUtil == nil || *resp.Limit.Window7dUtil != 0.4 {
		t.Fatalf("the gauge is unchanged: %+v", resp.Limit)
	}
	proj, ok := raw["projection"].(map[string]any)
	if !ok {
		t.Fatalf("projection missing: %v", raw)
	}
	if _, ok := proj["budgets"].([]any); !ok {
		t.Errorf("budgets must be an array (empty = none in force): %v", proj["budgets"])
	}
	if len(resp.Projection.Limits) != 1 {
		t.Fatalf("limits %+v, want the weekly window only", resp.Projection.Limits)
	}
	p := resp.Projection.Limits[0]
	if p.Key != "weekly" || p.State != predict.StateLive || p.Source != "proxy" {
		t.Errorf("key %q state %q source %q", p.Key, p.State, p.Source)
	}
	if p.Used.Tokens != 12_000 || p.Used.Sessions != 2 || p.Sessions == nil || p.Sessions.ThisShare == nil || *p.Sessions.ThisShare != 0.25 {
		t.Errorf("used %+v sessions %+v", p.Used, p.Sessions)
	}
	if p.CapacityTokensEst == nil || *p.CapacityTokensEst != 30_000 || p.Burn == nil || p.RunOut == nil {
		t.Errorf("capacity %v burn %+v run out %+v", p.CapacityTokensEst, p.Burn, p.RunOut)
	}
	if p.MorePrompts == nil {
		t.Errorf("more prompts missing (the predictor band is priced)")
	}
	if len(resp.Projection.CountedTools) != 1 || resp.Projection.CountedTools[0] != "claude-code" {
		t.Errorf("counted tools %v", resp.Projection.CountedTools)
	}
}

// TestHandleSessionPredict_ProjectionStaleReading pins the operator's
// screenshot: a 22-day-old weekly reading whose window reset is never
// projected from.
func TestHandleSessionPredict_ProjectionStaleReading(t *testing.T) {
	t.Parallel()
	database, cleanup := openForecastTestDB(t)
	defer cleanup()
	seedPredictSession(t, database, "sPS", "claude-opus-4-8")
	now := time.Now().UTC()
	seedRecentUsage(t, database, "sPS", now)
	insertWeeklySnapshot(t, database, "sPS", 0.01, now.Add(-21*24*time.Hour), now.Add(-22*24*time.Hour))

	srv := &Server{opts: Options{DB: database, CostEngine: newForecastTestEngine(t)}}
	resp, _ := getPredict(t, srv, "sPS")
	if len(resp.Projection.Limits) != 1 {
		t.Fatalf("limits %+v", resp.Projection.Limits)
	}
	p := resp.Projection.Limits[0]
	if p.State != predict.StateResetInferred || p.UsedFrac != nil || p.RunOut != nil || p.CapacityTokensEst != nil {
		t.Fatalf("a reset reading was projected from: %+v", p)
	}
	if p.ReadingAgeSec == nil || *p.ReadingAgeSec < 22*24*3600-60 {
		t.Errorf("reading age %v", p.ReadingAgeSec)
	}
}

// TestHandleSessionPredict_ProjectionBudgets pins the budget block: the
// node's own cap and an org window, tightest first; no budget is an empty
// list.
func TestHandleSessionPredict_ProjectionBudgets(t *testing.T) {
	t.Parallel()
	database, cleanup := openForecastTestDB(t)
	defer cleanup()
	seedPredictSession(t, database, "sPB", "claude-opus-4-8")
	now := time.Now().UTC()
	seedRecentUsage(t, database, "sPB", now)

	srv := &Server{opts: Options{DB: database, CostEngine: newForecastTestEngine(t)}}
	if resp, _ := getPredict(t, srv, "sPB"); len(resp.Projection.Budgets) != 0 {
		t.Fatalf("no budget configured, got %+v", resp.Projection.Budgets)
	}

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "observer.db")
	cfgPath := filepath.Join(dir, "config.toml")
	cfg := "[observer]\ndb_path = \"" + filepath.ToSlash(dbPath) + "\"\n\n[guard.budget]\nmonthly_usd = 100.0\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := budgetwarnfile.Write(budgetwarnfile.StatusPath(dbPath), budgetwarnfile.File{
		Schema: budgetwarnfile.Schema, WrittenAt: now,
		Windows: []budgetwarnfile.Window{
			{Window: "monthly", Unit: "tokens", Period: now.Format("2006-01"), Cap: 20_000, Spent: 16_000, Ratio: 0.8, Scope: "team:core", Enforcement: "hard", Level: "warning"},
			// A cap on another tool is not this session's budget.
			{Window: "daily", Unit: "usd", Subject: "tool:codex", Period: now.Format("2006-01-02"), Cap: 5, Spent: 1, Scope: "org", Enforcement: "soft"},
			// A window from a past period is not shown.
			{Window: "monthly", Unit: "usd", Period: now.AddDate(0, -3, 0).Format("2006-01"), Cap: 5, Spent: 1, Scope: "org", Enforcement: "soft"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	srv.opts.ConfigPath = cfgPath
	resp, _ := getPredict(t, srv, "sPB")
	if len(resp.Projection.Budgets) != 2 {
		t.Fatalf("budgets %+v, want the org token cap and the node's monthly dollars", resp.Projection.Budgets)
	}
	org, node := resp.Projection.Budgets[0], resp.Projection.Budgets[1]
	if org.Origin != "org" || org.Unit != "tokens" || org.Scope != "team:core" || org.LeftTokens == nil || *org.LeftTokens != 4000 || org.LeftTokensIsEstimate {
		t.Errorf("org budget %+v", org)
	}
	if node.Origin != "node" || node.Unit != "usd" || node.Key != "monthly" || node.Cap != 100 || node.Enforcement != "soft" {
		t.Errorf("node budget %+v", node)
	}
}

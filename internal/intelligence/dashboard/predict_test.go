package dashboard

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/predict"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// seedPredictSession seeds a claude-code session with token_usage turns
// (cached: a large cache_read prefix, near-zero fresh input, varying
// output) and user_prompt boundaries so the turns-per-message fan-out is
// observable. Mirrors the §0 cached-CC shape.
func seedPredictSession(t *testing.T, database *sql.DB, sessionID, model string) {
	t.Helper()
	ctx := context.Background()
	var projectID int64
	if err := database.QueryRowContext(ctx,
		`INSERT INTO projects (root_path, created_at) VALUES (?, '2026-06-09T00:00:00Z') RETURNING id`,
		"/tmp/pred-"+sessionID).Scan(&projectID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, tool, project_id, model, started_at)
		 VALUES (?, 'claude-code', ?, ?, '2026-06-09T00:00:00Z')`,
		sessionID, projectID, model); err != nil {
		t.Fatal(err)
	}

	base := time.Date(2026, 6, 9, 0, 0, 0, 0, time.UTC)
	// Three user messages (≥ threshold 3 → observed tier); fan-out 3/2/2.
	promptOffsets := []int{0, 30, 60} // minutes
	for i, off := range promptOffsets {
		if _, err := database.ExecContext(ctx,
			`INSERT INTO actions (session_id, project_id, timestamp, action_type, tool, source_file, source_event_id)
			 VALUES (?, ?, ?, 'user_prompt', 'claude-code', 'f', ?)`,
			sessionID, projectID, base.Add(time.Duration(off)*time.Minute).Format(time.RFC3339Nano),
			"up-"+sessionID+"-"+itoa(i)); err != nil {
			t.Fatal(err)
		}
	}
	// Turn rows: 3 in [0,30), 2 in [30,60), 2 in [60,+inf). Cached shape:
	// input≈cache_read so fresh≈0; cost variance is output + T.
	turns := []struct {
		minute           int
		input, cacheRead int64
		output           int64
	}{
		{2, 200_001, 200_000, 100},
		{5, 200_002, 200_000, 800},
		{9, 200_003, 200_000, 1600},
		{32, 205_001, 205_000, 400},
		{40, 205_002, 205_000, 1200},
		{62, 210_001, 210_000, 300},
		{70, 210_002, 210_000, 900},
	}
	for i, tr := range turns {
		if _, err := database.ExecContext(ctx,
			`INSERT INTO token_usage
			   (session_id, timestamp, tool, model, input_tokens, output_tokens, cache_read_tokens,
			    source, reliability, source_file, source_event_id)
			 VALUES (?, ?, 'claude-code', ?, ?, ?, ?, 'proxy', 'high', 'f', ?)`,
			sessionID, base.Add(time.Duration(tr.minute)*time.Minute).Format(time.RFC3339Nano),
			model, tr.input, tr.output, tr.cacheRead, "tu-"+sessionID+"-"+itoa(i)); err != nil {
			t.Fatal(err)
		}
	}
}

// TestHandleSessionPredict_CostBand seeds a cached claude-code session
// and asserts the predictor returns a monotonic low/mid/high message
// cost band on the observed-T tier, with the limit gauge gated behind
// needs-proxy.
func TestHandleSessionPredict_CostBand(t *testing.T) {
	t.Parallel()
	database, cleanup := openForecastTestDB(t)
	defer cleanup()
	seedPredictSession(t, database, "sP", "claude-opus-4-8")

	srv := &Server{opts: Options{DB: database, CostEngine: newForecastTestEngine(t)}}
	req := httptest.NewRequest(http.MethodGet, "/api/session/sP/predict", nil)
	rec := httptest.NewRecorder()
	srv.handleSessionDetail(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var resp PredictResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v — body %s", err, rec.Body.String())
	}
	if !resp.Estimate.HasEstimate {
		t.Fatalf("expected an estimate; warnings=%v reason=%q", resp.Estimate.Warnings, resp.Reason)
	}
	if resp.Model != "claude-opus-4-8" {
		t.Errorf("model = %q", resp.Model)
	}
	if string(resp.Estimate.TurnsTier) != "observed" {
		t.Errorf("turns tier = %q, want observed (3 messages ≥ threshold 3)", resp.Estimate.TurnsTier)
	}
	if resp.Estimate.SampleMessages != 3 {
		t.Errorf("sample messages = %d, want 3", resp.Estimate.SampleMessages)
	}
	// Monotonic band.
	lo, mid, hi := resp.Estimate.Low.MessageUSD, resp.Estimate.Mid.MessageUSD, resp.Estimate.High.MessageUSD
	if !(lo <= mid && mid <= hi) {
		t.Errorf("band not monotonic: %.6f / %.6f / %.6f", lo, mid, hi)
	}
	if mid <= 0 {
		t.Errorf("mid message cost should be positive, got %.6f", mid)
	}
	// Cache prefix carried (P "now" = latest cache_read).
	if resp.Estimate.PrefixTokens != 210_000 {
		t.Errorf("prefix tokens = %d, want 210000 (latest cache_read)", resp.Estimate.PrefixTokens)
	}
	// Limit gauge proxy-gated.
	if resp.Limit.Available || !resp.Limit.NeedsProxy {
		t.Errorf("limit gauge should be unavailable/needs-proxy, got %+v", resp.Limit)
	}
}

// TestHandleSessionPredict_LimitGaugeAvailable seeds a proxy-captured
// limit snapshot for the session's provider and asserts the gauge flips
// to available with the window utilization.
func TestHandleSessionPredict_LimitGaugeAvailable(t *testing.T) {
	t.Parallel()
	database, cleanup := openForecastTestDB(t)
	defer cleanup()
	seedPredictSession(t, database, "sL", "claude-opus-4-8")

	st := store.New(database)
	util := 0.42
	reset := time.Now().Add(2 * time.Hour).Unix()
	if err := st.InsertLimitSnapshot(context.Background(), models.LimitSnapshot{
		ScopeHash:     "default",
		Provider:      "anthropic",
		SessionID:     "sL", // the proxy stamps the source session; the gauge attributes by its tool
		ObservedAt:    time.Now().UTC(),
		Window5hUtil:  &util,
		Window5hReset: &reset,
	}); err != nil {
		t.Fatal(err)
	}

	srv := &Server{opts: Options{DB: database, CostEngine: newForecastTestEngine(t)}}
	req := httptest.NewRequest(http.MethodGet, "/api/session/sL/predict", nil)
	rec := httptest.NewRecorder()
	srv.handleSessionDetail(rec, req)

	var resp PredictResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Limit.Available || resp.Limit.NeedsProxy {
		t.Errorf("gauge should be available, got %+v", resp.Limit)
	}
	if resp.Limit.Window5hUtil == nil || *resp.Limit.Window5hUtil != 0.42 {
		t.Errorf("5h util = %v, want 0.42", resp.Limit.Window5hUtil)
	}
}

// TestHandleSessionPredict_NoCrossToolLimitLeak pins the cline-cli bug:
// a Claude Code session produces an anthropic subscription window
// (5h/weekly) through the proxy; a cline-cli session — same provider,
// but a different credential that emits no such headers — must NOT
// inherit it. Before the tool-attributed read, the node-wide
// per-provider lookup leaked the CC gauge onto every anthropic-default
// tool's session detail.
func TestHandleSessionPredict_NoCrossToolLimitLeak(t *testing.T) {
	t.Parallel()
	database, cleanup := openForecastTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// A claude-code session that produced the subscription window.
	seedPredictSession(t, database, "ccWin", "claude-opus-4-8")
	st := store.New(database)
	util5, util7 := 0.09, 0.65
	reset := time.Now().Add(2 * time.Hour).Unix()
	if err := st.InsertLimitSnapshot(ctx, models.LimitSnapshot{
		ScopeHash:     "default",
		Provider:      "anthropic",
		SessionID:     "ccWin",
		ObservedAt:    time.Now().UTC(),
		Window5hUtil:  &util5,
		Window5hReset: &reset,
		Window7dUtil:  &util7,
	}); err != nil {
		t.Fatal(err)
	}

	// A cline-cli session (anthropic-default provider) that produced no
	// snapshot of its own.
	var projectID int64
	if err := database.QueryRowContext(ctx,
		`INSERT INTO projects (root_path, created_at) VALUES ('/tmp/pred-clinecli', '2026-06-09T00:00:00Z') RETURNING id`).
		Scan(&projectID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, tool, project_id, model, started_at)
		 VALUES ('clcli', 'cline-cli', ?, 'claude-opus-4-8', '2026-06-09T00:00:00Z')`, projectID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO token_usage
		   (session_id, timestamp, tool, model, input_tokens, output_tokens, cache_read_tokens,
		    source, reliability, source_file, source_event_id)
		 VALUES ('clcli', '2026-06-09T00:05:00Z', 'cline-cli', 'claude-opus-4-8', 1200, 300, 0, 'jsonl', 'approximate', 'r.jsonl', 'tk:clcli:L1')`); err != nil {
		t.Fatal(err)
	}

	srv := &Server{opts: Options{DB: database, CostEngine: newForecastTestEngine(t)}}

	// cline-cli: gauge must NOT leak the CC window.
	reqCli := httptest.NewRequest(http.MethodGet, "/api/session/clcli/predict", nil)
	recCli := httptest.NewRecorder()
	srv.handleSessionDetail(recCli, reqCli)
	var respCli PredictResponse
	if err := json.Unmarshal(recCli.Body.Bytes(), &respCli); err != nil {
		t.Fatalf("decode cline-cli: %v", err)
	}
	if respCli.Limit.Available {
		t.Errorf("cline-cli gauge leaked a window: %+v", respCli.Limit)
	}
	if !respCli.Limit.NeedsProxy {
		t.Errorf("cline-cli gauge should be needs-proxy (no own snapshot), got %+v", respCli.Limit)
	}

	// claude-code: its own window still resolves.
	reqCC := httptest.NewRequest(http.MethodGet, "/api/session/ccWin/predict", nil)
	recCC := httptest.NewRecorder()
	srv.handleSessionDetail(recCC, reqCC)
	var respCC PredictResponse
	if err := json.Unmarshal(recCC.Body.Bytes(), &respCC); err != nil {
		t.Fatalf("decode claude-code: %v", err)
	}
	if !respCC.Limit.Available || respCC.Limit.Window5hUtil == nil || *respCC.Limit.Window5hUtil != 0.09 {
		t.Errorf("claude-code gauge should resolve its own window, got %+v", respCC.Limit)
	}
}

// TestHandleSessionPredict_CodexTranscriptGauge asserts the gauge falls
// back to the codex transcript-captured rate_limits (ActionRateLimit
// rows) when no proxy snapshot carries a subscription window — codex/
// OpenAI never sends 5h/weekly in HTTP headers.
func TestHandleSessionPredict_CodexTranscriptGauge(t *testing.T) {
	t.Parallel()
	database, cleanup := openForecastTestDB(t)
	defer cleanup()
	ctx := context.Background()

	var projectID int64
	if err := database.QueryRowContext(ctx,
		`INSERT INTO projects (root_path, created_at) VALUES ('/tmp/pred-codex', '2026-06-09T00:00:00Z') RETURNING id`).
		Scan(&projectID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, tool, project_id, model, started_at)
		 VALUES ('sCx', 'codex', ?, 'gpt-5.4', '2026-06-09T00:00:00Z')`, projectID); err != nil {
		t.Fatal(err)
	}
	// One token row so the cost half also has a basis.
	if _, err := database.ExecContext(ctx,
		`INSERT INTO token_usage
		   (session_id, timestamp, tool, model, input_tokens, output_tokens, cache_read_tokens,
		    source, reliability, source_file, source_event_id)
		 VALUES ('sCx', '2026-06-09T00:05:00Z', 'codex', 'gpt-5.4', 1200, 300, 0, 'jsonl', 'approximate', 'r.jsonl', 'tk:r.jsonl:L5')`); err != nil {
		t.Fatal(err)
	}
	// The codex rate_limits envelope as an ActionRateLimit row.
	if _, err := database.ExecContext(
		ctx,
		`INSERT INTO actions (session_id, project_id, timestamp, action_type, tool, raw_tool_input, source_file, source_event_id)
		 VALUES ('sCx', ?, '2026-06-09T00:05:01Z', 'rate_limit', 'codex', ?, 'r.jsonl', 'ratelimit:r.jsonl:L6')`,
		projectID,
		`{"limit_id":"codex","primary":{"used_percent":18,"window_minutes":300,"resets_at":1778867450},"secondary":{"used_percent":3,"window_minutes":10080,"resets_at":1779454250},"plan_type":"plus","rate_limit_reached_type":null}`,
	); err != nil {
		t.Fatal(err)
	}

	srv := &Server{opts: Options{DB: database, CostEngine: newForecastTestEngine(t)}}
	req := httptest.NewRequest(http.MethodGet, "/api/session/sCx/predict", nil)
	rec := httptest.NewRecorder()
	srv.handleSessionDetail(rec, req)

	var resp PredictResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v — body %s", err, rec.Body.String())
	}
	if !resp.Limit.Available || resp.Limit.NeedsProxy || resp.Limit.NoWindow {
		t.Errorf("codex gauge should be available via transcript, got %+v", resp.Limit)
	}
	if resp.Limit.Source != "transcript" {
		t.Errorf("source = %q, want transcript", resp.Limit.Source)
	}
	if resp.Limit.Window5hUtil == nil || *resp.Limit.Window5hUtil != 0.18 {
		t.Errorf("5h util = %v, want 0.18", resp.Limit.Window5hUtil)
	}
	if resp.Limit.Window7dUtil == nil || *resp.Limit.Window7dUtil != 0.03 {
		t.Errorf("7d util = %v, want 0.03", resp.Limit.Window7dUtil)
	}
}

// TestHandleSessionPredict_NoModel asserts the honest empty response for
// a hook-only session with no model/tokens (the §3 operator finding).
func TestHandleSessionPredict_NoModel(t *testing.T) {
	t.Parallel()
	database, cleanup := openForecastTestDB(t)
	defer cleanup()
	ctx := context.Background()
	var projectID int64
	if err := database.QueryRowContext(ctx,
		`INSERT INTO projects (root_path, created_at) VALUES ('/tmp/pred-nomodel', '2026-06-09T00:00:00Z') RETURNING id`).
		Scan(&projectID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, tool, project_id, started_at)
		 VALUES ('sN', 'claude-code', ?, '2026-06-09T00:00:00Z')`, projectID); err != nil {
		t.Fatal(err)
	}

	srv := &Server{opts: Options{DB: database, CostEngine: newForecastTestEngine(t)}}
	req := httptest.NewRequest(http.MethodGet, "/api/session/sN/predict", nil)
	rec := httptest.NewRecorder()
	srv.handleSessionDetail(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var resp PredictResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Estimate.HasEstimate {
		t.Errorf("hook-only session should have no estimate")
	}
	if resp.Reason == "" {
		t.Errorf("expected a reason explaining the empty estimate")
	}
}

// TestHandleSessionPredict_NoPricingKeepsTokenFacts pins the fix for the
// predictor's facts/pricing coupling, reproduced from a real remote node:
// an opencode session on the alias model "big-pickle" (no pricing entry)
// with three observed turns carrying cache_read 8320/8320/8448.
//
// Before the fix the handler short-circuited on the pricing miss and
// returned a zeroed estimate carrying a false no_session_history, so the
// session-detail CONTEXT WINDOW USED card rendered "n/a, no prefix
// observed yet" over three observed turns. The dollar half must still be
// absent (the cost card's "no pricing entry" reason is the honest one),
// but every token fact must survive.
func TestHandleSessionPredict_NoPricingKeepsTokenFacts(t *testing.T) {
	t.Parallel()
	database, cleanup := openForecastTestDB(t)
	defer cleanup()
	ctx := context.Background()

	var projectID int64
	if err := database.QueryRowContext(ctx,
		`INSERT INTO projects (root_path, created_at) VALUES ('/tmp/pred-nopricing', '2026-06-09T00:00:00Z') RETURNING id`).
		Scan(&projectID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, tool, project_id, model, started_at)
		 VALUES ('sUnpriced', 'opencode', ?, 'big-pickle', '2026-06-09T00:00:00Z')`, projectID); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 6, 9, 0, 0, 0, 0, time.UTC)
	turns := []struct {
		minute                   int
		input, output, cacheRead int64
	}{
		{2, 8440, 300, 8320},
		{5, 8560, 700, 8320},
		{9, 8808, 1500, 8448},
	}
	for i, tr := range turns {
		if _, err := database.ExecContext(ctx,
			`INSERT INTO token_usage
			   (session_id, timestamp, tool, model, input_tokens, output_tokens, cache_read_tokens,
			    source, reliability, source_file, source_event_id)
			 VALUES (?, ?, 'opencode', 'big-pickle', ?, ?, ?, 'jsonl', 'medium', 'f', ?)`,
			"sUnpriced", base.Add(time.Duration(tr.minute)*time.Minute).Format(time.RFC3339Nano),
			tr.input, tr.output, tr.cacheRead, "tu-unpriced-"+itoa(i)); err != nil {
			t.Fatal(err)
		}
	}

	srv := &Server{opts: Options{DB: database, CostEngine: newForecastTestEngine(t)}}
	req := httptest.NewRequest(http.MethodGet, "/api/session/sUnpriced/predict", nil)
	rec := httptest.NewRecorder()
	srv.handleSessionDetail(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var resp PredictResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v — body %s", err, rec.Body.String())
	}

	// Dollar half absent, and the reason names the PRICING gap.
	if resp.Estimate.HasEstimate {
		t.Errorf("an unpriced model must not produce a cost band")
	}
	if resp.Reason == "" || !strings.Contains(resp.Reason, "no pricing entry") {
		t.Errorf("reason = %q, want the no-pricing explanation", resp.Reason)
	}
	if resp.Estimate.Mid.MessageUSD != 0 {
		t.Errorf("mid message cost = %v, want 0 without pricing", resp.Estimate.Mid.MessageUSD)
	}

	// Fact half intact — this is the regression.
	if !resp.Estimate.HasShape {
		t.Fatalf("has_shape must be true: three turns were observed; warnings=%v", resp.Estimate.Warnings)
	}
	if resp.Estimate.PrefixTokens != 8448 {
		t.Errorf("prefix tokens = %d, want 8448 (latest observed cache_read)", resp.Estimate.PrefixTokens)
	}
	if resp.Estimate.SampleTurns != 3 {
		t.Errorf("sample turns = %d, want 3", resp.Estimate.SampleTurns)
	}
	if resp.Estimate.Mid.Output == 0 {
		t.Errorf("mid output quantile should be observed, got 0")
	}
	if resp.Estimate.TurnsTier == "" {
		t.Errorf("turns tier should be resolved even without pricing")
	}
	// A pricing gap must never be reported as a data gap.
	for _, warn := range resp.Estimate.Warnings {
		if warn == predict.WarnNoSessionHistory {
			t.Errorf("no_session_history on a session with three observed turns: %v", resp.Estimate.Warnings)
		}
	}
	var sawNoPricing bool
	for _, warn := range resp.Estimate.Warnings {
		if warn == predict.WarnNoPricing {
			sawNoPricing = true
		}
	}
	if !sawNoPricing {
		t.Errorf("want no_pricing warning, got %v", resp.Estimate.Warnings)
	}
	if resp.Model != "big-pickle" {
		t.Errorf("model = %q", resp.Model)
	}
}

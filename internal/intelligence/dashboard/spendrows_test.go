package dashboard

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestSpendSurfacesCountTwinsOnce pins that the Analysis tab and the monthly
// report read the ONE deduped spend substrate (spendTurns → cost engine →
// sessionmsg.DeriveVerdicts). Two proxied turns, each captured twice:
//
//   - Codex: proxy resp_1 and its transcript twin tk:rollout-x:L1 (disjoint
//     id schemes, identical shape);
//   - OpenCode: proxy resp_2 (gross output 200) and its transcript twin
//     tokens:9 (output 150 + reasoning 50).
//
// The old `proxy_turn_ids ... NOT IN` SQL matched neither (ids never agree),
// so both surfaces reported $0.98 over 4 turns; the one rule counts each turn
// once, at the proxy's recorded cost, with the twin's net output.
func TestSpendSurfacesCountTwinsOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	ctx := context.Background()
	base := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	root := t.TempDir()
	st := store.New(database)
	for sid, tool := range map[string]string{"s-codex": models.ToolCodex, "s-oc": models.ToolOpenCode} {
		if _, err := st.Ingest(ctx, []models.ToolEvent{{
			SourceFile: "f-act", SourceEventID: "a-" + sid, SessionID: sid,
			ProjectRoot: root, Timestamp: base, Tool: tool,
			ActionType: models.ActionReadFile, Target: "a.go", Success: true,
		}}, nil, store.IngestOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := database.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	ts := func(d time.Duration) string { return base.Add(d).Format(time.RFC3339Nano) }
	proxy := `INSERT INTO api_turns (session_id, timestamp, provider, model, request_id, input_tokens, output_tokens, cost_usd)
	          VALUES (?, ?, 'openai', 'gpt-5.4', ?, ?, ?, ?)`
	tok := `INSERT INTO token_usage (session_id, timestamp, tool, model, input_tokens, output_tokens, reasoning_tokens,
	          estimated_cost_usd, source, reliability, source_file, source_event_id)
	        VALUES (?, ?, ?, 'gpt-5.4', ?, ?, ?, ?, 'jsonl', 'approximate', 'f-tu', ?)`
	exec(proxy, "s-codex", ts(0), "resp_1", 1000, 300, 0.30)
	exec(tok, "s-codex", ts(5*time.Second), "codex", 1000, 300, 0, 0.29, "tk:rollout-x:L1")
	exec(proxy, "s-oc", ts(time.Minute), "resp_2", 500, 200, 0.20)
	exec(tok, "s-oc", ts(time.Minute+5*time.Second), "opencode", 500, 150, 50, 0.19, "tokens:9")

	srv, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	get := func(url string, into any) {
		t.Helper()
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, url, nil))
		if rr.Code != 200 {
			t.Fatalf("%s: %d %s", url, rr.Code, rr.Body.String())
		}
		if err := json.NewDecoder(rr.Body).Decode(into); err != nil {
			t.Fatal(err)
		}
	}

	var byHour struct {
		Buckets []struct {
			CostUSD   float64 `json:"cost_usd"`
			TurnCount int     `json:"turn_count"`
		} `json:"buckets"`
	}
	get("/api/analysis/cost-by-hour?days=30", &byHour)
	var hourCost float64
	var hourTurns int
	for _, b := range byHour.Buckets {
		hourCost += b.CostUSD
		hourTurns += b.TurnCount
	}
	if math.Abs(hourCost-0.50) > 1e-9 || hourTurns != 2 {
		t.Errorf("cost-by-hour = $%v over %d turns, want $0.50 over 2 (each twin counted once)", hourCost, hourTurns)
	}

	var report struct {
		Totals struct {
			CostUSD float64          `json:"cost_usd"`
			Turns   int64            `json:"turns"`
			Tokens  map[string]int64 `json:"tokens"`
		} `json:"totals"`
	}
	get("/api/report/monthly?month="+base.Format("2006-01"), &report)
	if math.Abs(report.Totals.CostUSD-0.50) > 1e-9 || report.Totals.Turns != 2 {
		t.Errorf("monthly report = $%v over %d turns, want $0.50 over 2", report.Totals.CostUSD, report.Totals.Turns)
	}
	// 300 (codex) + 150 (OpenCode's proxy row carries its twin's net output;
	// the 50 reasoning tokens are reasoning, not visible output).
	if report.Totals.Tokens["output"] != 450 || report.Totals.Tokens["input"] != 1500 {
		t.Errorf("monthly report tokens = %v, want input 1500 output 450", report.Totals.Tokens)
	}
}

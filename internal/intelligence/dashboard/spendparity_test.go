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

// nodeSpendRow is one seeded usage row for TestSessionsListMatchesDetail.
// proxy=true writes api_turns (Output gross), otherwise token_usage (Output
// net of Reasoning).
type nodeSpendRow struct {
	proxy     bool
	session   string // "" = a session-less proxy row
	id        string
	at        time.Duration // offset from the fixture's base time
	model     string
	in, out   int64
	cr        int64
	reasoning int64
	cost      float64
}

// TestSessionsListMatchesDetail is the node half of the list == detail
// cross-check (lane R2-PARITY-2): the Sessions list row (/api/sessions, the
// cost engine) and the session detail header (/api/session/<id>,
// sessionmsg.Derive) must report the same tokens and cost for a session. The
// engine used to dedup with its own three-level FIFO, which disagreed with
// Derive on every class below; it now applies sessionmsg.DeriveVerdicts per
// session. The org half is rollup's TestSessionDetailSpendFollowsDerive.
func TestSessionsListMatchesDetail(t *testing.T) {
	const sid = "s-parity"
	cases := []struct {
		name string
		tool string
		rows []nodeSpendRow
	}{
		{
			name: "reasoning-split twins fold (OpenCode)",
			tool: models.ToolOpenCode,
			rows: []nodeSpendRow{
				{proxy: true, session: sid, id: "resp_1", model: "m", in: 1000, out: 300, cr: 2000, cost: 0.30},
				{session: sid, id: "tokens:1", at: 5 * time.Second, model: "m", in: 1000, out: 250, reasoning: 50, cr: 2000, cost: 0.29},
				{proxy: true, session: sid, id: "resp_2", at: 5 * time.Minute, model: "m", in: 1100, out: 400, cr: 3000, cost: 0.40},
				{session: sid, id: "tokens:2", at: 5*time.Minute + 5*time.Second, model: "m", in: 1100, out: 380, reasoning: 20, cr: 3000, cost: 0.39},
				{session: sid, id: "tokens:4", at: 12 * time.Minute, model: "m", in: 10, out: 20, cost: 0.01},
			},
		},
		{
			name: "twin two hours away still folds",
			tool: models.ToolCodex,
			rows: []nodeSpendRow{
				{proxy: true, session: sid, id: "resp_h", model: "m", in: 100, out: 50, cr: 900, cost: 0.10},
				{session: sid, id: "tk:L7", at: 2 * time.Hour, model: "m", in: 100, out: 50, cr: 900, cost: 0.09},
			},
		},
		{
			name: "one proxy row claims one of two equal-shape rows",
			tool: models.ToolCodex,
			rows: []nodeSpendRow{
				{proxy: true, session: sid, id: "resp_e", model: "m", in: 10, out: 5, cost: 0.02},
				{session: sid, id: "tk:L1", at: 3 * time.Second, model: "m", in: 10, out: 5, cost: 0.02},
				{session: sid, id: "tk:L2", at: 20 * time.Minute, model: "m", in: 10, out: 5, cost: 0.02},
			},
		},
		{
			name: "request id held by another session does not erase this session's row",
			tool: models.ToolClaudeCode,
			rows: []nodeSpendRow{
				{proxy: true, session: "s-elsewhere", id: "msg_01A", model: "m", in: 7, out: 3, cr: 90, cost: 0.05},
				{session: sid, id: "msg_01A", at: 2 * time.Second, model: "m", in: 7, out: 3, cr: 90, cost: 0.05},
			},
		},
		{
			name: "session-less proxy row does not erase this session's row",
			tool: models.ToolClaudeCode,
			rows: []nodeSpendRow{
				{proxy: true, session: "", id: "resp_o", model: "m", in: 7, out: 3, cr: 90, cost: 0.05},
				{session: sid, id: "tk:L9", at: 20 * time.Second, model: "m", in: 7, out: 3, cr: 90, cost: 0.05},
			},
		},
		{
			name: "copilot shadow row pairs with its full row, a stray one counts",
			tool: models.ToolCopilotCLI,
			rows: []nodeSpendRow{
				{session: sid, id: "cp:1", model: "gpt-4.1", in: 500, out: 40, cost: 0.02},
				{session: sid, id: "cp:1s", at: time.Second, model: "gpt-4.1", out: 40, cost: 0.01},
				{session: sid, id: "cp:9s", at: 90 * time.Minute, model: "gpt-4.1", out: 40, cost: 0.01},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "d.db")
			database, err := openTestDB(context.Background(), db.Options{Path: path})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { database.Close() })
			ctx := context.Background()
			base := time.Now().UTC().Add(-3 * time.Hour).Truncate(time.Second)
			root := t.TempDir()
			st := store.New(database)
			for _, s := range []string{sid, "s-elsewhere"} {
				if _, err := st.Ingest(ctx, []models.ToolEvent{{
					SourceFile: "f-act", SourceEventID: "a-" + s, SessionID: s,
					ProjectRoot: root, Timestamp: base, Tool: c.tool,
					ActionType: models.ActionReadFile, Target: "a.go", Success: true,
				}}, nil, store.IngestOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			for _, r := range c.rows {
				ts := base.Add(r.at).Format(time.RFC3339Nano)
				var session any
				if r.session != "" {
					session = r.session
				}
				if r.proxy {
					if _, err := database.ExecContext(ctx,
						`INSERT INTO api_turns (session_id, timestamp, provider, model, request_id,
						   input_tokens, output_tokens, cache_read_tokens, cost_usd)
						 VALUES (?, ?, 'openai', ?, ?, ?, ?, ?, ?)`,
						session, ts, r.model, r.id, r.in, r.out, r.cr, r.cost); err != nil {
						t.Fatal(err)
					}
					continue
				}
				if _, err := database.ExecContext(ctx,
					`INSERT INTO token_usage (session_id, timestamp, tool, model, input_tokens, output_tokens,
					   cache_read_tokens, reasoning_tokens, estimated_cost_usd, source, reliability, source_file, source_event_id)
					 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'jsonl', 'approximate', 'f-tu', ?)`,
					session, ts, c.tool, r.model, r.in, r.out, r.cr, r.reasoning, r.cost, r.id); err != nil {
					t.Fatal(err)
				}
			}
			srv, err := New(Options{DB: database, DBPath: path})
			if err != nil {
				t.Fatal(err)
			}

			rr := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/session/"+sid, nil))
			if rr.Code != 200 {
				t.Fatalf("detail status %d: %s", rr.Code, rr.Body.String())
			}
			var detail struct {
				CostUSD float64          `json:"cost_usd"`
				Tokens  map[string]int64 `json:"tokens"`
			}
			if err := json.NewDecoder(rr.Body).Decode(&detail); err != nil {
				t.Fatal(err)
			}

			rr = httptest.NewRecorder()
			srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/sessions?limit=50", nil))
			if rr.Code != 200 {
				t.Fatalf("list status %d: %s", rr.Code, rr.Body.String())
			}
			var list struct {
				Rows []struct {
					ID              string  `json:"id"`
					Input           int64   `json:"input_tokens"`
					Output          int64   `json:"output_tokens"`
					CacheRead       int64   `json:"cache_read_tokens"`
					CacheCreation   int64   `json:"cache_creation_tokens"`
					ReasoningTokens int64   `json:"reasoning_tokens"`
					CostUSD         float64 `json:"cost_usd"`
				} `json:"rows"`
			}
			if err := json.NewDecoder(rr.Body).Decode(&list); err != nil {
				t.Fatal(err)
			}
			var found bool
			for _, row := range list.Rows {
				if row.ID != sid {
					continue
				}
				found = true
				if row.Input != detail.Tokens["input"] || row.Output != detail.Tokens["output"] ||
					row.CacheRead != detail.Tokens["cache_read"] || row.CacheCreation != detail.Tokens["cache_creation"] ||
					row.ReasoningTokens != detail.Tokens["reasoning"] {
					t.Errorf("list tokens in/out/cr/cc/reasoning = %d/%d/%d/%d/%d, detail = %v",
						row.Input, row.Output, row.CacheRead, row.CacheCreation, row.ReasoningTokens, detail.Tokens)
				}
				if math.Abs(row.CostUSD-detail.CostUSD) > 1e-9 {
					t.Errorf("list cost $%v != detail cost $%v", row.CostUSD, detail.CostUSD)
				}
			}
			if !found {
				t.Fatalf("session %s missing from /api/sessions", sid)
			}
		})
	}
}

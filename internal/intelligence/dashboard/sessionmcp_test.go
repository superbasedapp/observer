package dashboard

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/mcprelay/record"
)

// TestAPISessionMCPCalls pins GET /api/session/<id>/mcp-calls (Agent Access
// P11(a)): a relay call anchored by the client's tool-use id comes back
// linked exact at action level, with the wire shape the UI lane renders.
func TestAPISessionMCPCalls(t *testing.T) {
	t.Parallel()
	s, _ := newTestServer(t)
	ctx := context.Background()
	now := time.Now().UTC().Add(-30 * time.Minute)
	if _, err := s.opts.DB.ExecContext(ctx, `INSERT INTO actions (session_id, project_id, timestamp, turn_index, action_type, raw_tool_name, tool, source_file, source_event_id, message_id)
		SELECT 'sA', project_id, ?, 2, 'mcp_call', 'mcp__github__search_issues', 'claude-code', 'f', 'toolu_X', 'msg_X' FROM sessions WHERE id = 'sA'`,
		now.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, err := record.NewSQLStore(s.opts.DB, "node").Append(ctx, record.Record{
		Kind: record.KindDecision, TS: now.Unix(), VServer: "github", ServerRefHMAC: "h", ToolRefHMAC: "t", Server: "github", Tool: "search_issues",
		CallID: "call-1", CodingSessionID: "sA", ActionRef: "toolu_X", CorrConfidence: record.CorrExact, Method: "tools/call",
		EventKind: record.EventCall, Decision: record.DecisionAllow, ClientAttestation: record.AttestProcess, CredentialAssurance: "node_enrolled",
		CaptureLevel: record.CaptureL2,
	}); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/api/session/sA/mcp-calls", nil))
	if rec.Code != 200 {
		t.Fatalf("status %d %s", rec.Code, rec.Body)
	}
	var resp struct {
		SessionID string `json:"session_id"`
		Calls     []struct {
			CallID      string   `json:"call_id"`
			Sources     []string `json:"sources"`
			Tool        string   `json:"tool"`
			Correlation struct {
				Confidence string `json:"confidence"`
				Level      string `json:"level"`
				ActionKey  string `json:"action_key"`
				TurnIndex  *int64 `json:"turn_index"`
			} `json:"correlation"`
		} `json:"calls"`
		Totals struct {
			Calls int `json:"calls"`
			Exact int `json:"exact"`
		} `json:"totals"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.SessionID != "sA" || len(resp.Calls) != 1 || resp.Totals.Exact != 1 {
		t.Fatalf("resp %s", rec.Body)
	}
	c := resp.Calls[0]
	if c.CallID != "call-1" || c.Tool != "search_issues" || c.Correlation.Confidence != "exact" || c.Correlation.Level != "action" ||
		c.Correlation.ActionKey != "toolu_X" || c.Correlation.TurnIndex == nil || *c.Correlation.TurnIndex != 2 || len(c.Sources) != 1 || c.Sources[0] != "node" {
		t.Fatalf("call %s", rec.Body)
	}
	// A session with no relay records answers an empty list, not an error.
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/api/session/none/mcp-calls", nil))
	if rec.Code != 200 || !json.Valid(rec.Body.Bytes()) {
		t.Fatalf("empty session %d %s", rec.Code, rec.Body)
	}
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("POST", "/api/session/sA/mcp-calls", nil))
	if rec.Code == 200 {
		t.Fatalf("POST accepted: %d", rec.Code)
	}
}

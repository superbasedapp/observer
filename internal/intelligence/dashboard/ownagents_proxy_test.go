//go:build !sbo_omit_capture_proxy

package dashboard

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/ownagent"
	"github.com/marmutapp/superbased-observer/internal/proxy"
)

// TestClaimedProxyTurnShowsInMessagesAndCost (fix round 1): one request
// through the REAL proxy, carrying the own-agent headers and landing in the
// dashboard's own store, must show up as a custom-agent session: its row in
// the Sessions list, one message in its Messages tab (internal/sessionmsg)
// and its tokens under the custom-agent tool on the Cost page.
func TestClaimedProxyTurnShowsInMessagesAndCost(t *testing.T) {
	s, st := newTagTestServer(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_e2e","model":"claude-sonnet-4","stop_reason":"end_turn","usage":{"input_tokens":40,"output_tokens":9}}`))
	}))
	defer up.Close()
	p, err := proxy.New(proxy.Options{AnthropicUpstream: up.URL, Sink: st, OwnAgentSessions: st})
	if err != nil {
		t.Fatal(err)
	}
	ps := httptest.NewServer(p.Handler())
	defer ps.Close()

	req, _ := http.NewRequest(http.MethodPost, ps.URL+"/v1/messages",
		strings.NewReader(`{"model":"claude-sonnet-4","messages":[{"role":"user","content":"hello"}]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", "sk-ant-test")
	req.Header.Set(ownagent.AgentHeader, "e2e-bot")
	req.Header.Set(ownagent.SessionHeader, "run-1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("proxy status %d", resp.StatusCode)
	}
	sid := ownagent.SessionID("e2e-bot", "run-1")

	code, body := doJSON(t, s, http.MethodGet, "/api/sessions?tool=custom-agent&surface_host=agent:e2e-bot", "")
	if code != http.StatusOK {
		t.Fatalf("sessions = %d", code)
	}
	rows, _ := body["rows"].([]any)
	if len(rows) != 1 || rows[0].(map[string]any)["id"] != sid {
		t.Fatalf("sessions list = %v, want the one claimed session %s", body["rows"], sid)
	}

	code, body = doJSON(t, s, http.MethodGet, "/api/session/"+sid+"/messages", "")
	if code != http.StatusOK {
		t.Fatalf("messages = %d", code)
	}
	if msgs, _ := body["messages"].([]any); len(msgs) != 1 {
		t.Fatalf("messages = %v, want the one proxy turn", body["messages"])
	}

	code, body = doJSON(t, s, http.MethodGet, "/api/cost?group_by=tool&days=7", "")
	if code != http.StatusOK {
		t.Fatalf("cost = %d", code)
	}
	var found bool
	for _, r := range body["rows"].([]any) {
		row := r.(map[string]any)
		if row["key"] == models.ToolCustomAgent {
			found = true
			tokens, _ := row["tokens"].(map[string]any)
			if tokens["input"] != float64(40) || row["turn_count"] != float64(1) {
				t.Errorf("custom-agent cost row = %v, want 40 input tokens over 1 turn", row)
			}
		}
	}
	if !found {
		t.Fatalf("Cost by tool has no %s row: %v", models.ToolCustomAgent, body["rows"])
	}
}

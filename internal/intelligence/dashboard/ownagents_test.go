package dashboard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestOwnAgentsEndpoint: GET /api/own-agents groups custom-agent sessions by
// agent name, leaves coding-tool sessions out and carries the snippet facts
// the empty state prints.
func TestOwnAgentsEndpoint(t *testing.T) {
	s, st := newTagTestServer(t)
	ctx := context.Background()

	code, body := doJSON(t, s, http.MethodGet, "/api/own-agents", "")
	if code != http.StatusOK {
		t.Fatalf("GET = %d", code)
	}
	if agents, _ := body["agents"].([]any); len(agents) != 0 {
		t.Fatalf("empty store listed agents: %v", body["agents"])
	}
	if body["agent_header"] != "X-Superbased-Agent" || body["session_header"] != "X-Session-Id" || body["tool"] != models.ToolCustomAgent {
		t.Fatalf("snippet facts = %v", body)
	}
	if u, _ := body["proxy_base_url"].(string); u == "" {
		t.Fatal("no proxy_base_url")
	}
	if body["client_auth"] != false {
		t.Fatalf("client_auth = %v on a node without a client token", body["client_auth"])
	}
	if _, ok := body["client_token_file"]; ok {
		t.Fatalf("client_token_file = %v on a node without a client token", body["client_token_file"])
	}

	now := time.Now().UTC()
	if err := st.EnsureOwnAgentSession(ctx, "ca-x", "triage-bot", "[custom-agent]", "gpt-4o", now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertAPITurn(ctx, models.APITurn{SessionID: "ca-x", Timestamp: now, Provider: models.ProviderOpenAI, Model: "gpt-4o", InputTokens: 7, OutputTokens: 3}); err != nil {
		t.Fatal(err)
	}
	_, body = doJSON(t, s, http.MethodGet, "/api/own-agents", "")
	agents, _ := body["agents"].([]any)
	if len(agents) != 1 {
		t.Fatalf("agents = %v (coding-tool sessions must not appear)", body["agents"])
	}
	a, _ := agents[0].(map[string]any)
	if a["agent"] != "triage-bot" || a["surface_host"] != "agent:triage-bot" || a["turns"] != float64(1) || a["sessions"] != float64(1) {
		t.Fatalf("agent row = %v", a)
	}

	// The session's Messages tab comes from the one shared derivation
	// (internal/sessionmsg) over its proxy turn, and its detail resolves.
	code, body = doJSON(t, s, http.MethodGet, "/api/session/ca-x/messages", "")
	if code != http.StatusOK {
		t.Fatalf("messages = %d", code)
	}
	if msgs, _ := body["messages"].([]any); len(msgs) != 1 {
		t.Fatalf("messages = %v, want the one proxy turn", body["messages"])
	}
	if code, _ = doJSON(t, s, http.MethodGet, "/api/session/ca-x", ""); code != http.StatusOK {
		t.Fatalf("session detail = %d", code)
	}
	code, body = doJSON(t, s, http.MethodGet, "/api/sessions?tool=custom-agent&surface_host=agent:triage-bot", "")
	if code != http.StatusOK {
		t.Fatalf("sessions = %d", code)
	}
	if rows, _ := body["rows"].([]any); len(rows) != 1 {
		t.Fatalf("sessions filter = %v, want the one own-agent session", body["rows"])
	}

	if code, _ := doJSON(t, s, http.MethodPost, "/api/own-agents", "{}"); code != http.StatusMethodNotAllowed {
		t.Fatalf("POST = %d, want 405", code)
	}
}

// TestOwnAgentsTokenFilePathOnly (lane L5 B-R3): a node that wants the
// proxy client token gets the token FILE path for the Copy path button,
// and the token value never appears in the response.
func TestOwnAgentsTokenFilePathOnly(t *testing.T) {
	s, _ := newTagTestServer(t)
	const secret = "tok-very-secret-value-0123456789"
	s.opts.ProxyClientToken = secret
	s.opts.ConfigPath = ""
	rec := httptest.NewRecorder()
	s.handleOwnAgents(rec, httptest.NewRequest(http.MethodGet, "/api/own-agents", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET = %d", rec.Code)
	}
	raw := rec.Body.String()
	if strings.Contains(raw, secret) {
		t.Fatalf("the token value crossed the wire: %s", raw)
	}
	if !strings.Contains(raw, `"client_auth":true`) || !strings.Contains(raw, `"client_token_file":"~/.observer/proxy-client-token"`) {
		t.Fatalf("want client_auth and the default token path: %s", raw)
	}
}

// TestOwnAgentsClientAuth (fix round 1): when the node wants the proxy
// client token, the endpoint says so (the snippet then uses the
// /t/<token> base URL) and never returns the token, a View route.
func TestOwnAgentsClientAuth(t *testing.T) {
	s, _ := newTagTestServer(t)
	const tok = "sbo-test-client-token-value-0123456789"
	s.opts.ProxyClientToken = tok
	req := httptest.NewRequest(http.MethodGet, "/api/own-agents", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET = %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), tok) {
		t.Fatal("the proxy client token leaked into /api/own-agents")
	}
	if !strings.Contains(rec.Body.String(), `"client_auth":true`) {
		t.Fatalf("client_auth not reported: %s", rec.Body.String())
	}
}

// TestOwnAgentHasNoSetupWizard (fix round 1): the Connected tools Set up
// wizard offers a write exactly where `observer init` makes one; for
// custom-agent there is none, so no Set up action may be offered.
func TestOwnAgentHasNoSetupWizard(t *testing.T) {
	if w := wiringFor(models.ToolCustomAgent, nil); w != nil {
		t.Fatalf("Set up offers %+v for custom-agent, which nothing can write", w)
	}
}

// TestOwnAgentsSpanSourcedSession (PT-55 scope 4): a session that only the
// agent's OpenTelemetry spans produced (a turn with source agent_otel and a
// tool call from the export, written the way the OTLP ingest writes them)
// shows in the Own agents view with the "otlp" source label and goes
// through the same session detail, Messages tab and Sessions filter as a
// proxy session, with no other difference.
func TestOwnAgentsSpanSourcedSession(t *testing.T) {
	s, st := newTagTestServer(t)
	ctx := context.Background()
	now := time.Now().UTC()
	if err := st.EnsureOwnAgentSession(ctx, "ca-span", "span-bot", "[custom-agent]", "gpt-5.5-mini", now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.UpsertTurnByRequestID(ctx, models.APITurn{
		SessionID: "ca-span", Timestamp: now, Provider: models.ProviderOpenAI, Model: "gpt-5.5-mini",
		RequestID: "chatcmpl-span-1", InputTokens: 1234, OutputTokens: 56, Source: store.SourceAgentOTel,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Ingest(ctx, []models.ToolEvent{{
		SourceFile: "otlp:" + models.ToolCustomAgent, SourceEventID: "call_1", SessionID: "ca-span",
		ProjectRoot: "[custom-agent]", Timestamp: now.Add(time.Second), Tool: models.ToolCustomAgent,
		Model: "gpt-5.5-mini", ActionType: models.ActionUnknown, RawToolName: "list_files", Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}

	_, body := doJSON(t, s, http.MethodGet, "/api/own-agents", "")
	if body["agent_attr"] != "sbo.agent" {
		t.Fatalf("agent_attr = %v", body["agent_attr"])
	}
	agents, _ := body["agents"].([]any)
	if len(agents) != 1 {
		t.Fatalf("agents = %v", body["agents"])
	}
	a, _ := agents[0].(map[string]any)
	if a["agent"] != "span-bot" || a["via"] != store.OwnAgentViaOTLP || a["turns"] != float64(1) || a["input_tokens"] != float64(1234) {
		t.Fatalf("agent row = %v", a)
	}
	code, body := doJSON(t, s, http.MethodGet, "/api/session/ca-span/messages", "")
	if code != http.StatusOK {
		t.Fatalf("messages = %d", code)
	}
	if msgs, _ := body["messages"].([]any); len(msgs) < 2 {
		t.Fatalf("messages = %v, want the span turn and the span tool call", body["messages"])
	}
	if code, _ = doJSON(t, s, http.MethodGet, "/api/session/ca-span", ""); code != http.StatusOK {
		t.Fatalf("session detail = %d", code)
	}
	code, body = doJSON(t, s, http.MethodGet, "/api/sessions?tool=custom-agent&surface_host=agent:span-bot", "")
	if code != http.StatusOK {
		t.Fatalf("sessions = %d", code)
	}
	if rows, _ := body["rows"].([]any); len(rows) != 1 {
		t.Fatalf("sessions filter = %v, want the one span-sourced session", body["rows"])
	}
}

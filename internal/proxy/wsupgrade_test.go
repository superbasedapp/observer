package proxy

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// TestDecideUpgrade pins the ordered websocket-upgrade table, one case per
// row plus the fall-through.
func TestDecideUpgrade(t *testing.T) {
	cases := []struct {
		name  string
		facts upgradeFacts
		want  upgradeDecision
		rule  string
	}{
		{"chatgpt forced http", upgradeFacts{forceChatGPTHTTP: true, chatGPTTraffic: true}, upgradeHTTPFallback, "chatgpt_forced_http"},
		{"flag without chatgpt traffic does not fire", upgradeFacts{forceChatGPTHTTP: true}, upgradePassthrough, "passthrough"},
		{"responses endpoint falls back to http", upgradeFacts{httpEquivalent: true}, upgradeHTTPFallback, "http_equivalent_endpoint"},
		{"responses endpoint on the gateway still 426 (custody-safe, never dials)", upgradeFacts{httpEquivalent: true, gatewayRouted: true}, upgradeHTTPFallback, "http_equivalent_endpoint"},
		{"other endpoint on the gateway refused", upgradeFacts{gatewayRouted: true}, upgradeRefuseGateway, "gateway_http_only"},
		{"other endpoint passes through", upgradeFacts{}, upgradePassthrough, "passthrough"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, rule := decideUpgrade(tc.facts)
			if got != tc.want || rule != tc.rule {
				t.Fatalf("decideUpgrade(%+v) = (%d, %q), want (%d, %q)", tc.facts, got, rule, tc.want, tc.rule)
			}
		})
	}
}

// TestIsResponsesEndpoint pins the endpoint-segment match across every base
// URL shape codex can compose `<base_url>/responses` from.
func TestIsResponsesEndpoint(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/v1/responses", true},
		{"/v1/responses/", true},
		{"/backend-api/codex/responses", true},
		{"/api/v1/responses", true},
		{"/responses", true},
		{"/v1/Responses", true},
		{"/v1/responses/resp_123", false}, // a retrieve-by-id path, not the socket
		{"/v1/realtime", false},
		{"/v1/chat/completions", false},
		{"/v1/messages", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := isResponsesEndpoint(tc.path); got != tc.want {
			t.Errorf("isResponsesEndpoint(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// TestProxy_ResponsesWebSocketUpgradeAnswers426 is the end-to-end pin for
// backlog item 14 follow-up 2: a Responses websocket upgrade (codex's
// openai_base_url shape) is answered 426 WITHOUT dialing the upstream, so
// codex's FallbackToHttp path re-sends the turn over HTTP streaming where
// the proxy writes an api_turns row. Covers the canonical path, the ChatGPT
// backend path (with force_chatgpt_http OFF - the old knob is no longer
// needed for this endpoint) and a /up/<id> lane.
func TestProxy_ResponsesWebSocketUpgradeAnswers426(t *testing.T) {
	var hits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		t.Errorf("upstream dialed on a Responses websocket upgrade: %s", r.URL.Path)
	}))
	defer upstream.Close()

	sink := &fakeSink{}
	p, err := New(Options{
		AnthropicUpstream: upstream.URL,
		OpenAIUpstream:    upstream.URL,
		ChatGPTUpstream:   upstream.URL,
		Upstreams:         map[string]string{"lane": upstream.URL},
		Sink:              sink,
	})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	for _, path := range []string{"/v1/responses", "/backend-api/codex/responses", "/up/lane/v1/responses"} {
		t.Run(path, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, ts.URL+path, nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			req.Header.Set("Connection", "Upgrade")
			req.Header.Set("Upgrade", "websocket")
			req.Header.Set("Sec-WebSocket-Version", "13")
			req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
			req.Header.Set("Authorization", "Bearer sk-test")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("client request: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusUpgradeRequired {
				t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusUpgradeRequired)
			}
		})
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("upstream hits = %d, want 0", n)
	}
	if n := len(sink.all()); n != 0 {
		t.Errorf("turns recorded = %d, want 0 (the HTTP retry records the turn)", n)
	}
}

// TestGatewayAuthSub_ResponsesWebSocketUpgradeAnswers426 pins the row order:
// a Responses upgrade routed to the org AI Gateway gets 426 (so codex's HTTP
// retry reaches the gateway through the auth-substituting HTTP path), not
// the 502 refusal, and the gateway is still never dialed with the developer
// credential.
func TestGatewayAuthSub_ResponsesWebSocketUpgradeAnswers426(t *testing.T) {
	gateway := newRecordingUpstream(t, http.StatusOK)
	p := mustGatewayProxy(t, Options{
		Sink:             &fakeSink{},
		VirtualKeySource: &fakeVirtualKeySource{key: "sbo-vk-secret", gen: 1},
	}, gateway.srv.URL, nil, terminalHold, false)
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/v1/responses", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Authorization", "Bearer DEV-PROVIDER-TOKEN")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("client request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUpgradeRequired {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusUpgradeRequired)
	}
	if gateway.count() != 0 {
		t.Errorf("gateway dialed %d times on a WS upgrade; must be 0", gateway.count())
	}
}

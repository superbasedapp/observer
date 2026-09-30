package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestProxy_HostedIdentityStrippedFromForwardedRequest is the mutation-proof
// target for the hosted-app identity leak fix: X-Superbased-*, the explicit
// hostedAppSessionHeaders (X-OpenWebUI-Chat-Id), the operator-configured
// admission user header, and the sb_session query param must never reach
// the upstream LLM provider, on the normal forward path
// (copyRequestHeaders / stripHostedIdentityQueryParams via proxy.go's main
// forward). Unrelated headers/params pass through untouched, and the
// proxy's own session (api_turns.session_id) and admission-user
// (ChatTurnFacts.User) attribution — which read the ORIGINAL inbound
// request, never the stripped outgoing one — are unaffected.
func TestProxy_HostedIdentityStrippedFromForwardedRequest(t *testing.T) {
	const respBody = `{"id":"msg_hid","model":"claude-sonnet-4","stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`

	var (
		mu          sync.Mutex
		gotHeader   http.Header
		gotRawQuery string
	)
	anth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotHeader = r.Header.Clone()
		gotRawQuery = r.URL.RawQuery
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(respBody))
	}))
	defer anth.Close()

	sink := &fakeSink{}
	obsSink := &fakeObsSink{callDoneChan: make(chan struct{}, 1)}
	p, err := New(Options{
		AnthropicUpstream: anth.URL,
		// Route through an explicit /up/<id> hosted-app lane — the finding's
		// scenario, and the only lane where hostedSessionHeader/admissionUser
		// resolution is exercised end-to-end.
		Upstreams:           map[string]string{"hostedapp": anth.URL},
		Sink:                sink,
		ObsSink:             obsSink,
		AdmissionUserHeader: "X-OpenWebUI-User-Email",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	const reqBody = `{"model":"claude-sonnet-4","messages":[{"role":"user","content":"hi"}]}`
	req, _ := http.NewRequest(http.MethodPost,
		ts.URL+"/up/hostedapp/v1/messages?sb_session=conv-leak-1&foo=bar", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", "sk-ant-test")
	req.Header.Set("X-Superbased-User", "user-should-not-leak")
	req.Header.Set("X-Superbased-Session", "conv-superbased-1")
	req.Header.Set("X-OpenWebUI-Chat-Id", "owui-chat-should-not-leak")
	req.Header.Set("X-OpenWebUI-User-Email", "alice@example.com")
	req.Header.Set("X-Custom-Debug", "keep-me")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d want 200", resp.StatusCode)
	}

	mu.Lock()
	h := gotHeader
	rq := gotRawQuery
	mu.Unlock()

	// (a) hosted-identity headers never reach upstream.
	for _, name := range []string{
		"X-Superbased-User", "X-Superbased-Session",
		"X-OpenWebUI-Chat-Id", "X-OpenWebUI-User-Email",
	} {
		if v := h.Get(name); v != "" {
			t.Errorf("hosted-identity header %q leaked upstream: %q", name, v)
		}
	}

	// (b) sb_session absent from the forwarded URL.
	q, err := url.ParseQuery(rq)
	if err != nil {
		t.Fatalf("parse forwarded query %q: %v", rq, err)
	}
	if q.Has(hostedSessionQueryParam) {
		t.Errorf("sb_session leaked in forwarded query: %q", rq)
	}

	// (d) unrelated headers and query params pass through untouched.
	if got := h.Get("X-Api-Key"); got != "sk-ant-test" {
		t.Errorf("X-Api-Key: got %q want sk-ant-test", got)
	}
	if got := h.Get("X-Custom-Debug"); got != "keep-me" {
		t.Errorf("X-Custom-Debug: got %q want keep-me", got)
	}
	if got := q.Get("foo"); got != "bar" {
		t.Errorf("foo query param: got %q want bar", got)
	}

	// (c) session/admission attribution still resolves — read from the
	// ORIGINAL inbound request, unaffected by the strip on the forwarded copy.
	turns := sink.all()
	if len(turns) != 1 {
		t.Fatalf("api_turns recorded: got %d want 1", len(turns))
	}
	if got := turns[0].SessionID; got != "conv-superbased-1" {
		t.Errorf("api_turns session id: got %q want conv-superbased-1", got)
	}

	waitForCall(t, obsSink.callDoneChan, 2*time.Second)
	calls := obsSink.all()
	if len(calls) != 1 {
		t.Fatalf("obs sink calls: got %d want 1", len(calls))
	}
	if got := calls[0].User; got != "alice@example.com" {
		t.Errorf("admission user: got %q want alice@example.com", got)
	}
	if got := calls[0].SessionID; got != "conv-superbased-1" {
		t.Errorf("obs trace session id: got %q want conv-superbased-1", got)
	}
}

// TestProxy_WebSocketUpgradePassthrough_StripsHostedIdentity is the
// upgrade-lane counterpart: serveUpgradePassthrough must strip the same
// hosted-identity headers/query param from its Director-rewritten request,
// while leaving unrelated headers/query params — and the existing
// X-Session-Id strip — untouched. Mirrors
// TestProxy_OpenAIWebSocketUpgradePassthrough's raw-hijack pattern. Uses a
// non-Responses OpenAI path: a /v1/responses upgrade is answered 426 before
// the passthrough (wsupgrade.go).
func TestProxy_WebSocketUpgradePassthrough_StripsHostedIdentity(t *testing.T) {
	seen := make(chan *http.Request, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clone := r.Clone(r.Context())
		clone.Header = r.Header.Clone()
		seen <- clone

		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Error("upstream response writer does not support hijacking")
			return
		}
		conn, rw, err := hj.Hijack()
		if err != nil {
			t.Errorf("hijack upstream: %v", err)
			return
		}
		defer conn.Close()
		_, _ = fmt.Fprint(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: test\r\n\r\n")
		_ = rw.Flush()
	}))
	defer upstream.Close()

	sink := &fakeSink{}
	p, err := New(Options{
		AnthropicUpstream:   "https://api.anthropic.com",
		OpenAIUpstream:      upstream.URL + "/root",
		Sink:                sink,
		AdmissionUserHeader: "X-OpenWebUI-User-Email",
	})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	proxyURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	conn, err := net.Dial("tcp", proxyURL.Host)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	_, err = fmt.Fprintf(conn, "GET /v1/chat/completions?sb_session=conv-leak-2&conversation=abc HTTP/1.1\r\n"+
		"Host: %s\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"+
		"Authorization: [REDACTED]\r\nX-Session-Id: local-session\r\n"+
		"X-Superbased-User: user-should-not-leak\r\nX-Superbased-Session: conv-should-not-leak\r\n"+
		"X-OpenWebUI-Chat-Id: owui-should-not-leak\r\nX-OpenWebUI-User-Email: alice@example.com\r\n\r\n",
		proxyURL.Host)
	if err != nil {
		t.Fatalf("write upgrade request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status: got %d want %d", resp.StatusCode, http.StatusSwitchingProtocols)
	}

	select {
	case req := <-seen:
		// Unrelated path/query/header pass through untouched.
		if req.URL.Path != "/root/v1/chat/completions" {
			t.Errorf("upstream path: got %q want %q", req.URL.Path, "/root/v1/chat/completions")
		}
		q, err := url.ParseQuery(req.URL.RawQuery)
		if err != nil {
			t.Fatalf("parse upstream query %q: %v", req.URL.RawQuery, err)
		}
		if got := q.Get("conversation"); got != "abc" {
			t.Errorf("conversation query param: got %q want abc", got)
		}
		if got := req.Header.Get("Authorization"); got != "[REDACTED]" {
			t.Errorf("Authorization header: got %q", got)
		}
		if !headerHasToken(req.Header.Get("Connection"), "upgrade") {
			t.Errorf("Connection header: got %q, want upgrade token", req.Header.Get("Connection"))
		}

		// Hosted-identity + sb_session stripped.
		if q.Has(hostedSessionQueryParam) {
			t.Errorf("sb_session leaked in forwarded query: %q", req.URL.RawQuery)
		}
		if got := req.Header.Get("X-Session-Id"); got != "" {
			t.Errorf("X-Session-Id leaked upstream: %q", got)
		}
		for _, name := range []string{
			"X-Superbased-User", "X-Superbased-Session",
			"X-OpenWebUI-Chat-Id", "X-OpenWebUI-User-Email",
		} {
			if v := req.Header.Get(name); v != "" {
				t.Errorf("hosted-identity header %q leaked upstream: %q", name, v)
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not receive websocket upgrade request")
	}
}

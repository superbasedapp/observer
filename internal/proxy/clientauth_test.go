package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

const testProxyClientToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// clientAuthHarness is a proxy with recording upstreams and a captured log.
type clientAuthHarness struct {
	ts   *httptest.Server
	p    *Proxy
	sink *fakeSink
	log  *bytes.Buffer
	mu   sync.Mutex
	seen []string // upstream request URIs plus every header value
}

func newClientAuthHarness(t *testing.T, token string, required bool) *clientAuthHarness {
	t.Helper()
	h := &clientAuthHarness{log: &bytes.Buffer{}, sink: &fakeSink{}}
	record := func(w http.ResponseWriter, r *http.Request, body string) {
		h.mu.Lock()
		h.seen = append(h.seen, r.RequestURI)
		for k, vs := range r.Header {
			h.seen = append(h.seen, k+": "+strings.Join(vs, ","))
		}
		h.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}
	anth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		record(w, r, `{"id":"msg_1","model":"claude-sonnet-4","stop_reason":"end_turn","usage":{"input_tokens":3,"output_tokens":2}}`)
	}))
	oai := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		record(w, r, okChatCompletionBody)
	}))
	t.Cleanup(anth.Close)
	t.Cleanup(oai.Close)
	p, err := New(Options{
		AnthropicUpstream: anth.URL,
		OpenAIUpstream:    oai.URL,
		Sink:              h.sink,
		Logger:            slog.New(slog.NewTextHandler(h.log, &slog.HandlerOptions{Level: slog.LevelDebug})),
		ClientToken:       token,
		RequireClientAuth: required,
	})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	h.p = p
	h.ts = httptest.NewServer(p.Handler())
	t.Cleanup(h.ts.Close)
	return h
}

func (h *clientAuthHarness) post(t *testing.T, path, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, h.ts.URL+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", "sk-ant-test")
	req.Header.Set("Authorization", "Bearer sk-test")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (h *clientAuthHarness) upstreamSaw() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return strings.Join(h.seen, "\n")
}

const (
	anthBody = `{"model":"claude-sonnet-4","max_tokens":8,"messages":[{"role":"user","content":"hi"}]}`
	oaiBody  = `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`
)

// TestClientAuthRequiredRefusesPlainRequest: with enforcement on, a request
// without the token is refused with 401 and a body that names the setting,
// and nothing reaches an upstream.
func TestClientAuthRequiredRefusesPlainRequest(t *testing.T) {
	h := newClientAuthHarness(t, testProxyClientToken, true)
	for _, c := range []struct{ path, body, field string }{
		{"/v1/messages", anthBody, "error"},
		{"/v1/chat/completions", oaiBody, "error"},
	} {
		status, body := h.post(t, c.path, c.body)
		if status != http.StatusUnauthorized {
			t.Fatalf("%s: status %d, want 401 (%s)", c.path, status, body)
		}
		if !strings.Contains(body, "require_client_auth") {
			t.Fatalf("%s: refusal body does not name the setting: %s", c.path, body)
		}
		var v map[string]any
		if err := json.Unmarshal([]byte(body), &v); err != nil || v[c.field] == nil {
			t.Fatalf("%s: refusal body is not provider-shaped JSON: %s", c.path, body)
		}
	}
	if s := h.upstreamSaw(); s != "" {
		t.Fatalf("a refused request reached an upstream: %s", s)
	}
	if n := len(h.sink.all()); n != 0 {
		t.Fatalf("a refused request was captured: %d turns", n)
	}
	if !h.p.ClientAuthEnforced() || h.p.ClientAuthRefused() != 2 {
		t.Fatalf("enforced=%v refused=%d", h.p.ClientAuthEnforced(), h.p.ClientAuthRefused())
	}
	// The liveness probe stays open.
	resp, err := http.Get(h.ts.URL + healthzPath)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz under enforcement: %v %v", err, resp)
	}
	_ = resp.Body.Close()
}

// TestClientAuthTokenRouteWorks: the token form reaches the right upstream
// for an Anthropic route (env_settings, claude-code shape: the token is the
// whole base path), an OpenAI route (config_file and launcher shape: the
// token sits before /v1) and a lane route (/up/<id>/ after the token), and
// the token never reaches an upstream, the captured row or a log line.
func TestClientAuthTokenRouteWorks(t *testing.T) {
	for _, required := range []bool{false, true} {
		t.Run(fmt.Sprintf("required=%v", required), func(t *testing.T) {
			h := newClientAuthHarness(t, testProxyClientToken, required)
			pre := "/t/" + testProxyClientToken
			for _, c := range []struct{ path, body, wantURI string }{
				{pre + "/v1/messages", anthBody, "/v1/messages"},
				{pre + "/v1/chat/completions", oaiBody, "/v1/chat/completions"},
			} {
				status, body := h.post(t, c.path, c.body)
				if status != http.StatusOK {
					t.Fatalf("%s: status %d (%s)", c.path, status, body)
				}
				if !strings.Contains(h.upstreamSaw(), c.wantURI) {
					t.Fatalf("upstream did not get %s: %s", c.wantURI, h.upstreamSaw())
				}
			}
			// A lane after the token is resolved as without one: an unknown
			// lane is refused by the lane rule, not the token rule.
			status, body := h.post(t, pre+"/up/nolane/v1/chat/completions", oaiBody)
			if status == http.StatusUnauthorized || !strings.Contains(body, "observer_unknown_upstream_lane") {
				t.Fatalf("lane after the token: %d %s", status, body)
			}
			if strings.Contains(h.upstreamSaw(), testProxyClientToken) {
				t.Fatalf("the token reached an upstream: %s", h.upstreamSaw())
			}
			for _, tr := range h.sink.all() {
				if strings.Contains(fmt.Sprintf("%+v", tr), testProxyClientToken) {
					t.Fatalf("the token reached a captured row: %+v", tr)
				}
			}
			if len(h.sink.all()) != 2 {
				t.Fatalf("want 2 captured turns, got %d", len(h.sink.all()))
			}
			if strings.Contains(h.log.String(), testProxyClientToken) {
				t.Fatalf("the token reached the log:\n%s", h.log.String())
			}
		})
	}
}

// TestClientAuthWrongTokenIsAlwaysRefused: a presented token is verified
// whether or not enforcement is on, and the refusal log never carries it.
func TestClientAuthWrongTokenIsAlwaysRefused(t *testing.T) {
	wrong := strings.Repeat("f", 64)
	for _, required := range []bool{false, true} {
		h := newClientAuthHarness(t, testProxyClientToken, required)
		status, body := h.post(t, "/t/"+wrong+"/v1/messages", anthBody)
		if status != http.StatusUnauthorized || strings.Contains(body, wrong) {
			t.Fatalf("required=%v: %d %s", required, status, body)
		}
		if h.upstreamSaw() != "" || strings.Contains(h.log.String(), wrong) {
			t.Fatalf("required=%v: upstream %q log %q", required, h.upstreamSaw(), h.log.String())
		}
	}
}

// TestClientAuthNotRequiredServesPlainRequest: a token exists but
// enforcement is off (the migration step): plain requests are served.
func TestClientAuthNotRequiredServesPlainRequest(t *testing.T) {
	h := newClientAuthHarness(t, testProxyClientToken, false)
	if status, body := h.post(t, "/v1/messages", anthBody); status != http.StatusOK {
		t.Fatalf("status %d (%s)", status, body)
	}
	h.p.SetRequireClientAuth(true)
	if status, _ := h.post(t, "/v1/messages", anthBody); status != http.StatusUnauthorized {
		t.Fatalf("after SetRequireClientAuth(true): status %d", status)
	}
}

// TestClientAuthOffIsUnchanged: with no token (the default) every plain
// request is byte-identical to before and RequireClientAuth alone is inert.
// A well-formed /t/<token> prefix is refused locally and never forwarded
// (the provider would otherwise see the token in the path, audit F2); a /t/
// segment that is not a token passes as before.
func TestClientAuthOffIsUnchanged(t *testing.T) {
	h := newClientAuthHarness(t, "", true)
	if status, body := h.post(t, "/v1/messages", anthBody); status != http.StatusOK {
		t.Fatalf("status %d (%s)", status, body)
	}
	if h.p.ClientAuthEnforced() {
		t.Fatal("enforced without a token")
	}
	if !strings.Contains(h.upstreamSaw(), "/v1/messages") {
		t.Fatalf("the plain request did not reach the upstream: %s", h.upstreamSaw())
	}
	status, body := h.post(t, "/t/"+testProxyClientToken+"/v1/messages", anthBody)
	if status != http.StatusUnauthorized || strings.Contains(body, testProxyClientToken) {
		t.Fatalf("a token-shaped prefix with no token: %d %s", status, body)
	}
	if strings.Contains(h.upstreamSaw(), testProxyClientToken) {
		t.Fatalf("the token was forwarded: %s", h.upstreamSaw())
	}
	if strings.Contains(h.log.String(), testProxyClientToken) {
		t.Fatalf("the token reached the log:\n%s", h.log.String())
	}
	_, _ = h.post(t, "/t/abc/v1/messages", anthBody)
	if !strings.Contains(h.upstreamSaw(), "/t/abc/v1/messages") {
		t.Fatalf("a /t/ segment that is not a token must pass as before: %s", h.upstreamSaw())
	}
	if h.p.ClientAuthRefused() != 1 {
		t.Fatalf("refused = %d, want 1", h.p.ClientAuthRefused())
	}
}

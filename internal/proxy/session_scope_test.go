package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestNormalizePromptGuardRemoteHost(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want string
		ok   bool
	}{
		{name: "ipv4", in: "192.0.2.10:1234", want: "192.0.2.10", ok: true},
		{name: "ipv6", in: "[2001:db8::10]:1234", want: "2001:db8::10", ok: true},
		{name: "mapped ipv4", in: "[::ffff:192.0.2.10]:1234", want: "192.0.2.10", ok: true},
		{name: "missing port", in: "192.0.2.10", ok: false},
		{name: "non-numeric port", in: "192.0.2.10:port", ok: false},
		{name: "invalid host", in: "[not-an-ip]:1234", ok: false},
		{name: "empty", in: "", ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := normalizePromptGuardRemoteHost(tt.in)
			if ok != tt.ok || got != tt.want {
				t.Fatalf("normalizePromptGuardRemoteHost(%q) = (%q, %v), want (%q, %v)", tt.in, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestResolvePromptGuardScopeID(t *testing.T) {
	t.Parallel()
	newRequest := func(remoteAddr, userAgent string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "http://proxy.invalid/v1/messages", nil)
		r.RemoteAddr = remoteAddr
		r.Header.Set("User-Agent", userAgent)
		return r
	}

	t.Run("explicit identity wins byte for byte", func(t *testing.T) {
		r := newRequest("malformed", "")
		const explicit = "client-session/with spaces"
		if got := resolvePromptGuardScopeID(r, explicit, "lane:one", "anthropic"); got != explicit {
			t.Fatalf("scope = %q, want explicit identity %q", got, explicit)
		}
	})

	t.Run("same host survives reconnect source-port changes", func(t *testing.T) {
		r1 := newRequest("192.0.2.10:1001", "client/1")
		r2 := newRequest("192.0.2.10:2002", "client/1")
		got1 := resolvePromptGuardScopeID(r1, "", "lane:one", "openai")
		got2 := resolvePromptGuardScopeID(r2, "", "lane:one", "openai")
		if got1 == "" || got1 != got2 {
			t.Fatalf("scopes = %q and %q, want one stable scope", got1, got2)
		}
		if strings.Contains(got1, "192.0.2.10") || strings.Contains(got1, "client/1") {
			t.Fatalf("scope exposes a raw dimension: %q", got1)
		}
	})

	t.Run("identity dimensions stay isolated", func(t *testing.T) {
		base := newRequest("192.0.2.10:1001", "client/1")
		want := resolvePromptGuardScopeID(base, "", "lane:one", "openai")
		cases := []struct {
			name string
			edit func(*http.Request) (string, string, string, string)
		}{
			{name: "upstream lane", edit: func(r *http.Request) (string, string, string, string) {
				return r.RemoteAddr, r.UserAgent(), "lane:two", "openai"
			}},
			{name: "provider", edit: func(r *http.Request) (string, string, string, string) {
				return r.RemoteAddr, r.UserAgent(), "lane:one", "anthropic"
			}},
			{name: "user agent", edit: func(r *http.Request) (string, string, string, string) {
				r.Header.Set("User-Agent", "client/2")
				return r.RemoteAddr, r.UserAgent(), "lane:one", "openai"
			}},
			{name: "remote host", edit: func(r *http.Request) (string, string, string, string) {
				r.RemoteAddr = "2001:db8::10:1001" // invalid until bracketed
				return "[2001:db8::10]:1001", r.UserAgent(), "lane:one", "openai"
			}},
		}
		for _, tt := range cases {
			t.Run(tt.name, func(t *testing.T) {
				r := base.Clone(base.Context())
				remote, userAgent, lane, provider := tt.edit(r)
				r.RemoteAddr = remote
				r.Header.Set("User-Agent", userAgent)
				got := resolvePromptGuardScopeID(r, "", lane, provider)
				if got == "" || got == want {
					t.Fatalf("scope = %q, want a distinct non-empty scope from %q", got, want)
				}
			})
		}
	})

	t.Run("invalid request metadata fails closed", func(t *testing.T) {
		cases := []struct {
			name string
			addr string
			ua   string
		}{
			{name: "missing address", addr: "", ua: "client/1"},
			{name: "malformed address", addr: "192.0.2.10", ua: "client/1"},
			{name: "missing user agent", addr: "192.0.2.10:1001"},
		}
		for _, tt := range cases {
			t.Run(tt.name, func(t *testing.T) {
				r := newRequest(tt.addr, tt.ua)
				if got := resolvePromptGuardScopeID(r, "", "lane:one", "openai"); got != "" {
					t.Fatalf("scope = %q, want empty fail-closed scope", got)
				}
			})
		}
	})
}

// promptScopeGuard is a small two-phase guard double that models ask-once
// state by the scope it receives. It lets the proxy integration test prove
// that reconnects confirm the same prompt scope without making the fallback
// identity part of API-turn attribution.
type promptScopeGuard struct {
	mu       sync.Mutex
	seen     map[string]bool
	prompts  []string
	after    []string
	denyOnce bool
}

func (g *promptScopeGuard) ScanRequest(context.Context, string, []byte, string) GuardRequestResult {
	return GuardRequestResult{}
}

func (g *promptScopeGuard) ScanPrompt(_ context.Context, _ string, _ []byte, sessionID string) GuardRequestResult {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.prompts = append(g.prompts, sessionID)
	if g.denyOnce && !g.seen[sessionID] {
		g.seen[sessionID] = true
		return GuardRequestResult{
			Action: "prompt_deny",
			RuleID: "R-172",
			Reason: "observer: confirmation required",
			Status: http.StatusBadRequest,
		}
	}
	return GuardRequestResult{}
}

func (g *promptScopeGuard) ScanRequestAfterPrompt(_ context.Context, _ string, _ []byte, sessionID string) GuardRequestResult {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.after = append(g.after, sessionID)
	return GuardRequestResult{}
}

func (g *promptScopeGuard) InspectResponse(context.Context, string, int64, []GuardToolUse) {}

func (g *promptScopeGuard) snapshot() (prompts, after []string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.prompts...), append([]string(nil), g.after...)
}

func TestProxyPromptGuardFallbackKeepsAttributionEmpty(t *testing.T) {
	const requestBody = `{"model":"claude-sonnet-4","messages":[{"role":"user","content":"hello"}]}`
	const responseBody = `{"id":"msg_scope","model":"claude-sonnet-4","stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`

	var upstreamMu sync.Mutex
	var upstreamHits int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Session-Id"); got != "" {
			t.Errorf("synthetic scope leaked to upstream X-Session-Id: %q", got)
		}
		_, _ = io.Copy(io.Discard, r.Body)
		upstreamMu.Lock()
		upstreamHits++
		upstreamMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(responseBody))
	}))
	defer upstream.Close()

	guard := &promptScopeGuard{seen: make(map[string]bool), denyOnce: true}
	sink := &fakeSink{}
	p, err := New(Options{
		AnthropicUpstream: upstream.URL,
		OpenAIUpstream:    upstream.URL,
		Upstreams:         map[string]string{"lane-one": upstream.URL},
		Sink:              sink,
		Guard:             guard,
	})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	proxyServer := httptest.NewServer(p.Handler())
	defer proxyServer.Close()

	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	defer client.CloseIdleConnections()
	post := func(path string) {
		req, err := http.NewRequest(http.MethodPost, proxyServer.URL+path, strings.NewReader(requestBody))
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "sessionless-client/1")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("proxy request %s: %v", path, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}

	// The first request on each lane is interrupted; a reconnect from the
	// same host with a different source port confirms the same ask-once scope.
	post("/v1/messages")
	post("/v1/messages")
	post("/up/lane-one/v1/messages")
	post("/up/lane-one/v1/messages")

	prompts, after := guard.snapshot()
	if len(prompts) != 4 || len(after) != 2 {
		t.Fatalf("phase calls = prompts %d, after %d; want 4 and 2", len(prompts), len(after))
	}
	if prompts[0] == "" || prompts[0] != prompts[1] {
		t.Fatalf("direct reconnect scopes = %q and %q, want stable non-empty scope", prompts[0], prompts[1])
	}
	if prompts[2] == "" || prompts[2] != prompts[3] || prompts[2] == prompts[0] {
		t.Fatalf("lane scopes = %q and %q, want stable scope isolated from direct lane %q", prompts[2], prompts[3], prompts[0])
	}
	if after[0] != "" || after[1] != "" {
		t.Fatalf("phase-2 scopes = %q, want empty real IDs for session-less requests", after)
	}

	upstreamMu.Lock()
	if upstreamHits != 2 {
		t.Errorf("upstream hits = %d, want 2 confirmed requests", upstreamHits)
	}
	upstreamMu.Unlock()
	turns := sink.all()
	if len(turns) != 4 {
		t.Fatalf("api turns = %d, want one row per request", len(turns))
	}
	for i, turn := range turns {
		if turn.SessionID != "" {
			t.Errorf("turn %d SessionID = %q, want empty real attribution for session-less client", i, turn.SessionID)
		}
	}
}

func TestPromptGuardUpstreamIDSeparatesFixedAndNamedLanes(t *testing.T) {
	t.Parallel()
	if got := promptGuardUpstreamID("", "openai"); got != "provider:openai" {
		t.Fatalf("fixed upstream id = %q, want provider:openai", got)
	}
	if got := promptGuardUpstreamID("openai", "openai"); got != "lane:openai" {
		t.Fatalf("named upstream id = %q, want lane:openai", got)
	}
	if got := promptGuardUpstreamID("", ""); got != "" {
		t.Fatalf("empty upstream id = %q, want empty", got)
	}
}

var (
	_ GuardScanner       = (*promptScopeGuard)(nil)
	_ PromptPhaseScanner = (*promptScopeGuard)(nil)
)

package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// stripUpstreamPrefix is a test shorthand for resolveUpstreamPrefix's
// upstream and routing id (serve() reads the full result directly).
func (p *Proxy) stripUpstreamPrefix(r *http.Request) (*url.URL, string) {
	res := p.resolveUpstreamPrefix(r)
	return res.up, res.id
}

// newTestProxyWithUpstreams builds a proxy with the standard two fixed
// upstreams plus a map of explicit /up/<id>/ upstreams (Phase C).
func newTestProxyWithUpstreams(t *testing.T, anthropicHandler, openaiHandler http.Handler, upstreams map[string]string) (*Proxy, *fakeSink, func()) {
	t.Helper()
	anthUp := httptest.NewServer(anthropicHandler)
	oaiUp := httptest.NewServer(openaiHandler)
	sink := &fakeSink{}
	p, err := New(Options{
		AnthropicUpstream: anthUp.URL,
		OpenAIUpstream:    oaiUp.URL,
		Upstreams:         upstreams,
		Sink:              sink,
	})
	if err != nil {
		anthUp.Close()
		oaiUp.Close()
		t.Fatalf("proxy.New: %v", err)
	}
	return p, sink, func() {
		anthUp.Close()
		oaiUp.Close()
	}
}

func TestStripUpstreamPrefix(t *testing.T) {
	p, _, cleanup := newTestProxyWithUpstreams(t,
		http.NotFoundHandler(), http.NotFoundHandler(),
		map[string]string{"openrouter": "https://openrouter.ai/api"})
	defer cleanup()

	cases := []struct {
		name       string
		path       string
		wantHit    bool   // expect a non-nil upstream
		wantPath   string // r.URL.Path after stripping
		wantTarget string // upstream host when hit
	}{
		{"known id strips prefix, keeps /v1 path", "/up/openrouter/v1/chat/completions", true, "/v1/chat/completions", "openrouter.ai"},
		{"unknown id falls through", "/up/elsewhere/v1/chat/completions", false, "/up/elsewhere/v1/chat/completions", ""},
		{"no prefix untouched", "/v1/chat/completions", false, "/v1/chat/completions", ""},
		{"prefix with no trailing segment", "/up/openrouter", false, "/up/openrouter", ""},
		{"empty id", "/up//v1", false, "/up//v1", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, tc.path, nil)
			up, _ := p.stripUpstreamPrefix(r)
			if (up != nil) != tc.wantHit {
				t.Fatalf("stripUpstreamPrefix hit=%v, want %v", up != nil, tc.wantHit)
			}
			if r.URL.Path != tc.wantPath {
				t.Errorf("r.URL.Path = %q, want %q", r.URL.Path, tc.wantPath)
			}
			if tc.wantHit && up.Host != tc.wantTarget {
				t.Errorf("upstream host = %q, want %q", up.Host, tc.wantTarget)
			}
		})
	}
}

// TestStripUpstreamPrefix_NoUpstreamsConfigured: with no [proxy.upstreams], a
// /up/ path resolves nothing and is left untouched; serve() then REFUSES it
// instead of forwarding it to a fixed upstream (Sol A5-02).
func TestStripUpstreamPrefix_NoUpstreamsConfigured(t *testing.T) {
	p, _, cleanup := newTestProxy(t, http.NotFoundHandler(), http.NotFoundHandler())
	defer cleanup()
	r := httptest.NewRequest(http.MethodPost, "/up/openrouter/v1/chat/completions", nil)
	if up, _ := p.stripUpstreamPrefix(r); up != nil {
		t.Errorf("expected nil upstream with no config, got %v", up)
	}
	if r.URL.Path != "/up/openrouter/v1/chat/completions" {
		t.Errorf("path mutated despite no config: %q", r.URL.Path)
	}
}

// TestProxy_ExplicitUpstreamRoutesAndForwardsCanonicalPath is the
// end-to-end Phase C check, using the REAL OpenRouter shape
// (/up/openrouter/api/v1/chat/completions, upstream host root): the request
// reaches the mapped upstream at /api/v1/chat/completions, the default OpenAI
// upstream is NOT hit, AND the turn is captured as OpenAI with tokens. The
// `/api/v1` (no leading /v1) path is the regression guard for the live-hermes
// bug where provider detection missed it and the turn was dropped as empty.
func TestProxy_ExplicitUpstreamRoutesAndForwardsCanonicalPath(t *testing.T) {
	const responseBody = `{"id":"x","model":"some-model","choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":4,"completion_tokens":2}}`

	var gotPath string
	openrouter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(responseBody))
	}))
	defer openrouter.Close()

	anth := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("anthropic upstream unexpectedly hit: %s", r.URL.Path)
	})
	oai := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("default openai upstream unexpectedly hit: %s", r.URL.Path)
	})

	p, sink, cleanup := newTestProxyWithUpstreams(t, anth, oai, map[string]string{"openrouter": openrouter.URL})
	defer cleanup()
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/up/openrouter/api/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"some-model","messages":[{"role":"user","content":"hi"}],"stream":false}`))
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status: got %d want 200", resp.StatusCode)
	}
	if gotPath != "/api/v1/chat/completions" {
		t.Errorf("upstream received path %q, want /api/v1/chat/completions", gotPath)
	}
	turns := sink.all()
	if len(turns) != 1 {
		t.Fatalf("want 1 turn, got %d", len(turns))
	}
	// OpenAI-shaped traffic on a non-/v1 path (OpenRouter's /api/v1) is still
	// detected as OpenAI and CAPTURED with tokens — the regression guard.
	if turns[0].Provider != models.ProviderOpenAI {
		t.Errorf("provider = %s, want openai", turns[0].Provider)
	}
	if turns[0].InputTokens != 4 || turns[0].OutputTokens != 2 {
		t.Errorf("tokens in=%d out=%d, want 4/2 (turn must be captured, not dropped)", turns[0].InputTokens, turns[0].OutputTokens)
	}
}

// TestNewRejectsBadUpstreamURL pins that a malformed [proxy.upstreams]
// value fails fast at construction (not silently at request time).
func TestNewRejectsBadUpstreamURL(t *testing.T) {
	_, err := New(Options{
		AnthropicUpstream: "https://api.anthropic.com",
		OpenAIUpstream:    "https://api.openai.com",
		Upstreams:         map[string]string{"bad": "://nope"},
		Sink:              &fakeSink{},
	})
	if err == nil {
		t.Fatal("expected error for malformed upstream URL")
	}
}

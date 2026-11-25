//go:build !sbo_omit_capture_proxy

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/proxy"
)

// TestProviderOverrideRules: one case per row of providerOverrideRules.
func TestProviderOverrideRules(t *testing.T) {
	cases := []struct {
		name  string
		state providerOverrideState
		want  providerOverrideAction
	}{
		{"no proxy path", providerOverrideState{covered: false, hasEntry: false}, providerOverrideSkip},
		{"ours already there", providerOverrideState{covered: true, hasEntry: true, sameAsOurs: true}, providerOverrideWrite},
		{"operator's own entry", providerOverrideState{covered: true, hasEntry: true}, providerOverrideKeep},
		{"write", providerOverrideState{covered: true}, providerOverrideWrite},
	}
	if len(cases) != len(providerOverrideRules) {
		t.Fatalf("%d cases for %d rules", len(cases), len(providerOverrideRules))
	}
	for _, c := range cases {
		if got := decideProviderOverride(c.state); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// TestPrepareProviderOverridesWritesAndRestores: covered providers without an
// entry are pointed at the proxy, the operator's own entries and unrelated
// keys survive, the notice names the kept / uncovered / custom providers,
// and restore puts the file back byte-for-byte in content.
func TestPrepareProviderOverridesWritesAndRestores(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "models.json")
	orig := map[string]any{
		"providers": map[string]any{
			"anthropic": map[string]any{"baseUrl": "https://my-own-gateway.example"},
			"baseten":   map[string]any{"baseUrl": "https://inference.baseten.example/v1", "api": "openai-completions"},
			"local":     map[string]any{"baseUrl": "http://127.0.0.1:11434/v1"},
		},
		"other": true,
	}
	ovWriteJSON(t, path, orig)
	spec := providerOverridesSpec{
		tool: "pi", path: path, display: "~/.pi/agent/models.json",
		proxyRoot: "http://127.0.0.1:8820", ownName: "observer",
		overrides: integration.ProviderOverridesFor("pi"),
	}
	route, err := prepareProviderOverrides(spec)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	got := ovReadJSON(t, path)
	providers := got["providers"].(map[string]any)
	if b := providers["openai"].(map[string]any)["baseUrl"]; b != "http://127.0.0.1:8820/v1" {
		t.Errorf("openai baseUrl = %v", b)
	}
	if b := providers["openrouter"].(map[string]any)["baseUrl"]; b != "http://127.0.0.1:8820/up/openrouter/api/v1" {
		t.Errorf("openrouter baseUrl = %v", b)
	}
	if b := providers["anthropic"].(map[string]any)["baseUrl"]; b != "https://my-own-gateway.example" {
		t.Errorf("operator's anthropic entry overwritten: %v", b)
	}
	if _, ok := providers["amazon-bedrock"]; ok {
		t.Error("uncovered provider written")
	}
	for name, raw := range providers {
		if e, ok := raw.(map[string]any); ok {
			if _, hasKey := e["apiKey"]; hasKey && name != "baseten" {
				t.Errorf("%s: override carries an apiKey", name)
			}
		}
	}
	n := route.notice("pi")
	for _, want := range []string{"managed node", "anthropic", "amazon-bedrock", "baseten"} {
		if !strings.Contains(n, want) {
			t.Errorf("notice %q lacks %q", n, want)
		}
	}
	if strings.Contains(n, "local") || strings.Contains(n, "127.0.0.1") {
		t.Errorf("notice %q names a loopback provider or a URL", n)
	}
	if err := route.restore(); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if after := ovReadJSON(t, path); !sameJSON(after, orig) {
		t.Fatalf("restore left %v, want %v", after, orig)
	}
}

// TestPrepareProviderOverridesRestoreIsCompareAndSwap: an entry the operator
// edited during the session stays; a file the launch created is removed.
func TestPrepareProviderOverridesRestoreIsCompareAndSwap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "models.json")
	spec := testProviderOverridesSpec(path)
	route, err := prepareProviderOverrides(spec)
	if err != nil || route.restore == nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := route.restore(); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("a file the launch created must be removed, stat err = %v", err)
	}

	route, err = prepareProviderOverrides(spec)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	edited := ovReadJSON(t, path)
	edited["providers"].(map[string]any)["openai"] = map[string]any{"baseUrl": "https://edited.example/v1"}
	ovWriteJSON(t, path, edited)
	if err := route.restore(); err != nil {
		t.Fatalf("restore: %v", err)
	}
	after := ovReadJSON(t, path)
	ps := after["providers"].(map[string]any)
	if len(ps) != 1 || ps["openai"].(map[string]any)["baseUrl"] != "https://edited.example/v1" {
		t.Fatalf("restore after an edit left %v", ps)
	}
}

// TestApplyManagedProviderOverridesOnlyOnManagedNodes: an individual node
// writes nothing, and neither does a managed node whose proxy is not
// answering (lane launcher-proxy-down: never point every built-in provider at
// a dead proxy lane).
func TestApplyManagedProviderOverridesOnlyOnManagedNodes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "models.json")
	spec := testProviderOverridesSpec(path)
	prevUp := providerOverridesProxyUp
	t.Cleanup(func() { providerOverridesProxyUp = prevUp })
	for _, tc := range []struct{ managed, proxyUp, write bool }{
		{managed: false, proxyUp: true, write: false},
		{managed: true, proxyUp: true, write: true},
		{managed: true, proxyUp: false, write: false},
	} {
		prev := launcherManagedNode
		launcherManagedNode = func(context.Context, string) bool { return tc.managed }
		providerOverridesProxyUp = func(context.Context, string, providerOverridesSpec, io.Writer) bool { return tc.proxyUp }
		var stderr bytes.Buffer
		restore, err := applyManagedProviderOverrides(context.Background(), "", spec, &stderr)
		launcherManagedNode = prev
		if err != nil {
			t.Fatalf("%+v: %v", tc, err)
		}
		_, statErr := os.Stat(path)
		if tc.write != (statErr == nil) || tc.write != (restore != nil) {
			t.Fatalf("%+v: file written=%v restore=%v", tc, statErr == nil, restore != nil)
		}
		if restore != nil {
			restore()
		}
	}
}

// TestProviderOverridesReachTheirUpstreamThroughTheProxy is the T-035 route
// proof: for every covered built-in provider of pi and Prime Agent, the
// request the tool sends to its overridden base URL (the endpoint each API
// appends, grounded against pi 0.74.2 and prime-agent 0.9.8 with a local
// mock) goes through the real proxy, built with this daemon's agent lanes,
// to that provider's own upstream at the vendor path. Upstreams are local
// mocks: one per fixed upstream and one per lane.
func TestProviderOverridesReachTheirUpstreamThroughTheProxy(t *testing.T) {
	var mu sync.Mutex
	hits := map[string][]string{}
	mock := func(name string) *httptest.Server {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			hits[name] = append(hits[name], r.URL.Path)
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{}`))
		}))
		t.Cleanup(s.Close)
		return s
	}
	agent := map[string]string{}
	for id := range effectiveAgentUpstreams(config.Default()) {
		agent[id] = mock("lane:" + id).URL
	}
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	t.Cleanup(client.CloseIdleConnections)
	p, err := proxy.New(proxy.Options{
		AnthropicUpstream: mock("fixed:anthropic").URL,
		OpenAIUpstream:    mock("fixed:openai").URL,
		GeminiUpstream:    mock("fixed:gemini").URL,
		AgentUpstreams:    agent,
		PrewarmTargets:    []string{},
		Client:            client,
		Sink:              &guardwireAPITurnSink{},
	})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	front := httptest.NewServer(p.Handler())
	t.Cleanup(front.Close)

	endpoint := map[string]string{
		"anthropic-messages":   "/v1/messages",
		"openai-responses":     "/responses",
		"openai-completions":   "/chat/completions",
		"google-generative-ai": "/models/m:streamGenerateContent",
	}
	fixed := map[string]string{"anthropic-messages": "fixed:anthropic", "openai-responses": "fixed:openai", "google-generative-ai": "fixed:gemini"}
	seen := map[string]bool{}
	for _, tool := range []string{"pi", "prime-agent"} {
		for _, o := range integration.ProviderOverridesFor(tool) {
			if !o.Covered() || seen[o.Provider] {
				continue
			}
			seen[o.Provider] = true
			ep, ok := endpoint[o.API]
			if !ok {
				t.Errorf("%s: covered provider speaks %q, which this proof has no endpoint for", o.Provider, o.API)
				continue
			}
			want, wantPath := fixed[o.API], o.Path+ep
			if o.Lane != nil {
				want, wantPath = "lane:"+o.Lane.ID, strings.TrimPrefix(o.Path, "/up/"+o.Lane.ID)+ep
			}
			mu.Lock()
			before := len(hits[want])
			mu.Unlock()
			body, _ := json.Marshal(map[string]any{"model": "m", "messages": []any{map[string]any{"role": "user", "content": "hi"}}})
			resp, err := client.Post(front.URL+o.Path+ep, "application/json", bytes.NewReader(body))
			if err != nil {
				t.Errorf("%s: post: %v", o.Provider, err)
				continue
			}
			resp.Body.Close()
			mu.Lock()
			got := hits[want]
			mu.Unlock()
			if resp.StatusCode != http.StatusOK || len(got) != before+1 || got[len(got)-1] != wantPath {
				t.Errorf("%s: status %d, %s saw %v, want one more hit at %q", o.Provider, resp.StatusCode, want, got, wantPath)
			}
		}
	}
	if len(seen) < 20 {
		t.Fatalf("only %d covered providers proven", len(seen))
	}
}

func ovWriteJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func ovReadJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]any{}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func testProviderOverridesSpec(path string) providerOverridesSpec {
	return providerOverridesSpec{
		tool:      "pi",
		path:      path,
		display:   "m",
		proxyRoot: "http://127.0.0.1:8820",
		ownName:   "observer",
		overrides: integration.ProviderOverridesFor("pi"),
	}
}

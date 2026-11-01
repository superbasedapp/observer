package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

const (
	ciSentinel = "obsbx-sentinel-v1-anthropic-AAAA"
	ciRealKey  = "sk-ant-REAL-KEY-never-logged-0123456789"
	ciToken    = "relay-token-1"
)

// ciInjector injects ciRealKey for ciSentinel on the run with ciToken, and
// records what it was asked.
type ciInjector struct {
	host string
	mu   sync.Mutex
	seen []CredentialRequest
}

func (c *ciInjector) Inject(_ context.Context, in CredentialRequest) (string, string, bool) {
	c.mu.Lock()
	c.seen = append(c.seen, in)
	c.mu.Unlock()
	if in.RunID == "run1" && in.Token == ciToken && in.XAPIKey == ciSentinel && in.Host == c.host {
		return "X-Api-Key", ciRealKey, true
	}
	return "", "", false
}

// ciRun sends one relayed request through a proxy and returns the headers
// the upstream saw, the sink and the log.
func ciRun(t *testing.T, inj func(host string) CredentialInjector, edit func(*http.Request)) (http.Header, *fakeSink, string) {
	t.Helper()
	var seen http.Header
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"m1","model":"claude-sonnet-4","usage":{"input_tokens":3,"output_tokens":2}}`)
	}))
	defer up.Close()
	var logs bytes.Buffer
	sink := &fakeSink{}
	p, err := New(Options{AnthropicUpstream: up.URL, OpenAIUpstream: up.URL, Sink: sink, Logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(up.URL)
	if inj != nil {
		SetCredentialInjector(inj(u.Hostname()))
	}
	defer SetCredentialInjector(nil)
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/messages", strings.NewReader(`{"model":"claude-sonnet-4","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", ciSentinel)
	req.Header.Set(sandboxvocab.RelayRunHeader, "run1")
	req.Header.Set(SandboxCredTokenHeader, ciToken)
	if edit != nil {
		edit(req)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if strings.Contains(string(b), ciRealKey) {
		t.Fatal("the real key was echoed back to the box")
	}
	return seen, sink, logs.String()
}

// TestCredInjectNilGolden: with no injector the request goes upstream as
// before (the presented credential and every other header unchanged),
// except the relay token, which never leaves for a provider (audit F6).
func TestCredInjectNilGolden(t *testing.T) {
	seen, _, _ := ciRun(t, nil, nil)
	if seen.Get("X-Api-Key") != ciSentinel || seen.Get(sandboxvocab.RelayRunHeader) != "" {
		t.Fatalf("nil injector changed the request: %v", seen)
	}
	if seen.Get(SandboxCredTokenHeader) != "" {
		t.Fatal("the relay token went upstream with no injector installed")
	}
}

// TestCredTokenNeverOnThePassthrough (audit F6): an upgrade request takes
// the passthrough Rewrite, which drops the relay token as the main path
// does, with or without an injector.
func TestCredTokenNeverOnThePassthrough(t *testing.T) {
	for _, withInjector := range []bool{false, true} {
		var seen http.Header
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seen = r.Header.Clone()
			w.WriteHeader(http.StatusOK)
		}))
		p, err := New(Options{AnthropicUpstream: up.URL, OpenAIUpstream: up.URL, Sink: &fakeSink{}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
		if err != nil {
			t.Fatal(err)
		}
		if withInjector {
			SetCredentialInjector(&ciInjector{})
		}
		ts := httptest.NewServer(p.Handler())
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/chat/completions", nil)
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set(sandboxvocab.RelayRunHeader, "run1")
		req.Header.Set(SandboxCredTokenHeader, ciToken)
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()
		}
		ts.Close()
		up.Close()
		SetCredentialInjector(nil)
		if seen == nil {
			t.Fatalf("injector=%v: the upgrade request never reached the upstream (%v)", withInjector, err)
		}
		if seen.Get(SandboxCredTokenHeader) != "" || seen.Get(sandboxvocab.RelayRunHeader) != "" {
			t.Fatalf("injector=%v: the relay headers went upstream on the passthrough: %v", withInjector, seen)
		}
	}
}

// TestCredInjectSwaps: the injector's key replaces the sentinel, the relay
// token never goes upstream, and the key is in neither the log nor the
// api_turns rows.
func TestCredInjectSwaps(t *testing.T) {
	inj := &ciInjector{}
	seen, sink, logs := ciRun(t, func(h string) CredentialInjector { inj.host = h; return inj }, nil)
	if seen.Get("X-Api-Key") != ciRealKey {
		t.Fatalf("upstream saw %q, want the real key", seen.Get("X-Api-Key"))
	}
	if seen.Get(SandboxCredTokenHeader) != "" || seen.Get(sandboxvocab.RelayRunHeader) != "" {
		t.Fatal("the relay headers went upstream")
	}
	if strings.Contains(logs, ciRealKey) {
		t.Fatal("the real key is in the proxy log")
	}
	rows, _ := json.Marshal(sink.all())
	if strings.Contains(string(rows), ciRealKey) || len(sink.all()) == 0 {
		t.Fatalf("api_turns: %d rows, key present=%v", len(sink.all()), strings.Contains(string(rows), ciRealKey))
	}
	if len(inj.seen) != 1 || inj.seen[0].Host == "" {
		t.Fatalf("injector asked %+v", inj.seen)
	}
}

// TestCredInjectRefusalsLeaveTheRequest: a refused match leaves the
// sentinel in place (the provider answers its own 401) and still strips
// the relay token.
func TestCredInjectRefusalsLeaveTheRequest(t *testing.T) {
	cases := map[string]func(*http.Request){
		"box-forged token":  func(r *http.Request) { r.Header.Set(SandboxCredTokenHeader, "forged") },
		"no run header":     func(r *http.Request) { r.Header.Del(sandboxvocab.RelayRunHeader) },
		"another sentinel":  func(r *http.Request) { r.Header.Set("X-Api-Key", "obsbx-sentinel-v1-anthropic-BBBB") },
		"wrong auth form":   func(r *http.Request) { r.Header.Del("X-Api-Key"); r.Header.Set("Authorization", "Bearer "+ciSentinel) },
		"no relay token at": func(r *http.Request) { r.Header.Del(SandboxCredTokenHeader) },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			inj := &ciInjector{}
			seen, _, _ := ciRun(t, func(h string) CredentialInjector { inj.host = h; return inj }, edit)
			if strings.Contains(seen.Get("X-Api-Key")+seen.Get("Authorization"), ciRealKey) {
				t.Fatal("a refused request got the real key")
			}
			if seen.Get(SandboxCredTokenHeader) != "" {
				t.Fatal("the relay token went upstream")
			}
		})
	}
}

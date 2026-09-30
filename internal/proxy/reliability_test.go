package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// scriptedUpstream replies with the scripted status sequence (last
// entry repeats), capturing each request's body.
type scriptedUpstream struct {
	mu       sync.Mutex
	statuses []int
	hits     int
	bodies   []string
}

func (su *scriptedUpstream) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		su.mu.Lock()
		su.bodies = append(su.bodies, string(b))
		idx := su.hits
		su.hits++
		if idx >= len(su.statuses) {
			idx = len(su.statuses) - 1
		}
		status := su.statuses[idx]
		su.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if status == 503 {
			w.Header().Set("Retry-After", "0")
		}
		w.WriteHeader(status)
		if status == 200 {
			_, _ = w.Write([]byte(routerRespBody))
		} else {
			_, _ = w.Write([]byte(`{"type":"error","error":{"type":"overloaded_error","message":"try later"}}`))
		}
	})
}

func (su *scriptedUpstream) snapshot() (int, []string) {
	su.mu.Lock()
	defer su.mu.Unlock()
	return su.hits, append([]string{}, su.bodies...)
}

// reliabilityProxy wires a proxy with retries + an optional router
// chain against the scripted upstream.
func reliabilityProxy(t *testing.T, su *scriptedUpstream, rel ReliabilityOptions, router ModelRouter) (*httptest.Server, *fakeSink, func()) {
	t.Helper()
	up := httptest.NewServer(su.handler())
	sink := &fakeSink{}
	p, err := New(Options{
		AnthropicUpstream: up.URL,
		OpenAIUpstream:    up.URL,
		Sink:              sink,
		Reliability:       rel,
		ModelRouter:       router,
	})
	if err != nil {
		up.Close()
		t.Fatalf("proxy.New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	return ts, sink, func() { ts.Close(); up.Close() }
}

// Test529RetriedThenSucceeds pins §R12.2: a 529 overloaded retries on
// the same target within the budget and the client sees the eventual
// 200.
func Test529RetriedThenSucceeds(t *testing.T) {
	su := &scriptedUpstream{statuses: []int{529, 200}}
	ts, _, cleanup := reliabilityProxy(t, su,
		ReliabilityOptions{MaxRetries: 2, RetryOverloaded: true}, nil)
	defer cleanup()
	resp := postRouterRequest(t, ts, "sk-ant-key")
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200 after retry", resp.StatusCode)
	}
	if hits, _ := su.snapshot(); hits != 2 {
		t.Errorf("upstream hits = %d, want 2", hits)
	}
}

// Test529NotRetriedWhenDisabled pins the per-class toggle.
func Test529NotRetriedWhenDisabled(t *testing.T) {
	su := &scriptedUpstream{statuses: []int{529, 200}}
	ts, _, cleanup := reliabilityProxy(t, su,
		ReliabilityOptions{MaxRetries: 2, RetryOverloaded: false}, nil)
	defer cleanup()
	resp := postRouterRequest(t, ts, "sk-ant-key")
	defer resp.Body.Close()
	if resp.StatusCode != 529 {
		t.Fatalf("status = %d, want the 529 surfaced (class disabled)", resp.StatusCode)
	}
	if hits, _ := su.snapshot(); hits != 1 {
		t.Errorf("upstream hits = %d, want 1", hits)
	}
}

// Test503RetryAfterRequired pins §R12.2: 503 retries only WITH a
// Retry-After header (the scripted upstream sets it on every 503).
func Test503RetryAfterRequired(t *testing.T) {
	su := &scriptedUpstream{statuses: []int{503, 200}}
	ts, _, cleanup := reliabilityProxy(t, su,
		ReliabilityOptions{MaxRetries: 1, RetryUnavailable: true}, nil)
	defer cleanup()
	resp := postRouterRequest(t, ts, "sk-ant-key")
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200 (503 with Retry-After retried)", resp.StatusCode)
	}
}

// TestFallbackChainOn429 pins §R12.1: a rate-limited turn re-forwards
// against the chain's next same-shape entry; the served model lands on
// api_turns; RecordServed reports it for row annotation.
func TestFallbackChainOn429(t *testing.T) {
	su := &scriptedUpstream{statuses: []int{429, 200}}
	fr := &fakeRouter{verdict: RouterVerdict{
		FallbackModels: []string{"claude-sonnet-4-6"}, Token: 11,
	}}
	ts, sink, cleanup := reliabilityProxy(t, su, ReliabilityOptions{}, fr)
	defer cleanup()
	resp := postRouterRequest(t, ts, "sk-ant-key")
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200 via fallback", resp.StatusCode)
	}
	hits, bodies := su.snapshot()
	if hits != 2 {
		t.Fatalf("upstream hits = %d, want 2", hits)
	}
	if !strings.Contains(bodies[0], `"model":"claude-opus-4-8"`) {
		t.Errorf("first attempt body: %q", bodies[0])
	}
	if !strings.Contains(bodies[1], `"model":"claude-sonnet-4-6"`) {
		t.Errorf("fallback body: %q", bodies[1])
	}
	turns := sink.all()
	// The response body's model field wins on the turn row; the
	// scripted upstream echoes routerRespBody (haiku). What matters
	// here: the request-side served model was the fallback, so the
	// error path would have recorded it — assert via RecordServed.
	if len(turns) != 1 {
		t.Fatalf("turns = %d, want 1", len(turns))
	}
	served := waitServed(t, fr, 1)
	if served[0].token != 11 {
		t.Errorf("RecordServed = %+v", served[0])
	}
}

// TestFallbackChainExhausted pins the give-up path: every chain entry
// rate-limited → the final outcome surfaces to the client.
func TestFallbackChainExhausted(t *testing.T) {
	su := &scriptedUpstream{statuses: []int{429}}
	fr := &fakeRouter{verdict: RouterVerdict{
		FallbackModels: []string{"claude-sonnet-4-6", "claude-haiku-4-5"}, Token: 12,
	}}
	ts, _, cleanup := reliabilityProxy(t, su, ReliabilityOptions{}, fr)
	defer cleanup()
	resp := postRouterRequest(t, ts, "sk-ant-key")
	defer resp.Body.Close()
	if resp.StatusCode != 429 {
		t.Fatalf("status = %d, want the final 429 surfaced", resp.StatusCode)
	}
	if hits, _ := su.snapshot(); hits != 3 {
		t.Errorf("upstream hits = %d, want original + 2 fallbacks", hits)
	}
}

// TestHealthyUpstreamSingleHit pins that a configured chain costs
// nothing on the happy path.
func TestHealthyUpstreamSingleHit(t *testing.T) {
	su := &scriptedUpstream{statuses: []int{200}}
	fr := &fakeRouter{verdict: RouterVerdict{
		FallbackModels: []string{"claude-sonnet-4-6"}, Token: 13,
	}}
	ts, _, cleanup := reliabilityProxy(t, su,
		ReliabilityOptions{MaxRetries: 2, RetryOverloaded: true}, fr)
	defer cleanup()
	resp := postRouterRequest(t, ts, "sk-ant-key")
	defer resp.Body.Close()
	if hits, _ := su.snapshot(); hits != 1 {
		t.Errorf("upstream hits = %d, want 1 (no gratuitous retries)", hits)
	}
}

// TestLocalUpstreamOverride pins §R11.7 at the proxy: a request whose
// (routed) model is declared local forwards to the local endpoint, not
// the cloud upstream.
func TestLocalUpstreamOverride(t *testing.T) {
	var localHit, cloudHit bool
	localUp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		localHit = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"l1","model":"ollama/llama4","choices":[{"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":2}}`))
	}))
	defer localUp.Close()
	cloudUp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cloudHit = true
		w.WriteHeader(500)
	}))
	defer cloudUp.Close()

	sink := &fakeSink{}
	p, err := New(Options{
		AnthropicUpstream: cloudUp.URL,
		OpenAIUpstream:    cloudUp.URL,
		Sink:              sink,
		LocalUpstreams:    map[string]string{"ollama/llama4": localUp.URL},
	})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	body := `{"model":"ollama/llama4","messages":[{"role":"user","content":"hi"}]}`
	req, _ := http.NewRequest("POST", ts.URL+"/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200 from the local endpoint", resp.StatusCode)
	}
	if !localHit || cloudHit {
		t.Errorf("local=%v cloud=%v, want local only", localHit, cloudHit)
	}
}

// TestKeyPoolRotationOn429 pins §R12.4: a rate-limited API-key request
// retries with the pool's next key; the upstream sees both keys; an
// OAuth request is never rotated.
func TestKeyPoolRotationOn429(t *testing.T) {
	var keysSeen []string
	var mu sync.Mutex
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		key := r.Header.Get("x-api-key")
		if key == "" {
			key = r.Header.Get("Authorization")
		}
		keysSeen = append(keysSeen, key)
		n := len(keysSeen)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			w.WriteHeader(429)
			_, _ = w.Write([]byte(`{"type":"error","error":{"type":"rate_limit_error"}}`))
			return
		}
		_, _ = w.Write([]byte(routerRespBody))
	}))
	defer up.Close()
	sink := &fakeSink{}
	p, err := New(Options{
		AnthropicUpstream: up.URL, OpenAIUpstream: up.URL, Sink: sink,
		KeyPools: map[string][]string{"anthropic": {"sk-ant-key-A", "sk-ant-key-B"}},
	})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	resp := postRouterRequest(t, ts, "sk-ant-key-A")
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200 after rotation", resp.StatusCode)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(keysSeen) != 2 || keysSeen[0] == keysSeen[1] {
		t.Errorf("keys seen = %v, want two distinct attempts", keysSeen)
	}
}

// TestKeyPoolNeverRotatesOAuth pins the credential-form guard: a
// subscription (OAuth) request rate-limited upstream is NOT retried
// with pool keys.
func TestKeyPoolNeverRotatesOAuth(t *testing.T) {
	su := &scriptedUpstream{statuses: []int{429}}
	up := httptest.NewServer(su.handler())
	defer up.Close()
	sink := &fakeSink{}
	p, err := New(Options{
		AnthropicUpstream: up.URL, OpenAIUpstream: up.URL, Sink: sink,
		KeyPools: map[string][]string{"anthropic": {"sk-ant-key-A", "sk-ant-key-B"}},
	})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	resp := postRouterRequest(t, ts, "Bearer sk-ant-oat01-token")
	defer resp.Body.Close()
	if resp.StatusCode != 429 {
		t.Fatalf("status = %d, want 429 surfaced (no rotation for OAuth)", resp.StatusCode)
	}
	if hits, _ := su.snapshot(); hits != 1 {
		t.Errorf("upstream hits = %d, want 1 (G7: OAuth untouched)", hits)
	}
}

// TestKeyPoolRotatesOnlyPoolMemberCredential is the SR27-B2 regression
// (security review 2026-09-27). Before the fix a caller that presented ANY
// x-api-key / Bearer sk- value - its own, deliberately rate-limited key - got
// the 429 retried on the operator's pool key, so anything that could reach the
// proxy could borrow the operator's credential. Now a non-member credential is
// never rotated: the 429 passes through and the upstream only ever sees the
// caller's own key.
func TestKeyPoolRotatesOnlyPoolMemberCredential(t *testing.T) {
	var keysSeen []string
	var mu sync.Mutex
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("x-api-key")
		mu.Lock()
		keysSeen = append(keysSeen, key)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if key == "sk-ant-outsider" {
			w.WriteHeader(429)
			_, _ = w.Write([]byte(`{"type":"error","error":{"type":"rate_limit_error"}}`))
			return
		}
		_, _ = w.Write([]byte(routerRespBody))
	}))
	defer up.Close()
	p, err := New(Options{
		AnthropicUpstream: up.URL, OpenAIUpstream: up.URL, Sink: &fakeSink{},
		KeyPools: map[string][]string{"anthropic": {"sk-ant-key-A", "sk-ant-key-B"}},
	})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	resp := postRouterRequest(t, ts, "sk-ant-outsider")
	defer resp.Body.Close()
	if resp.StatusCode != 429 {
		t.Fatalf("status = %d, want the outsider's 429 passed through (no operator key lent)", resp.StatusCode)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, k := range keysSeen {
		if k != "sk-ant-outsider" {
			t.Fatalf("upstream saw %q; an operator pool key was lent to a non-member credential (keys seen %v)", k, keysSeen)
		}
	}
}

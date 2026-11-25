package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHealthz_GET pins the W1.2 liveness probe's happy path: an
// unauthenticated GET /-/healthz returns 200, application/json, and the
// literal {"status":"ok"} body — and never reaches any configured
// upstream. The backend below fails the test if it's ever dialed, so a
// regression that routes healthz through the normal forwarding path (e.g.
// resolveUpstreamPrefix / upstreamForPath) is caught even if it happens to
// still return 200.
func TestHealthz_GET(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("upstream backend was hit for %s %s — /-/healthz must never forward", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer backend.Close()

	p, err := New(Options{
		AnthropicUpstream: backend.URL,
		OpenAIUpstream:    backend.URL,
		Sink:              &fakeSink{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + healthzPath)
	if err != nil {
		t.Fatalf("GET %s: %v", healthzPath, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if got, want := string(body), `{"status":"ok"}`; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}

// TestHealthz_HEAD pins the HEAD variant: 200, no body.
func TestHealthz_HEAD(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("upstream backend was hit for %s %s — /-/healthz must never forward", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer backend.Close()

	p, err := New(Options{
		AnthropicUpstream: backend.URL,
		OpenAIUpstream:    backend.URL,
		Sink:              &fakeSink{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	resp, err := http.Head(ts.URL + healthzPath)
	if err != nil {
		t.Fatalf("HEAD %s: %v", healthzPath, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if len(body) != 0 {
		t.Errorf("HEAD body = %q, want empty", body)
	}
}

// TestHealthz_MethodNotAllowed pins the 405 for any method other than
// GET/HEAD (e.g. a client mistakenly POSTing to the probe path).
func TestHealthz_MethodNotAllowed(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("upstream backend was hit for %s %s — /-/healthz must never forward", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer backend.Close()

	p, err := New(Options{
		AnthropicUpstream: backend.URL,
		OpenAIUpstream:    backend.URL,
		Sink:              &fakeSink{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+healthzPath, "application/json", nil)
	if err != nil {
		t.Fatalf("POST %s: %v", healthzPath, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

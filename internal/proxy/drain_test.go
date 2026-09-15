package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"
)

// drain_test.go covers the W3 drain seam of
// docs/plans/enterprise-update-management-plan-2026-09-07.md (§3.7 step 4a,
// rulings R9/R13).
//
// The rule being tested is NOT "is anything in flight right now?" — that is a
// sample, and it races the request that arrives during the restart window.
// It is: the proxy stops ADMITTING, answers a retryable 503 with Retry-After,
// and the in-flight requests that were already running complete. A client
// mid-apply must receive a retryable status and NEVER a ConnectionRefused,
// which is the failure CLAUDE.md's daemon-restart rule exists to prevent.

// fakeGate is a hand-rolled DrainGate so this package's test does not import
// internal/quiesce. The interface is the seam; the concrete gate lives on the
// other side of it, exactly as with Sink / Admitter / CostComputer.
type fakeGate struct {
	mu       sync.Mutex
	draining bool
	inFlight int
	maxSeen  int
}

func (g *fakeGate) Enter() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.draining {
		return false
	}
	g.inFlight++
	if g.inFlight > g.maxSeen {
		g.maxSeen = g.inFlight
	}
	return true
}

func (g *fakeGate) Leave() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.inFlight--
}

func (g *fakeGate) RetryAfterSeconds() int { return 12 }

func (g *fakeGate) setDraining(v bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.draining = v
}

func (g *fakeGate) live() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.inFlight
}

// TestDrainRefusesNewRequestsWithRetryAfter: while the gate is closed, a new
// proxied request gets 503 + Retry-After and the upstream is never dialled.
func TestDrainRefusesNewRequestsWithRetryAfter(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("upstream was dialled during a drain (%s)", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	gate := &fakeGate{}
	p, err := New(Options{
		AnthropicUpstream: backend.URL,
		OpenAIUpstream:    backend.URL,
		Sink:              &fakeSink{},
		DrainGate:         gate,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()

	gate.setDraining(true)

	for _, path := range []string{"/v1/messages", "/v1/chat/completions"} {
		resp, err := http.Post(srv.URL+path, "application/json", nil)
		if err != nil {
			t.Fatalf("POST %s: %v — a drained proxy must answer, never refuse the connection", path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("POST %s = %d, want 503", path, resp.StatusCode)
		}
		ra := resp.Header.Get("Retry-After")
		if ra == "" {
			t.Errorf("POST %s carried no Retry-After — a refusal without a hint is an outage, not a drain", path)
		}
		if n, err := strconv.Atoi(ra); err != nil || n != 12 {
			t.Errorf("POST %s Retry-After = %q, want the gate's own budget 12", path, ra)
		}
		// The body must be provider-shaped so a client SDK surfaces it as a
		// normal, retryable API error rather than a malformed response.
		var probe map[string]any
		if err := json.Unmarshal(body, &probe); err != nil {
			t.Errorf("POST %s body is not JSON: %v (%s)", path, err, body)
		}
		if len(probe) == 0 {
			t.Errorf("POST %s returned an empty body", path)
		}
	}
}

// TestHealthzStillAnswersWhileDraining: the liveness probe must never be
// gated. A supervisor that reads /healthz would otherwise restart the daemon
// in the middle of its own update.
func TestHealthzStillAnswersWhileDraining(t *testing.T) {
	gate := &fakeGate{}
	p, err := New(Options{AnthropicUpstream: "http://127.0.0.1:1", Sink: &fakeSink{}, DrainGate: gate})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()
	gate.setDraining(true)

	resp, err := http.Get(srv.URL + healthzPath)
	if err != nil {
		t.Fatalf("GET %s: %v", healthzPath, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s during a drain = %d, want 200", healthzPath, resp.StatusCode)
	}
	if gate.live() != 0 {
		t.Errorf("the liveness probe was counted as in-flight work (%d)", gate.live())
	}
}

// TestInFlightRequestIsCountedForTheWholeRequest: a request admitted before
// the drain opened must keep the counter above zero until it FINISHES, which
// is what makes "wait for in-flight to reach zero" mean anything.
func TestInFlightRequestIsCountedForTheWholeRequest(t *testing.T) {
	release := make(chan struct{})
	arrived := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(arrived)
		<-release
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer backend.Close()

	gate := &fakeGate{}
	p, err := New(Options{AnthropicUpstream: backend.URL, Sink: &fakeSink{}, DrainGate: gate})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		resp, err := http.Post(srv.URL+"/v1/messages", "application/json", nil)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
	}()

	select {
	case <-arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("the request never reached the upstream")
	}
	if got := gate.live(); got != 1 {
		t.Fatalf("in-flight during an upstream call = %d, want 1", got)
	}
	close(release)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the request never completed")
	}
	// Poll briefly: the decrement is a defer on the handler goroutine.
	deadline := time.Now().Add(2 * time.Second)
	for gate.live() != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := gate.live(); got != 0 {
		t.Fatalf("in-flight after the request finished = %d, want 0", got)
	}
}

// TestNilDrainGateChangesNothing: a daemon that never wired an updater must
// behave byte-identically to today.
func TestNilDrainGateChangesNothing(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer backend.Close()
	p, err := New(Options{AnthropicUpstream: backend.URL, Sink: &fakeSink{}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/v1/messages", "application/json", nil)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 with no gate wired", resp.StatusCode)
	}
}

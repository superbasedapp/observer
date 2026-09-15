package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// Luna L16 — the Gateway-Mode fallback-ladder RUNTIME executor
// (internal/proxy/gatewayfallback.go). These tests drive a real proxy with
// fake gateway/provider upstreams and assert the ordered walk + each terminal
// rung, plus the fleet-alert signal and credential custody on the
// direct-fallback path.

// statusUpstream is a fake upstream that always answers a fixed status code
// (with okChatCompletionBody as the body so response parsing is uniform) and
// records hit count + the last request's headers.
type statusUpstream struct {
	srv    *httptest.Server
	status int
	hits   atomic.Int64
	mu     sync.Mutex
	last   http.Header
}

func newStatusUpstream(t *testing.T, status int) *statusUpstream {
	t.Helper()
	su := &statusUpstream{status: status}
	su.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		su.hits.Add(1)
		su.mu.Lock()
		su.last = r.Header.Clone()
		su.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(su.status)
		_, _ = w.Write([]byte(okChatCompletionBody))
	}))
	t.Cleanup(su.srv.Close)
	return su
}

func (su *statusUpstream) count() int64 { return su.hits.Load() }

// recordingAlerter captures every GatewayLadderAlert for assertions.
type recordingAlerter struct {
	mu     sync.Mutex
	alerts []GatewayLadderAlert
}

func (a *recordingAlerter) GatewayLadderAlert(al GatewayLadderAlert) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.alerts = append(a.alerts, al)
}

func (a *recordingAlerter) snapshot() []GatewayLadderAlert {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]GatewayLadderAlert, len(a.alerts))
	copy(out, a.alerts)
	return out
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return string(b)
}

// TestGatewayLadder_PrimarySuccessNoWalk: a healthy primary means exactly one
// forward and no fallback endpoint is touched.
func TestGatewayLadder_PrimarySuccessNoWalk(t *testing.T) {
	primary := newCountingUpstream(t)
	fallback := newCountingUpstream(t)
	alerter := &recordingAlerter{}

	p := mustGatewayProxy(t, Options{
		OpenAIUpstream:      "https://api.openai.example",
		Sink:                &fakeSink{},
		VirtualKeySource:    &fakeVirtualKeySource{key: "sbo-vk", gen: 1},
		GatewayFleetAlerter: alerter,
	}, primary.srv.URL, nil, "", false)
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	resp := doPost(t, ts.URL+"/v1/chat/completions", `{"model":"m","messages":[{"role":"user","content":"hi"}]}`, nil)
	_ = readBody(t, resp)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if primary.count() != 1 || fallback.count() != 0 {
		t.Fatalf("primary=%d fallback=%d, want 1/0", primary.count(), fallback.count())
	}
	if len(alerter.snapshot()) != 0 {
		t.Fatalf("unexpected alerts: %+v", alerter.snapshot())
	}
}

// TestGatewayLadder_PrimaryFailsFallbackServes: a 5xx primary advances to the
// fallback endpoint, which serves — and the virtual key rides onto the
// fallback gateway (custody preserved across the ladder).
func TestGatewayLadder_PrimaryFailsFallbackServes(t *testing.T) {
	primary := newStatusUpstream(t, http.StatusServiceUnavailable)
	fallback := newCountingUpstream(t)
	alerter := &recordingAlerter{}

	p := mustGatewayProxy(t, Options{
		OpenAIUpstream:      "https://api.openai.example",
		Sink:                &fakeSink{},
		VirtualKeySource:    &fakeVirtualKeySource{key: "sbo-vk-fb", gen: 1},
		GatewayFleetAlerter: alerter,
	}, primary.srv.URL, []string{fallback.srv.URL}, "", false)
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	resp := doPost(t, ts.URL+"/v1/chat/completions", `{"model":"m","messages":[{"role":"user","content":"hi"}]}`, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer sk-dev")
	})
	_ = readBody(t, resp)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200 (fallback served)", resp.StatusCode)
	}
	if primary.count() < 1 || fallback.count() != 1 {
		t.Fatalf("primary=%d fallback=%d, want >=1 / 1", primary.count(), fallback.count())
	}
	if got := fallback.header("X-Api-Key"); got != "sbo-vk-fb" {
		t.Errorf("fallback gateway X-Api-Key = %q, want the virtual key", got)
	}
	if got := fallback.header("Authorization"); got != "" {
		t.Errorf("fallback gateway saw Authorization %q, want stripped", got)
	}
	if len(alerter.snapshot()) != 0 {
		t.Fatalf("fallback served — no alert expected, got %+v", alerter.snapshot())
	}
}

// TestGatewayLadder_TerminalHold: all endpoints fail with hold ⇒ a structured
// 503 (Retry-After + rung/remedy) and a queue-and-hold fleet alert.
func TestGatewayLadder_TerminalHold(t *testing.T) {
	primary := newStatusUpstream(t, http.StatusServiceUnavailable)
	fallback := newStatusUpstream(t, http.StatusBadGateway)
	alerter := &recordingAlerter{}

	p := mustGatewayProxy(t, Options{
		OpenAIUpstream:      "https://api.openai.example",
		Sink:                &fakeSink{},
		VirtualKeySource:    &fakeVirtualKeySource{key: "sbo-vk", gen: 7},
		GatewayFleetAlerter: alerter,
	}, primary.srv.URL, []string{fallback.srv.URL}, terminalHold, false)
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	resp := doPost(t, ts.URL+"/v1/chat/completions", `{"model":"m","messages":[{"role":"user","content":"hi"}]}`, nil)
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Error("hold terminal must set Retry-After")
	}
	if !strings.Contains(body, "terminal:hold") {
		t.Errorf("body missing rung; got %s", body)
	}
	if primary.count() != 1 || fallback.count() != 1 {
		t.Fatalf("primary=%d fallback=%d, want 1/1 (each tried once)", primary.count(), fallback.count())
	}
	got := alerter.snapshot()
	if len(got) != 1 || got[0].Reason != gatewayLadderQueueAndHold {
		t.Fatalf("alerts = %+v, want one queue_and_hold", got)
	}
	if got[0].EndpointsTried != 2 || got[0].Generation != p.RoutingGeneration() {
		t.Errorf("alert = %+v, want EndpointsTried=2 Generation=%d", got[0], p.RoutingGeneration())
	}
}

// TestGatewayLadder_TerminalBreakGlass: break-glass with no lease fails closed
// with a break-glass-specific remedy + a break_glass_unavailable alert.
func TestGatewayLadder_TerminalBreakGlass(t *testing.T) {
	primary := newStatusUpstream(t, http.StatusServiceUnavailable)
	alerter := &recordingAlerter{}

	p := mustGatewayProxy(t, Options{
		OpenAIUpstream:      "https://api.openai.example",
		Sink:                &fakeSink{},
		VirtualKeySource:    &fakeVirtualKeySource{key: "sbo-vk", gen: 1},
		GatewayFleetAlerter: alerter,
	}, primary.srv.URL, nil, terminalBreakGlass, false)
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	resp := doPost(t, ts.URL+"/v1/chat/completions", `{"model":"m","messages":[{"role":"user","content":"hi"}]}`, nil)
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
	if !strings.Contains(body, "terminal:break_glass") {
		t.Errorf("body missing break_glass rung; got %s", body)
	}
	got := alerter.snapshot()
	if len(got) != 1 || got[0].Reason != gatewayLadderBreakGlassHeld {
		t.Fatalf("alerts = %+v, want one break_glass_unavailable", got)
	}
}

// TestGatewayLadder_TerminalDirectCustodyAck: with an explicit custody ack,
// exhaustion falls back to the developer's DIRECT provider with their ORIGINAL
// credential restored (the virtual key stripped) — and a direct_fallback alert.
func TestGatewayLadder_TerminalDirectCustodyAck(t *testing.T) {
	primary := newStatusUpstream(t, http.StatusServiceUnavailable)
	openai := newCountingUpstream(t)
	alerter := &recordingAlerter{}

	p := mustGatewayProxy(t, Options{
		OpenAIUpstream:      openai.srv.URL,
		Sink:                &fakeSink{},
		VirtualKeySource:    &fakeVirtualKeySource{key: "sbo-vk-secret", gen: 1},
		GatewayFleetAlerter: alerter,
	}, primary.srv.URL, nil, terminalDirect, true)
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	resp := doPost(t, ts.URL+"/v1/chat/completions", `{"model":"m","messages":[{"role":"user","content":"hi"}]}`, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer sk-openai-dev")
	})
	_ = readBody(t, resp)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200 (direct fallback served)", resp.StatusCode)
	}
	if openai.count() != 1 {
		t.Fatalf("openai direct hit = %d, want 1", openai.count())
	}
	if got := openai.header("Authorization"); got != "Bearer sk-openai-dev" {
		t.Errorf("direct provider Authorization = %q, want the restored developer credential", got)
	}
	if got := openai.header("X-Api-Key"); got == "sbo-vk-secret" {
		t.Error("the virtual key leaked to the direct provider on custody-acked fallback")
	}
	got := alerter.snapshot()
	if len(got) != 1 || got[0].Reason != gatewayLadderDirectFallback {
		t.Fatalf("alerts = %+v, want one direct_fallback", got)
	}
}

// TestGatewayLadder_TerminalDirectWithoutAckDegradesToHold: terminal=direct
// but no custody ack must NEVER silently downgrade custody — it degrades to a
// fail-closed hold, and no request reaches the direct provider.
func TestGatewayLadder_TerminalDirectWithoutAckDegradesToHold(t *testing.T) {
	primary := newStatusUpstream(t, http.StatusServiceUnavailable)
	openai := newCountingUpstream(t)
	alerter := &recordingAlerter{}

	p := mustGatewayProxy(t, Options{
		OpenAIUpstream:      openai.srv.URL,
		Sink:                &fakeSink{},
		VirtualKeySource:    &fakeVirtualKeySource{key: "sbo-vk", gen: 1},
		GatewayFleetAlerter: alerter,
	}, primary.srv.URL, nil, terminalDirect, false)
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	resp := doPost(t, ts.URL+"/v1/chat/completions", `{"model":"m","messages":[{"role":"user","content":"hi"}]}`, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer sk-openai-dev")
	})
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (degraded to hold)", resp.StatusCode)
	}
	if !strings.Contains(body, "terminal:hold") {
		t.Errorf("body missing hold rung; got %s", body)
	}
	if openai.count() != 0 {
		t.Fatalf("direct provider was hit %d times — custody downgraded without an ack", openai.count())
	}
	got := alerter.snapshot()
	if len(got) != 1 || got[0].Reason != gatewayLadderQueueAndHold {
		t.Fatalf("alerts = %+v, want one queue_and_hold (degraded)", got)
	}
}

// TestGatewayLadder_Definitive4xxNotWalked: a gateway 4xx (e.g. a 402 budget
// deny) is the gateway's real answer — it is returned as-is and the ladder
// does NOT advance to a fallback.
func TestGatewayLadder_Definitive4xxNotWalked(t *testing.T) {
	primary := newStatusUpstream(t, http.StatusPaymentRequired)
	fallback := newCountingUpstream(t)
	alerter := &recordingAlerter{}

	p := mustGatewayProxy(t, Options{
		OpenAIUpstream:      "https://api.openai.example",
		Sink:                &fakeSink{},
		VirtualKeySource:    &fakeVirtualKeySource{key: "sbo-vk", gen: 1},
		GatewayFleetAlerter: alerter,
	}, primary.srv.URL, []string{fallback.srv.URL}, terminalHold, false)
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	resp := doPost(t, ts.URL+"/v1/chat/completions", `{"model":"m","messages":[{"role":"user","content":"hi"}]}`, nil)
	_ = readBody(t, resp)
	if resp.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("status = %d, want 402 (definitive)", resp.StatusCode)
	}
	if fallback.count() != 0 {
		t.Fatalf("fallback hit %d times — a 4xx must not advance the ladder", fallback.count())
	}
	if len(alerter.snapshot()) != 0 {
		t.Fatalf("no terminal alert expected on a definitive 4xx, got %+v", alerter.snapshot())
	}
}

// mustGatewayProxy builds a proxy and installs a Gateway-Mode org-route with
// the given primary, fallbacks, and terminal policy.
func mustGatewayProxy(t *testing.T, opts Options, primary string, fallbacks []string, terminal string, custodyAck bool) *Proxy {
	t.Helper()
	if opts.AnthropicUpstream == "" {
		opts.AnthropicUpstream = "https://api.anthropic.example"
	}
	p, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := p.SetOrgGatewayRouteWithFallback(orgModeGateway, primary, fallbacks, terminal, custodyAck); err != nil {
		t.Fatalf("SetOrgGatewayRouteWithFallback: %v", err)
	}
	return p
}

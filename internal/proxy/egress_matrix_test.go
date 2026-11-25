package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// capturingReporter records the realized egress outcomes the proxy reports.
type capturingReporter struct {
	mu    sync.Mutex
	calls int
	last  EgressRealized
}

func (c *capturingReporter) ReportEgressRealized(_ context.Context, out EgressRealized) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	c.last = out
}

func (c *capturingReporter) snapshot() (int, EgressRealized) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls, c.last
}

func hostOf(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse %q: %v", rawURL, err)
	}
	return u.Host
}

// TestEgressEnforceMatrix table-drives the P7 hardening matrix: streaming (SSE),
// gzip request bodies, breaker-open refusal / fail-open, a pinned runtime dial
// failure, and the realized-outcome callback — all through the real proxy
// forward path with an enforce-mode Route.
func TestEgressEnforceMatrix(t *testing.T) {
	// SSE: an enforce route_upstream to a streaming target forwards correctly
	// and the realized outcome is applied=true.
	t.Run("sse streaming target applied", func(t *testing.T) {
		var targetHit atomic.Bool
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			targetHit.Store(true)
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			fl, _ := w.(http.Flusher)
			_, _ = io.WriteString(w, "event: message_start\ndata: {\"type\":\"message_start\"}\n\n")
			if fl != nil {
				fl.Flush()
			}
			_, _ = io.WriteString(w, "event: message_delta\ndata: {\"usage\":{\"output_tokens\":2}}\n\n")
		}))
		defer target.Close()
		defaultUp := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			t.Errorf("default upstream hit despite enforce route_upstream: %s", r.URL.Path)
		}))
		defer defaultUp.Close()

		rep := &capturingReporter{}
		adm := &fakeAdmitter{route: &AdmitRoute{
			Action: "route_upstream", UpstreamID: "local", TargetURL: target.URL,
			TargetShape: "anthropic", MustUseTarget: true, OnUnavailable: "deny", DecisionID: 7,
		}}
		p, err := New(Options{AnthropicUpstream: defaultUp.URL, Upstreams: map[string]string{"hosted": defaultUp.URL}, Sink: &fakeSink{}, Admitter: adm, EgressReporter: rep})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		ts := httptest.NewServer(p.Handler())
		defer ts.Close()

		resp := postMessages(t, ts.URL+"/up/hosted")
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if !targetHit.Load() {
			t.Error("SSE egress target was not reached")
		}
		if !strings.Contains(string(body), "message_start") {
			t.Errorf("SSE body not streamed through: %q", body)
		}
		calls, last := rep.snapshot()
		if calls == 0 || !last.Applied || last.DecisionID != 7 || last.Outcome != egressOutcomeApplied {
			t.Errorf("realized outcome wrong for SSE applied: calls=%d last=%+v", calls, last)
		}
	})

	// gzip request body: the proxy does not decode gzip (§3.5), so egress
	// never routes it and the request forwards UNROUTED to the default
	// upstream; admission sees the body as unreadable (finding H1, L-180).
	t.Run("gzip request body skips egress", func(t *testing.T) {
		var defaultHit, targetHit atomic.Bool
		defaultUp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			defaultHit.Store(true)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
		}))
		defer defaultUp.Close()
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			targetHit.Store(true)
			_, _ = w.Write([]byte(`{"ok":true}`))
		}))
		defer target.Close()

		adm := &fakeAdmitter{route: &AdmitRoute{
			Action: "route_upstream", UpstreamID: "local", TargetURL: target.URL, TargetShape: "anthropic", DecisionID: 9,
		}}
		p, err := New(Options{AnthropicUpstream: defaultUp.URL, Upstreams: map[string]string{"hosted": defaultUp.URL}, Sink: &fakeSink{}, Admitter: adm})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		ts := httptest.NewServer(p.Handler())
		defer ts.Close()

		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		_, _ = gz.Write([]byte(`{"model":"claude-opus-4-8","messages":[{"role":"user","content":"hi"}]}`))
		_ = gz.Close()
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/up/hosted/v1/messages", &buf)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Content-Encoding", "gzip")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		if !adm.called || !slices.Equal(adm.gotUnaccounted, []string{"body:unparsed"}) {
			t.Errorf("admitter called=%v unaccounted=%q; want the undecoded body reported as body:unparsed", adm.called, adm.gotUnaccounted)
		}
		if !defaultHit.Load() {
			t.Error("gzip request did not forward to the default upstream")
		}
		if targetHit.Load() {
			t.Error("gzip request was routed to the egress target — egress must skip undecoded bodies")
		}
	})

	// Breaker OPEN on a pinned locality target: fail CLOSED (403 refusal) WITHOUT
	// dialing the target — never hang, never leak to default.
	t.Run("breaker open pinned fails closed", func(t *testing.T) {
		var targetHit, defaultHit atomic.Bool
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			targetHit.Store(true)
			_, _ = w.Write([]byte(`{"ok":true}`))
		}))
		defer target.Close()
		defaultUp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			defaultHit.Store(true)
			_, _ = w.Write([]byte(`{"ok":true}`))
		}))
		defer defaultUp.Close()

		rep := &capturingReporter{}
		adm := &fakeAdmitter{route: &AdmitRoute{
			Action: "route_upstream", UpstreamID: "local", TargetURL: target.URL,
			TargetShape: "anthropic", MustUseTarget: true, OnUnavailable: "deny", DecisionID: 11,
		}}
		p, err := New(Options{AnthropicUpstream: defaultUp.URL, Upstreams: map[string]string{"hosted": defaultUp.URL}, Sink: &fakeSink{}, Admitter: adm, EgressReporter: rep})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		// Force the target's breaker OPEN.
		key := hostOf(t, target.URL)
		for i := 0; i < 5; i++ {
			p.egressBreaker.RecordFailure(key)
		}
		ts := httptest.NewServer(p.Handler())
		defer ts.Close()

		resp := postMessages(t, ts.URL+"/up/hosted")
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("breaker-open pinned route: status = %d, want 403 (fail closed)", resp.StatusCode)
		}
		if targetHit.Load() {
			t.Error("dialed the target despite an open breaker (must never hang/dial)")
		}
		if defaultHit.Load() {
			t.Error("leaked to the default upstream on a pinned fail-closed route")
		}
		_, last := rep.snapshot()
		if !last.FailClosed || last.Outcome != egressOutcomeBreakerOpen {
			t.Errorf("realized outcome wrong for breaker-open fail-closed: %+v", last)
		}
	})

	// Breaker OPEN on a fail-open convenience route: fall back to the DEFAULT
	// upstream WITHOUT dialing the dead target.
	t.Run("breaker open fail-open to default", func(t *testing.T) {
		var targetHit, defaultHit atomic.Bool
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			targetHit.Store(true)
			_, _ = w.Write([]byte(`{"ok":true}`))
		}))
		defer target.Close()
		defaultUp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			defaultHit.Store(true)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
		}))
		defer defaultUp.Close()

		rep := &capturingReporter{}
		adm := &fakeAdmitter{route: &AdmitRoute{
			Action: "route_upstream", UpstreamID: "beta", TargetURL: target.URL,
			TargetShape: "anthropic", OnUnavailable: "fail_open", DecisionID: 13,
		}}
		p, err := New(Options{AnthropicUpstream: defaultUp.URL, Upstreams: map[string]string{"hosted": defaultUp.URL}, Sink: &fakeSink{}, Admitter: adm, EgressReporter: rep})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		key := hostOf(t, target.URL)
		for i := 0; i < 5; i++ {
			p.egressBreaker.RecordFailure(key)
		}
		ts := httptest.NewServer(p.Handler())
		defer ts.Close()

		resp := postMessages(t, ts.URL+"/up/hosted")
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("fail-open route: status = %d, want 200 (fell open to default)", resp.StatusCode)
		}
		if targetHit.Load() {
			t.Error("dialed the target despite an open breaker on a fail-open route")
		}
		if !defaultHit.Load() {
			t.Error("fail-open route did not reach the default upstream")
		}
		_, last := rep.snapshot()
		if last.Applied || last.Outcome != egressOutcomeBreakerOpen {
			t.Errorf("realized outcome wrong for breaker-open fail-open: %+v", last)
		}
	})

	// Pinned target that DIALS but errs at runtime (dead target): fail CLOSED
	// with a provider-shaped refusal, not a raw 502, and train the breaker.
	t.Run("pinned runtime dial error fails closed", func(t *testing.T) {
		dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		deadURL := dead.URL
		dead.Close() // now every dial to deadURL fails fast (connection refused)

		defaultUp := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			t.Errorf("default upstream hit on a pinned fail-closed route: %s", r.URL.Path)
		}))
		defer defaultUp.Close()

		rep := &capturingReporter{}
		adm := &fakeAdmitter{route: &AdmitRoute{
			Action: "route_upstream", UpstreamID: "local", TargetURL: deadURL,
			TargetShape: "anthropic", MustUseTarget: true, OnUnavailable: "deny", DecisionID: 15,
		}}
		p, err := New(Options{AnthropicUpstream: defaultUp.URL, Upstreams: map[string]string{"hosted": defaultUp.URL}, Sink: &fakeSink{}, Admitter: adm, EgressReporter: rep})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		ts := httptest.NewServer(p.Handler())
		defer ts.Close()

		resp := postMessages(t, ts.URL+"/up/hosted")
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("pinned runtime error: status = %d, want 403 (fail closed, not 502)", resp.StatusCode)
		}
		_, last := rep.snapshot()
		if !last.FailClosed || last.Outcome != egressOutcomeUpstreamErr {
			t.Errorf("realized outcome wrong for pinned runtime error: %+v", last)
		}
		// The breaker recorded the failure.
		if p.egressBreaker.Allow(hostOf(t, deadURL)) && func() bool {
			// one failure is below the default threshold of 3, so still allowed;
			// assert the failure was at least counted by driving to threshold.
			p.egressBreaker.RecordFailure(hostOf(t, deadURL))
			p.egressBreaker.RecordFailure(hostOf(t, deadURL))
			return p.egressBreaker.Allow(hostOf(t, deadURL))
		}() {
			t.Error("breaker did not count the pinned target's runtime failure")
		}
	})

	// Fail-open convenience route to a DEAD target that dials-and-errs: the
	// proxy re-forwards to the default upstream once (never a byte streamed).
	t.Run("fail-open runtime error reforwards to default", func(t *testing.T) {
		dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		deadURL := dead.URL
		dead.Close()

		var defaultHit atomic.Bool
		defaultUp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			defaultHit.Store(true)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
		}))
		defer defaultUp.Close()

		rep := &capturingReporter{}
		adm := &fakeAdmitter{route: &AdmitRoute{
			Action: "route_upstream", UpstreamID: "beta", TargetURL: deadURL,
			TargetShape: "anthropic", OnUnavailable: "fail_open", DecisionID: 17,
		}}
		p, err := New(Options{AnthropicUpstream: defaultUp.URL, Upstreams: map[string]string{"hosted": defaultUp.URL}, Sink: &fakeSink{}, Admitter: adm, EgressReporter: rep})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		ts := httptest.NewServer(p.Handler())
		defer ts.Close()

		resp := postMessages(t, ts.URL+"/up/hosted")
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("fail-open runtime error: status = %d, want 200 (re-forwarded to default)", resp.StatusCode)
		}
		if !defaultHit.Load() {
			t.Error("fail-open route did not re-forward to the default upstream after the target erred")
		}
		_, last := rep.snapshot()
		if last.Outcome != egressOutcomeFallbackOpen {
			t.Errorf("realized outcome wrong for fail-open re-forward: %+v", last)
		}
	})
}

func postMessages(t *testing.T, base string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, base+"/v1/messages",
		strings.NewReader(`{"model":"claude-opus-4-8","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return resp
}

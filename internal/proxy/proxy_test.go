package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/processobs"
)

// fakeSink records inserted APITurns in memory for test assertions.
type fakeSink struct {
	mu    sync.Mutex
	turns []models.APITurn
}

func (f *fakeSink) InsertAPITurn(_ context.Context, t models.APITurn) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.turns = append(f.turns, t)
	return int64(len(f.turns)), nil
}

func (f *fakeSink) all() []models.APITurn {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]models.APITurn, len(f.turns))
	copy(out, f.turns)
	return out
}

type fakeNetworkSink struct {
	mu     sync.Mutex
	events []processobs.ProcessEvent
}

func (f *fakeNetworkSink) PersistProcessEvents(_ context.Context, events []processobs.ProcessEvent) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, events...)
	return len(events), nil
}

func (f *fakeNetworkSink) all() []processobs.ProcessEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]processobs.ProcessEvent, len(f.events))
	copy(out, f.events)
	return out
}

func (f *fakeNetworkSink) waitForCount(n int) []processobs.ProcessEvent {
	deadline := time.Now().Add(500 * time.Millisecond)
	for {
		events := f.all()
		if len(events) >= n || time.Now().After(deadline) {
			return events
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// fakeCostComputer is a deterministic CostComputer for tests. rate is
// multiplied by (Input+Output+CacheRead) to get a USD value;
// CacheCreation is ignored so test assertions stay simple.
type fakeCostComputer struct {
	mu         sync.Mutex
	rate       float64
	lastModel  string
	lastTokens CostTokens
}

func (f *fakeCostComputer) Compute(model string, t CostTokens) (float64, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastModel = model
	f.lastTokens = t
	return f.rate * float64(t.Input+t.Output+t.CacheRead), true
}

// newTestProxy wires a Proxy against two test upstream servers. The returned
// closer shuts both down.
func newTestProxy(t *testing.T, anthropicHandler, openaiHandler http.Handler) (*Proxy, *fakeSink, func()) {
	t.Helper()
	anthUp := httptest.NewServer(anthropicHandler)
	oaiUp := httptest.NewServer(openaiHandler)
	sink := &fakeSink{}
	p, err := New(Options{
		AnthropicUpstream: anthUp.URL,
		OpenAIUpstream:    oaiUp.URL,
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

func TestProxy_AnthropicNonStreaming(t *testing.T) {
	const requestBody = `{"model":"claude-sonnet-4","messages":[{"role":"user","content":"hi"}],"system":"You are helpful.","tools":[{"name":"tool1"}]}`
	const responseBody = `{"id":"msg_abc","model":"claude-sonnet-4","stop_reason":"end_turn","usage":{"input_tokens":42,"output_tokens":17,"cache_read_input_tokens":100,"cache_creation_input_tokens":0}}`

	var seenBody string
	var seenAuth string
	var seenXSession string
	anth := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seenBody = string(body)
		seenAuth = r.Header.Get("X-Api-Key")
		seenXSession = r.Header.Get("X-Session-Id")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-Id", "req_xyz")
		_, _ = w.Write([]byte(responseBody))
	})
	oai := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("openai upstream unexpectedly hit: %s", r.URL.Path)
	})

	p, sink, cleanup := newTestProxy(t, anth, oai)
	defer cleanup()
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	req, _ := http.NewRequest("POST", ts.URL+"/v1/messages", strings.NewReader(requestBody))
	req.Header.Set("X-Api-Key", "sk-ant-test")
	req.Header.Set("X-Session-Id", "sess-123")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	defer resp.Body.Close()
	gotBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		t.Fatalf("status: got %d want 200", resp.StatusCode)
	}
	if string(gotBody) != responseBody {
		t.Errorf("response body: got %q want %q", gotBody, responseBody)
	}
	if seenBody != requestBody {
		t.Errorf("upstream saw body %q want %q", seenBody, requestBody)
	}
	if seenAuth != "sk-ant-test" {
		t.Errorf("upstream saw X-Api-Key %q want %q", seenAuth, "sk-ant-test")
	}
	if seenXSession != "" {
		t.Errorf("X-Session-Id leaked to upstream: %q", seenXSession)
	}

	turns := sink.all()
	if len(turns) != 1 {
		t.Fatalf("want 1 turn, got %d", len(turns))
	}
	tr := turns[0]
	if tr.Provider != models.ProviderAnthropic {
		t.Errorf("provider: %s", tr.Provider)
	}
	if tr.Model != "claude-sonnet-4" {
		t.Errorf("model: %s", tr.Model)
	}
	if tr.SessionID != "sess-123" {
		t.Errorf("session id: %q", tr.SessionID)
	}
	if tr.RequestID != "msg_abc" {
		t.Errorf("request id: %q", tr.RequestID)
	}
	if tr.InputTokens != 42 || tr.OutputTokens != 17 {
		t.Errorf("tokens: in=%d out=%d", tr.InputTokens, tr.OutputTokens)
	}
	if tr.CacheReadTokens != 100 {
		t.Errorf("cache read: %d", tr.CacheReadTokens)
	}
	if tr.MessageCount != 1 {
		t.Errorf("message count: %d", tr.MessageCount)
	}
	if tr.ToolUseCount != 1 {
		t.Errorf("tool use count: %d", tr.ToolUseCount)
	}
	if tr.SystemPromptHash == "" {
		t.Error("expected non-empty system prompt hash")
	}
	if tr.StopReason != "end_turn" {
		t.Errorf("stop reason: %s", tr.StopReason)
	}
}

func TestProxy_OpenAINonStreaming(t *testing.T) {
	const requestBody = `{"model":"gpt-5","messages":[{"role":"user","content":"hi"},{"role":"assistant","content":"yo"}],"stream":false}`
	const responseBody = `{"id":"chatcmpl-1","model":"gpt-5","choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":11,"completion_tokens":3,"prompt_tokens_details":{"cached_tokens":5}}}`

	anth := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("anthropic upstream unexpectedly hit: %s", r.URL.Path)
	})
	oai := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(responseBody))
	})

	p, sink, cleanup := newTestProxy(t, anth, oai)
	defer cleanup()
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/v1/chat/completions", "application/json", strings.NewReader(requestBody))
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("status: got %d want 200", resp.StatusCode)
	}

	turns := sink.all()
	if len(turns) != 1 {
		t.Fatalf("want 1 turn, got %d", len(turns))
	}
	tr := turns[0]
	if tr.Provider != models.ProviderOpenAI {
		t.Errorf("provider: %s", tr.Provider)
	}
	if tr.Model != "gpt-5" {
		t.Errorf("model: %s", tr.Model)
	}
	// Input is NET non-cached: upstream reported prompt_tokens=11
	// with prompt_tokens_details.cached_tokens=5, so the netted
	// figure is 11-5=6 (per the Anthropic-style cost-engine
	// contract pinned in internal/intelligence/cost/engine.go).
	if tr.InputTokens != 6 || tr.OutputTokens != 3 {
		t.Errorf("tokens: in=%d out=%d (want in=6 out=3 net of cached)", tr.InputTokens, tr.OutputTokens)
	}
	if tr.CacheReadTokens != 5 {
		t.Errorf("cache read: %d", tr.CacheReadTokens)
	}
	if tr.StopReason != "stop" {
		t.Errorf("stop reason: %s", tr.StopReason)
	}
	if tr.MessageCount != 2 {
		t.Errorf("message count: %d", tr.MessageCount)
	}
}

func TestProxy_AnthropicStreaming(t *testing.T) {
	// Real-shape Anthropic SSE: message_start carries input_tokens +
	// cache_*_input_tokens on message.usage; message_delta carries
	// output_tokens on its top-level usage and stop_reason on delta.
	sse := strings.Join([]string{
		`event: message_start`,
		`data: {"type":"message_start","message":{"id":"msg_1","model":"claude-sonnet-4","usage":{"input_tokens":120,"cache_read_input_tokens":500,"cache_creation_input_tokens":0,"output_tokens":1}}}`,
		``,
		`event: content_block_delta`,
		`data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"Hello"}}`,
		``,
		`event: message_delta`,
		`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":42}}`,
		``,
		`event: message_stop`,
		`data: {"type":"message_stop"}`,
		``,
	}, "\n")

	anth := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		flusher, _ := w.(http.Flusher)
		// Write in two halves to exercise chunk boundaries.
		mid := len(sse) / 2
		_, _ = w.Write([]byte(sse[:mid]))
		if flusher != nil {
			flusher.Flush()
		}
		_, _ = w.Write([]byte(sse[mid:]))
		if flusher != nil {
			flusher.Flush()
		}
	})
	p, sink, cleanup := newTestProxy(t, anth, http.NotFoundHandler())
	defer cleanup()
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	req, _ := http.NewRequest("POST", ts.URL+"/v1/messages",
		strings.NewReader(`{"model":"claude-sonnet-4","stream":true,"messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	if string(body) != sse {
		t.Errorf("body mismatch after tee")
	}

	turns := sink.all()
	if len(turns) != 1 {
		t.Fatalf("want 1 turn, got %d", len(turns))
	}
	tr := turns[0]
	if tr.Model != "claude-sonnet-4" {
		t.Errorf("model: %q", tr.Model)
	}
	if tr.RequestID != "msg_1" {
		t.Errorf("request id: %q", tr.RequestID)
	}
	if tr.InputTokens != 120 {
		t.Errorf("input_tokens: %d", tr.InputTokens)
	}
	if tr.OutputTokens != 42 {
		t.Errorf("output_tokens: %d (expected delta to override message_start placeholder)", tr.OutputTokens)
	}
	if tr.CacheReadTokens != 500 {
		t.Errorf("cache_read: %d", tr.CacheReadTokens)
	}
	if tr.StopReason != "end_turn" {
		t.Errorf("stop_reason: %q", tr.StopReason)
	}
}

// TestProxy_PopulatesCostUSDOnInsert verifies that when a CostComputer
// is wired, the proxy populates APITurn.CostUSD before insertion. This
// matters for `scripts/ab-claude-report.sh` and `observer cost`, which
// SUM the column directly rather than recomputing on read. Pre-fix,
// cost_usd stayed NULL on every row and the live A/B headline showed
// $0 saved despite real token counts.
func TestProxy_PopulatesCostUSDOnInsert(t *testing.T) {
	const responseBody = `{"id":"msg_abc","model":"claude-sonnet-4","stop_reason":"end_turn","usage":{"input_tokens":100,"output_tokens":50,"cache_read_input_tokens":1000,"cache_creation_input_tokens":0}}`
	anth := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(responseBody))
	})
	anthUp := httptest.NewServer(anth)
	defer anthUp.Close()
	sink := &fakeSink{}
	cost := &fakeCostComputer{rate: 0.01} // $0.01 per (input+output+cache_read) token
	p, err := New(Options{
		AnthropicUpstream: anthUp.URL,
		Sink:              sink,
		CostComputer:      cost,
	})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	req, _ := http.NewRequest("POST", ts.URL+"/v1/messages",
		strings.NewReader(`{"model":"claude-sonnet-4","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	turns := sink.all()
	if len(turns) != 1 {
		t.Fatalf("want 1 turn, got %d", len(turns))
	}
	tr := turns[0]
	wantCost := 0.01 * float64(100+50+1000)
	if tr.CostUSD != wantCost {
		t.Errorf("cost_usd: got %v want %v", tr.CostUSD, wantCost)
	}
	if cost.lastModel != "claude-sonnet-4" {
		t.Errorf("computer received model %q want %q", cost.lastModel, "claude-sonnet-4")
	}
	if cost.lastTokens.Input != 100 || cost.lastTokens.Output != 50 || cost.lastTokens.CacheRead != 1000 {
		t.Errorf("computer received tokens %+v", cost.lastTokens)
	}
}

// TestProxy_CostUSDUnsetWhenComputerAbsent — proxies built without a
// CostComputer leave APITurn.CostUSD as the zero value. Existing
// downstream consumers (dashboard /api/cost, observer cost) that
// compute on read still work; nothing regresses for users who haven't
// upgraded their start.go yet.
func TestProxy_CostUSDUnsetWhenComputerAbsent(t *testing.T) {
	const responseBody = `{"id":"m","model":"claude-sonnet-4","usage":{"input_tokens":1,"output_tokens":1}}`
	anth := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(responseBody))
	})
	anthUp := httptest.NewServer(anth)
	defer anthUp.Close()
	sink := &fakeSink{}
	p, _ := New(Options{
		AnthropicUpstream: anthUp.URL,
		Sink:              sink,
		// CostComputer intentionally nil.
	})
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	req, _ := http.NewRequest("POST", ts.URL+"/v1/messages",
		strings.NewReader(`{"model":"claude-sonnet-4","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	turns := sink.all()
	if len(turns) != 1 {
		t.Fatalf("want 1 turn, got %d", len(turns))
	}
	if turns[0].CostUSD != 0 {
		t.Errorf("cost_usd: got %v want 0 (no computer wired)", turns[0].CostUSD)
	}
}

// TestProxy_AnthropicStreamingForcesIdentityEncoding guards the regression
// that surfaced once the OAuth-launcher started routing live Pro/Max
// traffic through the proxy: claude sends Accept-Encoding: gzip, br by
// default and api.anthropic.com responds Content-Encoding: gzip.
// Pre-fix, the SSE parser saw gzip-encoded bytes, found zero `data:`
// lines or `usage` keys, and api_turns rows landed with input/output
// tokens both zero (24 of 24 live OAuth A/B rows). Fix: the proxy
// overrides outgoing Accept-Encoding to `identity` so the upstream
// always returns plaintext we can parse. Test mocks an upstream that
// only emits real usage when Accept-Encoding == identity; if the
// override fails, parsed tokens stay at zero and this test fails.
func TestProxy_AnthropicStreamingForcesIdentityEncoding(t *testing.T) {
	const sse = "event: message_start\n" +
		`data: {"type":"message_start","message":{"id":"msg_id","model":"claude-sonnet-4","usage":{"input_tokens":7,"output_tokens":1}}}` + "\n\n" +
		"event: message_delta\n" +
		`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":42}}` + "\n\n"

	var seenAcceptEncoding string
	anth := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAcceptEncoding = r.Header.Get("Accept-Encoding")
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		flusher, _ := w.(http.Flusher)
		_, _ = w.Write([]byte(sse))
		if flusher != nil {
			flusher.Flush()
		}
	})
	p, sink, cleanup := newTestProxy(t, anth, http.NotFoundHandler())
	defer cleanup()
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	req, _ := http.NewRequest("POST", ts.URL+"/v1/messages",
		strings.NewReader(`{"model":"claude-sonnet-4","stream":true,"messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Content-Type", "application/json")
	// Mimic claude's default Accept-Encoding negotiation. Pre-fix, this
	// flowed straight through to api.anthropic.com.
	req.Header.Set("Accept-Encoding", "gzip, br")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	if seenAcceptEncoding != "identity" {
		t.Fatalf("upstream Accept-Encoding: got %q want %q (proxy must override so SSE comes back plaintext)",
			seenAcceptEncoding, "identity")
	}

	turns := sink.all()
	if len(turns) != 1 {
		t.Fatalf("want 1 turn, got %d", len(turns))
	}
	tr := turns[0]
	if tr.InputTokens != 7 {
		t.Errorf("input_tokens: got %d want 7 (zero would mean parser saw encoded bytes)", tr.InputTokens)
	}
	if tr.OutputTokens != 42 {
		t.Errorf("output_tokens: got %d want 42", tr.OutputTokens)
	}
}

// TestProxy_AnthropicStreamingZeroUsageDropped guards against audit item B2:
// upstream Anthropic SSE that delivers a model in message_start but never
// produces a usage-bearing message_delta (cancelled request, mid-flight
// error, or a malformed envelope) used to land as a zero-everything row in
// api_turns. 14 of 21 live install rows had this shape. The isEmptyUsage
// gate now drops them.
func TestProxy_AnthropicStreamingZeroUsageDropped(t *testing.T) {
	// Stream has model + id in message_start but no usage block — and no
	// message_delta to fill in tokens.
	sse := strings.Join([]string{
		`event: message_start`,
		`data: {"type":"message_start","message":{"id":"msg_zero","model":"claude-haiku-4-5"}}`,
		``,
		`event: message_stop`,
		`data: {"type":"message_stop"}`,
		``,
	}, "\n")

	anth := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		flusher, _ := w.(http.Flusher)
		_, _ = w.Write([]byte(sse))
		if flusher != nil {
			flusher.Flush()
		}
	})
	p, sink, cleanup := newTestProxy(t, anth, http.NotFoundHandler())
	defer cleanup()
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/v1/messages", "application/json",
		strings.NewReader(`{"model":"claude-haiku-4-5","stream":true,"messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	if n := len(sink.all()); n != 0 {
		t.Errorf("want 0 turns when stream carries model but zero usage, got %d (see audit B2)", n)
	}
}

func TestProxy_OpenAIStreamingWithUsage(t *testing.T) {
	// OpenAI include_usage=true emits a final non-delta chunk with top-level
	// usage right before [DONE].
	sse := strings.Join([]string{
		`data: {"id":"chatcmpl-stream","model":"gpt-5","choices":[{"delta":{"content":"hi"},"finish_reason":null}]}`,
		``,
		`data: {"id":"chatcmpl-stream","model":"gpt-5","choices":[{"delta":{},"finish_reason":"stop"}]}`,
		``,
		`data: {"id":"chatcmpl-stream","model":"gpt-5","choices":[],"usage":{"prompt_tokens":33,"completion_tokens":7,"prompt_tokens_details":{"cached_tokens":10}}}`,
		``,
		`data: [DONE]`,
		``,
	}, "\n")

	oai := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		flusher, _ := w.(http.Flusher)
		_, _ = w.Write([]byte(sse))
		if flusher != nil {
			flusher.Flush()
		}
	})
	p, sink, cleanup := newTestProxy(t, http.NotFoundHandler(), oai)
	defer cleanup()
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"gpt-5","stream":true,"messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	turns := sink.all()
	if len(turns) != 1 {
		t.Fatalf("want 1 turn, got %d", len(turns))
	}
	tr := turns[0]
	if tr.Model != "gpt-5" {
		t.Errorf("model: %q", tr.Model)
	}
	// Input is NET non-cached: upstream prompt_tokens=33 with
	// cached_tokens=10 → 23 (per cost-engine TokenBundle contract).
	if tr.InputTokens != 23 || tr.OutputTokens != 7 {
		t.Errorf("tokens: in=%d out=%d (want in=23 out=7 net of cached)", tr.InputTokens, tr.OutputTokens)
	}
	if tr.CacheReadTokens != 10 {
		t.Errorf("cache_read: %d", tr.CacheReadTokens)
	}
	if tr.StopReason != "stop" {
		t.Errorf("stop_reason: %q", tr.StopReason)
	}
}

func TestProxy_OpenAIResponsesStreamingCompletedUsage(t *testing.T) {
	// Responses API streams finish with a response.completed event whose
	// model and usage live under response.*, including on the ChatGPT
	// /backend-api/codex/responses endpoint.
	sse := strings.Join([]string{
		`event: response.created`,
		`data: {"type":"response.created","response":{"id":"resp_chatgpt","model":"gpt-5.5"}}`,
		``,
		`event: response.completed`,
		`data: {"type":"response.completed","response":{"id":"resp_chatgpt","model":"gpt-5.5","status":"completed","usage":{"input_tokens":121,"output_tokens":9,"input_tokens_details":{"cached_tokens":77}}}}`,
		``,
		`data: [DONE]`,
		``,
	}, "\n")

	oai := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		flusher, _ := w.(http.Flusher)
		_, _ = w.Write([]byte(sse))
		if flusher != nil {
			flusher.Flush()
		}
	})
	p, sink, cleanup := newTestProxy(t, http.NotFoundHandler(), oai)
	defer cleanup()
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/v1/responses", "application/json",
		strings.NewReader(`{"model":"gpt-5.5","stream":true,"input":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	turns := sink.all()
	if len(turns) != 1 {
		t.Fatalf("want 1 turn, got %d", len(turns))
	}
	tr := turns[0]
	if tr.Model != "gpt-5.5" {
		t.Errorf("model: %q", tr.Model)
	}
	if tr.RequestID != "resp_chatgpt" {
		t.Errorf("request_id: %q", tr.RequestID)
	}
	// Input is NET non-cached: upstream input_tokens=121 with
	// input_tokens_details.cached_tokens=77 → 44.
	if tr.InputTokens != 44 || tr.OutputTokens != 9 {
		t.Errorf("tokens: in=%d out=%d (want in=44 out=9 net of cached)", tr.InputTokens, tr.OutputTokens)
	}
	if tr.CacheReadTokens != 77 {
		t.Errorf("cache_read: %d", tr.CacheReadTokens)
	}
	if tr.MessageCount != 1 {
		t.Errorf("message_count: %d", tr.MessageCount)
	}
}

func TestProxy_OpenAIStreamingNoUsageDropped(t *testing.T) {
	// Without include_usage, we see no usage block. The tee must pass the
	// body through but drop the turn (zero tokens, empty model on some
	// chunks). Spec §24: unreliable tokens aren't worth recording as
	// "accurate"; leave them for the JSONL adapter to capture.
	//
	// Here the stream has no usage block AND no model on any chunk — the
	// serve() check on turn.Model drops it. The B2 isEmptyUsage gate
	// (added later) drops it again belt-and-suspenders if a model surfaces
	// elsewhere; the regression test for that case is
	// TestProxy_AnthropicStreamingZeroUsageDropped below.
	sse := strings.Join([]string{
		`data: {"choices":[{"delta":{"content":"hi"}}]}`,
		``,
		`data: [DONE]`,
		``,
	}, "\n")

	oai := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		flusher, _ := w.(http.Flusher)
		_, _ = w.Write([]byte(sse))
		if flusher != nil {
			flusher.Flush()
		}
	})
	p, sink, cleanup := newTestProxy(t, http.NotFoundHandler(), oai)
	defer cleanup()
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"stream":true,"messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	if n := len(sink.all()); n != 0 {
		t.Errorf("want 0 turns when neither stream nor request carries a model, got %d", n)
	}
}

func TestProxy_OpenAIStreamingNoUsageKeptWhenCompressed(t *testing.T) {
	sse := strings.Join([]string{
		`event: response.created`,
		`data: {"type":"response.created","response":{"id":"resp_keep","model":"gpt-5.5"}}`,
		``,
		`data: [DONE]`,
		``,
	}, "\n")

	oai := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		flusher, _ := w.(http.Flusher)
		_, _ = w.Write([]byte(sse))
		if flusher != nil {
			flusher.Flush()
		}
	})
	p, sink, cleanup := newTestProxy(t, http.NotFoundHandler(), oai)
	defer cleanup()
	p.compressor = &fakeCompressor{
		result: CompressionResult{
			Body:              []byte(`{"model":"gpt-5.5","stream":true,"input":[{"role":"user","content":"[1 messages compressed - use search_past_outputs]"}]}`),
			Skipped:           false,
			MessagePrefixHash: "keep-zero-usage",
			OriginalBytes:     120,
			CompressedBytes:   80,
			DroppedCount:      1,
			MarkerCount:       1,
			Events: []CompressionEvent{
				{Mechanism: "drop", OriginalBytes: 40, MsgIndex: 0, ImportanceScore: 0.1},
			},
		},
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/v1/responses", "application/json",
		strings.NewReader(`{"model":"gpt-5.5","stream":true,"input":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	turns := sink.all()
	if len(turns) != 1 {
		t.Fatalf("want 1 turn when compression happened, got %d", len(turns))
	}
	if turns[0].Model != "gpt-5.5" {
		t.Errorf("model: got %q want gpt-5.5", turns[0].Model)
	}
	if turns[0].CompressionDroppedCount != 1 {
		t.Errorf("compression_dropped_count: got %d want 1", turns[0].CompressionDroppedCount)
	}
	if turns[0].MessagePrefixHash != "keep-zero-usage" {
		t.Errorf("message_prefix_hash: got %q want keep-zero-usage", turns[0].MessagePrefixHash)
	}
	if turns[0].InputTokens != 0 || turns[0].OutputTokens != 0 {
		t.Errorf("expected zero usage to be preserved for observability, got in=%d out=%d", turns[0].InputTokens, turns[0].OutputTokens)
	}
}

// TestProxy_UpstreamError pins the v1.4.20 capture: non-2xx upstream
// responses are forwarded unchanged AND recorded as zero-token api_turn
// rows with HTTPStatus / ErrorClass / ErrorMessage populated. Pre-fix
// these were dropped silently (`if resp.StatusCode < 200 || >= 300 { return }`),
// matching the JSONL-side gap the same release closed.
func TestProxy_UpstreamError(t *testing.T) {
	anth := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-Id", "req_011err400")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"type":"error","error":{"type":"invalid_request_error","message":"messages: array too short"}}`))
	})
	p, sink, cleanup := newTestProxy(t, anth, http.NotFoundHandler())
	defer cleanup()
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/v1/messages", "application/json",
		strings.NewReader(`{"model":"claude-sonnet-4-6","messages":[]}`))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Errorf("status: %d want 400", resp.StatusCode)
	}

	turns := sink.all()
	if len(turns) != 1 {
		t.Fatalf("want 1 captured error turn, got %d", len(turns))
	}
	turn := turns[0]
	if turn.HTTPStatus != 400 {
		t.Errorf("http_status: %d want 400", turn.HTTPStatus)
	}
	if turn.ErrorClass != "invalid_request_error" {
		t.Errorf("error_class: %q want invalid_request_error", turn.ErrorClass)
	}
	if !strings.Contains(turn.ErrorMessage, "array too short") {
		t.Errorf("error_message: %q", turn.ErrorMessage)
	}
	if turn.RequestID != "req_011err400" {
		t.Errorf("request_id: %q want req_011err400", turn.RequestID)
	}
	if turn.Model != "claude-sonnet-4-6" {
		t.Errorf("model: %q want claude-sonnet-4-6 (from request body)", turn.Model)
	}
	if turn.Provider != models.ProviderAnthropic {
		t.Errorf("provider: %q", turn.Provider)
	}
	// Errors don't consume billing tokens — the row should be zero-token.
	if turn.InputTokens != 0 || turn.OutputTokens != 0 {
		t.Errorf("expected zero tokens on error: in=%d out=%d", turn.InputTokens, turn.OutputTokens)
	}
}

// TestProxy_UpstreamRateLimit pins 429 + the rate_limit_error class.
func TestProxy_UpstreamRateLimit(t *testing.T) {
	anth := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-Id", "req_011rate")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"type":"error","error":{"type":"rate_limit_error","message":"Number of request tokens has exceeded your per-minute rate limit"}}`))
	})
	p, sink, cleanup := newTestProxy(t, anth, http.NotFoundHandler())
	defer cleanup()
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	resp, _ := http.Post(ts.URL+"/v1/messages", "application/json",
		strings.NewReader(`{"model":"claude-opus-4-7"}`))
	resp.Body.Close()

	turns := sink.all()
	if len(turns) != 1 {
		t.Fatalf("want 1 turn, got %d", len(turns))
	}
	if turns[0].HTTPStatus != 429 || turns[0].ErrorClass != "rate_limit_error" {
		t.Errorf("turn = %+v", turns[0])
	}
}

// TestProxy_OpenAIErrorEnvelope pins capture against OpenAI's slightly
// different error shape (no top-level `type: "error"` wrapper, just
// `{error: {type, message, code}}`). parseErrorBody handles both.
func TestProxy_OpenAIErrorEnvelope(t *testing.T) {
	openai := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-Id", "req_oaerr")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"message":"Invalid API key","type":"invalid_request_error","code":"invalid_api_key"}}`))
	})
	p, sink, cleanup := newTestProxy(t, http.NotFoundHandler(), openai)
	defer cleanup()
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	resp, _ := http.Post(ts.URL+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"gpt-5"}`))
	resp.Body.Close()

	turns := sink.all()
	if len(turns) != 1 {
		t.Fatalf("want 1 turn, got %d", len(turns))
	}
	if turns[0].HTTPStatus != 401 || turns[0].ErrorClass != "invalid_request_error" {
		t.Errorf("turn = %+v", turns[0])
	}
	if !strings.Contains(turns[0].ErrorMessage, "Invalid API key") {
		t.Errorf("message: %q", turns[0].ErrorMessage)
	}
}

// TestProxy_StreamUpstreamError covers the streaming path: a non-2xx
// response code on a streaming endpoint records an error turn the same
// way the non-streaming path does. The captured body might be a plain
// JSON error (when the upstream rejects before any SSE events) or an
// SSE `event: error` envelope; extractStreamErrorBody handles both.
func TestProxy_StreamUpstreamError(t *testing.T) {
	anth := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Request-Id", "req_011stream_err")
		w.WriteHeader(http.StatusServiceUnavailable)
		// Anthropic's overloaded path emits the same JSON body shape
		// regardless of stream/non-stream when it rejects pre-flight.
		flusher, _ := w.(http.Flusher)
		_, _ = w.Write([]byte(`{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}`))
		if flusher != nil {
			flusher.Flush()
		}
	})
	p, sink, cleanup := newTestProxy(t, anth, http.NotFoundHandler())
	defer cleanup()
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	resp, _ := http.Post(ts.URL+"/v1/messages", "application/json",
		strings.NewReader(`{"model":"claude-sonnet-4-6","stream":true}`))
	// Drain before close — Body.Close() on a not-yet-drained body resets
	// the connection mid-write, which can race the proxy's teeStream and
	// the InsertAPITurn that follows it. Reading to EOF first guarantees
	// the proxy's serve has returned (and therefore inserted) by the
	// time we hit sink.all() below.
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	turns := sink.all()
	if len(turns) != 1 {
		t.Fatalf("want 1 turn, got %d", len(turns))
	}
	if turns[0].HTTPStatus != 503 || turns[0].ErrorClass != "overloaded_error" {
		t.Errorf("turn = %+v", turns[0])
	}
}

func TestProxy_UpstreamUnreachable(t *testing.T) {
	// An unparseable upstream URL is rejected at New(). An unreachable one
	// surfaces as 502 at request time.
	p, err := New(Options{
		AnthropicUpstream: "http://127.0.0.1:1", // port 1 is unreachable
		OpenAIUpstream:    "http://127.0.0.1:1",
		Sink:              &fakeSink{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Post(ts.URL+"/v1/messages", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status: got %d want 502", resp.StatusCode)
	}
}

// TestProxy_RetriesTransientConnectionReset pins the v1.4.24 retry
// behaviour: the proxy should swallow ONE "connection reset by peer"
// from the upstream transport and re-issue the request on a fresh
// connection. WSL2 / corporate-firewall NATs frequently close idle
// keep-alive entries before our IdleConnTimeout expires; without
// retry the user sees a 502 on what should be a successful call.
//
// Uses a custom RoundTripper since httptest can't simulate TCP-level
// connection resets cleanly.
func TestProxy_RetriesTransientConnectionReset(t *testing.T) {
	const responseBody = `{"id":"msg_R","model":"claude-sonnet-4","stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`

	var attempts int32
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		n := atomic.AddInt32(&attempts, 1)
		if n == 1 {
			// Mid-write transient — exactly the shape Claude Code reports.
			return nil, errors.New(`Post "https://api.anthropic.com/v1/messages": write tcp 127.0.0.1:54321->1.2.3.4:443: write: connection reset by peer`)
		}
		body := strings.NewReader(responseBody)
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(body),
			Header:     http.Header{"Content-Type": {"application/json"}, "X-Request-Id": {"req_R"}},
		}, nil
	})

	sink := &fakeSink{}
	p, err := New(Options{
		AnthropicUpstream: "https://api.anthropic.com",
		OpenAIUpstream:    "https://api.openai.com",
		Sink:              sink,
		Client:            &http.Client{Transport: rt},
	})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	req, _ := http.NewRequest("POST", ts.URL+"/v1/messages", strings.NewReader(`{"model":"claude-sonnet-4","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("client request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("status: got %d want 200 (retry should have succeeded)", resp.StatusCode)
	}
	if got := atomic.LoadInt32(&attempts); got != 2 {
		t.Errorf("attempts: got %d want 2 (one fail + one retry)", got)
	}
	if len(sink.all()) != 1 {
		t.Errorf("turns recorded: got %d want 1 (only successful retry should land)", len(sink.all()))
	}
}

// TestProxy_DoesNotRetryNonTransient confirms that we do NOT retry on
// non-transient errors — TLS handshake failures, dial timeouts, etc.
// The retry budget exists for stale-keep-alive recovery, not for
// masking real upstream outages.
func TestProxy_DoesNotRetryNonTransient(t *testing.T) {
	var attempts int32
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		atomic.AddInt32(&attempts, 1)
		return nil, errors.New(`Post "...": tls: handshake failure`)
	})

	sink := &fakeSink{}
	p, err := New(Options{
		AnthropicUpstream: "https://api.anthropic.com",
		OpenAIUpstream:    "https://api.openai.com",
		Sink:              sink,
		Client:            &http.Client{Transport: rt},
	})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	req, _ := http.NewRequest("POST", ts.URL+"/v1/messages", strings.NewReader(`{"model":"x","messages":[{"role":"user","content":"hi"}]}`))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("client request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status: got %d want 502", resp.StatusCode)
	}
	if got := atomic.LoadInt32(&attempts); got != 1 {
		t.Errorf("attempts: got %d want 1 (TLS handshake should not retry)", got)
	}
}

func TestProxy_ProcessNetworkCaptureDisabled(t *testing.T) {
	netSink := &fakeNetworkSink{}
	anth := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_ok","model":"claude-sonnet-4","usage":{"input_tokens":1,"output_tokens":1}}`))
	})
	anthUp := httptest.NewServer(anth)
	defer anthUp.Close()
	p, err := New(Options{
		AnthropicUpstream: anthUp.URL,
		OpenAIUpstream:    "https://api.openai.com",
		Sink:              &fakeSink{},
		NetworkSink:       netSink,
		NetworkCapture:    NetworkCaptureOptions{Enabled: false, CaptureBodies: "proxied"},
	})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/v1/messages", "application/json",
		strings.NewReader(`{"model":"claude-sonnet-4","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()
	if got := len(netSink.all()); got != 0 {
		t.Fatalf("network events: got %d want 0 when capture disabled", got)
	}
}

func TestProxy_ProcessNetworkCapturesTransportFailure(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return nil, errors.New(`Post "...": tls: handshake failure`)
	})
	sink := &fakeSink{}
	netSink := &fakeNetworkSink{}
	p, err := New(Options{
		AnthropicUpstream: "https://api.anthropic.com",
		OpenAIUpstream:    "https://api.openai.com",
		Sink:              sink,
		Client:            &http.Client{Transport: rt},
		NetworkSink:       netSink,
		NetworkCapture: NetworkCaptureOptions{
			Enabled:          true,
			CaptureBodies:    "proxied",
			MaxRequestBytes:  1024,
			MaxResponseBytes: 1024,
			CaptureHeaders:   true,
			ScrubBodies:      true,
		},
	})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	req, _ := http.NewRequest("POST", ts.URL+"/v1/messages",
		strings.NewReader(`{"model":"claude-sonnet-4","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", "sk-ant-secret")
	req.Header.Set("Authorization", "Bearer secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status: got %d want 502", resp.StatusCode)
	}
	if turns := sink.all(); len(turns) != 0 {
		t.Fatalf("api turns: got %d want 0 for transport failure", len(turns))
	}
	events := netSink.waitForCount(1)
	if len(events) != 1 {
		t.Fatalf("network events: got %d want 1", len(events))
	}
	ev := events[0]
	if ev.Type != processobs.EventNetworkConnect {
		t.Fatalf("event type: got %q", ev.Type)
	}
	if ev.TargetKind != "url" || ev.Target == "" {
		t.Fatalf("target not captured: kind=%q target=%q", ev.TargetKind, ev.Target)
	}
	if ev.NetworkBody == nil {
		t.Fatal("network body not captured")
	}
	body := ev.NetworkBody
	if body.StatusCode != 0 {
		t.Errorf("status code: got %d want 0 for no upstream response", body.StatusCode)
	}
	if body.BodyUnavailableReason != "upstream_transport_error" {
		t.Errorf("unavailable reason: got %q", body.BodyUnavailableReason)
	}
	if !strings.Contains(body.RequestBody, "claude-sonnet-4") {
		t.Errorf("request body excerpt missing model: %q", body.RequestBody)
	}
	if body.ResponseBody != "" || body.ResponseBodyBytes != 0 {
		t.Errorf("response body should be empty on transport failure: body=%q bytes=%d", body.ResponseBody, body.ResponseBodyBytes)
	}
	if strings.Contains(strings.ToLower(body.RequestHeadersJSON), "authorization") ||
		strings.Contains(strings.ToLower(body.RequestHeadersJSON), "x-api-key") {
		t.Fatalf("sensitive header leaked into capture: %s", body.RequestHeadersJSON)
	}
	if !strings.Contains(body.RequestHeadersJSON, "content-type") {
		t.Fatalf("allowed content-type header missing: %s", body.RequestHeadersJSON)
	}
	if got := fmt.Sprint(ev.Details["body_unavailable_reason"]); got != "upstream_transport_error" {
		t.Errorf("details unavailable reason: %q", got)
	}
	if !strings.Contains(fmt.Sprint(ev.Details["error"]), "handshake failure") {
		t.Errorf("details error missing transport error: %#v", ev.Details)
	}
}

func TestProxy_ProcessNetworkCapturesSuccessfulBodiesAndHeaders(t *testing.T) {
	const requestBody = `{"model":"claude-sonnet-4","messages":[{"role":"user","content":"hi"}]}`
	const responseBody = `{"id":"msg_net_ok","model":"claude-sonnet-4","usage":{"input_tokens":2,"output_tokens":3}}`
	netSink := &fakeNetworkSink{}
	anth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Api-Key"); got != "sk-ant-secret" {
			t.Errorf("upstream auth header = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-Id", "req-success")
		w.Header().Set("Set-Cookie", "sensitive=yes")
		_, _ = w.Write([]byte(responseBody))
	}))
	defer anth.Close()
	p, err := New(Options{
		AnthropicUpstream: anth.URL,
		OpenAIUpstream:    "https://api.openai.com",
		Sink:              &fakeSink{},
		NetworkSink:       netSink,
		NetworkCapture: NetworkCaptureOptions{
			Enabled:          true,
			CaptureBodies:    "proxied",
			MaxRequestBytes:  1024,
			MaxResponseBytes: 1024,
			CaptureHeaders:   true,
			ScrubBodies:      true,
		},
	})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	req, _ := http.NewRequest("POST", ts.URL+"/v1/messages", strings.NewReader(requestBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", "sk-ant-secret")
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("User-Agent", "observer-test")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d want 200", resp.StatusCode)
	}

	events := netSink.waitForCount(1)
	if len(events) != 1 {
		t.Fatalf("network events: got %d want 1", len(events))
	}
	ev := events[0]
	if got := ev.Details["body_unavailable_reason"]; got != nil {
		t.Fatalf("unexpected unavailable reason: %#v", got)
	}
	body := ev.NetworkBody
	if body == nil {
		t.Fatal("network body missing")
	}
	if body.StatusCode != http.StatusOK || body.RequestID != "msg_net_ok" {
		t.Errorf("status/request id = %d/%q", body.StatusCode, body.RequestID)
	}
	if body.RequestBody != requestBody {
		t.Errorf("request body = %q", body.RequestBody)
	}
	if body.ResponseBody != responseBody {
		t.Errorf("response body = %q", body.ResponseBody)
	}
	if body.RequestBodySHA256 == "" || body.ResponseBodySHA256 == "" {
		t.Error("body hashes should be present")
	}
	lowerReq := strings.ToLower(body.RequestHeadersJSON)
	if !strings.Contains(lowerReq, "content-type") || !strings.Contains(lowerReq, "user-agent") {
		t.Fatalf("allowed request headers missing: %s", body.RequestHeadersJSON)
	}
	if strings.Contains(lowerReq, "authorization") || strings.Contains(lowerReq, "x-api-key") {
		t.Fatalf("sensitive request header leaked: %s", body.RequestHeadersJSON)
	}
	lowerResp := strings.ToLower(body.ResponseHeadersJSON)
	if !strings.Contains(lowerResp, "x-request-id") || !strings.Contains(lowerResp, "content-type") {
		t.Fatalf("allowed response headers missing: %s", body.ResponseHeadersJSON)
	}
	if strings.Contains(lowerResp, "set-cookie") {
		t.Fatalf("sensitive response header leaked: %s", body.ResponseHeadersJSON)
	}
}

func TestProxy_ProcessNetworkCapturesStreamBody(t *testing.T) {
	sse := strings.Join([]string{
		`event: message_start`,
		`data: {"type":"message_start","message":{"id":"msg_stream_net","model":"claude-sonnet-4","usage":{"input_tokens":1,"output_tokens":0}}}`,
		``,
		`event: message_delta`,
		`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":2}}`,
		``,
		`event: message_stop`,
		`data: {"type":"message_stop"}`,
		``,
	}, "\n")
	netSink := &fakeNetworkSink{}
	anth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(sse))
	}))
	defer anth.Close()
	p, err := New(Options{
		AnthropicUpstream: anth.URL,
		OpenAIUpstream:    "https://api.openai.com",
		Sink:              &fakeSink{},
		NetworkSink:       netSink,
		NetworkCapture: NetworkCaptureOptions{
			Enabled:          true,
			CaptureBodies:    "proxied",
			MaxRequestBytes:  1024,
			MaxResponseBytes: 4096,
			CaptureHeaders:   true,
			ScrubBodies:      true,
		},
	})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/v1/messages", "application/json",
		strings.NewReader(`{"model":"claude-sonnet-4","stream":true,"messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d want 200", resp.StatusCode)
	}
	events := netSink.waitForCount(1)
	if len(events) != 1 {
		t.Fatalf("network events: got %d want 1", len(events))
	}
	ev := events[0]
	if stream, ok := ev.Details["stream"].(bool); !ok || !stream {
		t.Fatalf("stream detail = %#v want true", ev.Details["stream"])
	}
	if ev.NetworkBody == nil {
		t.Fatal("network body missing")
	}
	if ev.NetworkBody.ResponseContentType != "text/event-stream" {
		t.Errorf("response content type = %q", ev.NetworkBody.ResponseContentType)
	}
	if !strings.Contains(ev.NetworkBody.ResponseBody, "message_start") {
		t.Errorf("stream response body missing SSE content: %q", ev.NetworkBody.ResponseBody)
	}
}

func TestProcessNetworkCapBodyHardening(t *testing.T) {
	t.Run("binary body stores hash and byte count only", func(t *testing.T) {
		got := capBody([]byte{0, 1, 2, 3}, 1024, "application/octet-stream", false, false)
		if got.Text != "" {
			t.Fatalf("binary text = %q want empty", got.Text)
		}
		if got.Bytes != 4 || got.SHA256 == "" {
			t.Fatalf("bytes/hash = %d/%q", got.Bytes, got.SHA256)
		}
		if got.UnavailableReason != "binary_content_type" {
			t.Fatalf("unavailable = %q want binary_content_type", got.UnavailableReason)
		}
	})
	t.Run("text body caps and flags truncation", func(t *testing.T) {
		got := capBody([]byte("abcdef"), 3, "text/plain", false, false)
		if got.Text != "abc" || !got.Truncated || got.Bytes != 6 {
			t.Fatalf("cap = text %q truncated %v bytes %d", got.Text, got.Truncated, got.Bytes)
		}
	})
	t.Run("sse body is textual", func(t *testing.T) {
		got := capBody([]byte("data: {}\n\n"), 1024, "text/event-stream", false, false)
		if got.Text == "" || got.UnavailableReason != "" {
			t.Fatalf("sse cap = text %q unavailable %q", got.Text, got.UnavailableReason)
		}
	})
}

func TestProxy_OpenAIWebSocketUpgradePassthrough(t *testing.T) {
	seen := make(chan *http.Request, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clone := r.Clone(r.Context())
		clone.Header = r.Header.Clone()
		seen <- clone

		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Error("upstream response writer does not support hijacking")
			return
		}
		conn, rw, err := hj.Hijack()
		if err != nil {
			t.Errorf("hijack upstream: %v", err)
			return
		}
		defer conn.Close()
		_, _ = fmt.Fprint(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: test\r\n\r\n")
		_ = rw.Flush()
	}))
	defer upstream.Close()

	sink := &fakeSink{}
	p, err := New(Options{
		AnthropicUpstream: "https://api.anthropic.com",
		OpenAIUpstream:    upstream.URL + "/root",
		Sink:              sink,
	})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	proxyURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	conn, err := net.Dial("tcp", proxyURL.Host)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	_, err = fmt.Fprintf(conn, "GET /v1/responses?conversation=abc HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nAuthorization: Bearer chatgpt-token\r\nX-Session-Id: local-session\r\n\r\n", proxyURL.Host)
	if err != nil {
		t.Fatalf("write upgrade request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status: got %d want %d", resp.StatusCode, http.StatusSwitchingProtocols)
	}

	select {
	case req := <-seen:
		if req.URL.Path != "/root/v1/responses" {
			t.Errorf("upstream path: got %q want %q", req.URL.Path, "/root/v1/responses")
		}
		if req.URL.RawQuery != "conversation=abc" {
			t.Errorf("upstream query: got %q", req.URL.RawQuery)
		}
		if !headerHasToken(req.Header.Get("Connection"), "upgrade") {
			t.Errorf("Connection header: got %q, want upgrade token", req.Header.Get("Connection"))
		}
		if got := req.Header.Get("Upgrade"); !strings.EqualFold(got, "websocket") {
			t.Errorf("Upgrade header: got %q want websocket", got)
		}
		if got := req.Header.Get("Authorization"); got != "Bearer chatgpt-token" {
			t.Errorf("Authorization header: got %q", got)
		}
		if got := req.Header.Get("X-Session-Id"); got != "" {
			t.Errorf("X-Session-Id leaked upstream: %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not receive websocket upgrade request")
	}
	if len(sink.all()) != 0 {
		t.Errorf("turns recorded: got %d want 0 for opaque websocket tunnel", len(sink.all()))
	}
}

func TestProxy_ChatGPTBackendRoutesToChatGPTUpstream(t *testing.T) {
	seen := make(chan *http.Request, 1)
	chatgpt := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clone := r.Clone(r.Context())
		clone.Header = r.Header.Clone()
		seen <- clone
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"resp_chatgpt","model":"gpt-5.5","usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer chatgpt.Close()

	sink := &fakeSink{}
	p, err := New(Options{
		AnthropicUpstream: "https://anthropic.invalid",
		OpenAIUpstream:    "https://openai.invalid",
		ChatGPTUpstream:   chatgpt.URL + "/root",
		Sink:              sink,
	})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/backend-api/codex/responses", "application/json",
		strings.NewReader(`{"model":"gpt-5.5","input":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatalf("client request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d want 200", resp.StatusCode)
	}

	select {
	case req := <-seen:
		if req.URL.Path != "/root/backend-api/codex/responses" {
			t.Errorf("upstream path: got %q", req.URL.Path)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("chatgpt upstream was not hit")
	}
	turns := sink.all()
	if len(turns) != 1 {
		t.Fatalf("turns: got %d want 1", len(turns))
	}
	if turns[0].Provider != models.ProviderOpenAI {
		t.Errorf("provider: got %q want openai", turns[0].Provider)
	}
	if turns[0].MessageCount != 1 {
		t.Errorf("message count: got %d want 1", turns[0].MessageCount)
	}
}

func TestProxy_ChatGPTBackendWebSocketUpgradePassthrough(t *testing.T) {
	seen := make(chan *http.Request, 1)
	chatgpt := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clone := r.Clone(r.Context())
		clone.Header = r.Header.Clone()
		seen <- clone
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Error("upstream response writer does not support hijacking")
			return
		}
		conn, rw, err := hj.Hijack()
		if err != nil {
			t.Errorf("hijack upstream: %v", err)
			return
		}
		defer conn.Close()
		_, _ = fmt.Fprint(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: test\r\n\r\n")
		_ = rw.Flush()
	}))
	defer chatgpt.Close()

	p, err := New(Options{
		AnthropicUpstream: "https://anthropic.invalid",
		OpenAIUpstream:    "https://openai.invalid",
		ChatGPTUpstream:   chatgpt.URL,
		Sink:              &fakeSink{},
	})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	proxyURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	conn, err := net.Dial("tcp", proxyURL.Host)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	_, err = fmt.Fprintf(conn, "GET /backend-api/codex/responses HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nAuthorization: Bearer chatgpt-token\r\n\r\n", proxyURL.Host)
	if err != nil {
		t.Fatalf("write upgrade request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status: got %d want %d", resp.StatusCode, http.StatusSwitchingProtocols)
	}

	select {
	case req := <-seen:
		if req.URL.Path != "/backend-api/codex/responses" {
			t.Errorf("upstream path: got %q", req.URL.Path)
		}
		if got := req.Header.Get("Authorization"); got != "Bearer chatgpt-token" {
			t.Errorf("Authorization: got %q", got)
		}
		if !headerHasToken(req.Header.Get("Connection"), "upgrade") {
			t.Errorf("Connection header: got %q, want upgrade token", req.Header.Get("Connection"))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("chatgpt upstream did not receive websocket upgrade")
	}
}

func TestProxy_ForceChatGPTHTTPRejectsWebSocketUpgrade(t *testing.T) {
	chatgpt := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("chatgpt upstream unexpectedly hit: %s", r.URL.Path)
	}))
	defer chatgpt.Close()

	p, err := New(Options{
		AnthropicUpstream: "https://anthropic.invalid",
		OpenAIUpstream:    "https://openai.invalid",
		ChatGPTUpstream:   chatgpt.URL,
		ForceChatGPTHTTP:  true,
		Sink:              &fakeSink{},
	})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	req, err := http.NewRequest("GET", ts.URL+"/backend-api/codex/responses", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("client request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUpgradeRequired {
		t.Fatalf("status: got %d want %d", resp.StatusCode, http.StatusUpgradeRequired)
	}
}

func TestProxy_ZstdRequestCompressionRoundTrip(t *testing.T) {
	original := []byte(`{"model":"gpt-5","input":[{"role":"user","content":"large"}]}`)
	compressedJSON := []byte(`{"model":"gpt-5","input":[{"role":"user","content":"small"}]}`)
	encodedOriginal, err := encodeZstd(original)
	if err != nil {
		t.Fatalf("encode original: %v", err)
	}

	received := make(chan []byte, 1)
	openai := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Content-Encoding"); got != "zstd" {
			t.Errorf("Content-Encoding: got %q want zstd", got)
		}
		body, _ := io.ReadAll(r.Body)
		decoded, err := decodeZstd(body)
		if err != nil {
			t.Errorf("decode upstream body: %v", err)
		}
		received <- decoded
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"resp_1","model":"gpt-5","usage":{"input_tokens":1,"output_tokens":1}}`))
	})
	p, sink, cleanup := newTestProxy(t, http.NotFoundHandler(), openai)
	defer cleanup()
	fake := &fakeCompressor{result: CompressionResult{
		Body:            compressedJSON,
		Skipped:         false,
		OriginalBytes:   len(original),
		CompressedBytes: len(compressedJSON),
	}}
	p.compressor = fake

	ts := httptest.NewServer(p.Handler())
	defer ts.Close()
	req, err := http.NewRequest("POST", ts.URL+"/v1/responses", bytes.NewReader(encodedOriginal))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "zstd")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("client request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d want 200", resp.StatusCode)
	}

	if got := string(fake.received); got != string(original) {
		t.Fatalf("compressor input: got %s want %s", got, original)
	}
	select {
	case got := <-received:
		if !bytes.Equal(got, compressedJSON) {
			t.Fatalf("upstream decoded body: got %s want %s", got, compressedJSON)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not receive request")
	}
	turns := sink.all()
	if len(turns) != 1 {
		t.Fatalf("turns: got %d want 1", len(turns))
	}
	if turns[0].MessageCount != 1 {
		t.Errorf("message count: got %d want 1 from decoded zstd request", turns[0].MessageCount)
	}
}

// roundTripFunc is a tiny adapter so tests can pass a func as
// http.RoundTripper without spinning up a real httptest server (we
// can't simulate TCP-level resets through a real server).
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestProxy_NewValidation(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Error("missing sink should error")
	}
	if _, err := New(Options{Sink: &fakeSink{}, AnthropicUpstream: "not a url"}); err == nil {
		t.Error("bad upstream url should error")
	}
}

func TestProviderForPath(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"/v1/messages", models.ProviderAnthropic},
		{"/v1/messages/batches", models.ProviderAnthropic},
		{"/v1/chat/completions", models.ProviderOpenAI},
		{"/v1/responses", models.ProviderOpenAI},
		{"/v1/embeddings", models.ProviderOpenAI},
		{"/backend-api/codex/responses", models.ProviderOpenAI},
		{"/backend-api/plugins/list", models.ProviderOpenAI},
		{"/", models.ProviderAnthropic},
		{"/health", models.ProviderAnthropic},
	}
	for _, tc := range cases {
		if got := providerForPath(tc.path); got != tc.want {
			t.Errorf("providerForPath(%q) = %s, want %s", tc.path, got, tc.want)
		}
	}
}

func TestIsChatGPTAuthRequest(t *testing.T) {
	cases := []struct {
		name string
		auth string
		want bool
	}{
		{"chatgpt jwt", "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig", true},
		{"openai api key", "Bearer sk-proj-xyz123", false},
		{"anthropic key (no Bearer)", "x-api-key: sk-ant-xyz", false},
		{"empty", "", false},
		{"bearer empty", "Bearer ", false},
		{"non-jwt non-sk token", "Bearer some-other-token", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/v1/responses", nil)
			if tc.auth != "" {
				r.Header.Set("Authorization", tc.auth)
			}
			if got := isChatGPTAuthRequest(r); got != tc.want {
				t.Errorf("isChatGPTAuthRequest(%q) = %v, want %v", tc.auth, got, tc.want)
			}
		})
	}
}

func TestTranslateChatGPTPath(t *testing.T) {
	cases := map[string]string{
		"/v1/responses":                "/backend-api/codex/responses",
		"/v1/models":                   "/backend-api/codex/models",
		"/v1/chat/completions":         "/backend-api/codex/chat/completions",
		"/v1/messages":                 "/v1/messages", // anthropic — untouched
		"/backend-api/codex/responses": "/backend-api/codex/responses",
		"/health":                      "/health",
	}
	for in, want := range cases {
		if got := translateChatGPTPath(in); got != want {
			t.Errorf("translateChatGPTPath(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestProxy_ChatGPTAuthShortCircuitsModelsList: chatgpt.com doesn't
// expose /backend-api/codex/models, so codex's model-list refresher
// would hammer it and log 401s on every turn. The proxy short-circuits
// the request with a synthetic empty-list 200 and skips the upstream
// trip entirely.
func TestProxy_ChatGPTAuthShortCircuitsModelsList(t *testing.T) {
	chatgptHits := 0
	chatgpt := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chatgptHits++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer chatgpt.Close()
	openai := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("openai unexpectedly hit: %s", r.URL.Path)
	}))
	defer openai.Close()

	sink := &fakeSink{}
	p, err := New(Options{
		AnthropicUpstream: "https://anthropic.invalid",
		OpenAIUpstream:    openai.URL,
		ChatGPTUpstream:   chatgpt.URL,
		Sink:              sink,
	})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/v1/models?client_version=0.128.0", nil)
	req.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("client request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"models":[]`) {
		t.Errorf("body: got %q, want empty list", body)
	}
	if chatgptHits != 0 {
		t.Errorf("upstream hit %d times — should short-circuit", chatgptHits)
	}
	if len(sink.all()) != 0 {
		t.Errorf("api_turn recorded for synthetic /v1/models — should not be")
	}
}

// TestProxy_ChatGPTAuthRoutesV1ResponsesToChatGPTUpstream is the
// integration of isChatGPTAuthRequest + translateChatGPTPath: a codex
// 0.128.0+ POST to /v1/responses with a ChatGPT JWT bearer must land
// at chatgpt.com/backend-api/codex/responses, not api.openai.com/v1/responses.
func TestProxy_ChatGPTAuthRoutesV1ResponsesToChatGPTUpstream(t *testing.T) {
	chatgptHit := make(chan *http.Request, 1)
	chatgpt := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chatgptHit <- r.Clone(r.Context())
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"resp_x","model":"gpt-5.5","usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer chatgpt.Close()

	openai := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("openai upstream unexpectedly hit: %s", r.URL.Path)
	}))
	defer openai.Close()

	sink := &fakeSink{}
	p, err := New(Options{
		AnthropicUpstream: "https://anthropic.invalid",
		OpenAIUpstream:    openai.URL,
		ChatGPTUpstream:   chatgpt.URL,
		Sink:              sink,
	})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	req, _ := http.NewRequest("POST", ts.URL+"/v1/responses", strings.NewReader(`{"model":"gpt-5.5","input":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("client request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d", resp.StatusCode)
	}

	select {
	case got := <-chatgptHit:
		if got.URL.Path != "/backend-api/codex/responses" {
			t.Errorf("upstream path: got %q, want /backend-api/codex/responses", got.URL.Path)
		}
		if got.Header.Get("Authorization") != "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig" {
			t.Errorf("Authorization not forwarded: %q", got.Header.Get("Authorization"))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("chatgpt upstream was never hit")
	}
}

// fakeCompressor is a test double for the Compressor interface. It
// returns a fixed CompressionResult and records the body it received so
// assertions can verify the proxy fed the correct input.
type fakeCompressor struct {
	mu        sync.Mutex
	received  []byte
	provider  string
	result    CompressionResult
	callCount int
}

func (f *fakeCompressor) Compress(_ context.Context, provider string, body []byte) CompressionResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.received = append([]byte{}, body...)
	f.provider = provider
	f.callCount++
	return f.result
}

// fakeObsLog captures observer_log writes from the proxy.
type fakeObsLog struct {
	mu      sync.Mutex
	entries []obsEntry
}

type obsEntry struct {
	level, component, message, details string
}

func (f *fakeObsLog) InsertObserverLog(_ context.Context, level, component, message, details string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries = append(f.entries, obsEntry{level, component, message, details})
	return nil
}

func TestProxy_CompressorRunsBeforeForward(t *testing.T) {
	const clientBody = `{"model":"claude-sonnet-4","messages":[{"role":"user","content":"original input that will not reach upstream"}]}`
	const compressedBody = `{"model":"claude-sonnet-4","messages":[{"role":"user","content":"compressed"}]}`
	const responseBody = `{"id":"msg_abc","model":"claude-sonnet-4","stop_reason":"end_turn","usage":{"input_tokens":5,"output_tokens":2}}`

	var seenBody string
	anth := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seenBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(responseBody))
	})
	oai := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("openai unexpected") })

	anthUp := httptest.NewServer(anth)
	oaiUp := httptest.NewServer(oai)
	defer anthUp.Close()
	defer oaiUp.Close()

	sink := &fakeSink{}
	comp := &fakeCompressor{
		result: CompressionResult{
			Body:              []byte(compressedBody),
			Skipped:           false,
			MessagePrefixHash: "deadbeef",
			OriginalBytes:     len(clientBody),
			CompressedBytes:   len(compressedBody),
			CompressedCount:   1,
		},
	}
	obs := &fakeObsLog{}

	p, err := New(Options{
		AnthropicUpstream: anthUp.URL,
		OpenAIUpstream:    oaiUp.URL,
		Sink:              sink,
		Compressor:        comp,
		ObserverLog:       obs,
	})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	srv := httptest.NewServer(p.Handler())
	defer srv.Close()

	req, _ := http.NewRequest("POST", srv.URL+"/v1/messages", strings.NewReader(clientBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("client POST: %v", err)
	}
	_ = resp.Body.Close()

	if comp.callCount != 1 {
		t.Errorf("compressor call count = %d, want 1", comp.callCount)
	}
	if string(comp.received) != clientBody {
		t.Errorf("compressor received %q, want client body", comp.received)
	}
	if seenBody != compressedBody {
		t.Errorf("upstream saw %q, want compressed body %q", seenBody, compressedBody)
	}
	turns := sink.all()
	if len(turns) != 1 {
		t.Fatalf("turns = %d, want 1", len(turns))
	}
	if turns[0].MessagePrefixHash != "deadbeef" {
		t.Errorf("turn.MessagePrefixHash = %q, want deadbeef", turns[0].MessagePrefixHash)
	}
	obs.mu.Lock()
	entries := obs.entries
	obs.mu.Unlock()
	if len(entries) != 1 {
		t.Fatalf("observer_log entries = %d, want 1", len(entries))
	}
	if entries[0].component != "compress" {
		t.Errorf("observer_log component = %q, want compress", entries[0].component)
	}
	if !strings.Contains(entries[0].details, `"original_bytes":`+strconv.Itoa(len(clientBody))) {
		t.Errorf("observer_log details missing original_bytes: %q", entries[0].details)
	}
}

func TestProxy_SkippedCompressionLeavesBodyIntact(t *testing.T) {
	const clientBody = `{"model":"claude-sonnet-4","messages":[{"role":"user","content":"hi"}]}`
	const responseBody = `{"id":"msg_abc","model":"claude-sonnet-4","stop_reason":"end_turn","usage":{"input_tokens":5,"output_tokens":2}}`

	var seenBody string
	anth := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seenBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(responseBody))
	})
	oai := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("openai unexpected") })
	anthUp := httptest.NewServer(anth)
	oaiUp := httptest.NewServer(oai)
	defer anthUp.Close()
	defer oaiUp.Close()

	sink := &fakeSink{}
	comp := &fakeCompressor{result: CompressionResult{Skipped: true}}
	obs := &fakeObsLog{}
	p, err := New(Options{
		AnthropicUpstream: anthUp.URL,
		OpenAIUpstream:    oaiUp.URL,
		Sink:              sink,
		Compressor:        comp,
		ObserverLog:       obs,
	})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()

	req, _ := http.NewRequest("POST", srv.URL+"/v1/messages", strings.NewReader(clientBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("client POST: %v", err)
	}
	_ = resp.Body.Close()

	if seenBody != clientBody {
		t.Errorf("upstream saw %q, want original body", seenBody)
	}
	obs.mu.Lock()
	entries := obs.entries
	obs.mu.Unlock()
	if len(entries) != 0 {
		t.Errorf("skipped compression should not log to observer_log, got %d entries", len(entries))
	}
	turns := sink.all()
	if len(turns) != 1 {
		t.Fatalf("turns = %d, want 1", len(turns))
	}
	if turns[0].MessagePrefixHash != "" {
		t.Errorf("skipped: turn.MessagePrefixHash = %q, want empty", turns[0].MessagePrefixHash)
	}
}

// TestProxy_InvalidCompressedJSONFallsBackToOriginal is the hard-guard
// regression: when the compressor returns a non-empty body that is NOT
// valid JSON, the proxy must forward the ORIGINAL (pre-compression) body
// rather than the mangled one — forwarding invalid JSON makes the upstream
// reject the whole request (400 "unexpected character") and cascades the
// session. The request must still succeed and a turn must still record.
func TestProxy_InvalidCompressedJSONFallsBackToOriginal(t *testing.T) {
	const clientBody = `{"model":"claude-sonnet-4","messages":[{"role":"user","content":"original input must reach upstream"}]}`
	// Non-empty, Skipped:false, but malformed JSON (a truncated object —
	// the exact shape the conversation compressor produced on large bodies).
	const mangled = `{"model":"claude-sonnet-4","messages":[{"role":"user","content":`
	const responseBody = `{"id":"msg_abc","model":"claude-sonnet-4","stop_reason":"end_turn","usage":{"input_tokens":5,"output_tokens":2}}`

	var seenBody string
	anth := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seenBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(responseBody))
	})
	oai := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("openai unexpected") })
	anthUp := httptest.NewServer(anth)
	oaiUp := httptest.NewServer(oai)
	defer anthUp.Close()
	defer oaiUp.Close()

	sink := &fakeSink{}
	comp := &fakeCompressor{result: CompressionResult{
		Body:            []byte(mangled),
		Skipped:         false,
		OriginalBytes:   len(clientBody),
		CompressedBytes: len(mangled),
		CompressedCount: 1,
	}}
	obs := &fakeObsLog{}
	p, err := New(Options{
		AnthropicUpstream: anthUp.URL,
		OpenAIUpstream:    oaiUp.URL,
		Sink:              sink,
		Compressor:        comp,
		ObserverLog:       obs,
	})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()

	req, _ := http.NewRequest("POST", srv.URL+"/v1/messages", strings.NewReader(clientBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("client POST: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d want 200", resp.StatusCode)
	}
	_ = resp.Body.Close()

	if comp.callCount != 1 {
		t.Errorf("compressor call count = %d, want 1", comp.callCount)
	}
	if seenBody != clientBody {
		t.Fatalf("upstream saw %q, want ORIGINAL body (invalid compressed JSON must not be forwarded)", seenBody)
	}
	// A turn still records (the request went through, just uncompressed).
	if turns := sink.all(); len(turns) != 1 {
		t.Fatalf("turns = %d, want 1", len(turns))
	}
}

// fakeResolver implements SessionResolver for tests. It returns the
// pre-seeded session_id for one remote addr and records every call.
type fakeResolver struct {
	mu        sync.Mutex
	sessionID string
	ok        bool
	err       error
	calls     []string
}

func (f *fakeResolver) Resolve(_ context.Context, remoteAddr string) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, remoteAddr)
	return f.sessionID, f.ok, f.err
}

func (f *fakeResolver) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func TestProxy_SessionResolverFillsMissingHeader(t *testing.T) {
	const requestBody = `{"model":"claude-sonnet-4","messages":[{"role":"user","content":"hi"}]}`
	const responseBody = `{"id":"msg_abc","model":"claude-sonnet-4","stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`

	anth := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(responseBody))
	})
	oai := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("openai upstream unexpectedly hit")
	})
	anthUp := httptest.NewServer(anth)
	oaiUp := httptest.NewServer(oai)
	defer anthUp.Close()
	defer oaiUp.Close()

	sink := &fakeSink{}
	resolver := &fakeResolver{sessionID: "sess-from-bridge", ok: true}
	p, err := New(Options{
		AnthropicUpstream: anthUp.URL,
		OpenAIUpstream:    oaiUp.URL,
		Sink:              sink,
		SessionResolver:   resolver,
	})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	req, _ := http.NewRequest("POST", ts.URL+"/v1/messages", strings.NewReader(requestBody))
	req.Header.Set("Content-Type", "application/json")
	// No X-Session-Id — expect resolver to fill it in.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	resp.Body.Close()

	turns := sink.all()
	if len(turns) != 1 {
		t.Fatalf("want 1 turn, got %d", len(turns))
	}
	if turns[0].SessionID != "sess-from-bridge" {
		t.Errorf("session id: got %q want %q", turns[0].SessionID, "sess-from-bridge")
	}
	if resolver.callCount() != 1 {
		t.Errorf("resolver call count: got %d want 1", resolver.callCount())
	}
}

func TestProxy_SessionResolverNotCalledWhenHeaderPresent(t *testing.T) {
	const requestBody = `{"model":"claude-sonnet-4","messages":[{"role":"user","content":"hi"}]}`
	const responseBody = `{"id":"msg_abc","model":"claude-sonnet-4","stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`

	anth := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(responseBody))
	})
	anthUp := httptest.NewServer(anth)
	defer anthUp.Close()

	sink := &fakeSink{}
	resolver := &fakeResolver{sessionID: "sess-from-bridge", ok: true}
	p, err := New(Options{
		AnthropicUpstream: anthUp.URL,
		OpenAIUpstream:    "https://unused.example",
		Sink:              sink,
		SessionResolver:   resolver,
	})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	req, _ := http.NewRequest("POST", ts.URL+"/v1/messages", strings.NewReader(requestBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Session-Id", "header-wins")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	resp.Body.Close()

	turns := sink.all()
	if len(turns) != 1 {
		t.Fatalf("want 1 turn, got %d", len(turns))
	}
	if turns[0].SessionID != "header-wins" {
		t.Errorf("session id: got %q want %q", turns[0].SessionID, "header-wins")
	}
	if resolver.callCount() != 0 {
		t.Errorf("resolver should not be called when header is present (called %d times)", resolver.callCount())
	}
}

func TestProxy_SessionResolverMissLeavesNull(t *testing.T) {
	const requestBody = `{"model":"claude-sonnet-4","messages":[{"role":"user","content":"hi"}]}`
	const responseBody = `{"id":"msg_abc","model":"claude-sonnet-4","stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`

	anth := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(responseBody))
	})
	anthUp := httptest.NewServer(anth)
	defer anthUp.Close()

	sink := &fakeSink{}
	resolver := &fakeResolver{ok: false} // clean miss
	p, err := New(Options{
		AnthropicUpstream: anthUp.URL,
		OpenAIUpstream:    "https://unused.example",
		Sink:              sink,
		SessionResolver:   resolver,
	})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	req, _ := http.NewRequest("POST", ts.URL+"/v1/messages", strings.NewReader(requestBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	resp.Body.Close()

	turns := sink.all()
	if len(turns) != 1 {
		t.Fatalf("want 1 turn, got %d", len(turns))
	}
	if turns[0].SessionID != "" {
		t.Errorf("session id: got %q want empty", turns[0].SessionID)
	}
}

// TestProxy_OrdinaryResolvedSessionRejectedOnHostedLane is the PLANE BOUNDARY
// regression pin (operator-reported class, 2026-08-13): a request that
// arrives on an explicit /up/<id> hosted lane (Plane A) must never ACCEPT an
// ordinary process-resolved coding-agent session (Plane B). The Arena runner
// now has a narrowly prefixed synthetic exception, so the resolver is
// consulted but this ordinary result must still leave the turn unattributed.
func TestProxy_OrdinaryResolvedSessionRejectedOnHostedLane(t *testing.T) {
	const requestBody = `{"model":"claude-sonnet-4","messages":[{"role":"user","content":"hi"}]}`
	const responseBody = `{"id":"msg_abc","model":"claude-sonnet-4","stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`

	anth := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(responseBody))
	})
	anthUp := httptest.NewServer(anth)
	defer anthUp.Close()

	sink := &fakeSink{}
	resolver := &fakeResolver{sessionID: "sess-from-bridge", ok: true}
	p, err := New(Options{
		AnthropicUpstream: anthUp.URL,
		OpenAIUpstream:    "https://unused.example",
		// The hosted lane routes to the same upstream; its PRESENCE on the
		// /up/ prefix is what marks the request Plane A.
		Upstreams:       map[string]string{"hosted": anthUp.URL},
		Sink:            sink,
		SessionResolver: resolver,
	})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	// Hosted lane, NO X-Session-Id: an ordinary bridge result is rejected.
	req, _ := http.NewRequest("POST", ts.URL+"/up/hosted/v1/messages", strings.NewReader(requestBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	resp.Body.Close()

	turns := sink.all()
	if len(turns) != 1 {
		t.Fatalf("want 1 turn, got %d", len(turns))
	}
	if turns[0].SessionID != "" {
		t.Errorf("hosted-lane turn borrowed a coding-agent session_id: got %q want empty", turns[0].SessionID)
	}
	if resolver.callCount() != 1 {
		t.Errorf("SessionResolver calls = %d, want 1 prefix check", resolver.callCount())
	}
}

func TestProxy_ArenaSyntheticSessionAcceptedOnHostedLane(t *testing.T) {
	resolver := &fakeResolver{sessionID: models.ArenaSessionIDPrefix + "run-grok", ok: true}
	p := &Proxy{sessions: resolver, logger: slog.Default()}
	req := httptest.NewRequest(http.MethodPost, "/up/grok/v1/chat/completions", strings.NewReader(`{"model":"grok"}`))
	req = req.WithContext(context.WithValue(req.Context(), obsLaneCtxKey{}, "grok"))
	got := p.resolveAPITurnSessionID(req, models.ProviderOpenAI, []byte(`{"model":"grok"}`))
	if got != models.ArenaSessionIDPrefix+"run-grok" {
		t.Fatalf("synthetic Arena session = %q", got)
	}
}

// TestParseAnthropicResponse_CacheCreationTierBreakdown verifies the
// non-streaming response parser captures both
// usage.cache_creation_input_tokens (the legacy total) and the per-tier
// breakdown under usage.cache_creation. The 1h subset must land in
// CacheCreation1hTokens so the cost engine can bill it at the higher
// rate. Audit item C5.
func TestParseAnthropicResponse_CacheCreationTierBreakdown(t *testing.T) {
	body := []byte(`{
		"id": "msg_abc",
		"model": "claude-sonnet-4",
		"stop_reason": "end_turn",
		"usage": {
			"input_tokens": 100,
			"output_tokens": 50,
			"cache_read_input_tokens": 1000,
			"cache_creation_input_tokens": 600,
			"cache_creation": {
				"ephemeral_5m_input_tokens": 400,
				"ephemeral_1h_input_tokens": 200
			}
		}
	}`)
	got := parseAnthropicResponse(body)
	if got.CacheCreationTokens != 600 {
		t.Errorf("cache_creation total: got %d want 600", got.CacheCreationTokens)
	}
	if got.CacheCreation1hTokens != 200 {
		t.Errorf("cache_creation 1h: got %d want 200", got.CacheCreation1hTokens)
	}

	// Newer-only shape: breakdown present without the legacy total.
	bodyNew := []byte(`{
		"id": "msg_xyz",
		"model": "claude-sonnet-4",
		"usage": {
			"input_tokens": 50,
			"output_tokens": 25,
			"cache_creation": {
				"ephemeral_5m_input_tokens": 300,
				"ephemeral_1h_input_tokens": 150
			}
		}
	}`)
	got = parseAnthropicResponse(bodyNew)
	if got.CacheCreationTokens != 450 {
		t.Errorf("cache_creation total derived: got %d want 450", got.CacheCreationTokens)
	}
	if got.CacheCreation1hTokens != 150 {
		t.Errorf("cache_creation 1h derived: got %d want 150", got.CacheCreation1hTokens)
	}

	// Legacy-only shape (current data): cache_creation total is set, no
	// breakdown — 1h portion is zero.
	bodyLegacy := []byte(`{
		"id": "msg_old",
		"model": "claude-sonnet-4",
		"usage": {
			"input_tokens": 10,
			"output_tokens": 5,
			"cache_creation_input_tokens": 800
		}
	}`)
	got = parseAnthropicResponse(bodyLegacy)
	if got.CacheCreationTokens != 800 {
		t.Errorf("cache_creation legacy: got %d want 800", got.CacheCreationTokens)
	}
	if got.CacheCreation1hTokens != 0 {
		t.Errorf("cache_creation 1h on legacy shape: got %d want 0", got.CacheCreation1hTokens)
	}
}

// TestParseAnthropicStream_CacheCreationTierBreakdown verifies the SSE
// parser captures the 1h tier subset from message_start.message.usage
// and exposes it as CacheCreation1hTokens.
func TestParseAnthropicStream_CacheCreationTierBreakdown(t *testing.T) {
	sse := strings.Join([]string{
		`event: message_start`,
		`data: {"type":"message_start","message":{"id":"msg_1","model":"claude-sonnet-4","usage":{"input_tokens":120,"cache_read_input_tokens":500,"cache_creation_input_tokens":600,"cache_creation":{"ephemeral_5m_input_tokens":400,"ephemeral_1h_input_tokens":200},"output_tokens":1}}}`,
		``,
		`event: message_delta`,
		`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":42}}`,
		``,
	}, "\n")
	got := parseSSEStream([]byte(sse), models.ProviderAnthropic)
	if got.CacheCreationTokens != 600 {
		t.Errorf("cache_creation total: got %d want 600", got.CacheCreationTokens)
	}
	if got.CacheCreation1hTokens != 200 {
		t.Errorf("cache_creation 1h: got %d want 200", got.CacheCreation1hTokens)
	}

	// 1h breakdown lands on message_delta in some Anthropic SSE variants.
	sseDelta := strings.Join([]string{
		`event: message_start`,
		`data: {"type":"message_start","message":{"id":"msg_2","model":"claude-sonnet-4","usage":{"input_tokens":100,"output_tokens":1}}}`,
		``,
		`event: message_delta`,
		`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":50,"cache_creation_input_tokens":300,"cache_creation":{"ephemeral_5m_input_tokens":200,"ephemeral_1h_input_tokens":100}}}`,
		``,
	}, "\n")
	got = parseSSEStream([]byte(sseDelta), models.ProviderAnthropic)
	if got.CacheCreationTokens != 300 {
		t.Errorf("delta cache_creation total: got %d want 300", got.CacheCreationTokens)
	}
	if got.CacheCreation1hTokens != 100 {
		t.Errorf("delta cache_creation 1h: got %d want 100", got.CacheCreation1hTokens)
	}
}

// TestExtractOpenAISessionID covers the prompt_cache_key parse paths
// the proxy depends on for per-session grouping on OpenAI traffic.
// Codex 0.129.0 sets prompt_cache_key to a UUIDv7 equal to the
// session_id HTTP header value.
func TestExtractOpenAISessionID(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "codex shape",
			body: `{"model":"gpt-5-codex","prompt_cache_key":"019e05fc-dfe7-77a1-8db0-c7d13f8be248","input":[]}`,
			want: "019e05fc-dfe7-77a1-8db0-c7d13f8be248",
		},
		{name: "missing prompt_cache_key", body: `{"model":"gpt-5-codex","input":[]}`, want: ""},
		{name: "empty body", body: ``, want: ""},
		{name: "malformed top-level json", body: `{not json`, want: ""},
		{name: "prompt_cache_key empty string", body: `{"prompt_cache_key":""}`, want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractOpenAISessionID([]byte(tc.body)); got != tc.want {
				t.Errorf("extractOpenAISessionID(%q) = %q, want %q", tc.body, got, tc.want)
			}
		})
	}
}

// TestExtractAnthropicSessionID covers the metadata.user_id parse paths
// the proxy depends on for per-session A/B grouping. Claude Code SDK
// 2.1+ emits the session_id inside a JSON-encoded user_id string; older
// or non-Claude-Code Anthropic clients may set metadata.user_id to a
// bare string or omit metadata entirely.
func TestExtractAnthropicSessionID(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "claude code shape",
			body: `{"model":"x","metadata":{"user_id":"{\"device_id\":\"abc\",\"account_uuid\":\"\",\"session_id\":\"ad8c07eb-0978-4a96-bd85-7d01b9d9d7bd\"}"}}`,
			want: "ad8c07eb-0978-4a96-bd85-7d01b9d9d7bd",
		},
		{name: "missing metadata", body: `{"model":"x"}`, want: ""},
		{name: "missing user_id", body: `{"metadata":{}}`, want: ""},
		{name: "user_id is bare string (non-claude-code client)", body: `{"metadata":{"user_id":"plain-user-token"}}`, want: ""},
		{name: "user_id parses but no session_id", body: `{"metadata":{"user_id":"{\"device_id\":\"abc\"}"}}`, want: ""},
		{name: "empty body", body: ``, want: ""},
		{name: "malformed top-level json", body: `{not json`, want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractAnthropicSessionID([]byte(tc.body)); got != tc.want {
				t.Errorf("extractAnthropicSessionID(%q) = %q, want %q", tc.body, got, tc.want)
			}
		})
	}
}

// TestProxy_AnthropicSessionIDFromMetadata verifies the body-extracted
// session_id lands in api_turns.session_id end-to-end. Pre-fix all
// proxy rows from Pro/Max OAuth Claude Code carried session_id=NULL
// because no SessionStart hook fires for the launcher path. The SDK
// already embeds a stable per-session UUID in metadata.user_id; the
// proxy now reads it.
func TestProxy_AnthropicSessionIDFromMetadata(t *testing.T) {
	const responseBody = `{"id":"msg_abc","model":"claude-sonnet-4","stop_reason":"end_turn","usage":{"input_tokens":10,"output_tokens":5}}`
	anth := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(responseBody))
	})
	anthUp := httptest.NewServer(anth)
	defer anthUp.Close()
	sink := &fakeSink{}
	p, err := New(Options{AnthropicUpstream: anthUp.URL, Sink: sink})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	const wantSession = "ad8c07eb-0978-4a96-bd85-7d01b9d9d7bd"
	body := `{"model":"claude-sonnet-4","messages":[{"role":"user","content":"hi"}],"metadata":{"user_id":"{\"device_id\":\"abc\",\"account_uuid\":\"\",\"session_id\":\"` + wantSession + `\"}"}}`
	req, _ := http.NewRequest("POST", ts.URL+"/v1/messages", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	turns := sink.all()
	if len(turns) != 1 {
		t.Fatalf("want 1 turn, got %d", len(turns))
	}
	if turns[0].SessionID != wantSession {
		t.Errorf("session_id: got %q want %q", turns[0].SessionID, wantSession)
	}
}

// TestProxy_AnthropicSessionIDHeaderFallback covers the case where the
// body has no metadata.user_id (older SDK or non-Claude-Code Anthropic
// client): the existing X-Session-Id header path must still win.
func TestProxy_AnthropicSessionIDHeaderFallback(t *testing.T) {
	const responseBody = `{"id":"msg_abc","model":"claude-sonnet-4","stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`
	anth := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(responseBody))
	})
	anthUp := httptest.NewServer(anth)
	defer anthUp.Close()
	sink := &fakeSink{}
	p, _ := New(Options{AnthropicUpstream: anthUp.URL, Sink: sink})
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	req, _ := http.NewRequest("POST", ts.URL+"/v1/messages",
		strings.NewReader(`{"model":"claude-sonnet-4","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Session-Id", "from-header")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	turns := sink.all()
	if len(turns) != 1 {
		t.Fatalf("want 1 turn, got %d", len(turns))
	}
	if turns[0].SessionID != "from-header" {
		t.Errorf("session_id: got %q want %q", turns[0].SessionID, "from-header")
	}
}

// TestLooksLikeSSE pins the content-sniff predicate. Used as a fallback
// when an upstream omits Content-Type — chatgpt.com/backend-api/codex/responses
// returns SSE bodies with an empty Content-Type header (codex 0.129.0,
// observed 2026-05-08).
func TestLooksLikeSSE(t *testing.T) {
	cases := []struct {
		name string
		body []byte
		want bool
	}{
		{"event-prefix", []byte("event: response.created\ndata: {}\n\n"), true},
		{"data-prefix", []byte("data: {\"type\":\"x\"}\n\n"), true},
		{"event-no-space", []byte("event:response.created\n"), true},
		{"data-no-space", []byte("data:{\"x\":1}\n"), true},
		{"leading-whitespace", []byte("\n\nevent: response.created\n"), true},
		{"json-object", []byte(`{"id":"resp_1","usage":{"input_tokens":10}}`), false},
		{"plain-text", []byte("hello world"), false},
		{"empty", []byte{}, false},
		{"whitespace-only", []byte("   \n\t\r"), false},
		{"long-leading-whitespace-then-event", []byte(strings.Repeat(" ", 100) + "event: response.created\n"), false}, // sniff-window is 64 bytes
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := looksLikeSSE(tc.body); got != tc.want {
				t.Errorf("looksLikeSSE(%q) = %v, want %v", tc.body[:min(40, len(tc.body))], got, tc.want)
			}
		})
	}
}

// TestParseSSEStream_ChatGPTFixture pins parseOpenAIStream against the
// captured chatgpt.com fixture so we know the parser shape matches the
// terminal response.completed event payload, independent of the proxy
// integration test.
func TestParseSSEStream_ChatGPTFixture(t *testing.T) {
	body, err := os.ReadFile("testdata/chatgpt_codex_responses_sse.bin")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	result := parseSSEStream(body, models.ProviderOpenAI)
	if result.Model != "gpt-5.5" {
		t.Errorf("model = %q, want gpt-5.5", result.Model)
	}
	// Input is NET non-cached: fixture's response.completed reports
	// input_tokens=12669 with input_tokens_details.cached_tokens=3456,
	// netted to 9213 by applyOpenAIUsage. CacheReadTokens carries the
	// 3456 in its own column so the cost engine bills them at the
	// discounted rate without double-charging.
	if result.InputTokens != 9213 {
		t.Errorf("input_tokens = %d, want 9213 (net of 3456 cached)", result.InputTokens)
	}
	if result.OutputTokens != 15 {
		t.Errorf("output_tokens = %d, want 15", result.OutputTokens)
	}
	if result.CacheReadTokens != 3456 {
		t.Errorf("cache_read_tokens = %d, want 3456", result.CacheReadTokens)
	}
	if result.RequestID == "" {
		t.Errorf("request_id should be populated from response.created event")
	}
}

// TestProxy_ChatGPTSSEWithEmptyContentTypeRoutedToStreamParser pins the
// SSE content-sniffing fallback wired into serve(). chatgpt.com's
// /backend-api/codex/responses endpoint returns SSE bodies with an empty
// or missing Content-Type header (verified against codex 0.129.0 capture
// 2026-05-08; fixture lives in testdata/chatgpt_codex_responses_sse.bin).
// Without this fallback the response landed in the non-streaming branch,
// parseOpenAIResponse failed to JSON-unmarshal the SSE body, the proxy
// returned a turn with Model="" and bailed, and no api_turns row was
// recorded — so on chatgpt-auth codex sessions cost/token columns were
// silently dropped.
//
// Expected after fix: looksLikeSSE() catches the body, buildStreamTurn
// runs parseOpenAIStream on it, and the api_turns row carries the
// terminal response.completed event's usage.
func TestProxy_ChatGPTSSEWithEmptyContentTypeRoutedToStreamParser(t *testing.T) {
	captured, err := os.ReadFile("testdata/chatgpt_codex_responses_sse.bin")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	chatgpt := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Critical: explicit empty Content-Type to match chatgpt.com's
		// observed behaviour (it omits the header entirely; Go's
		// http.ResponseWriter would otherwise auto-detect from body
		// sniffing). nil-valued slot suppresses both the auto-detect
		// AND the default-set, so the proxy's contentType reads as "".
		w.Header()["Content-Type"] = nil
		w.WriteHeader(200)
		_, _ = w.Write(captured)
	})
	chatgptUp := httptest.NewServer(chatgpt)
	defer chatgptUp.Close()

	sink := &fakeSink{}
	p, err := New(Options{
		AnthropicUpstream: "http://127.0.0.1:1", // unused
		OpenAIUpstream:    "http://127.0.0.1:1", // unused — chatgpt-auth routes to ChatGPTUpstream
		ChatGPTUpstream:   chatgptUp.URL,
		Sink:              sink,
	})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/v1/responses",
		strings.NewReader(`{"model":"gpt-5-codex","input":[{"role":"user","content":"hi"}],"prompt_cache_key":"sess-1"}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	// ChatGPT-Plus JWT shape — triggers the chatgptAuth path.
	req.Header.Set("Authorization", "Bearer eyJfaketestjwtfortestonly")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	turns := sink.all()
	if len(turns) != 1 {
		t.Fatalf("want 1 turn, got %d (sniff fallback didn't fire)", len(turns))
	}
	tr := turns[0]
	// Net of cached (3456): 12669 - 3456 = 9213. Same netting as
	// TestParseSSEStream_ChatGPTFixture above.
	if tr.InputTokens != 9213 {
		t.Errorf("input_tokens = %d, want 9213 net of cached (from response.completed.response.usage)", tr.InputTokens)
	}
	if tr.OutputTokens != 15 {
		t.Errorf("output_tokens = %d, want 15", tr.OutputTokens)
	}
	if tr.CacheReadTokens != 3456 {
		t.Errorf("cache_read_tokens = %d, want 3456 (from input_tokens_details.cached_tokens)", tr.CacheReadTokens)
	}
	if tr.Provider != models.ProviderOpenAI {
		t.Errorf("provider = %q, want openai", tr.Provider)
	}
	if tr.Model == "" {
		t.Errorf("model is empty — terminal response.completed event should populate it")
	}
}

// TestProxy_ChatGPTAuthStreamsBytesIncrementally pins the V4-1 fix: when
// the request transited the ChatGPT-auth path, the proxy must take the
// streaming branch (teeStream) so SSE bytes flow to the client as they
// arrive from chatgpt.com — even though chatgpt.com omits the
// `Content-Type: text/event-stream` header. The pre-fix behavior buffered
// the entire response in io.ReadAll before writing any bytes back, which
// tripped codex's app-server inner-pipe ~15 s "wait for first byte"
// timeout and triggered the 5×/turn `Reconnecting... N/5` retry storm
// documented in docs/observer-platform-issues-v4.md V4-1.
//
// The assertion: TTFB to the client must be substantially LESS than the
// gap the upstream takes between its first flush and its body close.
// Under the buffered path TTFB would be ≥ the gap (the client would wait
// for io.ReadAll to drain the whole body); under the streaming path the
// client sees the early bytes immediately after the upstream's first
// flush.
func TestProxy_ChatGPTAuthStreamsBytesIncrementally(t *testing.T) {
	const upstreamGap = 400 * time.Millisecond

	captured, err := os.ReadFile("testdata/chatgpt_codex_responses_sse.bin")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	splitAt := len(captured) / 2
	earlyChunk := captured[:splitAt]
	lateChunk := captured[splitAt:]

	chatgpt := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Match chatgpt.com's observed behaviour: omit Content-Type so
		// the proxy's strings.HasPrefix(...) check fails. The fix gates
		// on chatgptAuth instead, so the streaming branch still fires.
		w.Header()["Content-Type"] = nil
		w.WriteHeader(200)
		_, _ = w.Write(earlyChunk)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		time.Sleep(upstreamGap)
		_, _ = w.Write(lateChunk)
	})
	chatgptUp := httptest.NewServer(chatgpt)
	defer chatgptUp.Close()

	sink := &fakeSink{}
	p, err := New(Options{
		AnthropicUpstream: "http://127.0.0.1:1",
		OpenAIUpstream:    "http://127.0.0.1:1",
		ChatGPTUpstream:   chatgptUp.URL,
		Sink:              sink,
	})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/v1/responses",
		strings.NewReader(`{"model":"gpt-5-codex","input":[{"role":"user","content":"hi"}],"prompt_cache_key":"sess-1"}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer eyJfaketestjwtfortestonly")
	req.Header.Set("Content-Type", "application/json")

	start := time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	// Read the first byte. Under the streaming path this returns soon
	// after the upstream's first flush (small window for httptest +
	// teeStream's 4 KiB read). Under the buffered path it blocks until
	// io.ReadAll completes, which is ≥ upstreamGap.
	one := make([]byte, 1)
	if _, err := io.ReadFull(resp.Body, one); err != nil {
		t.Fatalf("read first byte: %v", err)
	}
	ttfb := time.Since(start)

	// Drain the rest so the proxy's stream-tee can finalize the turn.
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatalf("drain body: %v", err)
	}

	// Generous margin: TTFB should be well under the upstream gap. The
	// buffered path's TTFB would be ≥ upstreamGap; the streaming path's
	// TTFB is typically <50 ms on a loopback httptest server.
	if ttfb >= upstreamGap {
		t.Fatalf("TTFB = %v ≥ upstream gap %v — proxy buffered the chatgpt-auth response instead of streaming it (V4-1 regression)", ttfb, upstreamGap)
	}

	turns := sink.all()
	if len(turns) != 1 {
		t.Fatalf("want 1 api_turn after stream completes, got %d", len(turns))
	}
	if turns[0].Model == "" {
		t.Errorf("api_turn model empty — streaming-branch parseOpenAIStream didn't populate it")
	}
}

// TestResolveAPITurnSessionID exercises the V4-4 fix: the helper must
// prefer the provider-specific body extractor, then the codex
// session_id/thread_id/x-client-request-id headers (for OpenAI), then
// the generic X-Session-Id header. Pre-fix, OpenAI requests skipped
// the body+header fallback entirely and relied solely on X-Session-Id,
// so codex's chatgpt-auth turns (which carry the UUID on `session_id`
// but not in the body) collapsed to an empty session_id.
// TestResolveAPITurnSessionIDHostedAppLaneHeaders pins the gateway-rail
// conversation-identity lift (operator-reported 4-rows-per-prompt class,
// 2026-08-14): on an explicit /up/<id> lane, X-Superbased-Session (our
// contract) and Open WebUI's native X-OpenWebUI-Chat-Id are accepted as the
// session id, in that priority order — and NEITHER is consulted on a
// default (Plane-B) lane, where hosted-app conventions must never leak
// into coding-agent attribution.
func TestResolveAPITurnSessionIDHostedAppLaneHeaders(t *testing.T) {
	p, err := New(Options{
		AnthropicUpstream: "http://127.0.0.1:1",
		OpenAIUpstream:    "http://127.0.0.1:1",
		ChatGPTUpstream:   "http://127.0.0.1:1",
		Sink:              &fakeSink{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cases := []struct {
		name    string
		lane    string
		headers map[string]string
		want    string
	}{
		{
			name:    "up-lane lifts X-Superbased-Session",
			lane:    "openrouter",
			headers: map[string]string{"X-Superbased-Session": "conv-abc"},
			want:    "conv-abc",
		},
		{
			name:    "up-lane lifts X-OpenWebUI-Chat-Id",
			lane:    "openrouter",
			headers: map[string]string{"X-OpenWebUI-Chat-Id": "owui-chat-7"},
			want:    "owui-chat-7",
		},
		{
			name: "X-Superbased-Session wins over X-OpenWebUI-Chat-Id",
			lane: "openrouter",
			headers: map[string]string{
				"X-Superbased-Session": "conv-abc",
				"X-OpenWebUI-Chat-Id":  "owui-chat-7",
			},
			want: "conv-abc",
		},
		{
			name:    "default lane must NOT lift hosted-app headers",
			lane:    "",
			headers: map[string]string{"X-Superbased-Session": "conv-abc", "X-OpenWebUI-Chat-Id": "owui-chat-7"},
			want:    "",
		},
		{
			name:    "up-lane blank header values are ignored",
			lane:    "openrouter",
			headers: map[string]string{"X-Superbased-Session": "   "},
			want:    "",
		},
		{
			name:    "up-lane hosted-app header outranks generic X-Session-Id",
			lane:    "openrouter",
			headers: map[string]string{"X-Session-Id": "generic", "X-OpenWebUI-Chat-Id": "owui-chat-7"},
			want:    "owui-chat-7",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPost, "http://test/v1/chat/completions", nil)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			if tc.lane != "" {
				req = req.WithContext(context.WithValue(req.Context(), obsLaneCtxKey{}, tc.lane))
			}
			got := p.resolveAPITurnSessionID(req, models.ProviderOpenAI, []byte(`{"model":"nvidia/nemotron-3.5-lightning:free"}`))
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestResolveAPITurnSessionID(t *testing.T) {
	p, err := New(Options{
		AnthropicUpstream: "http://127.0.0.1:1",
		OpenAIUpstream:    "http://127.0.0.1:1",
		ChatGPTUpstream:   "http://127.0.0.1:1",
		Sink:              &fakeSink{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cases := []struct {
		name     string
		provider string
		body     []byte
		headers  map[string]string
		want     string
	}{
		{
			name:     "openai body prompt_cache_key wins",
			provider: models.ProviderOpenAI,
			body:     []byte(`{"prompt_cache_key":"sess-from-body","model":"gpt-5-codex"}`),
			headers:  map[string]string{"Session-Id": "sess-from-header", "X-Session-Id": "x-fallback"},
			want:     "sess-from-body",
		},
		{
			name:     "openai chatgpt-auth body lacks prompt_cache_key → Session-Id header",
			provider: models.ProviderOpenAI,
			body:     []byte(`{"model":"gpt-5-codex","input":[{"role":"user","content":"hi"}]}`),
			headers:  map[string]string{"Session-Id": "sess-from-session-id-hdr"},
			want:     "sess-from-session-id-hdr",
		},
		{
			name:     "openai falls through Session-Id to Thread-Id",
			provider: models.ProviderOpenAI,
			body:     []byte(`{"model":"gpt-5-codex"}`),
			headers:  map[string]string{"Thread-Id": "sess-from-thread"},
			want:     "sess-from-thread",
		},
		{
			name:     "openai falls through to X-Client-Request-Id",
			provider: models.ProviderOpenAI,
			body:     []byte(`{"model":"gpt-5-codex"}`),
			headers:  map[string]string{"X-Client-Request-Id": "sess-from-xclient"},
			want:     "sess-from-xclient",
		},
		{
			name:     "openai falls through codex headers to X-Session-Id",
			provider: models.ProviderOpenAI,
			body:     []byte(`{"model":"gpt-5-codex"}`),
			headers:  map[string]string{"X-Session-Id": "sess-from-x-session-id"},
			want:     "sess-from-x-session-id",
		},
		{
			// Regression guard: codex's real headers are HYPHEN-separated
			// (`Session-Id`, `Thread-Id`, `X-Client-Request-Id`), NOT
			// underscore. Go's textproto.CanonicalMIMEHeaderKey preserves
			// the underscore-vs-hyphen distinction, so a fallback list
			// using "session_id" silently misses real codex traffic. This
			// case feeds underscored headers and asserts they are NOT
			// picked up — only the hyphen variants in the fallback list
			// match. Captured 2026-05-28 against codex 0.133 live.
			name:     "underscore-named pseudo-headers are NOT a fallback match",
			provider: models.ProviderOpenAI,
			body:     []byte(`{"model":"gpt-5-codex"}`),
			headers:  map[string]string{"session_id": "underscore-must-not-match", "thread_id": "neither-must-this"},
			want:     "",
		},
		{
			name:     "openai all empty → empty result",
			provider: models.ProviderOpenAI,
			body:     []byte(`{"model":"gpt-5-codex"}`),
			headers:  map[string]string{},
			want:     "",
		},
		{
			name:     "anthropic body lacks session_id → X-Session-Id",
			provider: models.ProviderAnthropic,
			body:     []byte(`{}`),
			headers:  map[string]string{"X-Session-Id": "x-fallback"},
			want:     "x-fallback",
		},
		{
			name:     "openai must NOT consult anthropic-only metadata.user_id",
			provider: models.ProviderOpenAI,
			body:     []byte(`{"metadata":{"user_id":"u_sess_x_account__session_anthropic-uuid"}}`),
			headers:  map[string]string{},
			want:     "",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPost, "http://test/v1/responses", nil)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			got := p.resolveAPITurnSessionID(req, tc.provider, tc.body)
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestProxy_ChatGPTAuthEndToEndCapturesSessionIDFromHeader pins the
// V4-4 fix end-to-end: a chatgpt-auth POST with `Session-Id` on the
// headers (and the prompt_cache_key omitted from the body — the
// ChatGPT-Plus auth shape codex actually emits) must land an api_turn
// row whose SessionID equals the header value, not "". Verified
// live against codex 0.133 on 2026-05-28: codex sends `Session-Id`
// (hyphenated, NOT `session_id`).
func TestProxy_ChatGPTAuthEndToEndCapturesSessionIDFromHeader(t *testing.T) {
	captured, err := os.ReadFile("testdata/chatgpt_codex_responses_sse.bin")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	chatgpt := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header()["Content-Type"] = nil
		w.WriteHeader(200)
		_, _ = w.Write(captured)
	})
	chatgptUp := httptest.NewServer(chatgpt)
	defer chatgptUp.Close()

	sink := &fakeSink{}
	p, err := New(Options{
		AnthropicUpstream: "http://127.0.0.1:1",
		OpenAIUpstream:    "http://127.0.0.1:1",
		ChatGPTUpstream:   chatgptUp.URL,
		Sink:              sink,
	})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	// Body intentionally omits prompt_cache_key — this is the
	// ChatGPT-Plus auth shape that V4-4 found in the wild. The
	// session UUID lives on the `Session-Id` header (hyphenated).
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/v1/responses",
		strings.NewReader(`{"model":"gpt-5-codex","input":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer eyJfaketestjwtfortestonly")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Session-Id", "019e05fc-dfe7-77a1-8db0-c7d13f8be248")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	turns := sink.all()
	if len(turns) != 1 {
		t.Fatalf("want 1 api_turn, got %d", len(turns))
	}
	if turns[0].SessionID != "019e05fc-dfe7-77a1-8db0-c7d13f8be248" {
		t.Errorf("api_turn SessionID = %q, want the value from the `session_id` header (V4-4)", turns[0].SessionID)
	}
}

// ctxSpySink records the ctx.Err() observed at every InsertAPITurn
// call. Used by the detached-context tests to assert that the proxy
// rides a still-live context even when the http.Request's context was
// cancelled by the client closing the connection.
type ctxSpySink struct {
	mu      sync.Mutex
	ctxErrs []error // ctx.Err() at the moment InsertAPITurn was called
	turns   []models.APITurn
}

func (s *ctxSpySink) InsertAPITurn(ctx context.Context, t models.APITurn) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ctxErrs = append(s.ctxErrs, ctx.Err())
	s.turns = append(s.turns, t)
	return int64(len(s.turns)), nil
}

func (s *ctxSpySink) snapshot() (errs []error, turns []models.APITurn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	errs = append(errs, s.ctxErrs...)
	turns = append(turns, s.turns...)
	return
}

// TestInsertTurnDetached_IgnoresAlreadyCancelledOuterContext is the
// deterministic core assertion behind PR #20: the helper's insert
// context is derived from context.Background(), not from any
// request-scoped context, so it survives a fully-cancelled outer
// context. The end-to-end TestProxy_InsertContextSurvivesClientClose
// below proves the behaviour through the real serve() path, but its
// pass/fail on a pre-fix tree is timing-dependent (depends on whether
// the client's close races the insert). This unit test is the proof
// the helper is correct regardless of timing.
func TestInsertTurnDetached_IgnoresAlreadyCancelledOuterContext(t *testing.T) {
	sink := &ctxSpySink{}
	p, err := New(Options{
		AnthropicUpstream: "http://127.0.0.1:1",
		OpenAIUpstream:    "http://127.0.0.1:1",
		ChatGPTUpstream:   "http://127.0.0.1:1",
		Sink:              sink,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Confirm the helper does NOT thread an outer context — even if a
	// caller had one to pass (the proxy doesn't; serve() invokes the
	// helper after the response is delivered), the helper's signature
	// takes no context, so there is no possible regression path that
	// re-introduces r.Context() without changing this signature.
	p.insertTurnDetached(models.APITurn{Model: "test", Provider: "anthropic"}, 0, "test-label")

	errs, turns := sink.snapshot()
	if len(turns) != 1 {
		t.Fatalf("turns = %d, want 1", len(turns))
	}
	if errs[0] != nil {
		t.Fatalf("ctx.Err() at insert = %v, want nil — the detached context was somehow already cancelled", errs[0])
	}
}

// TestProxy_InsertContextSurvivesClientClose pins the PR #20 fix: a
// client that closes its read side IMMEDIATELY after the SSE stream
// completes — codex 0.130+ does this deterministically — must NOT
// cancel the proxy's api_turn insert. Before the fix, the insert ran
// on r.Context(), the close cancelled it, and every codex turn
// silently dropped with `store.InsertAPITurn: context canceled`.
//
// The assertion: ctx.Err() observed at insert time is nil, and the
// turn lands.
func TestProxy_InsertContextSurvivesClientClose(t *testing.T) {
	const fixture = "event: message_start\n" +
		`data: {"type":"message_start","message":{"id":"msg_1","model":"claude-sonnet-4-6","usage":{"input_tokens":100,"output_tokens":1,"cache_read_input_tokens":0}}}` + "\n\n" +
		"event: message_delta\n" +
		`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":12}}` + "\n\n" +
		"event: message_stop\n" +
		`data: {"type":"message_stop"}` + "\n\n"

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, fixture)
	})
	upstreamSrv := httptest.NewServer(upstream)
	defer upstreamSrv.Close()

	sink := &ctxSpySink{}
	p, err := New(Options{
		AnthropicUpstream: upstreamSrv.URL,
		OpenAIUpstream:    "http://127.0.0.1:1",
		ChatGPTUpstream:   "http://127.0.0.1:1",
		Sink:              sink,
	})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	// DisableKeepAlives forces full connection teardown on Body.Close,
	// matching codex's observed behaviour.
	c := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/messages",
		strings.NewReader(`{"model":"claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer sk-fake")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	// Drain + close immediately, mirroring codex's post-stream close.
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	// Give the proxy a generous window to attempt the insert (the
	// detached-context branch survives client-close; a regression to
	// r.Context() would record context.Canceled on every attempt).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_, turns := sink.snapshot()
		if len(turns) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	errs, turns := sink.snapshot()
	if len(turns) != 1 {
		t.Fatalf("api_turn count = %d, want 1 (insert raced client close → row dropped — detached context regressed)", len(turns))
	}
	if errs[0] != nil {
		t.Fatalf("ctx.Err() at insert time = %v, want nil — proxy is still calling InsertAPITurn on r.Context()", errs[0])
	}
}

func TestJoinPath(t *testing.T) {
	cases := []struct {
		base, path, want string
	}{
		{"", "/v1/messages", "/v1/messages"},
		{"/", "/v1/messages", "/v1/messages"},
		{"/proxy", "/v1/messages", "/proxy/v1/messages"},
		{"/proxy/", "/v1/messages", "/proxy/v1/messages"},
	}
	for _, tc := range cases {
		if got := joinPath(tc.base, tc.path); got != tc.want {
			t.Errorf("joinPath(%q,%q) = %q, want %q", tc.base, tc.path, got, tc.want)
		}
	}
}

// TestCodexVariantRe_Coverage pins the V7-2 codex-variant model
// identifier regex against the v4 batch's empirical model strings
// plus negative cases that must not match.
func TestCodexVariantRe_Coverage(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		model string
		want  bool
	}{
		// codex-variant family — must match.
		{"gpt-5.3-codex", true},
		{"gpt-5.3-codex-low", true},
		{"gpt-5.3-codex-medium", true},
		{"gpt-5.3-codex-high", true},
		{"gpt-5.3-codex-xhigh", true},
		{"gpt-5.4-codex", true},
		{"gpt-5-codex-agent", true},
		{"codex-internal", true},
		{"codex-experimental-2026", true},
		// case-insensitive.
		{"GPT-5.3-CODEX", true},
		// non-codex — must NOT match.
		{"gpt-5.4-mini", false},
		{"gpt-5.5", false},
		{"gpt-5", false},
		{"claude-sonnet-4-6", false},
		{"claude-opus-4-7", false},
		{"o3-pro", false},
		// `codex` substring but not as a dash-delimited token.
		{"gpt-codexsomething", false},
		{"codexmini", false},
	} {
		tc := tc
		t.Run(tc.model, func(t *testing.T) {
			t.Parallel()
			got := codexVariantRe.MatchString(tc.model)
			if got != tc.want {
				t.Errorf("codexVariantRe.MatchString(%q) = %v, want %v", tc.model, got, tc.want)
			}
		})
	}
}

// captureProxy returns a Proxy with its logger wired to capture log
// records into the supplied buffer. The Proxy is otherwise inert —
// no upstream, no Sink. Used by V7-2 codex-variant warning tests to
// inspect logger output without spinning a full proxy + httptest stack.
func captureProxy(t *testing.T, compressTypes []string, buf *bytes.Buffer) *Proxy {
	t.Helper()
	handler := slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := slog.New(handler)
	// We can construct Proxy directly (the warning method doesn't
	// touch any URL/Sink fields). Skipping New() avoids the
	// upstream-URL requirement.
	return &Proxy{
		logger:        logger,
		compressTypes: compressTypes,
	}
}

// TestProxy_CodexVariantWarning_FiresOncePerSession pins the per-session
// dedup contract: repeat OpenAI requests on the same session_id with a
// codex-variant model emit one warning total, not one per request.
func TestProxy_CodexVariantWarning_FiresOncePerSession(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	p := captureProxy(t, []string{"json", "logs", "code"}, &buf)
	for i := 0; i < 5; i++ {
		p.maybeWarnCodexVariantModel("sess-1", "gpt-5.3-codex")
	}
	got := strings.Count(buf.String(), "codex-variant model")
	if got != 1 {
		t.Errorf("warning fired %d times, want 1; log: %s", got, buf.String())
	}
}

// TestProxy_CodexVariantWarning_SuppressedWhenCompressTypesEmpty pins
// that the warning is silent when the operator has already adopted
// the codex-variant recipe (compress_types = []).
func TestProxy_CodexVariantWarning_SuppressedWhenCompressTypesEmpty(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	p := captureProxy(t, nil, &buf)
	p.maybeWarnCodexVariantModel("sess-1", "gpt-5.3-codex")
	if strings.Contains(buf.String(), "codex-variant model") {
		t.Errorf("warning fired with empty compress_types: %s", buf.String())
	}
}

// TestProxy_CodexVariantWarning_NoFireOnNonCodex pins that benign
// OpenAI models (gpt-mini family, plain gpt-5) don't trigger the
// warning even when compress_types is non-empty.
func TestProxy_CodexVariantWarning_NoFireOnNonCodex(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	p := captureProxy(t, []string{"json", "logs", "code"}, &buf)
	for _, model := range []string{"gpt-5.4-mini", "gpt-5.5", "o3-pro", "gpt-5"} {
		p.maybeWarnCodexVariantModel("sess-"+model, model)
	}
	if strings.Contains(buf.String(), "codex-variant model") {
		t.Errorf("warning fired on non-codex model(s): %s", buf.String())
	}
}

// TestProxy_CodexVariantWarning_FiresOnSuffixVariants pins that the
// effort-suffix codex variants (gpt-5.3-codex-low/medium/high/xhigh)
// all trigger the warning, not just the base name.
func TestProxy_CodexVariantWarning_FiresOnSuffixVariants(t *testing.T) {
	t.Parallel()
	suffixes := []string{
		"gpt-5.3-codex",
		"gpt-5.3-codex-low",
		"gpt-5.3-codex-medium",
		"gpt-5.3-codex-high",
		"gpt-5.3-codex-xhigh",
		"gpt-5-codex-agent",
	}
	for _, model := range suffixes {
		model := model
		t.Run(model, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			p := captureProxy(t, []string{"logs"}, &buf)
			p.maybeWarnCodexVariantModel("sess-1", model)
			if !strings.Contains(buf.String(), "codex-variant model") {
				t.Errorf("expected warning for model %q; log: %s", model, buf.String())
			}
		})
	}
}

// TestProxy_CodexVariantWarning_NoFireWithoutSessionID pins that
// requests lacking a session_id (rare, but possible on older codex
// builds) are silently skipped — we can't dedup without a key, and
// firing a per-request warning would spam the operator.
func TestProxy_CodexVariantWarning_NoFireWithoutSessionID(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	p := captureProxy(t, []string{"logs"}, &buf)
	p.maybeWarnCodexVariantModel("", "gpt-5.3-codex")
	if strings.Contains(buf.String(), "codex-variant model") {
		t.Errorf("warning fired without session_id: %s", buf.String())
	}
}

// TestExtractOpenAIModel_Roundtrip pins the request-body extractor
// against the OpenAI Responses API + Chat Completions shapes that
// codex sends in practice.
// TestParseRequest_FastModeSpeedField pins that parseRequest extracts
// Anthropic Messages API's `speed` field into requestShape.Speed so the
// APITurn builder can stamp Fast=true on the row. Opus 4.8's fast mode
// is request-side only (the response usage block doesn't surface a
// directly-usable signal in every shape the proxy sees), so this is
// the singular reliable capture point. Empty/missing speed → empty
// Speed → APITurn.Fast=false (no fast-mode billing).
// TestParseRequest_HandoffMarker proves the proxy boundary scans the raw
// body for the session-handoff marker so cachetrack can attribute a
// handoff target's first-turn cold write as handoff_rehydration.
func TestParseRequest_HandoffMarker(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		body string
		want bool
	}{
		{"marker in a user message", `{"model":"claude-opus-4-8","messages":[{"role":"user","content":"<!-- superbased-handoff a1b2c3d4 -->\nresume here"}]}`, true},
		{"no marker", `{"model":"claude-opus-4-8","messages":[{"role":"user","content":"hello"}]}`, false},
		{"empty body", ``, false},
		{"malformed JSON still scanned as bytes", `{"messages": <!-- superbased-handoff zz -->`, true},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := parseRequest([]byte(tc.body)).HandoffMarker; got != tc.want {
				t.Errorf("parseRequest(%q).HandoffMarker = %v, want %v", tc.body, got, tc.want)
			}
		})
	}
}

// TestBuildCacheObserveInput_OpenAIThreadsHandoffMarker proves the
// §15.3 implicit-cache boundary threads reqShape.HandoffMarker into
// the ObserveInput so a proxied codex/OpenAI handoff target's
// bootstrap turn reaches the implicit lane's
// ruleImplicitHandoffRehydration (the flag was scanned by
// parseRequest but the OpenAI branch previously dropped it).
func TestBuildCacheObserveInput_OpenAIThreadsHandoffMarker(t *testing.T) {
	t.Parallel()
	p := &Proxy{now: func() time.Time { return time.Unix(0, 0) }}
	turn := models.APITurn{SessionID: "sess-1", Model: "gpt-5", RequestID: "req-1"}
	for _, want := range []bool{true, false} {
		reqShape := requestShape{HandoffMarker: want}
		in, ok := p.buildCacheObserveInput(turn, reqShape, models.ProviderOpenAI, 1)
		if !ok {
			t.Fatalf("buildCacheObserveInput(OpenAI) returned ok=false")
		}
		if !in.Caps.ImplicitCache {
			t.Fatalf("OpenAI branch must overlay ImplicitCache=true")
		}
		if in.HandoffMarker != want {
			t.Errorf("ObserveInput.HandoffMarker = %v, want %v", in.HandoffMarker, want)
		}
	}
}

func TestParseRequest_FastModeSpeedField(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		body      string
		wantSpeed string
	}{
		{"fast on Opus 4.8", `{"model":"claude-opus-4-8","speed":"fast","messages":[]}`, "fast"},
		{"absent → empty", `{"model":"claude-opus-4-8","messages":[]}`, ""},
		{"explicit standard not modelled — passthrough", `{"model":"claude-sonnet-4-6","speed":"standard","messages":[]}`, "standard"},
		{"empty body → empty", ``, ""},
		{"malformed JSON → empty", `{`, ""},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := parseRequest([]byte(tc.body))
			if got.Speed != tc.wantSpeed {
				t.Errorf("parseRequest(%q).Speed = %q, want %q", tc.body, got.Speed, tc.wantSpeed)
			}
		})
	}
}

// TestBuildTurn_FastFromSpeed pins the proxy's wire-shape contract:
// req.Speed == "fast" → APITurn.Fast = true, and anything else (empty
// or non-"fast" value) → APITurn.Fast = false. Stamped on both the
// non-streaming buildTurn and the streaming buildStreamTurn paths so
// fast-mode billing is captured regardless of whether the client
// requested SSE.
func TestBuildTurn_FastFromSpeed(t *testing.T) {
	t.Parallel()
	p := &Proxy{now: func() time.Time { return time.Unix(0, 0) }}
	for _, tc := range []struct {
		name     string
		speed    string
		wantFast bool
	}{
		{"speed=fast → Fast=true", "fast", true},
		{"speed=standard → Fast=false", "standard", false},
		{"speed empty → Fast=false", "", false},
		{"speed=anything-else → Fast=false (only 'fast' triggers)", "ultra-fast", false},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := requestShape{Model: "claude-opus-4-8", Speed: tc.speed}
			// Minimal non-streaming response: model + zero usage.
			resp := []byte(`{"model":"claude-opus-4-8","usage":{"input_tokens":0,"output_tokens":0}}`)
			turn := p.buildTurn(models.ProviderAnthropic, req, resp, http.Header{}, time.Unix(0, 0), "")
			if turn.Fast != tc.wantFast {
				t.Errorf("buildTurn(speed=%q).Fast = %v, want %v", tc.speed, turn.Fast, tc.wantFast)
			}
			// Streaming path parity — same Speed shape, same Fast result.
			turnStream := p.buildStreamTurn(models.ProviderAnthropic, req, []byte{}, http.Header{}, time.Unix(0, 0), "")
			if turnStream.Fast != tc.wantFast {
				t.Errorf("buildStreamTurn(speed=%q).Fast = %v, want %v", tc.speed, turnStream.Fast, tc.wantFast)
			}
			// Error path parity — a non-2xx fast request still records the
			// fast selection (tokens are zero so cost is unaffected, but
			// the flag stays consistent across all three turn-build paths).
			errTurn := buildErrorTurn(models.ProviderAnthropic, req,
				[]byte(`{"type":"error","error":{"type":"rate_limit_error","message":"slow down"}}`),
				http.Header{}, 429, time.Unix(0, 0), "")
			if errTurn.Fast != tc.wantFast {
				t.Errorf("buildErrorTurn(speed=%q).Fast = %v, want %v", tc.speed, errTurn.Fast, tc.wantFast)
			}
		})
	}
}

// TestBuildTurn_FastFromServiceTier pins the Codex/OpenAI fast-mode capture
// (added 2026-06-08): service_tier == "priority" → APITurn.Fast=true so the
// cost engine applies the gpt-5.x FastMultiplier. The *served* tier echoed
// on the response is authoritative (OpenAI can downgrade priority→default
// under load and bill at the standard rate); the request-side tier is the
// fallback used on the error path (no response body to read). parseRequest
// must surface the request-side service_tier. "default"/"auto"/"flex" are
// NOT fast.
func TestBuildTurn_FastFromServiceTier(t *testing.T) {
	t.Parallel()

	// parseRequest surfaces the request-body service_tier.
	if got := parseRequest([]byte(`{"model":"gpt-5.4","service_tier":"priority"}`)); got.ServiceTier != "priority" {
		t.Errorf("parseRequest service_tier = %q, want priority", got.ServiceTier)
	}

	p := &Proxy{now: func() time.Time { return time.Unix(0, 0) }}
	for _, tc := range []struct {
		name     string
		reqTier  string
		respTier string // served tier echoed in the response (empty = absent)
		wantFast bool
	}{
		{"served priority → fast", "priority", "priority", true},
		{"served default downgrade → not fast", "priority", "default", false},
		{"served auto → not fast", "auto", "auto", false},
		{"served flex → not fast", "flex", "flex", false},
		{"no served tier, requested priority → fast (fallback)", "priority", "", true},
		{"no tier anywhere → not fast", "", "", false},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := requestShape{Model: "gpt-5.4", ServiceTier: tc.reqTier}

			// Non-streaming: service_tier on the JSON response body.
			respBody := []byte(`{"model":"gpt-5.4","usage":{"input_tokens":10,"output_tokens":5}}`)
			if tc.respTier != "" {
				respBody = []byte(`{"model":"gpt-5.4","service_tier":"` + tc.respTier +
					`","usage":{"input_tokens":10,"output_tokens":5}}`)
			}
			turn := p.buildTurn(models.ProviderOpenAI, req, respBody, http.Header{}, time.Unix(0, 0), "")
			if turn.Fast != tc.wantFast {
				t.Errorf("buildTurn(req=%q,resp=%q).Fast = %v, want %v", tc.reqTier, tc.respTier, turn.Fast, tc.wantFast)
			}

			// Streaming: service_tier on the response.completed event's
			// response object (OpenAI Responses API shape).
			inner := `{"type":"response.completed","response":{"id":"r1","model":"gpt-5.4","status":"completed",`
			if tc.respTier != "" {
				inner += `"service_tier":"` + tc.respTier + `",`
			}
			inner += `"usage":{"input_tokens":10,"output_tokens":5}}}`
			sse := []byte("event: response.completed\ndata: " + inner + "\n\n")
			turnStream := p.buildStreamTurn(models.ProviderOpenAI, req, sse, http.Header{}, time.Unix(0, 0), "")
			if turnStream.Fast != tc.wantFast {
				t.Errorf("buildStreamTurn(req=%q,resp=%q).Fast = %v, want %v", tc.reqTier, tc.respTier, turnStream.Fast, tc.wantFast)
			}
		})
	}

	// Error path: no response body, so the request-side tier decides.
	req := requestShape{Model: "gpt-5.4", ServiceTier: "priority"}
	errTurn := buildErrorTurn(models.ProviderOpenAI, req,
		[]byte(`{"error":{"message":"boom"}}`), http.Header{}, 500, time.Unix(0, 0), "")
	if !errTurn.Fast {
		t.Error("buildErrorTurn with requested priority: Fast=false, want true")
	}
}

// TestApplyCost_ThreadsFastFlag pins the fix for the bug the live
// capture exposed: applyCost (the proxy's cost-at-insert path) must
// pass APITurn.Fast through to the CostComputer as CostTokens.Fast, so
// the FastMultiplier premium lands on the recorded cost_usd. Before the
// fix, a real Opus 4.8 /fast turn was stored at the STANDARD rate (the
// engine never saw the flag), understating the spend by 2×. The
// ComputeBreakdown unit tests covered the math but not this wiring.
func TestApplyCost_ThreadsFastFlag(t *testing.T) {
	fake := &fakeCostComputer{rate: 0.01}
	p := &Proxy{cost: fake}

	p.applyCost(&models.APITurn{Model: "claude-opus-4-8", InputTokens: 1000, Fast: true})
	if !fake.lastTokens.Fast {
		t.Errorf("applyCost dropped the Fast flag — fast turns would store standard cost")
	}

	p.applyCost(&models.APITurn{Model: "claude-opus-4-8", InputTokens: 1000, Fast: false})
	if fake.lastTokens.Fast {
		t.Errorf("applyCost set Fast on a standard turn")
	}
}

// TestApplyCost_ThreadsTimestamp pins Phase 1 slice B of peak/off-peak
// pricing (the Q3 live-path fix): applyCost must pass APITurn.Timestamp
// through to the CostComputer as CostTokens.At, so a peak/off-peak-aware
// cost engine resolves the rate at the turn's own wall-clock time rather
// than at capture-time-blind current/flat rates. Before this fix the
// proxy dropped the timestamp on the floor, so `api_turns.cost_usd`
// could never reflect time-of-day pricing.
func TestApplyCost_ThreadsTimestamp(t *testing.T) {
	fake := &fakeCostComputer{rate: 0.01}
	p := &Proxy{cost: fake}

	want := time.Date(2026, 9, 21, 14, 30, 0, 0, time.UTC)
	p.applyCost(&models.APITurn{Model: "claude-opus-4-8", InputTokens: 1000, Timestamp: want})
	if !fake.lastTokens.At.Equal(want) {
		t.Errorf("applyCost.At = %v, want %v", fake.lastTokens.At, want)
	}

	// A zero Timestamp must ride through as a zero At, not get
	// silently defaulted to time.Now() somewhere along the seam.
	p.applyCost(&models.APITurn{Model: "claude-opus-4-8", InputTokens: 1000})
	if !fake.lastTokens.At.IsZero() {
		t.Errorf("applyCost.At = %v, want zero", fake.lastTokens.At)
	}
}

func TestExtractOpenAIModel_Roundtrip(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		body string
		want string
	}{
		{`{"model":"gpt-5.3-codex","input":[]}`, "gpt-5.3-codex"},
		{`{"model":"gpt-5.4-mini","messages":[]}`, "gpt-5.4-mini"},
		{`{"messages":[]}`, ""},
		{`{`, ""},
		{``, ""},
	} {
		tc := tc
		t.Run(tc.body, func(t *testing.T) {
			t.Parallel()
			got := extractOpenAIModel([]byte(tc.body))
			if got != tc.want {
				t.Errorf("extractOpenAIModel(%q) = %q, want %q", tc.body, got, tc.want)
			}
		})
	}
}

// fakeClassAwareCompressor records the request class the proxy
// passed (Track R / R2+R3) alongside the SessionAware fields.
type fakeClassAwareCompressor struct {
	mu    sync.Mutex
	class RequestClass
	sid   string
	calls int
}

func (f *fakeClassAwareCompressor) Compress(_ context.Context, provider string, _ []byte) CompressionResult {
	return CompressionResult{Skipped: true}
}

func (f *fakeClassAwareCompressor) CompressInSession(_ context.Context, provider string, _ []byte, sid string) CompressionResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.class, f.sid, f.calls = RequestClass{Provider: provider}, sid, f.calls+1
	return CompressionResult{Skipped: true}
}

func (f *fakeClassAwareCompressor) CompressInSessionClass(_ context.Context, class RequestClass, _ []byte, sid string) CompressionResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.class, f.sid, f.calls = class, sid, f.calls+1
	return CompressionResult{Skipped: true}
}

// fakeToolResolver implements SessionResolver + ToolResolver +
// CWDResolver with fixed answers.
type fakeToolResolver struct {
	sid  string
	tool string
	cwd  string
}

func (f *fakeToolResolver) Resolve(context.Context, string) (string, bool, error) {
	return f.sid, f.sid != "", nil
}

func (f *fakeToolResolver) ResolveTool(context.Context, string) (string, bool, error) {
	return f.tool, f.tool != "", nil
}

func (f *fakeToolResolver) ResolveCWD(context.Context, string) (string, bool, error) {
	return f.cwd, f.cwd != "", nil
}

// TestProxy_CompressInSessionForTool_ReceivesResolvedTool pins the R2
// seam: when the compressor is tool-aware AND the session resolver
// can name the connection's owning tool, the proxy threads the tool
// through so per-tool profile assignments can apply.
func TestProxy_CompressInSessionForTool_ReceivesResolvedTool(t *testing.T) {
	anth := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"m","model":"claude-opus-4-8","stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`))
	})
	anthUp := httptest.NewServer(anth)
	defer anthUp.Close()

	comp := &fakeClassAwareCompressor{}
	p, err := New(Options{
		AnthropicUpstream: anthUp.URL,
		OpenAIUpstream:    anthUp.URL,
		Sink:              &fakeSink{},
		Compressor:        comp,
		SessionResolver:   &fakeToolResolver{sid: "bridge-sess", tool: "kilo-code-cli", cwd: "/repo/demo"},
	})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()

	body := `{"model":"claude-opus-4-8","messages":[{"role":"user","content":"hi"}],"metadata":{"user_id":"{\"session_id\":\"body-sess\"}"}}`
	req, _ := http.NewRequest("POST", srv.URL+"/v1/messages", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	_ = resp.Body.Close()

	comp.mu.Lock()
	defer comp.mu.Unlock()
	if comp.calls != 1 {
		t.Fatalf("compressor calls: %d, want 1", comp.calls)
	}
	if comp.class.Tool != "kilo-code-cli" {
		t.Errorf("tool: got %q want kilo-code-cli (ToolResolver output must reach the compressor)", comp.class.Tool)
	}
	if comp.class.CWD != "/repo/demo" {
		t.Errorf("cwd: got %q want /repo/demo (CWDResolver output must reach the compressor)", comp.class.CWD)
	}
	if comp.sid != "body-sess" {
		t.Errorf("session: got %q want body-sess (body extraction still wins for session identity)", comp.sid)
	}
	if comp.class.Provider != models.ProviderAnthropic {
		t.Errorf("provider: got %q", comp.class.Provider)
	}
}

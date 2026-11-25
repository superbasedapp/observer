package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// fakeObsSink records every ChatTurnFacts handed to it, or returns a
// canned error when errToReturn is set (fail-open verification). callDoneChan,
// when set, is signaled once per call so async tests can synchronize on "the
// sink was invoked" without a sleep-based race.
type fakeObsSink struct {
	mu           sync.Mutex
	calls        []ChatTurnFacts
	errToReturn  error
	callDoneChan chan struct{} // optional: signaled once per call, for async tests
	block        chan struct{} // optional: SynthesizeChatTurn blocks on this until closed
}

func (f *fakeObsSink) SynthesizeChatTurn(_ context.Context, facts ChatTurnFacts) error {
	if f.block != nil {
		<-f.block
	}
	f.mu.Lock()
	f.calls = append(f.calls, facts)
	f.mu.Unlock()
	if f.callDoneChan != nil {
		f.callDoneChan <- struct{}{}
	}
	return f.errToReturn
}

func (f *fakeObsSink) all() []ChatTurnFacts {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]ChatTurnFacts, len(f.calls))
	copy(out, f.calls)
	return out
}

// waitForCall blocks until the sink's callDoneChan fires or the timeout
// elapses, failing the test in the latter case.
// hostedLaneReq marks req as having arrived via a /up/<id> hosted-app lane —
// the obsLaneCtxKey stamp serve() applies after resolveUpstreamPrefix. The
// gateway rail only synthesizes for such requests (plane boundary).
func hostedLaneReq(req *http.Request) *http.Request {
	return req.WithContext(context.WithValue(req.Context(), obsLaneCtxKey{}, "openrouter"))
}

func waitForCall(t *testing.T, ch chan struct{}, d time.Duration) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(d):
		t.Fatal("timed out waiting for obs sink call")
	}
}

// TestSynthesizeObsTrace_TableDriven exercises p.synthesizeObsTrace directly
// (the gateway-rail call site helper) across the nil-sink no-op case, the
// zero-apiTurnID no-op case (insert itself failed — nothing to anchor to),
// a normal invocation asserting the facts projection (incl. request/response
// bodies), and the fail-open case where the sink returns an error and the
// call must not panic or otherwise surface it to the caller.
//
// synthesizeObsTrace is fire-and-forget (Finding 1): every subtest that
// expects a sink call synchronizes on fakeObsSink.callDoneChan rather than
// reading sink.all() immediately, since the sink now runs on its own
// goroutine.
func TestSynthesizeObsTrace_TableDriven(t *testing.T) {
	baseTurn := models.APITurn{
		RequestID:           "req-123",
		SessionID:           "sess-abc",
		Provider:            "anthropic",
		Model:               "claude-sonnet-4",
		Timestamp:           time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC),
		TotalResponseMS:     1500,
		TimeToFirstTokenMS:  200,
		InputTokens:         100,
		OutputTokens:        50,
		CacheReadTokens:     10,
		CacheCreationTokens: 5,
		CostUSD:             0.0123,
		StopReason:          "end_turn",
		HTTPStatus:          200,
	}
	reqBody := []byte(`{"messages":[{"role":"user","content":"hi"}]}`)
	respBody := []byte(`{"content":[{"type":"text","text":"hello"}]}`)

	t.Run("default (Plane-B) lane never synthesizes", func(t *testing.T) {
		// PLANE BOUNDARY regression pin (operator-reported 2026-08-13):
		// coding-agent turns on the default provider lanes must never enter
		// the Hosted Apps Trajectory explorer. A request WITHOUT the
		// /up/<id> lane context (exactly what ANTHROPIC_BASE_URL/codex
		// traffic looks like) must skip synthesis entirely.
		sink := &fakeObsSink{}
		p, err := New(Options{Sink: &fakeSink{}, ObsSink: sink})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		req := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
		p.synthesizeObsTrace(baseTurn, 77, req, reqBody, respBody)
		time.Sleep(50 * time.Millisecond)
		if got := sink.all(); len(got) != 0 {
			t.Fatalf("default-lane turn synthesized %d trace(s); Plane-B traffic must never reach the obs sink", len(got))
		}
	})

	t.Run("nil sink is a no-op", func(t *testing.T) {
		p, err := New(Options{Sink: &fakeSink{}})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		req := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
		// Must not panic with a nil obsSink.
		p.synthesizeObsTrace(baseTurn, 42, req, reqBody, respBody)
	})

	t.Run("zero apiTurnID skips the sink", func(t *testing.T) {
		sink := &fakeObsSink{}
		p, err := New(Options{Sink: &fakeSink{}, ObsSink: sink})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		req := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
		p.synthesizeObsTrace(baseTurn, 0, req, reqBody, respBody)
		// Nothing was spawned at all (apiTurnID==0 short-circuits before the
		// goroutine), so there's nothing to wait for — a brief grace period
		// is enough to catch a regression that spawns anyway.
		time.Sleep(50 * time.Millisecond)
		if got := sink.all(); len(got) != 0 {
			t.Fatalf("expected no sink calls when apiTurnID is 0, got %d", len(got))
		}
	})

	t.Run("invokes sink with the projected facts, including admission user and bodies", func(t *testing.T) {
		sink := &fakeObsSink{callDoneChan: make(chan struct{}, 1)}
		p, err := New(Options{Sink: &fakeSink{}, ObsSink: sink, AdmissionUserHeader: "X-End-User"})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		req := hostedLaneReq(httptest.NewRequest(http.MethodPost, "/v1/messages", nil))
		req.Header.Set("X-End-User", "alice@example.com")
		// The trace session comes ONLY from explicit headers (X-Session-Id
		// here; hosted-app conversation headers covered below) — never
		// turn.SessionID, whose SessionResolver fallback attributes
		// unheadered turns to a recent coding-agent session (plane boundary).
		req.Header.Set("X-Session-Id", "sess-abc")
		p.synthesizeObsTrace(baseTurn, 7, req, reqBody, respBody)
		waitForCall(t, sink.callDoneChan, 2*time.Second)

		calls := sink.all()
		if len(calls) != 1 {
			t.Fatalf("expected exactly one sink call, got %d", len(calls))
		}
		got := calls[0]
		want := ChatTurnFacts{
			APITurnID:           7,
			RequestID:           "req-123",
			SessionID:           "sess-abc",
			User:                "alice@example.com",
			Provider:            "anthropic",
			Model:               "claude-sonnet-4",
			Timestamp:           baseTurn.Timestamp,
			TotalResponseMS:     1500,
			TimeToFirstTokenMS:  200,
			InputTokens:         100,
			OutputTokens:        50,
			CacheReadTokens:     10,
			CacheCreationTokens: 5,
			CostUSD:             0.0123,
			StopReason:          "end_turn",
			HTTPStatus:          200,
			RequestBody:         reqBody,
			ResponseBody:        respBody,
		}
		if got.APITurnID != want.APITurnID || got.RequestID != want.RequestID ||
			got.SessionID != want.SessionID || got.User != want.User ||
			got.Provider != want.Provider || got.Model != want.Model ||
			!got.Timestamp.Equal(want.Timestamp) || got.TotalResponseMS != want.TotalResponseMS ||
			got.TimeToFirstTokenMS != want.TimeToFirstTokenMS || got.InputTokens != want.InputTokens ||
			got.OutputTokens != want.OutputTokens || got.CacheReadTokens != want.CacheReadTokens ||
			got.CacheCreationTokens != want.CacheCreationTokens || got.CostUSD != want.CostUSD ||
			got.StopReason != want.StopReason || got.HTTPStatus != want.HTTPStatus {
			t.Fatalf("facts mismatch:\n got  %+v\n want %+v", got, want)
		}
		if string(got.RequestBody) != string(want.RequestBody) {
			t.Errorf("RequestBody = %q, want %q", got.RequestBody, want.RequestBody)
		}
		if string(got.ResponseBody) != string(want.ResponseBody) {
			t.Errorf("ResponseBody = %q, want %q", got.ResponseBody, want.ResponseBody)
		}
	})

	t.Run("hosted-app conversation headers feed the trace session", func(t *testing.T) {
		// The harness gateway (X-Superbased-Session) and Open WebUI
		// (X-OpenWebUI-Chat-Id) send an explicit conversation id per call.
		// resolveAPITurnSessionID already lifts these onto
		// api_turns.session_id; the synthesized trace must carry the SAME
		// id or the conversation groups in Plane-B cost rollups while the
		// Hosted Apps views show uncorrelated single-call traces (the blank
		// obs session_id class, 2026-08-14). X-Session-Id still wins when
		// both are present.
		cases := []struct {
			name    string
			headers map[string]string
			want    string
		}{
			{"X-Superbased-Session alone", map[string]string{"X-Superbased-Session": "conv-superbased-1"}, "conv-superbased-1"},
			{"X-OpenWebUI-Chat-Id alone", map[string]string{"X-OpenWebUI-Chat-Id": "owui-chat-2"}, "owui-chat-2"},
			{"X-Session-Id outranks the hosted headers", map[string]string{
				"X-Session-Id":         "explicit-3",
				"X-Superbased-Session": "conv-superbased-3",
			}, "explicit-3"},
			{"blank hosted header is ignored", map[string]string{"X-Superbased-Session": "   "}, ""},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				sink := &fakeObsSink{callDoneChan: make(chan struct{}, 1)}
				p, err := New(Options{Sink: &fakeSink{}, ObsSink: sink})
				if err != nil {
					t.Fatalf("New: %v", err)
				}
				req := hostedLaneReq(httptest.NewRequest(http.MethodPost, "/v1/messages", nil))
				for k, v := range tc.headers {
					req.Header.Set(k, v)
				}
				p.synthesizeObsTrace(baseTurn, 11, req, reqBody, respBody)
				waitForCall(t, sink.callDoneChan, 2*time.Second)
				calls := sink.all()
				if len(calls) != 1 {
					t.Fatalf("expected exactly one sink call, got %d", len(calls))
				}
				if got := calls[0].SessionID; got != tc.want {
					t.Fatalf("facts.SessionID = %q, want %q", got, tc.want)
				}
			})
		}
	})

	t.Run("sb_session query param feeds the trace session (codex query_params lane)", func(t *testing.T) {
		// codex 0.147 dropped model-provider http_headers; query_params is
		// its only per-request identity channel (verified live: the param
		// lands on POST /v1/responses?sb_session=...). Explicit-only, same
		// lane gate as the headers; a header still outranks the param.
		sink := &fakeObsSink{callDoneChan: make(chan struct{}, 1)}
		p, err := New(Options{Sink: &fakeSink{}, ObsSink: sink})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		req := hostedLaneReq(httptest.NewRequest(http.MethodPost, "/v1/responses?sb_session=conv-codex-7", nil))
		p.synthesizeObsTrace(baseTurn, 12, req, reqBody, respBody)
		waitForCall(t, sink.callDoneChan, 2*time.Second)
		calls := sink.all()
		if len(calls) != 1 {
			t.Fatalf("expected exactly one sink call, got %d", len(calls))
		}
		if got := calls[0].SessionID; got != "conv-codex-7" {
			t.Fatalf("facts.SessionID = %q, want %q", got, "conv-codex-7")
		}
	})

	t.Run("sink error is fail-open (never surfaces, never panics)", func(t *testing.T) {
		sink := &fakeObsSink{errToReturn: errors.New("boom"), callDoneChan: make(chan struct{}, 1)}
		p, err := New(Options{Sink: &fakeSink{}, ObsSink: sink})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		req := hostedLaneReq(httptest.NewRequest(http.MethodPost, "/v1/messages", nil))
		// Must not panic despite the sink returning an error.
		p.synthesizeObsTrace(baseTurn, 9, req, reqBody, respBody)
		waitForCall(t, sink.callDoneChan, 2*time.Second)
		if got := sink.all(); len(got) != 1 {
			t.Fatalf("expected the sink to still be called once despite returning an error, got %d calls", len(got))
		}
	})

	t.Run("a panic inside the sink is recovered", func(t *testing.T) {
		sink := &panicObsSink{done: make(chan struct{}, 1)}
		p, err := New(Options{Sink: &fakeSink{}, ObsSink: sink})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		req := hostedLaneReq(httptest.NewRequest(http.MethodPost, "/v1/messages", nil))
		// Must not crash the test process.
		p.synthesizeObsTrace(baseTurn, 11, req, reqBody, respBody)
		waitForCall(t, sink.done, 2*time.Second)
	})
}

// panicObsSink always panics inside SynthesizeChatTurn, proving the
// fire-and-forget goroutine's recover() guard (Finding 1) actually protects
// the process. done is signaled from the deferred recover, after the panic
// unwinds, so the test can synchronize on "the panic was handled" rather than
// racing a background goroutine.
type panicObsSink struct {
	done chan struct{}
}

func (p *panicObsSink) SynthesizeChatTurn(context.Context, ChatTurnFacts) error {
	defer func() {
		recover() //nolint:errcheck // re-panic is not the point; we want THIS goroutine's panic to propagate to synthesizeObsTrace's own recover
		p.done <- struct{}{}
	}()
	panic("boom: sink panicked")
}

// TestSynthesizeObsTrace_Async proves Finding 1's core invariant: the caller
// (synthesizeObsTrace itself, standing in for the request-handling goroutine)
// returns immediately even though the sink blocks — the response path never
// waits on obs synthesis, only how promptly the trace appears is affected.
func TestSynthesizeObsTrace_Async(t *testing.T) {
	block := make(chan struct{})
	sink := &fakeObsSink{block: block, callDoneChan: make(chan struct{}, 1)}
	p, err := New(Options{Sink: &fakeSink{}, ObsSink: sink})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := hostedLaneReq(httptest.NewRequest(http.MethodPost, "/v1/messages", nil))
	turn := models.APITurn{RequestID: "req-async", Timestamp: time.Now()}

	returned := make(chan struct{})
	go func() {
		p.synthesizeObsTrace(turn, 1, req, nil, nil)
		close(returned)
	}()

	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("synthesizeObsTrace did not return promptly — it must not block on the sink")
	}

	// The sink must NOT have been called yet (still blocked on `block`).
	if got := sink.all(); len(got) != 0 {
		t.Fatalf("sink was called before being unblocked: %d calls", len(got))
	}

	close(block)
	waitForCall(t, sink.callDoneChan, 2*time.Second)
	if got := sink.all(); len(got) != 1 {
		t.Fatalf("expected exactly one sink call after unblocking, got %d", len(got))
	}
}

// TestSynthesizeObsTrace_EndToEndViaServe drives a full HTTP round trip
// through the proxy's serve() path (a real Anthropic-shaped non-streaming
// success turn) and asserts the wired ObsSink receives the same turn the
// api_turns sink recorded, with a request id and request/response bodies
// carried through, and that the HTTP response itself is not delayed by the
// (fire-and-forget) sink call.
func TestSynthesizeObsTrace_EndToEndViaServe(t *testing.T) {
	const responseBody = `{"id":"msg_e2e","model":"claude-sonnet-4","stop_reason":"end_turn","usage":{"input_tokens":42,"output_tokens":17,"cache_read_input_tokens":0,"cache_creation_input_tokens":0}}`

	anth := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(responseBody))
	})
	oai := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("openai upstream unexpectedly hit: %s", r.URL.Path)
	})

	anthUp := httptest.NewServer(anth)
	defer anthUp.Close()
	oaiUp := httptest.NewServer(oai)
	defer oaiUp.Close()

	sink := &fakeSink{}
	obsSink := &fakeObsSink{callDoneChan: make(chan struct{}, 1)}
	p, err := New(Options{
		AnthropicUpstream: anthUp.URL,
		OpenAIUpstream:    oaiUp.URL,
		// The gateway rail only synthesizes for /up/<id> hosted-app lanes
		// (plane boundary) — route this test's traffic through one.
		Upstreams: map[string]string{"hostedapp": anthUp.URL},
		Sink:      sink,
		ObsSink:   obsSink,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	const reqBody = `{"model":"claude-sonnet-4","messages":[{"role":"user","content":"hi"}]}`
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/up/hostedapp/v1/messages", strings.NewReader(reqBody))
	req.Header.Set("X-Api-Key", "sk-ant-test")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d want 200", resp.StatusCode)
	}

	waitForCall(t, obsSink.callDoneChan, 2*time.Second)
	calls := obsSink.all()
	if len(calls) != 1 {
		t.Fatalf("expected exactly one obs sink call, got %d", len(calls))
	}
	got := calls[0]
	if got.RequestID != "msg_e2e" {
		t.Errorf("RequestID: got %q want %q", got.RequestID, "msg_e2e")
	}
	if got.Model != "claude-sonnet-4" {
		t.Errorf("Model: got %q want claude-sonnet-4", got.Model)
	}
	if got.InputTokens != 42 || got.OutputTokens != 17 {
		t.Errorf("tokens: got in=%d out=%d want in=42 out=17", got.InputTokens, got.OutputTokens)
	}
	if got.APITurnID == 0 {
		t.Errorf("APITurnID: expected non-zero, got 0")
	}
	if !strings.Contains(string(got.RequestBody), `"role":"user"`) {
		t.Errorf("RequestBody not threaded through: %q", got.RequestBody)
	}
	if !strings.Contains(string(got.ResponseBody), "msg_e2e") {
		t.Errorf("ResponseBody not threaded through: %q", got.ResponseBody)
	}
}

// TestSynthesizeObsTrace_ConcurrencyBound proves Finding 3's fix: once
// obsGatewayMaxConcurrentSynthesis synthesis goroutines are in flight, every
// further call to synthesizeObsTrace returns immediately and drops the
// synthesis (fail-open) instead of blocking the caller or growing goroutines
// unboundedly. It also proves the bound is exactly respected — no more than
// obsGatewayMaxConcurrentSynthesis calls ever reach the sink concurrently.
func TestSynthesizeObsTrace_ConcurrencyBound(t *testing.T) {
	block := make(chan struct{})
	const extra = 5
	total := obsGatewayMaxConcurrentSynthesis + extra
	sink := &fakeObsSink{block: block, callDoneChan: make(chan struct{}, total)}
	p, err := New(Options{Sink: &fakeSink{}, ObsSink: sink})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := hostedLaneReq(httptest.NewRequest(http.MethodPost, "/v1/messages", nil))
	turn := models.APITurn{RequestID: "req-bound", Timestamp: time.Now()}

	// Every call must return promptly regardless of whether its slot was
	// acquired or dropped — none of them may block on the (currently
	// blocked) sink, and the semaphore acquire itself must never wait.
	done := make(chan struct{})
	go func() {
		for i := 0; i < total; i++ {
			p.synthesizeObsTrace(turn, int64(i+1), req, nil, nil)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("synthesizeObsTrace calls did not all return promptly — the concurrency bound must never block the caller")
	}

	// Give the goroutines that acquired a slot a moment to actually reach
	// the (blocked) sink call before unblocking, so the steady-state count
	// below is stable.
	time.Sleep(50 * time.Millisecond)

	close(block)
	deadline := time.After(2 * time.Second)
	got := 0
	for got < obsGatewayMaxConcurrentSynthesis {
		select {
		case <-sink.callDoneChan:
			got++
		case <-deadline:
			t.Fatalf("timed out waiting for sink calls: got %d, want %d", got, obsGatewayMaxConcurrentSynthesis)
		}
	}

	// The extra callers beyond the bound must have been DROPPED, not
	// queued — no further sink call should ever arrive.
	select {
	case <-sink.callDoneChan:
		t.Fatalf("expected exactly %d sink calls (the concurrency bound), got at least %d", obsGatewayMaxConcurrentSynthesis, got+1)
	case <-time.After(150 * time.Millisecond):
	}

	if calls := sink.all(); len(calls) != obsGatewayMaxConcurrentSynthesis {
		t.Fatalf("sink calls = %d, want %d (the concurrency bound); %d of %d callers should have been dropped",
			len(calls), obsGatewayMaxConcurrentSynthesis, extra, total)
	}
}

// TestObsClipResponseBody covers the F6 follow-up found by live verification
// against a real OpenRouter stream from a reasoning model
// (nvidia/nemotron-3.5-lightning:free): the turn synthesized a trace with a
// prompt content row but NO response content row, because obsClipBody's
// unconditional HEAD clip discarded the tail of the SSE body — exactly
// where a reasoning model's assistant `content` deltas live, after
// potentially many kilobytes of `reasoning` deltas that come first.
//
// The fixture below reproduces OpenRouter's actual shape: an SSE COMMENT
// line (": OPENROUTER PROCESSING", no "data:" prefix) before any data line,
// a long run of reasoning-only deltas (no "content" field at all — the
// shape a reasoning model emits) padded well past obsGatewayMaxBodyBytes,
// then the real content deltas, then "[DONE]". obsClipResponseBody must
// keep the TAIL (where the content lives) for this SSE-shaped body, while a
// plain (non-streaming) JSON response body must still be head-clipped
// (unchanged behaviour — verified by the "plain JSON" case below).
func TestObsClipResponseBody(t *testing.T) {
	reasoningDelta := `data: {"choices":[{"delta":{"reasoning":"` +
		strings.Repeat("reasoning filler text. ", 200) + `"}}]}` + "\n\n"
	// Pad well past the clip bound with reasoning-only deltas, exactly
	// like a real reasoning-model stream that "thinks" before answering.
	var sseBody strings.Builder
	sseBody.WriteString(": OPENROUTER PROCESSING\n\n")
	for sseBody.Len() < obsGatewayMaxBodyBytes*2 {
		sseBody.WriteString(reasoningDelta)
	}
	sseBody.WriteString(`data: {"choices":[{"delta":{"content":"Earth"}}]}` + "\n\n")
	sseBody.WriteString("data: [DONE]\n\n")
	sseBytes := []byte(sseBody.String())
	if len(sseBytes) <= obsGatewayMaxBodyBytes {
		t.Fatalf("test fixture too small to exercise clipping: %d bytes", len(sseBytes))
	}

	t.Run("SSE body is tail-clipped, keeping the trailing content delta", func(t *testing.T) {
		clipped := obsClipResponseBody(sseBytes)
		if len(clipped) != obsGatewayMaxBodyBytes {
			t.Fatalf("clipped length = %d, want %d", len(clipped), obsGatewayMaxBodyBytes)
		}
		if !bytes.Equal(clipped, sseBytes[len(sseBytes)-obsGatewayMaxBodyBytes:]) {
			t.Fatal("obsClipResponseBody did not keep the TAIL of the SSE body")
		}
		if !bytes.Contains(clipped, []byte(`"content":"Earth"`)) {
			t.Fatal("tail-clipped SSE body lost the trailing content delta — the exact live-verification failure this test guards against")
		}
		if !bytes.Contains(clipped, []byte("[DONE]")) {
			t.Error("tail-clipped SSE body should retain the stream's trailing [DONE] sentinel")
		}
	})

	t.Run("a HEAD clip of the same body would have lost the content (documents the bug this fixes)", func(t *testing.T) {
		headClipped := sseBytes[:obsGatewayMaxBodyBytes]
		if bytes.Contains(headClipped, []byte(`"content":"Earth"`)) {
			t.Fatal("fixture is unrealistic: the head clip unexpectedly retained the content delta")
		}
	})

	t.Run("a plain (non-streaming) JSON response body is still head-clipped", func(t *testing.T) {
		var jsonBody strings.Builder
		jsonBody.WriteString(`{"id":"resp-1","choices":[{"message":{"content":"Earth"}}],"padding":"`)
		for jsonBody.Len() < obsGatewayMaxBodyBytes*2 {
			jsonBody.WriteString("x")
		}
		jsonBody.WriteString(`"}`)
		jsonBytes := []byte(jsonBody.String())
		clipped := obsClipResponseBody(jsonBytes)
		if len(clipped) != obsGatewayMaxBodyBytes {
			t.Fatalf("clipped length = %d, want %d", len(clipped), obsGatewayMaxBodyBytes)
		}
		if !bytes.Equal(clipped, jsonBytes[:obsGatewayMaxBodyBytes]) {
			t.Fatal("obsClipResponseBody did not HEAD-clip a plain JSON response body")
		}
	})

	t.Run("bodies within bound pass through unchanged", func(t *testing.T) {
		small := []byte("data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n")
		if got := obsClipResponseBody(small); !bytes.Equal(got, small) {
			t.Fatalf("small body was modified: got %q, want %q", got, small)
		}
	})

	t.Run("obsLooksLikeStreamBody discriminates SSE (incl. leading comment lines) from plain JSON", func(t *testing.T) {
		cases := []struct {
			name string
			body string
			want bool
		}{
			{"plain JSON object", `{"choices":[]}`, false},
			{"plain JSON array", `[{"type":"text"}]`, false},
			{"SSE data line", "data: {\"choices\":[]}\n\n", true},
			{"SSE with a leading OpenRouter-style comment line", ": OPENROUTER PROCESSING\n\ndata: {\"choices\":[]}\n\n", true},
			{"empty", "", false},
			{"whitespace only", "   \n\t  ", false},
		}
		for _, c := range cases {
			if got := obsLooksLikeStreamBody([]byte(c.body)); got != c.want {
				t.Errorf("%s: obsLooksLikeStreamBody(%q) = %v, want %v", c.name, c.body, got, c.want)
			}
		}
	})
}

// TestSynthesizeObsTrace_ContentExtractor pins Lane B (trajectory-ui-
// rollup-and-spandetail-fixes spec): when Options.ObsContentExtractor is
// wired, synthesizeObsTrace must call it SYNCHRONOUSLY over the FULL,
// unclipped request/response bodies (never the obsClipBody/
// obsClipResponseBody-clipped prefix/tail), and the resulting ChatTurnFacts
// must carry the extractor's own output on PromptText/ResponseText with
// ContentExtracted=true and nil Request/ResponseBody — even when the input
// bodies exceed obsGatewayMaxBodyBytes. The nil-extractor (legacy) path is
// already pinned byte-for-byte by TestSynthesizeObsTrace_TableDriven's
// "invokes sink with the projected facts, including admission user and
// bodies" subtest and is deliberately left untouched here.
func TestSynthesizeObsTrace_ContentExtractor(t *testing.T) {
	baseTurn := models.APITurn{
		RequestID:  "req-extract-1",
		Provider:   "openrouter",
		Model:      "some/model",
		Timestamp:  time.Date(2026, 8, 14, 9, 0, 0, 0, time.UTC),
		HTTPStatus: 200,
	}

	// Oversized bodies (> obsGatewayMaxBodyBytes) — the legacy path would
	// clip these; the extractor must see them whole. Echo the exact byte
	// lengths into the returned text so the test can assert nothing was
	// clipped before the extractor ran.
	reqBody := bytes.Repeat([]byte("A"), obsGatewayMaxBodyBytes*2)
	respBody := bytes.Repeat([]byte("B"), obsGatewayMaxBodyBytes*2)

	var gotReqLen, gotRespLen int
	extractor := func(req, resp []byte) (string, string) {
		gotReqLen = len(req)
		gotRespLen = len(resp)
		return "EXTRACTED-PROMPT", "EXTRACTED-RESPONSE"
	}

	sink := &fakeObsSink{callDoneChan: make(chan struct{}, 1)}
	p, err := New(Options{Sink: &fakeSink{}, ObsSink: sink, ObsContentExtractor: extractor})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := hostedLaneReq(httptest.NewRequest(http.MethodPost, "/v1/messages", nil))
	p.synthesizeObsTrace(baseTurn, 99, req, reqBody, respBody)
	waitForCall(t, sink.callDoneChan, 2*time.Second)

	if gotReqLen != len(reqBody) {
		t.Errorf("extractor received a request body of length %d, want the FULL unclipped %d (obsGatewayMaxBodyBytes=%d)", gotReqLen, len(reqBody), obsGatewayMaxBodyBytes)
	}
	if gotRespLen != len(respBody) {
		t.Errorf("extractor received a response body of length %d, want the FULL unclipped %d (obsGatewayMaxBodyBytes=%d)", gotRespLen, len(respBody), obsGatewayMaxBodyBytes)
	}

	calls := sink.all()
	if len(calls) != 1 {
		t.Fatalf("expected exactly one sink call, got %d", len(calls))
	}
	got := calls[0]
	if !got.ContentExtracted {
		t.Error("ContentExtracted = false, want true when an extractor is wired")
	}
	if got.PromptText != "EXTRACTED-PROMPT" {
		t.Errorf("PromptText = %q, want %q", got.PromptText, "EXTRACTED-PROMPT")
	}
	if got.ResponseText != "EXTRACTED-RESPONSE" {
		t.Errorf("ResponseText = %q, want %q", got.ResponseText, "EXTRACTED-RESPONSE")
	}
	if got.RequestBody != nil {
		t.Errorf("RequestBody = %v, want nil when an extractor is wired", got.RequestBody)
	}
	if got.ResponseBody != nil {
		t.Errorf("ResponseBody = %v, want nil when an extractor is wired", got.ResponseBody)
	}
}

package proxy

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestAdmissionViewNode is the node half of finding H1 (L-180): the proxy's
// hosted-app admission reads the shared promptturn.AdmissionView, so the
// text it judges and the content it cannot read are the AI gateway's.
func TestAdmissionViewNode(t *testing.T) {
	tests := []struct {
		name      string
		provider  string
		body      string
		want      string
		wantUnacc []string
	}{
		{
			name: "anthropic string content", provider: models.ProviderAnthropic,
			body: `{"messages":[{"role":"user","content":"hello there"}]}`, want: "hello there",
		},
		{
			name: "anthropic block content, last user wins", provider: models.ProviderAnthropic,
			body: `{"messages":[{"role":"user","content":"first"},{"role":"assistant","content":"hi"},` +
				`{"role":"user","content":[{"type":"text","text":"second ask"}]}]}`,
			want: "second ask",
		},
		{
			name: "anthropic tool_result-only with no opening prompt: nothing", provider: models.ProviderAnthropic,
			body: `{"messages":[{"role":"user","content":[{"type":"tool_result","content":"x"}]}]}`, want: "",
		},
		{
			name: "anthropic tool loop judges the opening prompt", provider: models.ProviderAnthropic,
			body: `{"messages":[{"role":"user","content":"book a flight"},{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"s","input":{}}]},` +
				`{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"x"}]}]}`,
			want: "book a flight",
		},
		{
			name: "openai chat messages", provider: models.ProviderOpenAI,
			body: `{"messages":[{"role":"system","content":"sys"},{"role":"user","content":"chat ask"}]}`, want: "chat ask",
		},
		{
			name: "openai responses input string", provider: models.ProviderOpenAI,
			body: `{"input":"responses ask"}`, want: "responses ask",
		},
		{
			name: "openai responses input array input_text", provider: models.ProviderOpenAI,
			body: `{"input":[{"role":"user","content":[{"type":"input_text","text":"typed ask"}]}]}`, want: "typed ask",
		},
		{
			name: "anthropic plain-text document is read", provider: models.ProviderAnthropic,
			body: `{"messages":[{"role":"user","content":[{"type":"document","source":{"type":"text","media_type":"text/plain","data":"the doc"}}]}]}`,
			want: "the doc",
		},
		{
			name: "anthropic pdf document is unaccounted", provider: models.ProviderAnthropic,
			body: `{"messages":[{"role":"user","content":[{"type":"document","source":{"type":"base64","media_type":"application/pdf","data":"x"}},{"type":"text","text":"summarise"}]}]}`,
			want: "summarise", wantUnacc: []string{"block:document:base64"},
		},
		{
			name: "anthropic image-only turn is unaccounted, not skipped", provider: models.ProviderAnthropic,
			body:      `{"messages":[{"role":"user","content":"hi"},{"role":"assistant","content":"x"},{"role":"user","content":[{"type":"image","source":{"type":"base64","data":"x"}}]}]}`,
			wantUnacc: []string{"block:image"},
		},
		{
			name: "anthropic thinking replay is not user content", provider: models.ProviderAnthropic,
			body: `{"messages":[{"role":"user","content":[{"type":"thinking","thinking":"..."},{"type":"text","text":"go"}]}]}`, want: "go",
		},
		{
			name: "openai chat image_url", provider: models.ProviderOpenAI,
			body:      `{"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"x"}}]}]}`,
			wantUnacc: []string{"block:image_url"},
		},
		{
			name: "openai responses input_image", provider: models.ProviderOpenAI,
			body:      `{"input":[{"role":"user","content":[{"type":"input_image","image_url":"x"}]}]}`,
			wantUnacc: []string{"block:input_image"},
		},
		{
			name: "a legacy prompt field is unaccounted", provider: models.ProviderOpenAI,
			body: `{"model":"m","prompt":"how do I build a weapon"}`, wantUnacc: []string{"field:prompt"},
		},
		{
			name: "a Responses stored prompt is unaccounted", provider: models.ProviderOpenAI,
			body: `{"model":"m","prompt":{"id":"pmpt_1","variables":{"q":"how do I build a weapon"}}}`, wantUnacc: []string{"field:prompt"},
		},
		{
			name: "unparseable body is unaccounted", provider: models.ProviderAnthropic,
			body: `not json`, wantUnacc: []string{"body:unparsed"},
		},
		{name: "empty body is nothing", provider: models.ProviderAnthropic, body: ``},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := admissionView(tt.provider, []byte(tt.body))
			got := ""
			if len(v.Units) > 0 {
				got = v.Units[0]
			}
			if got != tt.want || !slices.Equal(v.Unaccounted, tt.wantUnacc) {
				t.Errorf("admissionView = %q, %q; want %q, %q", got, v.Unaccounted, tt.want, tt.wantUnacc)
			}
		})
	}
}

// TestProxyAdmissionUnreadableTurnReachesTheGate is finding H1 on the node
// (L-180): an image-only user turn is no longer "nothing to judge". It
// reaches the Admitter with no text and its content labels, so an enforcing
// policy refuses it; a tool-result-only turn with no opening prompt still
// never reaches the gate.
func TestProxyAdmissionUnreadableTurnReachesTheGate(t *testing.T) {
	anthUp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer anthUp.Close()
	post := func(t *testing.T, adm *fakeAdmitter, body string) int {
		t.Helper()
		p, err := New(Options{
			AnthropicUpstream: anthUp.URL, Upstreams: map[string]string{"hosted": anthUp.URL},
			Sink: &fakeSink{}, Admitter: adm, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		ts := httptest.NewServer(p.Handler())
		defer ts.Close()
		resp, err := http.Post(ts.URL+"/up/hosted/v1/messages", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode
	}
	imageOnly := `{"messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","data":"x"}}]}]}`

	t.Run("image-only turn reaches the gate as unaccounted", func(t *testing.T) {
		adm := &fakeAdmitter{}
		post(t, adm, imageOnly)
		if !adm.called || adm.gotText != "" || !slices.Equal(adm.gotUnaccounted, []string{"block:image"}) {
			t.Errorf("admitter called=%v text=%q unaccounted=%q; want called with no text and [block:image]", adm.called, adm.gotText, adm.gotUnaccounted)
		}
	})
	t.Run("an enforcing gate refuses it", func(t *testing.T) {
		adm := &fakeAdmitter{block: true, reason: "unreadable"}
		if code := post(t, adm, imageOnly); code != http.StatusForbidden {
			t.Errorf("status = %d, want 403", code)
		}
	})
	t.Run("tool-result-only turn with no opening prompt: not gated", func(t *testing.T) {
		adm := &fakeAdmitter{}
		post(t, adm, `{"messages":[{"role":"user","content":[{"type":"tool_result","content":"x"}]}]}`)
		if adm.called {
			t.Error("Admitter was called for a tool-result-only turn with nothing to judge")
		}
	})
}

func TestWriteAdmissionRefusalShapes(t *testing.T) {
	t.Run("anthropic", func(t *testing.T) {
		w := httptest.NewRecorder()
		writeAdmissionRefusal(w, models.ProviderAnthropic, "off-scope")
		if w.Code != http.StatusForbidden {
			t.Errorf("status = %d, want 403", w.Code)
		}
		var body struct {
			Type  string `json:"type"`
			Error struct {
				Type    string `json:"type"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if body.Type != "error" || body.Error.Type != "permission_error" || body.Error.Message != "off-scope" {
			t.Errorf("anthropic refusal body = %s", w.Body.String())
		}
	})
	t.Run("openai", func(t *testing.T) {
		w := httptest.NewRecorder()
		writeAdmissionRefusal(w, models.ProviderOpenAI, "off-scope")
		var body struct {
			Error struct {
				Message string `json:"message"`
				Code    string `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if body.Error.Code != "admission_denied" || body.Error.Message != "off-scope" {
			t.Errorf("openai refusal body = %s", w.Body.String())
		}
	})
}

// fakeAdmitter is a test Admitter that records the text it saw. It also models
// the two-phase persist contract: unless persistAtAdmit is set it returns a
// finalize handle and records the (single) FinalizeAdmission call, so tests can
// assert the deferred row lands exactly once with the resolved request id.
type fakeAdmitter struct {
	mu             sync.Mutex
	block          bool
	reason         string
	called         bool
	gotText        string
	gotUser        string
	gotReqID       string
	gotModel       string
	gotUnaccounted []string
	route          *AdmitRoute
	persistAtAdmit bool // when true, Admit returns no finalize handle

	finalizeCalls  int
	finalizeReqIDs []string
	finalizeTokens []AdmitToken
}

// admitHandle is the opaque value the fake hands back as its finalize token.
type admitHandle struct{ id string }

func (f *fakeAdmitter) Admit(_ context.Context, in AdmitInput) AdmitResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.called = true
	f.gotText = in.Text
	f.gotUser = in.User
	f.gotReqID = in.RequestID
	f.gotModel = in.Model
	f.gotUnaccounted = in.Unaccounted
	res := AdmitResult{Block: f.block, Reason: f.reason, Criterion: "AD-100", Route: f.route}
	// A blocked verdict persists inside Admit (nothing is forwarded), exactly
	// like the real obs adapter — no finalize handle travels back.
	if !f.persistAtAdmit && !f.block {
		res.Finalize = &admitHandle{id: in.RequestID}
	}
	return res
}

func (f *fakeAdmitter) FinalizeAdmission(_ context.Context, handle AdmitToken, resolvedRequestID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.finalizeCalls++
	f.finalizeReqIDs = append(f.finalizeReqIDs, resolvedRequestID)
	f.finalizeTokens = append(f.finalizeTokens, handle)
}

// finalized returns the recorded finalize calls under the fake's lock.
func (f *fakeAdmitter) finalized() (int, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.finalizeCalls, append([]string(nil), f.finalizeReqIDs...)
}

// finalizedTokens returns the handles the proxy carried back, under the lock.
func (f *fakeAdmitter) finalizedTokens() []AdmitToken {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]AdmitToken(nil), f.finalizeTokens...)
}

// TestProxyEgressRouteUpstream proves the P6 proxy application: an enforce-mode
// route_upstream directive redirects the forward to the resolved target and
// away from the default upstream.
func TestProxyEgressRouteUpstream(t *testing.T) {
	var defaultHit, targetHit bool
	defaultUp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		defaultHit = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer defaultUp.Close()
	targetUp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetHit = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer targetUp.Close()

	adm := &fakeAdmitter{route: &AdmitRoute{
		Action: "route_upstream", UpstreamID: "local", TargetURL: targetUp.URL,
		TargetShape: "anthropic", OnUnavailable: "deny", MustUseTarget: true,
	}}
	p, err := New(Options{AnthropicUpstream: defaultUp.URL, Upstreams: map[string]string{"hosted": defaultUp.URL}, Sink: &fakeSink{}, Admitter: adm})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/up/hosted/v1/messages",
		strings.NewReader(`{"model":"claude-opus-4-8","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if !targetHit {
		t.Error("egress route_upstream did not reach the target upstream")
	}
	if defaultHit {
		t.Error("request leaked to the default upstream despite an enforce route_upstream")
	}
}

// TestProxyEgressRouteModelSplice proves an enforce route_model rewrites the
// top-level model in the forwarded body.
func TestProxyEgressRouteModelSplice(t *testing.T) {
	var gotModel string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Model string `json:"model"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotModel = body.Model
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer up.Close()

	adm := &fakeAdmitter{route: &AdmitRoute{Action: "route_model", Model: "claude-3-5-haiku-20241022"}}
	p, err := New(Options{AnthropicUpstream: up.URL, Upstreams: map[string]string{"hosted": up.URL}, Sink: &fakeSink{}, Admitter: adm})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/up/hosted/v1/messages",
		strings.NewReader(`{"model":"claude-opus-4-8","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if gotModel != "claude-3-5-haiku-20241022" {
		t.Errorf("forwarded model = %q, want the egress route_model target", gotModel)
	}
}

// TestProxyAdmissionEstablishesRequestIDAndModel proves the design's P0
// contract prerequisites: the proxy hands admission a STABLE request id
// (established before admit()) and the pre-mutation top-level model, so the
// audit rows can soft-join to the api_turns row and egress can match the model.
func TestProxyAdmissionEstablishesRequestIDAndModel(t *testing.T) {
	anthUp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer anthUp.Close()

	adm := &fakeAdmitter{block: false}
	p, err := New(Options{AnthropicUpstream: anthUp.URL, Upstreams: map[string]string{"hosted": anthUp.URL}, Sink: &fakeSink{}, Admitter: adm})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/up/hosted/v1/messages",
		strings.NewReader(`{"model":"claude-opus-4-8","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if !adm.called {
		t.Fatal("admitter was not consulted")
	}
	if adm.gotReqID == "" {
		t.Error("admitter saw empty RequestID — the P0 stable request id is not established before admit()")
	}
	if adm.gotModel != "claude-opus-4-8" {
		t.Errorf("admitter saw model %q, want claude-opus-4-8 (pre-mutation top-level model)", adm.gotModel)
	}
}

// TestTopLevelModel pins the pre-admit model extractor: present/absent/
// non-string/unparseable all resolve as documented (fail-open to "").
func TestTopLevelModel(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{"present", `{"model":"gpt-5","messages":[]}`, "gpt-5"},
		{"absent", `{"messages":[]}`, ""},
		{"nested-only", `{"messages":[{"role":"user","content":[{"model":"x"}]}]}`, ""},
		{"non-string", `{"model":123}`, ""},
		{"unparseable", `not json`, ""},
		{"empty", ``, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := topLevelModel([]byte(tc.body)); got != tc.want {
				t.Errorf("topLevelModel(%q) = %q, want %q", tc.body, got, tc.want)
			}
		})
	}
}

// TestProxyAdmissionThreadsUserHeader proves the configured AdmissionUserHeader
// is read off the request and threaded into AdmitInput.User (the org-hosted-app
// per-end-user identity path).
func TestProxyAdmissionThreadsUserHeader(t *testing.T) {
	anthUp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer anthUp.Close()

	adm := &fakeAdmitter{block: false}
	p, err := New(Options{
		AnthropicUpstream: anthUp.URL,
		Upstreams:         map[string]string{"hosted": anthUp.URL},
		Sink:              &fakeSink{}, Admitter: adm,
		AdmissionUserHeader: "X-Superbased-User",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/up/hosted/v1/messages",
		strings.NewReader(`{"messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Superbased-User", "alice@example.com")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if !adm.called {
		t.Fatal("admitter was not consulted")
	}
	if adm.gotUser != "alice@example.com" {
		t.Errorf("admitter saw user %q, want alice@example.com", adm.gotUser)
	}
}

// TestProxyAdmissionBlocksBeforeForward proves an enforce-mode block short-
// circuits with a provider-shaped 403 and never touches the upstream.
func TestProxyAdmissionBlocksBeforeForward(t *testing.T) {
	anthUp := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Errorf("upstream hit despite admission block: %s", r.URL.Path)
	}))
	defer anthUp.Close()

	adm := &fakeAdmitter{block: true, reason: "off-scope request"}
	p, err := New(Options{AnthropicUpstream: anthUp.URL, Upstreams: map[string]string{"hosted": anthUp.URL}, Sink: &fakeSink{}, Admitter: adm})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/up/hosted/v1/messages", "application/json",
		strings.NewReader(`{"messages":[{"role":"user","content":"do the forbidden thing"}]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	if !adm.called || adm.gotText != "do the forbidden thing" {
		t.Errorf("admitter saw text %q (called=%v)", adm.gotText, adm.called)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "off-scope request") {
		t.Errorf("refusal body missing reason: %s", body)
	}
}

// TestProxyAdmissionObserveForwards proves a non-blocking verdict (observe
// mode, or an allow) forwards to the upstream unchanged.
func TestProxyAdmissionObserveForwards(t *testing.T) {
	hit := false
	anthUp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"content":[{"type":"text","text":"ok"}],` +
			`"usage":{"input_tokens":3,"output_tokens":2}}`))
	}))
	defer anthUp.Close()

	adm := &fakeAdmitter{block: false}
	p, err := New(Options{AnthropicUpstream: anthUp.URL, Upstreams: map[string]string{"hosted": anthUp.URL}, Sink: &fakeSink{}, Admitter: adm})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/up/hosted/v1/messages", "application/json",
		strings.NewReader(`{"messages":[{"role":"user","content":"a fine question"}]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if !hit {
		t.Error("upstream was not forwarded to on a non-blocking verdict")
	}
	if !adm.called {
		t.Error("admitter was not consulted")
	}
}

// --- two-phase Admit/Finalize (admission-trace-linkage spec §1/§4) --------

// TestProxyAdmissionFinalizesWithProviderEchoedRequestID proves the deferred
// persist contract on the allowed+forwarded path: the proxy calls
// FinalizeAdmission exactly once, and with the PROVIDER-echoed request id (the
// same value stamped on the api_turn and used to seed the synthesized trace),
// not the pre-forward proxy id admit() saw. Reverting the finalize wiring in
// serve() fails this on finalizeCalls == 0.
func TestProxyAdmissionFinalizesWithProviderEchoedRequestID(t *testing.T) {
	anthUp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_provider_echo","model":"claude-opus-4-8",` +
			`"content":[{"type":"text","text":"ok"}],` +
			`"usage":{"input_tokens":3,"output_tokens":2}}`))
	}))
	defer anthUp.Close()

	adm := &fakeAdmitter{}
	p, err := New(Options{AnthropicUpstream: anthUp.URL, Upstreams: map[string]string{"hosted": anthUp.URL}, Sink: &fakeSink{}, Admitter: adm})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/up/hosted/v1/messages", "application/json",
		strings.NewReader(`{"model":"claude-opus-4-8","messages":[{"role":"user","content":"a fine question"}]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	calls, ids := adm.finalized()
	if calls != 1 {
		t.Fatalf("FinalizeAdmission called %d times, want exactly 1 (the deferred row must land once)", calls)
	}
	if ids[0] != "msg_provider_echo" {
		t.Errorf("finalized with request id %q, want the provider-echoed %q — the admission row would not share the api_turn's id (nor its synthesized trace id)", ids[0], "msg_provider_echo")
	}
	if adm.gotReqID == "msg_provider_echo" {
		t.Error("admit() already saw the provider id; the test no longer proves the pre-forward/post-forward divergence")
	}
	// The handle must round-trip unchanged: the proxy carries it, never
	// reconstructs it (no obs type crosses the seam for it to rebuild).
	tokens := adm.finalizedTokens()
	h, ok := tokens[0].(*admitHandle)
	if !ok || h.id != adm.gotReqID {
		t.Errorf("finalize handle = %#v, want the exact value Admit returned", tokens[0])
	}
}

// TestProxyAdmissionBlockedVerdictDoesNotFinalize proves a blocked verdict
// persists inside Admit and never travels to FinalizeAdmission — nothing is
// forwarded, so no later request id can resolve for it.
func TestProxyAdmissionBlockedVerdictDoesNotFinalize(t *testing.T) {
	anthUp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("upstream was forwarded to despite a blocking verdict")
	}))
	defer anthUp.Close()

	adm := &fakeAdmitter{block: true, reason: "off-scope"}
	p, err := New(Options{AnthropicUpstream: anthUp.URL, Upstreams: map[string]string{"hosted": anthUp.URL}, Sink: &fakeSink{}, Admitter: adm})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/up/hosted/v1/messages", "application/json",
		strings.NewReader(`{"messages":[{"role":"user","content":"do a bad thing"}]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if calls, _ := adm.finalized(); calls != 0 {
		t.Errorf("FinalizeAdmission called %d times on a blocked verdict, want 0", calls)
	}
}

// TestProxyAdmissionFinalizesOnUpstreamError is the defer fail-safe: an
// upstream that cannot be reached still yields exactly one finalize, falling
// back to the proxy's own request id (no lost row, no double insert).
func TestProxyAdmissionFinalizesOnUpstreamError(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close() // nothing is listening now: the forward fails at the transport

	adm := &fakeAdmitter{}
	p, err := New(Options{AnthropicUpstream: deadURL, Upstreams: map[string]string{"hosted": deadURL}, Sink: &fakeSink{}, Admitter: adm})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/up/hosted/v1/messages", "application/json",
		strings.NewReader(`{"messages":[{"role":"user","content":"a fine question"}]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 (upstream unreachable)", resp.StatusCode)
	}

	calls, ids := adm.finalized()
	if calls != 1 {
		t.Fatalf("FinalizeAdmission called %d times on the upstream-error path, want exactly 1", calls)
	}
	if ids[0] != adm.gotReqID {
		t.Errorf("finalized with %q, want the proxy request id %q (the only id that ever resolved)", ids[0], adm.gotReqID)
	}
}

// TestProxyAdmissionSkippedOffLane proves the lane gate still holds under the
// two-phase seam: a default-lane request never admits, so nothing finalizes.
func TestProxyAdmissionSkippedOffLane(t *testing.T) {
	anthUp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer anthUp.Close()

	adm := &fakeAdmitter{}
	p, err := New(Options{AnthropicUpstream: anthUp.URL, Sink: &fakeSink{}, Admitter: adm})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/v1/messages", "application/json",
		strings.NewReader(`{"messages":[{"role":"user","content":"plane-B coding turn"}]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if adm.called {
		t.Error("admitter ran on a default (Plane-B) lane")
	}
	if calls, _ := adm.finalized(); calls != 0 {
		t.Errorf("FinalizeAdmission called %d times off-lane, want 0", calls)
	}
}

// TestProxyAdmissionNonDeferringGateNeverFinalizes covers the other half of the
// seam contract: a gate that persists inside Admit returns no handle, and the
// proxy must then never call FinalizeAdmission (a nil handle is a no-op, not a
// finalize with nothing to write).
func TestProxyAdmissionNonDeferringGateNeverFinalizes(t *testing.T) {
	anthUp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","model":"claude-opus-4-8","content":[{"type":"text","text":"ok"}],` +
			`"usage":{"input_tokens":3,"output_tokens":2}}`))
	}))
	defer anthUp.Close()

	adm := &fakeAdmitter{persistAtAdmit: true}
	p, err := New(Options{AnthropicUpstream: anthUp.URL, Upstreams: map[string]string{"hosted": anthUp.URL}, Sink: &fakeSink{}, Admitter: adm})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/up/hosted/v1/messages", "application/json",
		strings.NewReader(`{"messages":[{"role":"user","content":"a fine question"}]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if !adm.called {
		t.Fatal("admitter was not consulted")
	}
	if calls, _ := adm.finalized(); calls != 0 {
		t.Errorf("FinalizeAdmission called %d times for a gate that returned no handle, want 0", calls)
	}
}

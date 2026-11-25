package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/applane"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// fakeAppLaneGate records every reservation and every close.
type fakeAppLaneGate struct {
	mu       sync.Mutex
	refuse   bool
	code     string
	reserves []AppLaneReserve
	closes   []AppLaneClose
}

type fakeAppLaneHold struct{ g *fakeAppLaneGate }

func (h fakeAppLaneHold) CloseAppLane(c AppLaneClose) {
	h.g.mu.Lock()
	defer h.g.mu.Unlock()
	h.g.closes = append(h.g.closes, c)
}

func (g *fakeAppLaneGate) ReserveAppLane(_ context.Context, in AppLaneReserve) AppLaneDecision {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.reserves = append(g.reserves, in)
	if g.refuse {
		return AppLaneDecision{Refused: true, Code: g.code, Reason: "Usage budget exceeded for this service (daily)."}
	}
	return AppLaneDecision{Hold: fakeAppLaneHold{g: g}}
}

func (g *fakeAppLaneGate) snapshot() ([]AppLaneReserve, []AppLaneClose) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]AppLaneReserve(nil), g.reserves...), append([]AppLaneClose(nil), g.closes...)
}

// laneHarness is a proxy with one /up/hostedapp lane in front of an upstream
// handler, counting upstream hits.
type laneHarness struct {
	ts    *httptest.Server
	sink  *fakeSink
	hits  *atomic.Int32
	close func()
}

func newLaneHarness(t *testing.T, upstream http.HandlerFunc, mutate func(*Options)) laneHarness {
	t.Helper()
	hits := &atomic.Int32{}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		upstream(w, r)
	}))
	sink := &fakeSink{}
	opts := Options{
		AnthropicUpstream: up.URL,
		OpenAIUpstream:    up.URL,
		Upstreams:         map[string]string{"hostedapp": up.URL},
		Sink:              sink,
		CostComputer:      &fakeCostComputer{rate: 0.001},
	}
	if mutate != nil {
		mutate(&opts)
	}
	p, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(p.Handler())
	return laneHarness{ts: ts, sink: sink, hits: hits, close: func() { ts.Close(); up.Close() }}
}

func (h laneHarness) post(t *testing.T, path, body string, headers map[string]string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, h.ts.URL+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", "sk-ant-test")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, b
}

const laneAnthropicOK = `{"id":"msg_provider","model":"claude-haiku-5-5","stop_reason":"end_turn","usage":{"input_tokens":10,"output_tokens":5}}`

func anthropicOK(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(laneAnthropicOK))
}

const laneBody = `{"model":"claude-haiku-5-5","max_tokens":100,"messages":[{"role":"user","content":"hi"}]}`

// TestAppLaneRequestIDHonouredAndEchoed pins L7 gap 4: on a lane a valid
// X-SBO-Request-Id is echoed and the turn is recorded under it (not the
// provider's id); an invalid one, or one on the default lane, changes
// nothing.
func TestAppLaneRequestIDHonouredAndEchoed(t *testing.T) {
	h := newLaneHarness(t, anthropicOK, nil)
	defer h.close()
	cases := []struct {
		name, path, id string
		wantEcho       string
		wantTurnID     string
	}{
		{"lane honours a valid id", "/up/hostedapp/v1/messages", "sdk-0123456789abcdef", "sdk-0123456789abcdef", "sdk-0123456789abcdef"},
		{"lane ignores an invalid id", "/up/hostedapp/v1/messages", "bad id", "", "msg_provider"},
		{"default lane never honours", "/v1/messages", "sdk-0123456789abcdef", "", "msg_provider"},
	}
	for i, tc := range cases {
		resp, _ := h.post(t, tc.path, laneBody, map[string]string{applane.HeaderRequestID: tc.id})
		if got := resp.Header.Get(applane.HeaderRequestID); got != tc.wantEcho {
			t.Errorf("%s: echo = %q, want %q", tc.name, got, tc.wantEcho)
		}
		turns := h.sink.all()
		if len(turns) != i+1 {
			t.Fatalf("%s: turns = %d, want %d", tc.name, len(turns), i+1)
		}
		if got := turns[i].RequestID; got != tc.wantTurnID {
			t.Errorf("%s: turn request id = %q, want %q", tc.name, got, tc.wantTurnID)
		}
	}
}

// TestAppLaneServiceReachesAdmissionAndSpan pins L7 gap 1.
func TestAppLaneServiceReachesAdmissionAndSpan(t *testing.T) {
	var gotService string
	adm := &serviceAdmitter{seen: func(in AdmitInput) { gotService = in.Service }}
	obs := &fakeObsSink{callDoneChan: make(chan struct{}, 1)}
	h := newLaneHarness(t, anthropicOK, func(o *Options) {
		o.Admitter = adm
		o.ObsSink = obs
	})
	defer h.close()
	h.post(t, "/up/hostedapp/v1/messages", laneBody, map[string]string{applane.HeaderService: " support-bot "})
	if gotService != "support-bot" {
		t.Fatalf("admission service = %q, want support-bot", gotService)
	}
	waitForCall(t, obs.callDoneChan, 5*time.Second)
	if calls := obs.all(); len(calls) != 1 || calls[0].Service != "support-bot" {
		t.Fatalf("synthesized facts = %+v, want service support-bot", calls)
	}
}

type serviceAdmitter struct{ seen func(AdmitInput) }

func (a *serviceAdmitter) Admit(_ context.Context, in AdmitInput) AdmitResult {
	a.seen(in)
	return AdmitResult{}
}
func (a *serviceAdmitter) FinalizeAdmission(context.Context, AdmitToken, string) {}

// TestAppLaneModelAllowList pins L7 gap 6: a lane with a models list
// refuses (403 model_not_allowed, never forwarded) a model outside it.
func TestAppLaneModelAllowList(t *testing.T) {
	h := newLaneHarness(t, anthropicOK, func(o *Options) {
		o.AppLanes.Models = map[string][]string{"hostedapp": {"claude-haiku-*"}}
	})
	defer h.close()
	resp, body := h.post(t, "/up/hostedapp/v1/messages", strings.Replace(laneBody, "claude-haiku-5-5", "claude-opus-5-5", 1), nil)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "model_not_allowed") {
		t.Fatalf("refusal = %d %s, want 403 model_not_allowed", resp.StatusCode, body)
	}
	if h.hits.Load() != 0 {
		t.Fatal("a refused model reached the upstream")
	}
	if resp, _ := h.post(t, "/up/hostedapp/v1/messages", laneBody, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("allowed model = %d, want 200", resp.StatusCode)
	}
	// The default lane is never policed by the app-lane list.
	if resp, _ := h.post(t, "/v1/messages", strings.Replace(laneBody, "claude-haiku-5-5", "claude-opus-5-5", 1), nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("default lane = %d, want 200", resp.StatusCode)
	}
}

// TestAppLaneReservation pins L7 gap 2 on the proxy side: the gate is asked
// before the forward with the call's worst case, a refusal is a 402 never
// forwarded, and every hold closes exactly once with what the call cost.
func TestAppLaneReservation(t *testing.T) {
	t.Run("refused is 402 and never forwarded", func(t *testing.T) {
		gate := &fakeAppLaneGate{refuse: true}
		h := newLaneHarness(t, anthropicOK, func(o *Options) { o.AppLanes.Gate = gate })
		defer h.close()
		resp, body := h.post(t, "/up/hostedapp/v1/messages", laneBody, map[string]string{applane.HeaderService: "bot", "X-Superbased-User": "u1"})
		if resp.StatusCode != http.StatusPaymentRequired || !strings.Contains(string(body), "budget_exceeded") {
			t.Fatalf("got %d %s, want 402 budget_exceeded", resp.StatusCode, body)
		}
		if h.hits.Load() != 0 {
			t.Fatal("a refused call reached the upstream")
		}
		res, _ := gate.snapshot()
		if len(res) != 1 || res[0].Service != "bot" || res[0].Lane != "hostedapp" || res[0].Model != "claude-haiku-5-5" {
			t.Fatalf("reserve = %+v", res)
		}
		// max_tokens 100 + the prompt estimate; priced by the fake engine.
		if res[0].WorstCaseTokens < 100 || !res[0].Priced || res[0].WorstCaseUSD <= 0 {
			t.Fatalf("worst case = %+v", res[0])
		}
	})
	t.Run("model_unpriced is 403", func(t *testing.T) {
		gate := &fakeAppLaneGate{refuse: true, code: "model_unpriced"}
		h := newLaneHarness(t, anthropicOK, func(o *Options) { o.AppLanes.Gate = gate })
		defer h.close()
		if resp, _ := h.post(t, "/up/hostedapp/v1/messages", laneBody, nil); resp.StatusCode != http.StatusForbidden {
			t.Fatalf("got %d, want 403", resp.StatusCode)
		}
	})
	closeCases := []struct {
		name     string
		upstream http.HandlerFunc
		want     AppLaneOutcome
	}{
		{"usage known settles", anthropicOK, AppLaneSettle},
		{"upstream error releases", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"type":"error","error":{"type":"rate_limit_error","message":"slow down"}}`))
		}, AppLaneRelease},
		{"no usage keeps the worst case", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"msg_x","model":"claude-haiku-5-5","stop_reason":"end_turn"}`))
		}, AppLaneUnknown},
	}
	for _, tc := range closeCases {
		t.Run(tc.name, func(t *testing.T) {
			gate := &fakeAppLaneGate{}
			h := newLaneHarness(t, tc.upstream, func(o *Options) { o.AppLanes.Gate = gate })
			defer h.close()
			h.post(t, "/up/hostedapp/v1/messages", laneBody, nil)
			_, closes := gate.snapshot()
			if len(closes) != 1 || closes[0].Outcome != tc.want {
				t.Fatalf("closes = %+v, want one %s", closes, tc.want)
			}
			if tc.want == AppLaneSettle && (closes[0].USD <= 0 || closes[0].Tokens != 15) {
				t.Fatalf("settle = %+v, want the priced 15 tokens", closes[0])
			}
		})
	}
	t.Run("default lane never reserves", func(t *testing.T) {
		gate := &fakeAppLaneGate{refuse: true}
		h := newLaneHarness(t, anthropicOK, func(o *Options) { o.AppLanes.Gate = gate })
		defer h.close()
		if resp, _ := h.post(t, "/v1/messages", laneBody, nil); resp.StatusCode != http.StatusOK {
			t.Fatalf("default lane = %d, want 200", resp.StatusCode)
		}
		if res, _ := gate.snapshot(); len(res) != 0 {
			t.Fatalf("default lane reserved: %+v", res)
		}
	})
}

// TestAppLaneIncludeUsageDecision pins APPLANE-2: only a chat-completions
// path, only a known host, only when on.
func TestAppLaneIncludeUsageDecision(t *testing.T) {
	p := &Proxy{appLanes: AppLaneOptions{IncludeUsage: true}}
	off := &Proxy{}
	u := func(s string) *url.URL { v, _ := url.Parse(s); return v }
	cases := []struct {
		name string
		p    *Proxy
		up   *url.URL
		path string
		want bool
	}{
		{"openai chat", p, u("https://api.openai.com"), "/v1/chat/completions", true},
		{"openrouter chat", p, u("https://openrouter.ai/api"), "/api/v1/chat/completions", true},
		{"responses never", p, u("https://api.openai.com"), "/v1/responses", false},
		{"unknown host never", p, u("https://api.together.xyz"), "/v1/chat/completions", false},
		{"local server never", p, u("http://127.0.0.1:11434"), "/v1/chat/completions", false},
		{"off", off, u("https://api.openai.com"), "/v1/chat/completions", false},
		{"nil upstream", p, nil, "/v1/chat/completions", false},
	}
	for _, tc := range cases {
		if got := tc.p.appLaneIncludeUsage(tc.up, strings.Contains(tc.path, "/chat/"+"completions")); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestRequestMaxOutputTokens(t *testing.T) {
	cases := map[string]int{
		`{"max_tokens":100}`:                           100,
		`{"max_completion_tokens":300,"max_tokens":5}`: 300,
		`{"max_output_tokens":42}`:                     42,
		`{}`:                                           0,
		`not json`:                                     0,
	}
	for body, want := range cases {
		if got := requestMaxOutputTokens([]byte(body)); got != want {
			t.Errorf("requestMaxOutputTokens(%s) = %d, want %d", body, got, want)
		}
	}
	p := &Proxy{appLanes: AppLaneOptions{WorstCaseOutputTokens: 1000}, now: time.Now}
	if _, tokens, priced := p.appLaneWorstCase("m", []byte(`{"model":"m"}`)); tokens != 1003 || priced {
		t.Fatalf("worst case with no cost engine = %d tokens priced=%v, want 1003 unpriced", tokens, priced)
	}
}

func TestAppLaneCloseFor(t *testing.T) {
	ok := models.APITurn{Model: "m", InputTokens: 3, OutputTokens: 4, CostUSD: 0.5}
	cases := []struct {
		name   string
		turn   models.APITurn
		status int
		want   AppLaneOutcome
	}{
		{"usage settles", ok, 200, AppLaneSettle},
		{"error status releases", ok, 500, AppLaneRelease},
		{"error turn releases", models.APITurn{Model: "m", HTTPStatus: 400}, 200, AppLaneRelease},
		{"no usage unknown", models.APITurn{Model: "m"}, 200, AppLaneUnknown},
		{"no model unknown", models.APITurn{}, 200, AppLaneUnknown},
	}
	for _, tc := range cases {
		if got := appLaneCloseFor(tc.turn, tc.status, true).Outcome; got != tc.want {
			t.Errorf("%s: %s, want %s", tc.name, got, tc.want)
		}
	}
}

func TestAppLaneRefusalBodyShapes(t *testing.T) {
	var oa struct {
		Error struct{ Type, Code string } `json:"error"`
	}
	if err := json.Unmarshal(appLaneRefusalBody(models.ProviderOpenAI, http.StatusPaymentRequired, "budget_exceeded", "x"), &oa); err != nil || oa.Error.Type != "insufficient_quota" || oa.Error.Code != "budget_exceeded" {
		t.Fatalf("openai body = %+v err=%v", oa, err)
	}
	var an struct {
		Type  string
		Error struct{ Type, Code string } `json:"error"`
	}
	if err := json.Unmarshal(appLaneRefusalBody(models.ProviderAnthropic, http.StatusForbidden, "model_not_allowed", "x"), &an); err != nil || an.Type != "error" || an.Error.Type != "permission_error" || an.Error.Code != "model_not_allowed" {
		t.Fatalf("anthropic body = %+v err=%v", an, err)
	}
}

// TestAppLanesRefusedOnAnExposedListener (hosted AI gateway review L6; plan
// decision 8, loopback only): a proxy bound beyond loopback with no client
// authentication refuses the /up/<id> app lanes before anything is
// forwarded (anything that can reach it could use every lane, and a lane
// with a loopback upstream would relay the network to that loopback
// service). Coding-agent lanes and the default lanes are unaffected; with
// client authentication enforced the lanes are served to token holders; a
// loopback-bound listener serves them as before.
func TestAppLanesRefusedOnAnExposedListener(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	serve := func(t *testing.T, bind string, mutate func(*Options)) (string, *atomic.Int32) {
		t.Helper()
		hits := &atomic.Int32{}
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			anthropicOK(w, r)
		}))
		t.Cleanup(up.Close)
		opts := Options{
			AnthropicUpstream: up.URL, OpenAIUpstream: up.URL,
			Upstreams:      map[string]string{"hostedapp": up.URL},
			AgentUpstreams: map[string]string{"agentlane": up.URL},
			Sink:           &fakeSink{}, CostComputer: &fakeCostComputer{rate: 0.001},
		}
		if mutate != nil {
			mutate(&opts)
		}
		p, err := New(opts)
		if err != nil {
			t.Fatal(err)
		}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		_, port, _ := net.SplitHostPort(ln.Addr().String())
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		// The listener really is on loopback; the configured address is what
		// the proxy judges exposure on, exactly as the daemon's bind does.
		go func() { _ = p.Serve(ctx, ln, net.JoinHostPort(bind, port)); close(done) }()
		t.Cleanup(func() { cancel(); <-done })
		return "http://" + ln.Addr().String(), hits
	}
	post := func(t *testing.T, base, path string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, base+path, strings.NewReader(laneBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Api-Key", "sk-ant-test")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode, string(b)
	}

	t.Run("exposed, no client auth: app lanes refused", func(t *testing.T) {
		for _, bind := range []string{"0.0.0.0", "", "192.0.2.10"} {
			base, hits := serve(t, bind, nil)
			code, body := post(t, base, "/up/hostedapp/v1/messages")
			if code != http.StatusForbidden || !strings.Contains(body, appLaneCodeExposed) || hits.Load() != 0 {
				t.Fatalf("bind %q: app lane = %d %s (upstream hits %d), want 403 %s and no dial", bind, code, body, hits.Load(), appLaneCodeExposed)
			}
			if code, body := post(t, base, "/up/agentlane/v1/messages"); code != http.StatusOK {
				t.Fatalf("bind %q: coding-agent lane = %d %s, want served", bind, code, body)
			}
			if code, body := post(t, base, "/v1/messages"); code != http.StatusOK {
				t.Fatalf("bind %q: default lane = %d %s, want served", bind, code, body)
			}
		}
	})
	t.Run("exposed with client auth: served to token holders", func(t *testing.T) {
		base, hits := serve(t, "0.0.0.0", func(o *Options) { o.ClientToken, o.RequireClientAuth = token, true })
		if code, body := post(t, base, "/t/"+token+"/up/hostedapp/v1/messages"); code != http.StatusOK || hits.Load() != 1 {
			t.Fatalf("app lane with the client token = %d %s (hits %d), want served", code, body, hits.Load())
		}
		if code, _ := post(t, base, "/up/hostedapp/v1/messages"); code == http.StatusOK {
			t.Fatal("app lane without the client token was served on an exposed listener")
		}
	})
	t.Run("loopback bind: served", func(t *testing.T) {
		base, hits := serve(t, "127.0.0.1", nil)
		if code, body := post(t, base, "/up/hostedapp/v1/messages"); code != http.StatusOK || hits.Load() != 1 {
			t.Fatalf("loopback app lane = %d %s, want served", code, body)
		}
	})
}

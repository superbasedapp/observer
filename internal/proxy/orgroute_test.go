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

// Phase P5a: Sol S7 (single routing-generation snapshot), Sol S8 (/up/auto
// fall-through guard), and Sol S2 (Gateway Mode auth-substitution).
// docs/plans/plane-b-dual-mode-gateway-rbac-ia-design-2026-08-29.md §2.

// okChatCompletionBody is a minimal OpenAI-shaped completion response used
// by every fake upstream in this file so response parsing never depends on
// which physical server actually answered.
const okChatCompletionBody = `{"id":"x","model":"m","choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`

// fakeVirtualKeySource is a minimal VirtualKeySource for Sol S2 tests. A
// non-nil err always wins (simulates a keychain/file read failure); an
// empty key with a nil err simulates "not yet provisioned" the same way
// orgclient.ErrNoSecret would surface through a real adapter.
type fakeVirtualKeySource struct {
	key string
	gen uint64
	err error
}

func (f *fakeVirtualKeySource) LoadVirtualKey() (string, uint64, error) {
	if f.err != nil {
		return "", 0, f.err
	}
	return f.key, f.gen, nil
}

// countingUpstream is an httptest fake that records every request it
// receives (count, plus the last request's headers) and always answers
// okChatCompletionBody.
type countingUpstream struct {
	srv     *httptest.Server
	hits    atomic.Int64
	mu      sync.Mutex
	lastReq *http.Request
}

func newCountingUpstream(t *testing.T) *countingUpstream {
	t.Helper()
	cu := &countingUpstream{}
	cu.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cu.hits.Add(1)
		cu.mu.Lock()
		clone := r.Clone(r.Context())
		body, _ := io.ReadAll(r.Body)
		clone.Body = io.NopCloser(strings.NewReader(string(body)))
		cu.lastReq = clone
		cu.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(okChatCompletionBody))
	}))
	t.Cleanup(cu.srv.Close)
	return cu
}

func (cu *countingUpstream) count() int64 {
	return cu.hits.Load()
}

func (cu *countingUpstream) header(name string) string {
	cu.mu.Lock()
	defer cu.mu.Unlock()
	if cu.lastReq == nil {
		return ""
	}
	return cu.lastReq.Header.Get(name)
}

func doPost(t *testing.T, url, body string, setHeaders func(*http.Request)) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if setHeaders != nil {
		setHeaders(req)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return resp
}

// ---------------------------------------------------------------------
// Item 5, table 1: plane-boundary — which physical upstream a request
// lands on, per lane shape, with Gateway Mode installed.
// ---------------------------------------------------------------------

// TestOrgRoute_PlaneBoundaryTable pins Sol S8's fall-through guard across
// every /up/ lane shape: a named lane and a resolved-auto lane are both
// "explicitly lane-routed" (stripUpstreamPrefix returns a non-empty
// upstreamLaneID, "x" or "auto") and so NEVER fall through to org-route,
// even though the auto lane's own resolution (resolveAutoLane) is a
// completely separate mechanism from upstreamForPath's org-route branch.
// An unresolved-auto request keeps that same exemption — the placeholder
// upstreamForPath computed BEFORE the body was read already saw
// upstreamLaneID=="auto" (non-empty) and so never considered org-route,
// and resolveAutoLane's own "unresolvable" branch never revisits it. Only
// genuinely lane-less traffic — no /up/ prefix at all, OR an unrecognized
// /up/<badid>/ id (stripUpstreamPrefix fails open to upstreamLaneID=="")
// — is eligible for org-route redirection.
func TestOrgRoute_PlaneBoundaryTable(t *testing.T) {
	gateway := newCountingUpstream(t)
	anthropic := newCountingUpstream(t)
	openai := newCountingUpstream(t)
	laneX := newCountingUpstream(t)
	laneA := newCountingUpstream(t)

	p, err := New(Options{
		AnthropicUpstream: anthropic.srv.URL,
		OpenAIUpstream:    openai.srv.URL,
		Upstreams: map[string]string{
			"x":      laneX.srv.URL,
			"lane-a": laneA.srv.URL,
		},
		Sink:             &fakeSink{},
		VirtualKeySource: &fakeVirtualKeySource{key: "sbo-vk-planeboundary", gen: 1},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := p.SetOrgGatewayRoute(orgModeGateway, gateway.srv.URL, nil); err != nil {
		t.Fatalf("SetOrgGatewayRoute: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	upstreams := map[string]*countingUpstream{
		"gateway":   gateway,
		"anthropic": anthropic,
		"openai":    openai,
		"lane-x":    laneX,
		"lane-a":    laneA,
	}

	tests := []struct {
		name string
		path string
		body string
		want string // key into upstreams that must receive exactly this request
	}{
		{
			name: "named lane never falls through",
			path: "/up/x/v1/chat/completions",
			body: `{"model":"whatever","messages":[{"role":"user","content":"hi"}]}`,
			want: "lane-x",
		},
		{
			name: "resolved-auto never falls through",
			path: "/up/auto/v1/chat/completions",
			body: `{"model":"lane-a/gpt-mini","messages":[{"role":"user","content":"hi"}]}`,
			want: "lane-a",
		},
		{
			name: "unresolved-auto still exempt (falls to the fixed provider upstream, not the gateway)",
			path: "/up/auto/v1/chat/completions",
			body: `{"model":"unmatched/gpt-mini","messages":[{"role":"user","content":"hi"}]}`,
			want: "openai",
		},
		{
			name: "unknown /up/<id> fails open into org-route",
			path: "/up/totally-not-configured/v1/chat/completions",
			body: `{"model":"whatever","messages":[{"role":"user","content":"hi"}]}`,
			want: "gateway",
		},
		{
			name: "no /up/ prefix at all — the default lane — is org-routed",
			path: "/v1/chat/completions",
			body: `{"model":"whatever","messages":[{"role":"user","content":"hi"}]}`,
			want: "gateway",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			before := make(map[string]int64, len(upstreams))
			for k, u := range upstreams {
				before[k] = u.count()
			}
			resp := doPost(t, ts.URL+tc.path, tc.body, nil)
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", resp.StatusCode)
			}
			for k, u := range upstreams {
				delta := u.count() - before[k]
				want := int64(0)
				if k == tc.want {
					want = 1
				}
				if delta != want {
					t.Errorf("upstream %q hit-delta = %d, want %d", k, delta, want)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------
// obsUpstreamLane must be unaffected by whether org-route redirected the
// request's DESTINATION — the lane id on the request context reflects
// only stripUpstreamPrefix's (later resolveAutoLane's) computation, never
// which physical URL ended up serving it.
// ---------------------------------------------------------------------

func TestOrgRoute_ObsLaneUnchangedByRedestination(t *testing.T) {
	gateway := newCountingUpstream(t)
	anthropic := newCountingUpstream(t)
	openai := newCountingUpstream(t)

	adm := &ctxCapturingAdmitter{}
	p, err := New(Options{
		AnthropicUpstream: anthropic.srv.URL,
		OpenAIUpstream:    openai.srv.URL,
		Admitter:          adm,
		Sink:              &fakeSink{},
		VirtualKeySource:  &fakeVirtualKeySource{key: "sbo-vk-lanecheck", gen: 1},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	readLane := func() string {
		adm.mu.Lock()
		defer adm.mu.Unlock()
		return adm.gotLane
	}

	// Gateway mode OFF: default-lane request, org-route inert.
	resp := doPost(t, ts.URL+"/v1/chat/completions", `{"model":"m","messages":[{"role":"user","content":"hi"}]}`, nil)
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	laneBefore := readLane()
	if laneBefore != "" {
		t.Fatalf("obsUpstreamLane before gateway mode = %q, want empty (no /up/ prefix)", laneBefore)
	}

	// Gateway mode ON: the same default-lane request now redirects to the
	// gateway primary — the destination changed, the lane id must not.
	if err := p.SetOrgGatewayRoute(orgModeGateway, gateway.srv.URL, nil); err != nil {
		t.Fatalf("SetOrgGatewayRoute: %v", err)
	}
	resp = doPost(t, ts.URL+"/v1/chat/completions", `{"model":"m","messages":[{"role":"user","content":"hi"}]}`, nil)
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if gateway.count() != 1 {
		t.Fatalf("gateway hit count = %d, want 1 (redirection must have fired)", gateway.count())
	}
	laneAfter := readLane()
	if laneAfter != laneBefore {
		t.Errorf("obsUpstreamLane changed under redirection: before=%q after=%q, want unchanged", laneBefore, laneAfter)
	}
}

// ---------------------------------------------------------------------
// Sol S7: one immutable routing-generation snapshot, no torn state under
// concurrent installs.
// ---------------------------------------------------------------------

func TestOrgRoute_ConcurrentInstallRace(t *testing.T) {
	gateway := newCountingUpstream(t)
	anthropic := newCountingUpstream(t)
	openai := newCountingUpstream(t)

	p, err := New(Options{
		AnthropicUpstream: anthropic.srv.URL,
		OpenAIUpstream:    openai.srv.URL,
		Sink:              &fakeSink{},
		VirtualKeySource:  &fakeVirtualKeySource{key: "sbo-vk-race", gen: 1},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	stop := make(chan struct{})
	var writeWG sync.WaitGroup
	writeWG.Add(1)
	go func() {
		defer writeWG.Done()
		gateOn := true
		for {
			select {
			case <-stop:
				return
			default:
			}
			var err error
			if gateOn {
				err = p.SetOrgGatewayRoute(orgModeGateway, gateway.srv.URL, nil)
			} else {
				err = p.SetOrgGatewayRoute(orgModeNode, "", nil)
			}
			if err != nil {
				t.Errorf("SetOrgGatewayRoute: %v", err)
				return
			}
			gateOn = !gateOn
		}
	}()

	const goroutines = 20
	const itersPer = 50
	var readWG sync.WaitGroup
	readWG.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer readWG.Done()
			for i := 0; i < itersPer; i++ {
				// Reader 1: hit the proxy — whichever snapshot is live, the
				// request must resolve successfully every time (200), never
				// against a torn (mode, primary) pairing (e.g. mode==gateway
				// with a nil primary would panic inside upstreamForPath).
				resp := doPost(t, ts.URL+"/v1/chat/completions", `{"model":"m","messages":[{"role":"user","content":"hi"}]}`, nil)
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					t.Errorf("status = %d, want 200 (must never observe torn org-route state)", resp.StatusCode)
					return
				}

				// Reader 2: the OrgRoute() accessor itself must never report
				// mode==gateway with an empty primary — every publish is one
				// atomic Store of a fully-built laneTable (Sol S7).
				mode, primary, _, _ := p.OrgRoute()
				if mode == orgModeGateway && primary == "" {
					t.Errorf("OrgRoute observed torn state: mode=%q primary=%q", mode, primary)
					return
				}
			}
		}()
	}
	readWG.Wait()
	close(stop)
	writeWG.Wait()
}

// ---------------------------------------------------------------------
// Sol S2: auth-substitution custody. The developer's own provider
// credential must never reach a gateway-bound request, and the virtual
// key must never leak to a direct-provider destination.
// ---------------------------------------------------------------------

func TestOrgRoute_AuthSubstitutionCustody(t *testing.T) {
	t.Run("gateway-bound request never carries the developer credential", func(t *testing.T) {
		gateway := newCountingUpstream(t)
		anthropic := newCountingUpstream(t)
		openai := newCountingUpstream(t)

		p, err := New(Options{
			AnthropicUpstream: anthropic.srv.URL,
			OpenAIUpstream:    openai.srv.URL,
			Sink:              &fakeSink{},
			VirtualKeySource:  &fakeVirtualKeySource{key: "sbo-vk-custody", gen: 1},
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if err := p.SetOrgGatewayRoute(orgModeGateway, gateway.srv.URL, nil); err != nil {
			t.Fatalf("SetOrgGatewayRoute: %v", err)
		}
		ts := httptest.NewServer(p.Handler())
		defer ts.Close()

		resp := doPost(t, ts.URL+"/v1/chat/completions", `{"model":"m","messages":[{"role":"user","content":"hi"}]}`, func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer sk-openai-dev-secret")
			r.Header.Set("X-Api-Key", "sk-ant-dev-secret")
		})
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if gateway.count() != 1 {
			t.Fatalf("gateway hit count = %d, want 1", gateway.count())
		}
		if got := gateway.header("Authorization"); got != "" {
			t.Errorf("gateway saw Authorization %q, want empty (developer credential must be stripped)", got)
		}
		if got := gateway.header("X-Api-Key"); got != "sbo-vk-custody" {
			t.Errorf("gateway saw X-Api-Key %q, want the virtual key %q", got, "sbo-vk-custody")
		}
	})

	t.Run("virtual key never reaches a direct-provider destination", func(t *testing.T) {
		anthropic := newCountingUpstream(t)
		openai := newCountingUpstream(t)

		p, err := New(Options{
			AnthropicUpstream: anthropic.srv.URL,
			OpenAIUpstream:    openai.srv.URL,
			Sink:              &fakeSink{},
			VirtualKeySource:  &fakeVirtualKeySource{key: "sbo-vk-must-not-leak", gen: 1},
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		// No SetOrgGatewayRoute call — org-route stays orgModeNode (inert).
		ts := httptest.NewServer(p.Handler())
		defer ts.Close()

		resp := doPost(t, ts.URL+"/v1/chat/completions", `{"model":"m","messages":[{"role":"user","content":"hi"}]}`, func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer sk-openai-dev-secret")
		})
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if openai.count() != 1 {
			t.Fatalf("openai hit count = %d, want 1", openai.count())
		}
		if got := openai.header("Authorization"); got != "Bearer sk-openai-dev-secret" {
			t.Errorf("openai saw Authorization %q, want the developer's own credential unchanged", got)
		}
		if got := openai.header("X-Api-Key"); got == "sbo-vk-must-not-leak" {
			t.Error("openai saw the virtual key — it must never be sent to a direct-provider destination")
		}
	})
}

// ---------------------------------------------------------------------
// Sol S2: fail-closed. Gateway mode active with no usable virtual key must
// return a local error and never forward the request anywhere — neither
// to the gateway (no key to attach) nor, silently, to a direct provider
// (the fallback ladder is a separate, explicit config; absent that
// config, there is no fallback).
// ---------------------------------------------------------------------

func TestOrgRoute_FailClosedNoVirtualKey(t *testing.T) {
	tests := []struct {
		name string
		vks  VirtualKeySource
	}{
		{"no VirtualKeySource configured", nil},
		{"VirtualKeySource errors", &fakeVirtualKeySource{err: errNoVK}},
		{"VirtualKeySource returns an empty key", &fakeVirtualKeySource{key: ""}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gateway := newCountingUpstream(t)
			anthropic := newCountingUpstream(t)
			openai := newCountingUpstream(t)

			p, err := New(Options{
				AnthropicUpstream: anthropic.srv.URL,
				OpenAIUpstream:    openai.srv.URL,
				Sink:              &fakeSink{},
				VirtualKeySource:  tc.vks,
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if err := p.SetOrgGatewayRoute(orgModeGateway, gateway.srv.URL, nil); err != nil {
				t.Fatalf("SetOrgGatewayRoute: %v", err)
			}
			ts := httptest.NewServer(p.Handler())
			defer ts.Close()

			resp := doPost(t, ts.URL+"/v1/chat/completions", `{"model":"m","messages":[{"role":"user","content":"hi"}]}`, nil)
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()

			if resp.StatusCode != http.StatusBadGateway {
				t.Errorf("status = %d, want %d (fail closed)", resp.StatusCode, http.StatusBadGateway)
			}
			if gateway.count() != 0 {
				t.Errorf("gateway hit count = %d, want 0 (never forward without a virtual key)", gateway.count())
			}
			if anthropic.count() != 0 || openai.count() != 0 {
				t.Errorf("direct-provider hit counts = anthropic=%d openai=%d, want 0,0 (no silent fallback to direct provider)", anthropic.count(), openai.count())
			}
		})
	}
}

// errNoVK is a stand-in for orgclient.ErrNoSecret / a keychain read
// failure — the exact error type is irrelevant to the proxy, which only
// checks err != nil.
var errNoVK = &vkError{"no virtual key available"}

type vkError struct{ msg string }

func (e *vkError) Error() string { return e.msg }

// ---------------------------------------------------------------------
// Default posture: with no org-route ever installed, every new P5a
// mechanism is inert and behavior is byte-identical to pre-P5a.
// ---------------------------------------------------------------------

func TestOrgRoute_InertByDefault(t *testing.T) {
	anthropic := newCountingUpstream(t)
	openai := newCountingUpstream(t)

	p, err := New(Options{
		AnthropicUpstream: anthropic.srv.URL,
		OpenAIUpstream:    openai.srv.URL,
		Sink:              &fakeSink{},
		// No VirtualKeySource: proves the fail-closed gate never even
		// evaluates when org-route was never installed.
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	mode, primary, fallbacks, gen1 := p.OrgRoute()
	if mode != orgModeNode || primary != "" || fallbacks != nil {
		t.Fatalf("OrgRoute() on a fresh Proxy = (%q, %q, %v), want (%q, \"\", nil)", mode, primary, fallbacks, orgModeNode)
	}
	if gen1 != p.RoutingGeneration() {
		t.Errorf("OrgRoute generation %d != RoutingGeneration() %d", gen1, p.RoutingGeneration())
	}

	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	resp := doPost(t, ts.URL+"/v1/chat/completions", `{"model":"m","messages":[{"role":"user","content":"hi"}]}`, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer sk-openai-dev-secret")
	})
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (inert org-route must never block a request)", resp.StatusCode)
	}
	if openai.count() != 1 || anthropic.count() != 0 {
		t.Fatalf("hit counts openai=%d anthropic=%d, want 1,0", openai.count(), anthropic.count())
	}
	if got := openai.header("Authorization"); got != "Bearer sk-openai-dev-secret" {
		t.Errorf("openai saw Authorization %q, want the caller's header passed through unchanged", got)
	}

	// Installing and then clearing an org-route must leave OrgRoute() back
	// at the same inert shape, on a strictly newer generation.
	gw := newCountingUpstream(t)
	if err := p.SetOrgGatewayRoute(orgModeGateway, gw.srv.URL, nil); err != nil {
		t.Fatalf("SetOrgGatewayRoute(gateway): %v", err)
	}
	if err := p.SetOrgGatewayRoute(orgModeNode, "", nil); err != nil {
		t.Fatalf("SetOrgGatewayRoute(node): %v", err)
	}
	mode, primary, fallbacks, gen2 := p.OrgRoute()
	if mode != orgModeNode || primary != "" || fallbacks != nil {
		t.Fatalf("OrgRoute() after install+clear = (%q, %q, %v), want back to inert", mode, primary, fallbacks)
	}
	if gen2 <= gen1 {
		t.Errorf("generation did not advance: gen1=%d gen2=%d", gen1, gen2)
	}
}

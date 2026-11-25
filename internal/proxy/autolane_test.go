package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// mustParseAutoLaneURL is a tiny url.Parse wrapper for table-test fixtures —
// resolveAutoLane's upstreams parameter is a plain map[string]*url.URL, so
// its unit tests don't need a live httptest server per lane.
func mustParseAutoLaneURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	return u
}

// ---------------------------------------------------------------------
// Phase 1 — hot-reloadable lane map
// ---------------------------------------------------------------------

// TestSetUpstreams_HotSwap pins the Phase 1 contract: a successful
// SetUpstreams swap is visible to the very next request (old lane ids stop
// resolving, new ones start), and a FAILED swap (any bad URL in the new map)
// leaves the previously-live map serving unchanged — all-or-nothing, no
// partial swap.
func TestSetUpstreams_HotSwap(t *testing.T) {
	p, err := New(Options{
		AnthropicUpstream: "https://api.anthropic.com",
		OpenAIUpstream:    "https://api.openai.com",
		Upstreams:         map[string]string{"a": "https://a.example.com"},
		Sink:              &fakeSink{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	r := httptest.NewRequest(http.MethodPost, "/up/a/v1/x", nil)
	up, id := p.stripUpstreamPrefix(r)
	if up == nil || id != "a" || up.Host != "a.example.com" {
		t.Fatalf("lane 'a' before swap: up=%v id=%q, want a.example.com/\"a\"", up, id)
	}

	if err := p.SetUpstreams(map[string]string{"b": "https://b.example.com"}); err != nil {
		t.Fatalf("SetUpstreams (valid): %v", err)
	}

	r2 := httptest.NewRequest(http.MethodPost, "/up/a/v1/x", nil)
	if up2, _ := p.stripUpstreamPrefix(r2); up2 != nil {
		t.Errorf("lane 'a' still resolves after a swap that dropped it: %v", up2)
	}
	r3 := httptest.NewRequest(http.MethodPost, "/up/b/v1/x", nil)
	up3, id3 := p.stripUpstreamPrefix(r3)
	if up3 == nil || id3 != "b" || up3.Host != "b.example.com" {
		t.Fatalf("lane 'b' after swap: up=%v id=%q, want b.example.com/\"b\"", up3, id3)
	}

	// A malformed URL in the NEXT swap must fail wholesale — no partial
	// map, and the map from the PREVIOUS successful swap keeps serving.
	if err := p.SetUpstreams(map[string]string{"b": "https://b.example.com", "c": "://nope"}); err == nil {
		t.Fatal("expected error for a malformed URL in the new map")
	}
	r4 := httptest.NewRequest(http.MethodPost, "/up/b/v1/x", nil)
	up4, id4 := p.stripUpstreamPrefix(r4)
	if up4 == nil || id4 != "b" || up4.Host != "b.example.com" {
		t.Fatalf("after a FAILED swap, lane 'b' from the prior successful swap must still resolve: up=%v id=%q", up4, id4)
	}
}

// TestSetUpstreams_ConcurrentSwapRace pins the concurrency contract under
// -race: many goroutines issuing /up/<id> lookups while another goroutine
// repeatedly calls SetUpstreams must never race (copy-on-write: the map
// VALUE is never mutated in place, only the atomic.Pointer is swapped) and
// a lane present in every generation of the swapped map must always
// resolve, mid-swap or not.
func TestSetUpstreams_ConcurrentSwapRace(t *testing.T) {
	p, err := New(Options{
		AnthropicUpstream: "https://api.anthropic.com",
		OpenAIUpstream:    "https://api.openai.com",
		Upstreams:         map[string]string{"x": "https://one.example.com"},
		Sink:              &fakeSink{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	stop := make(chan struct{})
	var swapWG sync.WaitGroup
	swapWG.Add(1)
	go func() {
		defer swapWG.Done()
		gens := []map[string]string{
			{"x": "https://one.example.com"},
			{"x": "https://two.example.com"},
		}
		i := 0
		for {
			select {
			case <-stop:
				return
			default:
			}
			if err := p.SetUpstreams(gens[i%len(gens)]); err != nil {
				t.Errorf("SetUpstreams: %v", err)
				return
			}
			i++
		}
	}()

	const goroutines = 20
	const itersPer = 200
	var readWG sync.WaitGroup
	readWG.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer readWG.Done()
			for i := 0; i < itersPer; i++ {
				r := httptest.NewRequest(http.MethodPost, "/up/x/v1/y", nil)
				up, id := p.stripUpstreamPrefix(r)
				if up == nil || id != "x" {
					t.Errorf("lane 'x' failed to resolve mid-swap (up=%v id=%q)", up, id)
					return
				}
			}
		}()
	}
	readWG.Wait()
	close(stop)
	swapWG.Wait()
}

// TestSetLaneTable pins the Phase 3 contract: SetLaneTable swaps the
// upstream map AND the auto-default lane id together, atomically, with
// all-or-nothing validation over the CANDIDATE table (a bad upstream URL,
// a dangling default, or "auto" as the default all leave the previously
// live table serving unchanged).
func TestSetLaneTable(t *testing.T) {
	p, err := New(Options{
		AnthropicUpstream: "https://api.anthropic.com",
		OpenAIUpstream:    "https://api.openai.com",
		Upstreams:         map[string]string{"a": "https://a.example.com"},
		AutoDefaultLane:   "a",
		Sink:              &fakeSink{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	assertDefault := func(t *testing.T, want string) {
		t.Helper()
		if got := p.laneSnapshot().autoDefault; got != want {
			t.Errorf("laneSnapshot().autoDefault = %q, want %q", got, want)
		}
	}
	assertDefault(t, "a")

	// Valid swap: both halves change together.
	if err := p.SetLaneTable(map[string]string{"b": "https://b.example.com"}, "b"); err != nil {
		t.Fatalf("SetLaneTable (valid): %v", err)
	}
	assertDefault(t, "b")
	r := httptest.NewRequest(http.MethodPost, "/up/b/v1/x", nil)
	if up, id := p.stripUpstreamPrefix(r); up == nil || id != "b" || up.Host != "b.example.com" {
		t.Fatalf("lane 'b' after SetLaneTable: up=%v id=%q", up, id)
	}

	// Empty default is valid and clears it.
	if err := p.SetLaneTable(map[string]string{"b": "https://b.example.com"}, ""); err != nil {
		t.Fatalf("SetLaneTable (empty default): %v", err)
	}
	assertDefault(t, "")

	// Reserved "auto" lane id in upstreams is rejected; previous table
	// (empty default, lane b) keeps serving unchanged.
	if err := p.SetLaneTable(map[string]string{"auto": "https://x.example.com"}, ""); err == nil {
		t.Fatal("expected error for a reserved 'auto' lane id in upstreams")
	}
	assertDefault(t, "")
	r2 := httptest.NewRequest(http.MethodPost, "/up/b/v1/x", nil)
	if up, id := p.stripUpstreamPrefix(r2); up == nil || id != "b" {
		t.Errorf("lane 'b' must still resolve after a rejected swap: up=%v id=%q", up, id)
	}

	// "auto" as the default lane id is always rejected, even though it
	// would otherwise "name" nothing in upstreams.
	if err := p.SetLaneTable(map[string]string{"b": "https://b.example.com"}, "auto"); err == nil {
		t.Fatal("expected error for auto_default_lane == \"auto\"")
	}
	assertDefault(t, "")

	// A dangling default (not present in the candidate upstreams map) is
	// rejected wholesale — the previous table is untouched.
	if err := p.SetLaneTable(map[string]string{"c": "https://c.example.com"}, "missing"); err == nil {
		t.Fatal("expected error for a dangling auto_default_lane")
	}
	assertDefault(t, "")
	r3 := httptest.NewRequest(http.MethodPost, "/up/c/v1/x", nil)
	if up, _ := p.stripUpstreamPrefix(r3); up != nil {
		t.Errorf("lane 'c' from the REJECTED swap must not resolve: %v", up)
	}

	// A malformed upstream URL is rejected wholesale too, regardless of a
	// valid default alongside it.
	if err := p.SetLaneTable(map[string]string{"d": "://nope"}, ""); err == nil {
		t.Fatal("expected error for a malformed upstream URL")
	}
}

// TestSetLaneTable_ConcurrentSwapRace pins the concurrency contract under
// -race for the Phase 3 combined swap: many goroutines resolving the auto
// lane (which reads BOTH the upstream map and the default lane id from one
// laneSnapshot Load) while another goroutine repeatedly calls SetLaneTable
// must never race, and every generation's (upstream, default) pairing must
// be internally consistent — a reader must never observe the upstream map
// from one generation paired with the default lane id from another.
func TestSetLaneTable_ConcurrentSwapRace(t *testing.T) {
	laneX := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"x","model":"m","choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	}))
	defer laneX.Close()
	laneY := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"x","model":"m","choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	}))
	defer laneY.Close()

	p, err := New(Options{
		AnthropicUpstream: "https://api.anthropic.com",
		OpenAIUpstream:    "https://api.openai.com",
		Upstreams:         map[string]string{"x": laneX.URL},
		AutoDefaultLane:   "x",
		Sink:              &fakeSink{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	stop := make(chan struct{})
	var swapWG sync.WaitGroup
	swapWG.Add(1)
	go func() {
		defer swapWG.Done()
		gens := []struct {
			upstreams map[string]string
			def       string
		}{
			{map[string]string{"x": laneX.URL}, "x"},
			{map[string]string{"y": laneY.URL}, "y"},
		}
		i := 0
		for {
			select {
			case <-stop:
				return
			default:
			}
			g := gens[i%len(gens)]
			if err := p.SetLaneTable(g.upstreams, g.def); err != nil {
				t.Errorf("SetLaneTable: %v", err)
				return
			}
			i++
		}
	}()

	const goroutines = 20
	const itersPer = 100
	var readWG sync.WaitGroup
	readWG.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer readWG.Done()
			for i := 0; i < itersPer; i++ {
				// An unmatched-prefix model always falls to whichever
				// default lane is live in THIS request's snapshot — the
				// request must resolve successfully every time (200),
				// never against a torn (upstreams, default) pairing.
				reqBody := `{"model":"unmatched/gpt-mini"}`
				resp, err := http.Post(ts.URL+"/up/auto/v1/chat/completions", "application/json", strings.NewReader(reqBody))
				if err != nil {
					t.Errorf("post: %v", err)
					return
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode != 200 {
					t.Errorf("status = %d, want 200 (auto default lane must always resolve mid-swap)", resp.StatusCode)
					return
				}
			}
		}()
	}
	readWG.Wait()
	close(stop)
	swapWG.Wait()
}

// ---------------------------------------------------------------------
// Phase 2 — the virtual "auto" lane
// ---------------------------------------------------------------------

// TestAutoLane is the unit-level table test over resolveAutoLane covering
// every branch in the gateway config plane spec Phase 2 resolution: a
// matching model prefix routes + rewrites; everything else (unknown
// prefix, no slash, empty/GET model, a rewrite that fails json.Valid) falls
// to the configured default lane with the body untouched; and with no
// usable default the request is fully unresolvable (the caller then treats
// it exactly like an unknown /up/<id>).
func TestAutoLane(t *testing.T) {
	laneA := mustParseAutoLaneURL(t, "https://lane-a.example.com")
	fallback := mustParseAutoLaneURL(t, "https://default.example.com")
	upstreams := map[string]*url.URL{"lane-a": laneA, "fallback": fallback}

	cases := []struct {
		name          string
		defaultLane   string
		model         string
		body          []byte
		wantHost      string // "" ⇒ resolveAutoLane must return a nil upstream
		wantLaneID    string
		wantRewritten bool
		wantBodyModel string // checked only when wantRewritten
	}{
		{
			name:          "prefix match rewrites model to the suffix",
			defaultLane:   "fallback",
			model:         "lane-a/gpt-mini",
			body:          []byte(`{"model":"lane-a/gpt-mini","messages":[{"role":"user","content":"hi"}]}`),
			wantHost:      "lane-a.example.com",
			wantLaneID:    "lane-a",
			wantRewritten: true,
			wantBodyModel: "gpt-mini",
		},
		{
			name:        "unknown prefix falls to default, body untouched",
			defaultLane: "fallback",
			model:       "unknown-lane/gpt-mini",
			body:        []byte(`{"model":"unknown-lane/gpt-mini"}`),
			wantHost:    "default.example.com",
			wantLaneID:  "fallback",
		},
		{
			name:        "no slash in model falls to default",
			defaultLane: "fallback",
			model:       "plainmodel",
			body:        []byte(`{"model":"plainmodel"}`),
			wantHost:    "default.example.com",
			wantLaneID:  "fallback",
		},
		{
			name:        "empty model (GET / unparseable body) falls to default",
			defaultLane: "fallback",
			model:       "",
			body:        nil,
			wantHost:    "default.example.com",
			wantLaneID:  "fallback",
		},
		{
			name:        "prefix with empty suffix falls to default",
			defaultLane: "fallback",
			model:       "lane-a/",
			body:        []byte(`{"model":"lane-a/"}`),
			wantHost:    "default.example.com",
			wantLaneID:  "fallback",
		},
		{
			name:        "prefix matches but the body fails json.Valid rewrite -> default, untouched",
			defaultLane: "fallback",
			model:       "lane-a/gpt-mini",
			body:        []byte(`not-json-at-all`),
			wantHost:    "default.example.com",
			wantLaneID:  "fallback",
		},
		{
			name:        "no default configured, unresolvable prefix -> nil",
			defaultLane: "",
			model:       "unknown-lane/gpt-mini",
			body:        []byte(`{"model":"unknown-lane/gpt-mini"}`),
			wantHost:    "",
			wantLaneID:  "",
		},
		{
			name:        "default lane configured but absent from the snapshot -> nil",
			defaultLane: "vanished",
			model:       "unknown-lane/gpt-mini",
			body:        []byte(`{"model":"unknown-lane/gpt-mini"}`),
			wantHost:    "",
			wantLaneID:  "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &Proxy{}
			lanes := &laneTable{upstreams: upstreams, autoDefault: tc.defaultLane}
			gotUp, gotLane, gotBody, gotRewrote := p.resolveAutoLane(lanes, tc.model, tc.body)

			if tc.wantHost == "" {
				if gotUp != nil {
					t.Fatalf("upstream = %v, want nil", gotUp)
				}
			} else if gotUp == nil || gotUp.Host != tc.wantHost {
				t.Fatalf("upstream host = %v, want %q", gotUp, tc.wantHost)
			}
			if gotLane != tc.wantLaneID {
				t.Errorf("laneID = %q, want %q", gotLane, tc.wantLaneID)
			}
			if gotRewrote != tc.wantRewritten {
				t.Errorf("rewritten = %v, want %v", gotRewrote, tc.wantRewritten)
			}
			if tc.wantRewritten {
				var fields map[string]json.RawMessage
				if err := json.Unmarshal(gotBody, &fields); err != nil {
					t.Fatalf("rewritten body not valid JSON: %v (%s)", err, gotBody)
				}
				var m string
				_ = json.Unmarshal(fields["model"], &m)
				if m != tc.wantBodyModel {
					t.Errorf("rewritten body model = %q, want %q", m, tc.wantBodyModel)
				}
			} else if gotBody != nil {
				t.Errorf("non-rewritten path must return a nil newBody, got %q", gotBody)
			}
		})
	}
}

// TestAutoLaneEndToEnd exercises the full HTTP path (resolveUpstreamPrefix →
// serve()'s auto-lane resolution → forward) rather than resolveAutoLane in
// isolation, so it also pins Content-Length correctness (the existing
// outReq.ContentLength = len(reqBody) convention) and the exact byte
// content the upstream receives.
func TestAutoLaneEndToEnd(t *testing.T) {
	var laneABody []byte
	var laneAContentLength int64
	laneA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		laneAContentLength = r.ContentLength
		laneABody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"x","model":"gpt-mini","choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	}))
	defer laneA.Close()

	var defaultBody []byte
	var defaultHit bool
	defaultLane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defaultHit = true
		defaultBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"x","model":"m","choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	}))
	defer defaultLane.Close()

	p, err := New(Options{
		AnthropicUpstream: "https://api.anthropic.com",
		OpenAIUpstream:    "https://api.openai.com",
		Upstreams:         map[string]string{"lane-a": laneA.URL, "fallback": defaultLane.URL},
		AutoDefaultLane:   "fallback",
		Sink:              &fakeSink{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	t.Run("prefix match rewrites model, hits lane-a, Content-Length correct", func(t *testing.T) {
		reqBody := `{"model":"lane-a/gpt-mini","messages":[{"role":"user","content":"hi"}],"stream":false}`
		resp, err := http.Post(ts.URL+"/up/auto/v1/chat/completions", "application/json", strings.NewReader(reqBody))
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		if resp.StatusCode != 200 {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		if defaultHit {
			t.Error("default lane was hit; expected lane-a")
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(laneABody, &fields); err != nil {
			t.Fatalf("lane-a body not JSON: %v (%s)", err, laneABody)
		}
		var m string
		_ = json.Unmarshal(fields["model"], &m)
		if m != "gpt-mini" {
			t.Errorf("model reaching lane-a = %q, want gpt-mini", m)
		}
		if _, ok := fields["messages"]; !ok {
			t.Error("unrelated field 'messages' lost across the rewrite round-trip")
		}
		if laneAContentLength != int64(len(laneABody)) {
			t.Errorf("Content-Length %d != actual body length %d", laneAContentLength, len(laneABody))
		}
	})

	t.Run("unknown prefix falls to default lane, body byte-identical", func(t *testing.T) {
		defaultHit = false
		reqBody := `{"model":"totally-unknown/gpt-mini","messages":[{"role":"user","content":"hi"}]}`
		resp, err := http.Post(ts.URL+"/up/auto/v1/chat/completions", "application/json", strings.NewReader(reqBody))
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		if !defaultHit {
			t.Fatal("expected default lane to be hit")
		}
		if string(defaultBody) != reqBody {
			t.Errorf("default-lane body mutated: got %q want %q", defaultBody, reqBody)
		}
	})

	t.Run("no slash falls to default lane, body byte-identical", func(t *testing.T) {
		defaultHit = false
		reqBody := `{"model":"plainmodel","messages":[{"role":"user","content":"hi"}]}`
		resp, err := http.Post(ts.URL+"/up/auto/v1/chat/completions", "application/json", strings.NewReader(reqBody))
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		if !defaultHit {
			t.Fatal("expected default lane to be hit")
		}
		if string(defaultBody) != reqBody {
			t.Errorf("default-lane body mutated: got %q want %q", defaultBody, reqBody)
		}
	})

	t.Run("GET without a body routes to the default lane", func(t *testing.T) {
		defaultHit = false
		req, err := http.NewRequest(http.MethodGet, ts.URL+"/up/auto/v1/models", nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		if !defaultHit {
			t.Fatal("expected default lane to be hit for a GET with no body")
		}
	})

	t.Run("ChatGPT-JWT-shaped Authorization header on GET /up/auto/v1/models still reaches the default lane", func(t *testing.T) {
		// Bug W1.3a: chatgptAuth used to fire on ANY OpenAI-shaped request
		// carrying a ChatGPT JWT, including /up/ lane traffic (explicit
		// upstream is nil for the "auto" lane too, since its target isn't
		// resolved until here). That wrongly tripped the /v1/models
		// short-circuit above serve()'s auto-lane resolution block and
		// returned the synthetic {"models":[]} body instead of ever
		// reaching resolveAutoLane. A lane request always carries the
		// routed tool's own key, never a ChatGPT JWT, so this must behave
		// identically to the plain GET case above: default lane, real
		// upstream round trip.
		defaultHit = false
		req, err := http.NewRequest(http.MethodGet, ts.URL+"/up/auto/v1/models", nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		// isChatGPTAuthRequest: Bearer token starting "eyJ" (not "sk-").
		req.Header.Set("Authorization", "Bearer eyJhbGciOiJSUzI1NiJ9.fakejwtpayload.sig")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if !defaultHit {
			t.Fatalf("expected default lane to be hit for a ChatGPT-JWT GET on /up/auto/v1/models; got synthetic body %q instead of a real upstream round trip", body)
		}
		if string(body) == `{"models":[]}` {
			t.Errorf("got the synthetic ChatGPT-auth short-circuit body %q — /up/auto traffic must never trip that branch", body)
		}
	})

	t.Run("invalid JSON body falls to default lane, body untouched", func(t *testing.T) {
		defaultHit = false
		reqBody := `not json at all`
		resp, err := http.Post(ts.URL+"/up/auto/v1/chat/completions", "application/json", strings.NewReader(reqBody))
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		if !defaultHit {
			t.Fatal("expected default lane to be hit")
		}
		if string(defaultBody) != reqBody {
			t.Errorf("default-lane body mutated: got %q want %q", defaultBody, reqBody)
		}
	})
}

// TestAutoLane_NoDefaultConfigured_WarnsOnce pins the fully-unresolvable
// fallback: with no auto_default_lane (or one that can't resolve) and no
// prefix match, the request is treated EXACTLY like an unknown /up/<id>
// (refused locally since Sol A5-02, warn-once) — sharing
// warnUnknownUpstreamOnce's dedup, keyed by the literal "auto". The refusal
// itself is pinned by TestUnknownUpstreamLaneNeverForwardsCredentials.
func TestAutoLane_NoDefaultConfigured_WarnsOnce(t *testing.T) {
	fixedUp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"x","model":"m","choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	}))
	defer fixedUp.Close()

	wc := &warnCounter{want: "unknown /up/ upstream id"}
	p, err := New(Options{
		AnthropicUpstream: fixedUp.URL,
		OpenAIUpstream:    fixedUp.URL,
		Upstreams:         map[string]string{"lane-a": fixedUp.URL},
		// AutoDefaultLane intentionally unset.
		Sink:   &fakeSink{},
		Logger: slog.New(wc),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	for i := 0; i < 5; i++ {
		resp, err := http.Post(ts.URL+"/up/auto/v1/chat/completions", "application/json",
			strings.NewReader(`{"model":"unmatched/gpt-mini","messages":[{"role":"user","content":"hi"}]}`))
		if err != nil {
			t.Fatalf("post %d: %v", i, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	if got := wc.n(); got != 1 {
		t.Errorf("5 unresolvable auto-lane requests produced %d warns, want exactly 1: %s", got, wc.buf.String())
	}
}

// TestAutoLane_ResolvedLaneInObsContext pins the obsLaneCtxKey contract for
// the auto lane: admission/egress/the gateway rail must see the RESOLVED
// lane id, never the literal "auto". ChatTurnFacts has no dedicated lane
// field to assert through, so this uses a context-capturing fake Admitter
// (the admission gate is the first consumer of r.Context() after the
// auto-lane resolution block re-stamps it).
type ctxCapturingAdmitter struct {
	mu      sync.Mutex
	called  bool
	gotLane string
}

func (a *ctxCapturingAdmitter) Admit(ctx context.Context, _ AdmitInput) AdmitResult {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.called = true
	lane, _ := ctx.Value(obsLaneCtxKey{}).(string)
	a.gotLane = lane
	return AdmitResult{}
}

// FinalizeAdmission satisfies the two-phase seam; this fake never defers a row.
func (a *ctxCapturingAdmitter) FinalizeAdmission(context.Context, AdmitToken, string) {}

func TestAutoLane_ResolvedLaneInObsContext(t *testing.T) {
	laneA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"x","model":"m","choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	}))
	defer laneA.Close()

	adm := &ctxCapturingAdmitter{}
	p, err := New(Options{
		AnthropicUpstream: "https://api.anthropic.com",
		OpenAIUpstream:    "https://api.openai.com",
		Upstreams:         map[string]string{"lane-a": laneA.URL},
		Admitter:          adm,
		Sink:              &fakeSink{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/up/auto/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"lane-a/gpt-mini","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	adm.mu.Lock()
	defer adm.mu.Unlock()
	if !adm.called {
		t.Fatal("admitter was never called — obsUpstreamLane(r) must be non-empty for a resolved auto lane")
	}
	if adm.gotLane != "lane-a" {
		t.Errorf("obs lane ctx = %q, want the resolved lane id %q (never the literal %q)", adm.gotLane, "lane-a", autoLaneID)
	}
}

// TestAutoLaneWebSocketUpgradeRoutesToDefaultLane pins bug W1.3b: the
// isWebSocketUpgrade branch in serve() exits (via serveUpgradePassthrough)
// BEFORE the request body is read, so — pre-fix — an /up/auto/... websocket
// upgrade never reached the auto lane's own resolution at all and instead
// went straight to the placeholder fixed upstream computed for the literal
// (unresolved) "auto" id. This drives a real hijack-based upgrade (the same
// technique as TestProxy_OpenAIWebSocketUpgradePassthrough) through
// /up/auto/... and asserts the auto-default lane backend receives it, while
// the WRONG fixed upstream (deliberately left pointed at a non-lane URL) is
// never dialed at all.
func TestAutoLaneWebSocketUpgradeRoutesToDefaultLane(t *testing.T) {
	seen := make(chan *http.Request, 1)
	defaultLane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clone := r.Clone(r.Context())
		clone.Header = r.Header.Clone()
		seen <- clone

		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Error("default-lane response writer does not support hijacking")
			return
		}
		conn, rw, err := hj.Hijack()
		if err != nil {
			t.Errorf("hijack default lane: %v", err)
			return
		}
		defer conn.Close()
		_, _ = fmt.Fprint(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: test\r\n\r\n")
		_ = rw.Flush()
	}))
	defer defaultLane.Close()

	wrongFixedUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("wrong fixed upstream was hit for %s %s — the auto-lane websocket upgrade must resolve to the auto-default lane, not the placeholder fixed upstream", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer wrongFixedUpstream.Close()

	p, err := New(Options{
		// Deliberately the "wrong" answer: if the bug regresses, the
		// upgrade lands here instead of the auto-default lane.
		AnthropicUpstream: wrongFixedUpstream.URL,
		OpenAIUpstream:    wrongFixedUpstream.URL,
		Upstreams:         map[string]string{"fallback": defaultLane.URL},
		AutoDefaultLane:   "fallback",
		Sink:              &fakeSink{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
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

	_, err = fmt.Fprintf(conn, "GET /up/auto/v1/realtime HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", proxyURL.Host)
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
		if req.URL.Path != "/v1/realtime" {
			t.Errorf("default-lane path: got %q want %q (the /up/auto prefix must be stripped)", req.URL.Path, "/v1/realtime")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("auto-default lane did not receive the websocket upgrade")
	}
}

// TestLaneTable_ReadsBothHalvesFromOneSnapshot pins the read counterpart of
// SetLaneTable (added for the P0-6 gateway.providers effective-state row,
// docs/plans/policy-state-v2-gateway-providers-spec-2026-08-15.md §2.2): the
// upstreams map and the auto-default lane id must come from ONE
// laneSnapshot() load, and the returned map must be a copy the caller owns.
func TestLaneTable_ReadsBothHalvesFromOneSnapshot(t *testing.T) {
	p, err := New(Options{
		AnthropicUpstream: "https://api.anthropic.com",
		OpenAIUpstream:    "https://api.openai.com",
		Upstreams:         map[string]string{"a": "https://a.example.com"},
		AutoDefaultLane:   "a",
		Sink:              &fakeSink{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	lanes, autoDefault := p.LaneTable()
	if autoDefault != "a" {
		t.Fatalf("auto default = %q, want a", autoDefault)
	}
	if len(lanes) != 1 || lanes["a"] == "" {
		t.Fatalf("lanes = %v, want one entry for a", lanes)
	}

	// The returned map is a copy: mutating it must not disturb the proxy.
	lanes["a"] = "https://evil.example.com"
	delete(lanes, "a")
	if again, _ := p.LaneTable(); len(again) != 1 || again["a"] == "https://evil.example.com" {
		t.Fatalf("live lanes = %v, want the caller's mutation to be isolated", again)
	}

	// A swap is observed by the next read, both halves together.
	if err := p.SetLaneTable(map[string]string{"b": "https://b.example.com"}, "b"); err != nil {
		t.Fatalf("SetLaneTable: %v", err)
	}
	lanes, autoDefault = p.LaneTable()
	if autoDefault != "b" || len(lanes) != 1 || lanes["b"] == "" {
		t.Fatalf("after swap: lanes=%v default=%q, want the b lane and default b", lanes, autoDefault)
	}

	// An empty table reads back empty rather than nil-panicking.
	if err := p.SetLaneTable(map[string]string{}, ""); err != nil {
		t.Fatalf("SetLaneTable (empty): %v", err)
	}
	if lanes, autoDefault = p.LaneTable(); len(lanes) != 0 || autoDefault != "" {
		t.Fatalf("empty table read back as lanes=%v default=%q", lanes, autoDefault)
	}
}

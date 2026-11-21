package proxy

import (
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
	"github.com/marmutapp/superbased-observer/internal/ownagent"
)

// fakeOwnAgentSink records EnsureOwnAgentSession calls.
type fakeOwnAgentSink struct {
	mu    sync.Mutex
	calls []ownAgentCall
	fail  bool
}

type ownAgentCall struct {
	sessionID, agent, root, model string
}

func (f *fakeOwnAgentSink) EnsureOwnAgentSession(_ context.Context, sessionID, agent, projectRoot, model string, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, ownAgentCall{sessionID, agent, projectRoot, model})
	if f.fail {
		return errors.New("boom")
	}
	return nil
}

func (f *fakeOwnAgentSink) all() []ownAgentCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]ownAgentCall(nil), f.calls...)
}

// codingSessionResolver stands in for the pid bridge identifying the
// connection's process as a registered coding tool (claude-code, session
// coding-sess-1). Process identity wins over the agent header (M2).
type codingSessionResolver struct{}

func (codingSessionResolver) Resolve(context.Context, string) (string, bool, error) {
	return "coding-sess-1", true, nil
}

func (codingSessionResolver) ResolveTool(context.Context, string) (string, bool, error) {
	return models.ToolClaudeCode, true, nil
}

// noProcessResolver is the pid bridge finding no registered coding tool
// behind the connection: a developer's own program.
type noProcessResolver struct{}

func (noProcessResolver) Resolve(context.Context, string) (string, bool, error) {
	return "", false, nil
}

// ownAgentLane is one default provider lane the claim must work on.
type ownAgentLane struct {
	name, path, body, resp, model string
}

var ownAgentLanes = []ownAgentLane{
	{
		name: "anthropic messages", path: "/v1/messages", model: "claude-sonnet-4",
		body: `{"model":"claude-sonnet-4","messages":[{"role":"user","content":"hi"}]}`,
		resp: `{"id":"msg_oa","model":"claude-sonnet-4","stop_reason":"end_turn","usage":{"input_tokens":5,"output_tokens":2}}`,
	},
	{
		name: "openai chat", path: "/v1/chat/completions", model: "gpt-4o",
		body: `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`,
		resp: `{"id":"chatcmpl-oa","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":2,"total_tokens":7}}`,
	},
	{
		name: "openai responses", path: "/v1/responses", model: "gpt-4o",
		body: `{"model":"gpt-4o","input":"hi"}`,
		resp: `{"id":"resp_oa","object":"response","model":"gpt-4o","status":"completed","output":[],"usage":{"input_tokens":5,"output_tokens":2,"total_tokens":7}}`,
	},
	{
		// The Gemini lane names its model only in the path and the response;
		// the session row must still carry it (fix round 1).
		name: "gemini generateContent", path: "/v1beta/models/gemini-2.5-flash:generateContent", model: "gemini-2.5-flash",
		body: `{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}`,
		resp: `{"candidates":[{"content":{"parts":[{"text":"hi"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":5,"candidatesTokenCount":2},"modelVersion":"gemini-2.5-flash"}`,
	},
}

// ownAgentNonTurnPaths are POST endpoints that answer without a model turn
// (no model, no usage), so the proxy writes no api_turn for them.
var ownAgentNonTurnPaths = map[string]string{
	"/v1/messages/count_tokens": `{"input_tokens":12}`,
}

// ownAgentHarness is a proxy whose three provider upstreams are one test
// server answering per path, recording the headers each forward carried.
type ownAgentHarness struct {
	p        *Proxy
	sink     *fakeSink
	agents   *fakeOwnAgentSink
	ts       *httptest.Server
	mu       sync.Mutex
	upstream []http.Header
}

func newOwnAgentHarness(t *testing.T, withSink bool, upstreams map[string]string) *ownAgentHarness {
	t.Helper()
	return newOwnAgentHarnessWith(t, withSink, upstreams, noProcessResolver{})
}

func newOwnAgentHarnessWith(t *testing.T, withSink bool, upstreams map[string]string, resolver SessionResolver) *ownAgentHarness {
	return newOwnAgentHarnessLanes(t, withSink, upstreams, nil, resolver)
}

// newOwnAgentHarnessLanes also takes coding-agent lanes
// (Options.AgentUpstreams, the shape node-local route lanes share).
func newOwnAgentHarnessLanes(t *testing.T, withSink bool, upstreams, agentUpstreams map[string]string, resolver SessionResolver) *ownAgentHarness {
	return newOwnAgentHarnessGuard(t, withSink, upstreams, agentUpstreams, resolver, nil)
}

// newOwnAgentHarnessGuard also takes a guard scanner.
func newOwnAgentHarnessGuard(t *testing.T, withSink bool, upstreams, agentUpstreams map[string]string, resolver SessionResolver, guard GuardScanner) *ownAgentHarness {
	t.Helper()
	h := &ownAgentHarness{sink: &fakeSink{}, agents: &fakeOwnAgentSink{}}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		h.mu.Lock()
		h.upstream = append(h.upstream, r.Header.Clone())
		h.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if body, ok := ownAgentNonTurnPaths[r.URL.Path]; ok {
			_, _ = w.Write([]byte(body))
			return
		}
		for _, l := range ownAgentLanes {
			if strings.HasSuffix(r.URL.Path, l.path) {
				_, _ = w.Write([]byte(l.resp))
				return
			}
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(up.Close)
	opts := Options{
		AnthropicUpstream: up.URL,
		OpenAIUpstream:    up.URL,
		GeminiUpstream:    up.URL,
		Sink:              h.sink,
		SessionResolver:   resolver,
		Upstreams:         map[string]string{},
	}
	for k := range upstreams {
		opts.Upstreams[k] = up.URL
	}
	if len(agentUpstreams) > 0 {
		opts.AgentUpstreams = map[string]string{}
		for k := range agentUpstreams {
			opts.AgentUpstreams[k] = up.URL
		}
	}
	if withSink {
		opts.OwnAgentSessions = h.agents
	}
	if guard != nil {
		opts.Guard = guard
	}
	p, err := New(opts)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	h.p = p
	h.ts = httptest.NewServer(p.Handler())
	t.Cleanup(h.ts.Close)
	return h
}

func (h *ownAgentHarness) do(t *testing.T, path, body string, headers map[string]string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, h.ts.URL+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer sk-test")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func (h *ownAgentHarness) lastUpstream() http.Header {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.upstream) == 0 {
		return nil
	}
	return h.upstream[len(h.upstream)-1]
}

// TestOwnAgentClaimPerLane: every default provider lane honours the agent
// header (present with and without X-Session-Id), ignores a malformed one
// and leaves headerless traffic exactly as before (the pid resolver's
// session), and never forwards either header upstream.
func TestOwnAgentClaimPerLane(t *testing.T) {
	headerCases := []struct {
		name        string
		headers     map[string]string
		wantSession func(t *testing.T, sid string)
		wantEnsure  bool
	}{
		{
			name:    "agent and session",
			headers: map[string]string{ownagent.AgentHeader: "Research Bot", ownagent.SessionHeader: "run-7"},
			wantSession: func(t *testing.T, sid string) {
				if sid != ownagent.SessionID("research-bot", "run-7") {
					t.Errorf("session = %q, want the namespaced explicit id", sid)
				}
			},
			wantEnsure: true,
		},
		{
			name:    "agent without session",
			headers: map[string]string{ownagent.AgentHeader: "research-bot"},
			wantSession: func(t *testing.T, sid string) {
				if !strings.HasPrefix(sid, "ca-") {
					t.Errorf("session = %q, want an implicit own-agent session", sid)
				}
			},
			wantEnsure: true,
		},
		{
			name:    "agent absent keeps today's attribution",
			headers: map[string]string{ownagent.SessionHeader: "plain-7"},
			wantSession: func(t *testing.T, sid string) {
				if sid != "plain-7" {
					t.Errorf("session = %q, want the plain X-Session-Id", sid)
				}
			},
		},
		{
			name:    "no headers stays unattributed as today",
			headers: nil,
			wantSession: func(t *testing.T, sid string) {
				// No body id, no header and no process identity: the
				// pre-feature answer is an unattributed turn.
				if sid != "" {
					t.Errorf("session = %q, want unattributed", sid)
				}
			},
		},
		{
			name:    "malformed agent is ignored",
			headers: map[string]string{ownagent.AgentHeader: "!!!"},
			wantSession: func(t *testing.T, sid string) {
				if sid != "" {
					t.Errorf("session = %q, want unattributed (claim ignored)", sid)
				}
			},
		},
	}
	for _, lane := range ownAgentLanes {
		for _, hc := range headerCases {
			t.Run(lane.name+"/"+hc.name, func(t *testing.T) {
				h := newOwnAgentHarness(t, true, nil)
				h.do(t, lane.path, lane.body, hc.headers)
				turns := h.sink.all()
				if len(turns) != 1 {
					t.Fatalf("want 1 turn, got %d", len(turns))
				}
				hc.wantSession(t, turns[0].SessionID)
				calls := h.agents.all()
				if hc.wantEnsure {
					if len(calls) != 1 {
						t.Fatalf("EnsureOwnAgentSession calls = %d, want 1", len(calls))
					}
					c := calls[0]
					if c.sessionID != turns[0].SessionID || c.agent != "research-bot" || c.root != "[custom-agent]" || c.model != lane.model {
						t.Errorf("ensure call = %+v, turn session %q", c, turns[0].SessionID)
					}
				} else if len(calls) != 0 {
					t.Errorf("headerless request made an own-agent session: %+v", calls)
				}
				up := h.lastUpstream()
				for _, name := range []string{ownagent.AgentHeader, ownagent.SessionHeader} {
					if v := up.Get(name); v != "" {
						t.Errorf("%s leaked upstream: %q", name, v)
					}
				}
			})
		}
	}
}

// TestOwnAgentSessionContinuation: requests that share X-Session-Id land on
// one session and make its row once; a different agent with the same
// X-Session-Id is a different session; an implicit session continues.
func TestOwnAgentSessionContinuation(t *testing.T) {
	lane := ownAgentLanes[0]
	h := newOwnAgentHarness(t, true, nil)
	h.do(t, lane.path, lane.body, map[string]string{ownagent.AgentHeader: "bot", ownagent.SessionHeader: "s1"})
	h.do(t, lane.path, lane.body, map[string]string{ownagent.AgentHeader: "bot", ownagent.SessionHeader: "s1"})
	h.do(t, lane.path, lane.body, map[string]string{ownagent.AgentHeader: "other", ownagent.SessionHeader: "s1"})
	h.do(t, lane.path, lane.body, map[string]string{ownagent.AgentHeader: "bot"})
	h.do(t, lane.path, lane.body, map[string]string{ownagent.AgentHeader: "bot"})
	turns := h.sink.all()
	if len(turns) != 5 {
		t.Fatalf("want 5 turns, got %d", len(turns))
	}
	if turns[0].SessionID != turns[1].SessionID {
		t.Error("explicit session did not continue")
	}
	if turns[2].SessionID == turns[0].SessionID {
		t.Error("two agents sharing X-Session-Id share a session")
	}
	if turns[3].SessionID != turns[4].SessionID || turns[3].SessionID == turns[0].SessionID {
		t.Error("implicit session did not continue on its own id")
	}
	if n := len(h.agents.all()); n != 3 {
		t.Errorf("EnsureOwnAgentSession calls = %d, want 3 (one per session)", n)
	}
}

// TestOwnAgentEnsureFailureRetries: a failed session-row write is retried on
// the next request instead of leaving the session without a row.
func TestOwnAgentEnsureFailureRetries(t *testing.T) {
	lane := ownAgentLanes[0]
	h := newOwnAgentHarness(t, true, nil)
	h.agents.fail = true
	hdr := map[string]string{ownagent.AgentHeader: "bot", ownagent.SessionHeader: "s1"}
	h.do(t, lane.path, lane.body, hdr)
	h.do(t, lane.path, lane.body, hdr)
	if n := len(h.agents.all()); n != 2 {
		t.Errorf("EnsureOwnAgentSession calls = %d, want 2 (retry after failure)", n)
	}
}

// TestOwnAgentOffAndHostedLanes: with the capture off (no sink) or on an
// /up/<id> hosted-app lane, the agent header changes nothing about
// attribution and still never reaches the upstream.
func TestOwnAgentOffAndHostedLanes(t *testing.T) {
	lane := ownAgentLanes[0]
	hdr := map[string]string{ownagent.AgentHeader: "bot", ownagent.SessionHeader: "s1"}
	cases := []struct {
		name     string
		withSink bool
		path     string
		wantSID  string
	}{
		{"capture off", false, lane.path, "s1"},
		{"hosted-app lane", true, "/up/hostedapp" + lane.path, "s1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newOwnAgentHarness(t, tc.withSink, map[string]string{"hostedapp": ""})
			h.do(t, tc.path, lane.body, hdr)
			turns := h.sink.all()
			if len(turns) != 1 {
				t.Fatalf("want 1 turn, got %d", len(turns))
			}
			if turns[0].SessionID != tc.wantSID {
				t.Errorf("session = %q, want %q", turns[0].SessionID, tc.wantSID)
			}
			if n := len(h.agents.all()); n != 0 {
				t.Errorf("own-agent session made: %d calls", n)
			}
			up := h.lastUpstream()
			if up.Get(ownagent.AgentHeader) != "" || up.Get(ownagent.SessionHeader) != "" {
				t.Errorf("own-agent headers leaked upstream: %v", up)
			}
		})
	}
}

// TestOwnAgentRequestClassTool: the claim names the client tool for the
// guard and the compression router, overriding the pid bridge.
func TestOwnAgentRequestClassTool(t *testing.T) {
	h := newOwnAgentHarness(t, true, nil)
	r := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	r.Header.Set(ownagent.AgentHeader, "bot")
	r = h.p.withOwnAgentClaim(r)
	if got := h.p.requestClass(r, models.ProviderAnthropic).Tool; got != models.ToolCustomAgent {
		t.Errorf("requestClass tool = %q, want %q", got, models.ToolCustomAgent)
	}
	get := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	get.Header.Set(ownagent.AgentHeader, "bot")
	if _, ok := ownAgentClaim(h.p.withOwnAgentClaim(get)); ok {
		t.Error("a GET took an own-agent claim (it would open an empty session)")
	}
	plain := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	if got := h.p.requestClass(h.p.withOwnAgentClaim(plain), models.ProviderAnthropic).Tool; got == models.ToolCustomAgent {
		t.Error("a headerless request was classed as custom-agent")
	}
}

// errBody is a request body whose read fails part way, the aborted-upload
// shape that makes serve answer 400 before any turn is written.
type errBody struct{}

func (errBody) Read([]byte) (int, error) { return 0, errors.New("client went away") }
func (errBody) Close() error             { return nil }

// TestOwnAgentFailedFirstRequestStillMakesRow (fix round 1, M1): a claimed
// request that fails before its turn (here an aborted body read, 400; a
// 413 takes the same early return) must not mark the session ready, so the
// next good request of that session makes the row (the 413 row lowers the
// cap on its own proxy instance). Before the fix the
// failed request consumed the first-seen mark and every later turn landed
// in api_turns with no sessions row.
func TestOwnAgentFailedFirstRequestStillMakesRow(t *testing.T) {
	lane := ownAgentLanes[0]
	cases := []struct {
		name     string
		body     func() io.ReadCloser
		wantCode int
	}{
		{"aborted body read", func() io.ReadCloser { return errBody{} }, http.StatusBadRequest},
		// The cap is lowered on this proxy instance only (fix round 2),
		// so the 413 path runs without a 512 MiB body.
		{"body over the cap", func() io.ReadCloser {
			return io.NopCloser(strings.NewReader(strings.Repeat("x", ownAgentTestBodyCap+1)))
		}, http.StatusRequestEntityTooLarge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newOwnAgentHarness(t, true, nil)
			h.p.maxRequestBody = ownAgentTestBodyCap
			hdr := map[string]string{ownagent.AgentHeader: "bot", ownagent.SessionHeader: "s1"}

			bad := httptest.NewRequest(http.MethodPost, lane.path, nil)
			bad.Body = tc.body()
			for k, v := range hdr {
				bad.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()
			h.p.Handler().ServeHTTP(rec, bad)
			if rec.Code != tc.wantCode {
				t.Fatalf("failed first request = %d, want %d", rec.Code, tc.wantCode)
			}

			h.do(t, lane.path, lane.body, hdr)
			turns := h.sink.all()
			if len(turns) != 1 {
				t.Fatalf("want 1 turn, got %d", len(turns))
			}
			calls := h.agents.all()
			if len(calls) != 1 || calls[0].sessionID != turns[0].SessionID {
				t.Fatalf("the good request did not make the session row: calls %+v, turn session %q", calls, turns[0].SessionID)
			}
		})
	}
}

// ownAgentTestBodyCap is the lowered body cap the 413 row uses; the lane
// bodies are well under it.
const ownAgentTestBodyCap = 4096

// TestOwnAgentProcessIdentityWins (fix round 1, M2, docs/security.md
// OWNAGENT-1): when the pid bridge identifies a registered coding tool's own
// process, the agent header is ignored on every lane: the turn keeps that
// tool's session, the client tool stays the coding tool, and no own-agent
// session is made. Before the fix the header moved the turn to a
// custom-agent session, off the tool's per-tool cap subject.
func TestOwnAgentProcessIdentityWins(t *testing.T) {
	for _, lane := range ownAgentLanes {
		t.Run(lane.name, func(t *testing.T) {
			h := newOwnAgentHarnessWith(t, true, nil, codingSessionResolver{})
			h.do(t, lane.path, lane.body, map[string]string{ownagent.AgentHeader: "bot", ownagent.SessionHeader: "s1"})
			turns := h.sink.all()
			if len(turns) != 1 {
				t.Fatalf("want 1 turn, got %d", len(turns))
			}
			// The Anthropic/OpenAI lanes take the plain X-Session-Id ahead of
			// the resolver, exactly as a headerless-agent request does today;
			// what must never happen is the namespaced own-agent id.
			if strings.HasPrefix(turns[0].SessionID, "ca-") {
				t.Errorf("session = %q: the agent header displaced the coding tool's process identity", turns[0].SessionID)
			}
			if n := len(h.agents.all()); n != 0 {
				t.Errorf("own-agent session made for a coding tool's process: %d calls", n)
			}
			r := httptest.NewRequest(http.MethodPost, lane.path, nil)
			r.Header.Set(ownagent.AgentHeader, "bot")
			if got := h.p.requestClass(h.p.withOwnAgentClaim(r), models.ProviderAnthropic).Tool; got != models.ToolClaudeCode {
				t.Errorf("client tool = %q, want the bridge's claude-code", got)
			}
		})
	}
}

// TestOwnAgentDefaultLanesOnly (fix round 1, L1): a coding-agent lane
// (/up/<id> from Options.AgentUpstreams, the same upstreamPrefix shape as a
// node-local /up/route-<host> lane) runs as Plane-B coding-agent traffic but
// is NOT a default provider lane, so the agent header must not open an
// own-agent session there. Before the fix only hosted-app lanes were
// excluded.
func TestOwnAgentDefaultLanesOnly(t *testing.T) {
	lane := ownAgentLanes[0]
	h := newOwnAgentHarnessLanes(t, true, nil, map[string]string{"codinglane": ""}, noProcessResolver{})
	h.do(t, "/up/codinglane"+lane.path, lane.body, map[string]string{ownagent.AgentHeader: "bot", ownagent.SessionHeader: "s1"})
	turns := h.sink.all()
	if len(turns) != 1 {
		t.Fatalf("want 1 turn, got %d", len(turns))
	}
	if strings.HasPrefix(turns[0].SessionID, "ca-") || len(h.agents.all()) != 0 {
		t.Errorf("a coding-agent lane took the own-agent claim: session %q, ensure calls %d", turns[0].SessionID, len(h.agents.all()))
	}
	up := h.lastUpstream()
	if up.Get(ownagent.AgentHeader) != "" || up.Get(ownagent.SessionHeader) != "" {
		t.Errorf("own-agent headers leaked upstream on a coding-agent lane: %v", up)
	}
}

// TestOwnAgentNonTurnPostOpensNoSession (fix round 1, L2): a claimed POST
// that produces no turn (Anthropic count_tokens) must not open a
// custom-agent session with zero turns. The row is now made right before a
// turn is inserted, so no turn means no session. Before the fix the row
// was made for every claimed POST.
func TestOwnAgentNonTurnPostOpensNoSession(t *testing.T) {
	h := newOwnAgentHarness(t, true, nil)
	h.do(t, "/v1/messages/count_tokens", `{"model":"claude-sonnet-4","messages":[{"role":"user","content":"hi"}]}`,
		map[string]string{ownagent.AgentHeader: "bot", ownagent.SessionHeader: "s1"})
	if n := len(h.sink.all()); n != 0 {
		t.Fatalf("count_tokens wrote %d turns, want 0", n)
	}
	if calls := h.agents.all(); len(calls) != 0 {
		t.Fatalf("count_tokens opened an own-agent session: %+v", calls)
	}
}

// denyGuard denies every request the way the real guard's budget and
// egress rules do, and records the session id each scan was keyed by.
type denyGuard struct {
	mu       sync.Mutex
	rule     string
	sessions []string
}

func (g *denyGuard) ScanRequest(_ context.Context, _ string, _ []byte, sessionID string) GuardRequestResult {
	g.mu.Lock()
	g.sessions = append(g.sessions, sessionID)
	g.mu.Unlock()
	return GuardRequestResult{Action: "deny", RuleID: g.rule, Reason: "denied for the test"}
}

func (g *denyGuard) InspectResponse(context.Context, string, int64, []GuardToolUse) {}

// TestOwnAgentGuardDenyApplies (fix round 1): a guard deny (here an egress
// rule and a hard budget rule; the real guard's budget engine is exercised
// in cmd/observer TestOwnAgentBudgetDenyAppliesThroughRealGuard) stops a
// claimed request before the upstream, keyed by the claim's session, and
// the deny turn lands on that session with its row made.
func TestOwnAgentGuardDenyApplies(t *testing.T) {
	for _, rule := range []string{"E-101", "B-601"} {
		t.Run(rule, func(t *testing.T) {
			lane := ownAgentLanes[0]
			g := &denyGuard{rule: rule}
			h := newOwnAgentHarnessGuard(t, true, nil, nil, noProcessResolver{}, g)
			req, _ := http.NewRequest(http.MethodPost, h.ts.URL+lane.path, strings.NewReader(lane.body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(ownagent.AgentHeader, "bot")
			req.Header.Set(ownagent.SessionHeader, "s1")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("status %d, want 403", resp.StatusCode)
			}
			if h.lastUpstream() != nil {
				t.Fatal("a denied request reached the upstream")
			}
			want := ownagent.SessionID("bot", "s1")
			g.mu.Lock()
			scanned := append([]string(nil), g.sessions...)
			g.mu.Unlock()
			if len(scanned) == 0 || scanned[len(scanned)-1] != want {
				t.Fatalf("guard scanned sessions %v, want the claim's %s", scanned, want)
			}
			turns := h.sink.all()
			if len(turns) != 1 || turns[0].SessionID != want {
				t.Fatalf("deny turn = %+v, want one on %s", turns, want)
			}
			if calls := h.agents.all(); len(calls) != 1 || calls[0].sessionID != want {
				t.Fatalf("deny turn's session row not made: %+v", calls)
			}
		})
	}
}

// erroringResolver is a pid bridge whose lookup fails.
type erroringResolver struct{}

func (erroringResolver) Resolve(context.Context, string) (string, bool, error) {
	return "", false, errors.New("proc walk failed")
}

func (erroringResolver) ResolveTool(context.Context, string) (string, bool, error) {
	return "", false, errors.New("proc walk failed")
}

// claudeCodeUA is the User-Agent Claude Code sends (toolSignatures row).
const claudeCodeUA = "claude-cli/2.1.0 (external, cli)"

// TestOwnAgentClientIdentityWins (fix round 2, N1 and N5): with no bridge
// entry (the stub off Linux) or a failing bridge lookup, a request the
// proxy's client identification table already recognises as a registered
// coding tool (here Claude Code's User-Agent, as sent with
// ANTHROPIC_CUSTOM_HEADERS carrying the agent header) keeps that tool, on
// every lane. Only a request no signal identifies takes the claim, also
// when the bridge errors. Before the fix the header relabelled the coding
// tool's traffic as custom-agent.
func TestOwnAgentClientIdentityWins(t *testing.T) {
	cases := []struct {
		name      string
		resolver  SessionResolver
		ua        string
		wantClaim bool
	}{
		{"no bridge entry, Claude Code UA", noProcessResolver{}, claudeCodeUA, false},
		{"bridge error, Claude Code UA", erroringResolver{}, claudeCodeUA, false},
		{"bridge error, stock SDK UA", erroringResolver{}, "Anthropic/Python 0.40.0", true},
		{"no bridge entry, stock SDK UA", noProcessResolver{}, "OpenAI/JS 4.0.0", true},
	}
	for _, lane := range ownAgentLanes {
		for _, tc := range cases {
			t.Run(lane.name+"/"+tc.name, func(t *testing.T) {
				h := newOwnAgentHarnessWith(t, true, nil, tc.resolver)
				h.do(t, lane.path, lane.body, map[string]string{
					ownagent.AgentHeader: "bot", ownagent.SessionHeader: "s1", "User-Agent": tc.ua,
				})
				turns := h.sink.all()
				if len(turns) != 1 {
					t.Fatalf("want 1 turn, got %d", len(turns))
				}
				claimed := turns[0].SessionID == ownagent.SessionID("bot", "s1")
				if claimed != tc.wantClaim {
					t.Errorf("claimed = %v (session %q), want %v", claimed, turns[0].SessionID, tc.wantClaim)
				}
				if made := len(h.agents.all()) > 0; made != tc.wantClaim {
					t.Errorf("own-agent session made = %v, want %v", made, tc.wantClaim)
				}
				r := httptest.NewRequest(http.MethodPost, lane.path, nil)
				r.Header.Set(ownagent.AgentHeader, "bot")
				r.Header.Set("User-Agent", tc.ua)
				gotTool := h.p.requestClass(h.p.withOwnAgentClaim(r), models.ProviderAnthropic).Tool
				if !tc.wantClaim && gotTool != models.ToolClaudeCode {
					t.Errorf("client tool = %q, want the User-Agent's claude-code", gotTool)
				}
			})
		}
	}
}

// treeResolver is the pid bridge seeing a connection under claude-code's
// session: own reports whether the socket owner is claude-code itself (the
// tool's main process) or a child it started (a script in its shell).
type treeResolver struct{ own bool }

func (treeResolver) Resolve(context.Context, string) (string, bool, error) {
	return "coding-sess-1", true, nil
}

func (treeResolver) ResolveTool(context.Context, string) (string, bool, error) {
	return models.ToolClaudeCode, true, nil
}

func (t treeResolver) ResolveOwnTool(context.Context, string) (string, bool, error) {
	if !t.own {
		return "", false, nil
	}
	return models.ToolClaudeCode, true, nil
}

// TestOwnAgentChildOfToolIsAnOwnAgent (fix round 2, N2): the bridge signal
// overrides the claim only when the connection's own process is the tool's
// binary. A script started from the tool's shell (or inside a dashboard-
// launched `observer <tool>` terminal) that sends the agent header is an
// own agent; the tool's own process sending it is not. Before the fix the
// ancestor walk swallowed the child into the tool's session.
func TestOwnAgentChildOfToolIsAnOwnAgent(t *testing.T) {
	cases := []struct {
		name      string
		own       bool
		wantClaim bool
	}{
		{"the tool's own process", true, false},
		{"a child script under the tool", false, true},
	}
	for _, lane := range ownAgentLanes {
		for _, tc := range cases {
			t.Run(lane.name+"/"+tc.name, func(t *testing.T) {
				h := newOwnAgentHarnessWith(t, true, nil, treeResolver{own: tc.own})
				h.do(t, lane.path, lane.body, map[string]string{ownagent.AgentHeader: "bot", ownagent.SessionHeader: "s1"})
				turns := h.sink.all()
				if len(turns) != 1 {
					t.Fatalf("want 1 turn, got %d", len(turns))
				}
				claimed := turns[0].SessionID == ownagent.SessionID("bot", "s1")
				if claimed != tc.wantClaim {
					t.Errorf("claimed = %v (session %q), want %v", claimed, turns[0].SessionID, tc.wantClaim)
				}
				r := httptest.NewRequest(http.MethodPost, lane.path, nil)
				r.Header.Set(ownagent.AgentHeader, "bot")
				want := models.ToolClaudeCode
				if tc.wantClaim {
					want = models.ToolCustomAgent
				}
				if got := h.p.requestClass(h.p.withOwnAgentClaim(r), models.ProviderAnthropic).Tool; got != want {
					t.Errorf("client tool = %q, want %q", got, want)
				}
			})
		}
	}
}

// TestOwnAgentSessionModelFilledLater (fix round 2, N4): when a session's
// first turn carries no model (an error turn), the next turn that has one
// goes through the row write again so the session gets that model; after
// that no turn touches the row again.
func TestOwnAgentSessionModelFilledLater(t *testing.T) {
	h := newOwnAgentHarness(t, true, nil)
	r := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	r.Header.Set(ownagent.AgentHeader, "bot")
	r.Header.Set(ownagent.SessionHeader, "s1")
	r = h.p.withOwnAgentClaim(r)
	for _, m := range []string{"", "", "claude-sonnet-4", "claude-opus-4", ""} {
		h.p.ensureOwnAgentSession(r, models.APITurn{Provider: models.ProviderAnthropic, Model: m, HTTPStatus: 500})
	}
	calls := h.agents.all()
	if len(calls) != 2 || calls[0].model != "" || calls[1].model != "claude-sonnet-4" {
		t.Fatalf("row writes = %+v, want one without a model then one with claude-sonnet-4", calls)
	}
}

// TestRequestBodyCapZeroMeansDefault (sdk-1f L6): a proxy built as a
// struct literal (as many tests do) or by New has no override, and its cap
// is the 512 MiB default, never zero; an override applies as set.
func TestRequestBodyCapZeroMeansDefault(t *testing.T) {
	cases := []struct {
		name string
		p    *Proxy
		want int64
	}{
		{"struct literal", &Proxy{}, maxRequestBodyBytes},
		{"negative override", &Proxy{maxRequestBody: -1}, maxRequestBodyBytes},
		{"override", &Proxy{maxRequestBody: 4096}, 4096},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.p.requestBodyCap(); got != tc.want {
				t.Fatalf("requestBodyCap = %d, want %d", got, tc.want)
			}
		})
	}
	p, err := New(Options{Sink: &fakeSink{}})
	if err != nil {
		t.Fatal(err)
	}
	if got := p.requestBodyCap(); got != maxRequestBodyBytes {
		t.Fatalf("New: requestBodyCap = %d, want the default", got)
	}
}

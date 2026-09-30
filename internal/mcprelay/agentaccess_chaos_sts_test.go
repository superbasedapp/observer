package mcprelay_test

// Lane CHAOS (doc3 §10 rows "STS down" and "LB retries", node half): the
// relay rides a cached access token through an STS outage while the token
// is valid (including the early-refresh window - Lane NODE Q2 fix), FAILS
// CLOSED once it is inside the clock-skew margin or expired (loopback 503 + Retry-After with a
// CodeUnavailable frame for the request id, zero front requests), and
// recovers on the first call after the STS returns. A front that answers
// 503 is never retried by the relay (the call may have executed) and its
// Retry-After reaches the loopback client.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dpop/jose"
	"github.com/marmutapp/superbased-observer/internal/mcprelay"
)

type chaosClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *chaosClock) Now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *chaosClock) Advance(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

// downTransport fails every round trip while down (the STS is unreachable:
// dial refused / black-holed), else delegates.
type downTransport struct {
	down  atomic.Bool
	tries atomic.Int64
}

func (d *downTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	d.tries.Add(1)
	if d.down.Load() {
		return nil, errors.New("dial tcp: connect: connection refused")
	}
	return http.DefaultTransport.RoundTrip(r)
}

type chaosRelay struct {
	clk    *chaosClock
	sts    *fakeSTS
	front  *fakeFront
	stsNet *downTransport
	srv    *httptest.Server
}

func newChaosRelay(t *testing.T, frontHandler http.Handler) *chaosRelay {
	t.Helper()
	c := &chaosRelay{clk: &chaosClock{t: time.Now().Truncate(time.Second)}, sts: newFakeSTS(t), stsNet: &downTransport{}}
	c.front = newFakeFront(t, c.sts)
	frontURL := c.front.srv.URL
	if frontHandler != nil {
		fs := httptest.NewServer(frontHandler)
		t.Cleanup(fs.Close)
		frontURL = fs.URL
	}
	keys := &fakeKeys{key: newKey(t, jose.AlgEdDSA)}
	tc, err := mcprelay.NewTokenClient(mcprelay.TokenClientConfig{
		TokenEndpoint: c.sts.endpoint(), Keys: keys, HTTP: &http.Client{Transport: c.stsNet}, Now: c.clk.Now,
		SubjectToken: func(context.Context) (string, error) { return "enrol-bearer", nil },
		Actor:        mcprelay.ActorSpec{NodeID: "node_t", CredentialID: "cred_t", MemberID: "usr_t", MachineFP: "fp_t", CredGen: 1, Agent: "agent:claude-code"},
	})
	if err != nil {
		t.Fatal(err)
	}
	r, err := mcprelay.New(mcprelay.Options{
		GatewayURL: "https://mcp-gw.example", FrontURL: frontURL, Tokens: tc, HTTP: http.DefaultClient,
		Records: newMemStore(), SidecarPath: t.TempDir() + "/" + mcprelay.SidecarName, CaptureLevel: "L2", Now: c.clk.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	c.srv = httptest.NewServer(r.ServeLoopbackHTTP())
	t.Cleanup(c.srv.Close)
	return c
}

type loopbackReply struct {
	status int
	retry  string
	code   int
	id     string
}

func (c *chaosRelay) call(t *testing.T, id int) loopbackReply {
	t.Helper()
	resp, err := http.Post(c.srv.URL+"/mcp/gh", "application/json", bytes.NewReader(toolCall(id, "gh_search")))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var m struct {
		ID    json.RawMessage `json:"id"`
		Error *struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(b, &m)
	out := loopbackReply{status: resp.StatusCode, retry: resp.Header.Get("Retry-After"), id: string(m.ID)}
	if m.Error != nil {
		out.code = m.Error.Code
	}
	return out
}

func TestChaosSTSOutageDuringRefresh(t *testing.T) {
	c := newChaosRelay(t, nil)
	if r := c.call(t, 1); r.status != 200 || r.code != 0 {
		t.Fatalf("baseline = %+v", r)
	}
	if n := len(c.sts.issuedTokens()); n != 1 {
		t.Fatalf("exchanges = %d", n)
	}

	// The STS goes down. The cached token (300 s) is still valid and outside
	// the early-refresh window: calls keep flowing on it, no exchange tried.
	c.stsNet.down.Store(true)
	c.clk.Advance(200 * time.Second)
	tries := c.stsNet.tries.Load()
	if r := c.call(t, 2); r.status != 200 || r.code != 0 {
		t.Fatalf("valid cached token during the STS outage = %+v", r)
	}
	if c.stsNet.tries.Load() != tries {
		t.Fatal("an exchange was attempted while the cached token was fresh")
	}

	// Inside the early-refresh window (token valid for 20 s more) the relay
	// tries to refresh, the STS is down, and the still-valid cached token
	// keeps serving (Lane NODE, CHAOS Q2: tokens EXPIRE -> fail closed, not
	// EarlyRefresh before).
	c.clk.Advance(80 * time.Second)
	tries = c.stsNet.tries.Load()
	if r := c.call(t, 3); r.status != 200 || r.code != 0 {
		t.Fatalf("early-refresh window with the STS down = %+v (want served on the still-valid cached token)", r)
	}
	if c.stsNet.tries.Load() == tries {
		t.Fatal("no refresh was attempted inside the early-refresh window")
	}

	// Inside the clock-skew margin (4 s left) the token is no longer
	// presented: fail closed, zero front requests.
	c.clk.Advance(16 * time.Second)
	before := len(c.front.requests())
	if r := c.call(t, 30); r.status != http.StatusServiceUnavailable || r.retry == "" || r.code != mcprelay.CodeUnavailable {
		t.Fatalf("token inside the skew margin + STS down = %+v (want 503 + Retry-After + CodeUnavailable)", r)
	}
	if len(c.front.requests()) != before {
		t.Fatal("the relay reached the front with a token inside the skew margin")
	}

	// Past exp with the STS still down: fail closed, zero front requests.
	c.clk.Advance(14 * time.Second)
	before = len(c.front.requests())
	r := c.call(t, 4)
	if r.status != http.StatusServiceUnavailable || r.retry == "" || r.code != mcprelay.CodeUnavailable || r.id != "4" {
		t.Fatalf("expired token + STS down = %+v (want 503 + Retry-After + CodeUnavailable for id 4)", r)
	}
	if len(c.front.requests()) != before {
		t.Fatal("the relay reached the front without a valid token")
	}

	// The STS returns: the next call re-exchanges and serves.
	c.stsNet.down.Store(false)
	if r := c.call(t, 5); r.status != 200 || r.code != 0 {
		t.Fatalf("after the STS came back = %+v", r)
	}
	if n := len(c.sts.issuedTokens()); n != 2 {
		t.Fatalf("exchanges after recovery = %d, want 2", n)
	}
}

// TestChaosRelayNeverRetriesAFront503 - the node half of "LB retries": a
// front answering 503 + Retry-After (draining, PDP down, hop down) gets ONE
// request per call - the relay never replays a tools/call - and the
// loopback client sees the 503 with the front's Retry-After.
func TestChaosRelayNeverRetriesAFront503(t *testing.T) {
	var hits atomic.Int64
	front := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		var m mcprelay.Message
		_ = json.NewDecoder(r.Body).Decode(&m)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "7")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write(mcprelay.ErrorFrame(m.ID, mcprelay.CodeUnavailable, "draining"))
	})
	c := newChaosRelay(t, front)
	for i := 1; i <= 3; i++ {
		before := hits.Load()
		r := c.call(t, i)
		if r.status != http.StatusServiceUnavailable || r.code != mcprelay.CodeUnavailable {
			t.Fatalf("call %d = %+v", i, r)
		}
		if hits.Load()-before != 1 {
			t.Fatalf("call %d reached the front %d times (a 503 must never be retried by the relay)", i, hits.Load()-before)
		}
		if r.retry != "7" {
			t.Fatalf("call %d: the front's Retry-After did not reach the loopback client (got %q)", i, r.retry)
		}
	}
}

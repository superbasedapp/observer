package mcprelay_test

// Lane NODE (P10 wave 3, Lane CHAOS Q2): an early refresh that fails because
// the STS is UNAVAILABLE keeps serving the still-valid cached token (retried
// with backoff, not on every call) and fails closed only at real expiry
// minus the clock-skew margin; a REFUSAL evicts and fails closed at once.

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dpop/jose"
	"github.com/marmutapp/superbased-observer/internal/mcprelay"
)

type outageEnv struct {
	clk *chaosClock
	sts *fakeSTS
	net *downTransport
	tc  *mcprelay.TokenClient
}

func newOutageEnv(t *testing.T) *outageEnv {
	t.Helper()
	e := &outageEnv{clk: &chaosClock{t: time.Now().Truncate(time.Second)}, sts: newFakeSTS(t), net: &downTransport{}}
	tc, err := mcprelay.NewTokenClient(mcprelay.TokenClientConfig{
		TokenEndpoint: e.sts.endpoint(), Keys: &fakeKeys{key: newKey(t, jose.AlgEdDSA)},
		HTTP: &http.Client{Transport: e.net}, Now: e.clk.Now,
		SubjectToken: func(context.Context) (string, error) { return "enrol-bearer", nil },
		Actor:        mcprelay.ActorSpec{CredentialID: "cred_t", MemberID: "usr_t", MachineFP: "fp_t", CredGen: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	e.tc = tc
	return e
}

const outageResource = "https://mcp-gw.example/mcp/gh"

func (e *outageEnv) token() (mcprelay.AccessToken, error) {
	return e.tc.TokenFor(context.Background(), outageResource, "", "")
}

// TestTokenForSTSOutageTable pins the refresh-failure decision per row: the
// token is 300 s; `left` is how much of it remains when the refresh runs.
func TestTokenForSTSOutageTable(t *testing.T) {
	cases := []struct {
		name  string
		left  time.Duration
		fail  func(*outageEnv) // makes the next exchange fail
		serve bool             // the cached token is served
		want  error            // else the error class
	}{
		{"transport down, 20s left -> cached", 20 * time.Second, func(e *outageEnv) { e.net.down.Store(true) }, true, nil},
		{"transport down, 6s left -> cached", 6 * time.Second, func(e *outageEnv) { e.net.down.Store(true) }, true, nil},
		{"STS 503 temporarily_unavailable, 20s left -> cached", 20 * time.Second, func(e *outageEnv) {
			e.sts.refuse, e.sts.status = "temporarily_unavailable", http.StatusServiceUnavailable
		}, true, nil},
		{"STS 500 server_error, 20s left -> cached", 20 * time.Second, func(e *outageEnv) {
			e.sts.refuse, e.sts.status = "server_error", http.StatusInternalServerError
		}, true, nil},
		{"transport down, 5s left (inside skew) -> fail closed", 5 * time.Second, func(e *outageEnv) { e.net.down.Store(true) }, false, mcprelay.ErrSTSUnavailable},
		{"transport down, 4s left (inside skew) -> fail closed", 4 * time.Second, func(e *outageEnv) { e.net.down.Store(true) }, false, mcprelay.ErrSTSUnavailable},
		{"transport down, expired -> fail closed", -time.Second, func(e *outageEnv) { e.net.down.Store(true) }, false, mcprelay.ErrSTSUnavailable},
		{"refused invalid_grant, 20s left -> fail closed", 20 * time.Second, func(e *outageEnv) { e.sts.refuse = "invalid_grant" }, false, mcprelay.ErrExchangeRefused},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newOutageEnv(t)
			first, err := e.token()
			if err != nil {
				t.Fatal(err)
			}
			e.clk.Advance(300*time.Second - tc.left)
			tc.fail(e)
			tries := e.net.tries.Load()
			got, err := e.token()
			if e.net.tries.Load() == tries {
				t.Fatal("no refresh was attempted inside the early-refresh window")
			}
			if tc.serve {
				if err != nil || got.Value != first.Value {
					t.Fatalf("want the cached token served, got %v (same=%v)", err, got.Value == first.Value)
				}
				return
			}
			if !errors.Is(err, tc.want) || got.Value != "" {
				t.Fatalf("want %v and no token, got %v (token=%q)", tc.want, err, got.Value)
			}
		})
	}
}

// TestTokenForOutageBackoff: while a still-valid token serves, a failing
// refresh is retried with backoff (1s, 2s, ...) - not on every call - and a
// recovered STS replaces the token on the next due attempt.
func TestTokenForOutageBackoff(t *testing.T) {
	e := newOutageEnv(t)
	first, err := e.token()
	if err != nil {
		t.Fatal(err)
	}
	e.clk.Advance(270 * time.Second) // 30 s left: early-refresh window
	e.net.down.Store(true)
	attempt := func(wantTry bool) {
		t.Helper()
		before := e.net.tries.Load()
		got, err := e.token()
		if err != nil || got.Value != first.Value {
			t.Fatalf("want the cached token, got %v", err)
		}
		if tried := e.net.tries.Load() != before; tried != wantTry {
			t.Fatalf("refresh attempted = %v, want %v", tried, wantTry)
		}
	}
	attempt(true)  // failure 1 -> next in 1s
	attempt(false) // inside backoff: no dial
	e.clk.Advance(time.Second)
	attempt(true) // failure 2 -> next in 2s
	e.clk.Advance(time.Second)
	attempt(false)
	e.clk.Advance(time.Second)
	attempt(true) // failure 3 -> next in 4s
	e.net.down.Store(false)
	attempt(false) // STS back, still inside backoff: the old token serves
	e.clk.Advance(4 * time.Second)
	got, err := e.token()
	if err != nil || got.Value == first.Value {
		t.Fatalf("recovered STS must mint a fresh token, got %v (same=%v)", err, got.Value == first.Value)
	}
}

// TestTokenForRefusalEvictsCachedToken: after a refusal the old token is
// gone - a following outage cannot resurrect it.
func TestTokenForRefusalEvictsCachedToken(t *testing.T) {
	e := newOutageEnv(t)
	if _, err := e.token(); err != nil {
		t.Fatal(err)
	}
	e.clk.Advance(280 * time.Second)
	e.sts.refuse = "invalid_grant"
	if _, err := e.token(); !errors.Is(err, mcprelay.ErrExchangeRefused) {
		t.Fatalf("want refusal, got %v", err)
	}
	e.net.down.Store(true)
	if got, err := e.token(); !errors.Is(err, mcprelay.ErrSTSUnavailable) || got.Value != "" {
		t.Fatalf("a refused token must not be served again, got %v (token=%q)", err, got.Value)
	}
}

// TestTokenClientExpirySkewBounds: a configured skew larger than
// MaxExpirySkew is clamped (the relay never fails closed earlier than
// MaxExpirySkew before expiry on an STS outage).
func TestTokenClientExpirySkewBounds(t *testing.T) {
	e := newOutageEnv(t)
	tc, err := mcprelay.NewTokenClient(mcprelay.TokenClientConfig{
		TokenEndpoint: e.sts.endpoint(), Keys: &fakeKeys{key: newKey(t, jose.AlgEdDSA)},
		HTTP: &http.Client{Transport: e.net}, Now: e.clk.Now, ExpirySkew: time.Minute,
		SubjectToken: func(context.Context) (string, error) { return "enrol-bearer", nil },
		Actor:        mcprelay.ActorSpec{CredentialID: "cred_t", MemberID: "usr_t", MachineFP: "fp_t", CredGen: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := tc.Token(context.Background(), outageResource, "")
	if err != nil {
		t.Fatal(err)
	}
	e.clk.Advance(290 * time.Second) // 10 s left: a 60 s skew would refuse
	e.net.down.Store(true)
	got, err := tc.Token(context.Background(), outageResource, "")
	if err != nil || got.Value != first.Value {
		t.Fatalf("skew must be clamped to %v, got %v", mcprelay.MaxExpirySkew, err)
	}
}

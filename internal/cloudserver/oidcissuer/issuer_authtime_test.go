package oidcissuer_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer/oidctest"
)

// issuer_authtime_test.go: auth_time conformance (OIDC Core 2, 3.1.2.1).
// auth_time is the portal session's authentication and never the mint time;
// a session whose authentication time is not known yields a token without
// one, and only for a request that asked for no freshness; and prompt /
// max_age decide whether that session may be used or a fresh sign-in comes
// first.

// TestAuthTimeIsTheSessionsAuthenticationNotTheMintTime: a session that
// authenticated hours ago, reused to sign in now, yields its own auth_time;
// time passing between authorize and token moves iat, never auth_time.
func TestAuthTimeIsTheSessionsAuthenticationNotTheMintTime(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	iss, _ := w.replica(t, oidctest.NewKey(t), "vm-a")
	ctx := context.Background()
	p := newRP(orgA)

	authAt := start.Add(-3 * time.Hour)
	code := codeFrom(t, p, iss.Authorize(ctx, p.authorize(), oidcissuer.Session{AccountID: alice, AuthTime: authAt}))
	w.clock.Advance(30 * time.Second)
	resp, err := iss.Token(ctx, p.token(code))
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	c := verifyWithJWKS(t, iss, resp.IDToken)
	if c.AuthTime != authAt.Unix() {
		t.Errorf("auth_time = %d, want the session's authentication %d", c.AuthTime, authAt.Unix())
	}
	if c.Iat != start.Add(30*time.Second).Unix() || c.AuthTime == c.Iat {
		t.Errorf("iat %d auth_time %d: auth_time must not follow the mint time", c.Iat, c.AuthTime)
	}
}

// rawPayloadHas reports whether the id_token's raw payload names claim (as
// opposed to the decoded Claims, where an absent number reads as zero).
func rawPayloadHas(t *testing.T, token, claim string) bool {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("id_token has %d parts", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("payload: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("payload: %v", err)
	}
	_, ok := m[claim]
	return ok
}

// TestAuthTimePresentWhenKnown: the raw payload carries auth_time whenever
// the session's authentication time is known, max_age or not; when it is not
// known (an ordinary AuthKit sign-in AuthKit may have answered from its own
// session), a request that asked for no freshness gets a token WITHOUT
// auth_time rather than an invented one, and a request with max_age is sent
// to a fresh sign-in instead of being issued.
func TestAuthTimePresentWhenKnown(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	iss, _ := w.replica(t, oidctest.NewKey(t), "vm-a")
	ctx := context.Background()
	for _, maxAge := range []string{"", "3600"} {
		p := newRP(orgA)
		r := p.authorize()
		r.MaxAge = maxAge
		code := codeFrom(t, p, iss.Authorize(ctx, r, signedIn(alice)))
		resp, err := iss.Token(ctx, p.token(code))
		if err != nil {
			t.Fatalf("max_age %q: Token: %v", maxAge, err)
		}
		if c := verifyWithJWKS(t, iss, resp.IDToken); c.AuthTime != start.Unix() || !rawPayloadHas(t, resp.IDToken, "auth_time") {
			t.Errorf("max_age %q: auth_time = %d, want %d", maxAge, c.AuthTime, start.Unix())
		}
	}

	unknown := oidcissuer.Session{AccountID: alice}
	p := newRP(orgA)
	code := codeFrom(t, p, iss.Authorize(ctx, p.authorize(), unknown))
	resp, err := iss.Token(ctx, p.token(code))
	if err != nil {
		t.Fatalf("unknown auth time: Token: %v", err)
	}
	if rawPayloadHas(t, resp.IDToken, "auth_time") {
		t.Error("a session whose authentication time is not known produced a token claiming one")
	}

	for _, ask := range []struct{ prompt, maxAge string }{{"", "3600"}, {"", "0"}, {"login", ""}} {
		r := newRP(orgA).authorize()
		r.Prompt, r.MaxAge = ask.prompt, ask.maxAge
		if res := iss.Authorize(ctx, r, unknown); res.Outcome != oidcissuer.OutcomeLogin || !res.FreshSignIn {
			t.Errorf("%+v on a session of unknown authentication time = %+v, want a fresh sign-in", ask, res)
		}
	}
}

// TestForcedSignInThenResume is the whole prompt=login / max_age=0 round
// trip at the service level: the existing session gets no code, the browser
// is sent to a FRESH sign-in with the demand's time, and the resumed request
// (carrying the marker) issues from the new session with its auth_time.
func TestForcedSignInThenResume(t *testing.T) {
	t.Parallel()
	for _, ask := range []struct{ prompt, maxAge string }{{"login", "0"}, {"login", ""}, {"", "0"}} {
		w := newWorld(t)
		iss, _ := w.replica(t, oidctest.NewKey(t), "vm-a")
		ctx := context.Background()
		p := newRP(orgA)
		r := p.authorize()
		r.Prompt, r.MaxAge = ask.prompt, ask.maxAge

		old := oidcissuer.Session{AccountID: alice, AuthTime: start.Add(-time.Minute)}
		res := iss.Authorize(ctx, r, old)
		if res.Outcome != oidcissuer.OutcomeLogin || !res.FreshSignIn || !res.ReauthAt.Equal(start) {
			t.Fatalf("%+v: authorize on a reused session = %+v, want a fresh sign-in demanded at %v", ask, res, start)
		}
		if n := w.store.Codes(); n != 0 {
			t.Fatalf("%+v: %d codes stored for a session that had to re-authenticate", ask, n)
		}

		// The resumed request, still on the OLD session (the sign-in was
		// abandoned): demanded again, never issued.
		resumed, err := url.ParseQuery(oidcissuer.ResumeQuery(url.Values{}, res.ReauthAt))
		if err != nil {
			t.Fatal(err)
		}
		r.ReauthAt = resumed.Get(oidcissuer.ReauthParam)
		w.clock.Advance(20 * time.Second)
		if again := iss.Authorize(ctx, r, old); again.Outcome != oidcissuer.OutcomeLogin || !again.FreshSignIn {
			t.Fatalf("%+v: resumed on the old session = %+v, want another fresh sign-in", ask, again)
		}

		// The fresh sign-in completed: a new session authenticated now.
		fresh := oidcissuer.Session{AccountID: alice, AuthTime: w.clock.Now()}
		code := codeFrom(t, p, iss.Authorize(ctx, r, fresh))
		resp, err := iss.Token(ctx, p.token(code))
		if err != nil {
			t.Fatalf("%+v: Token: %v", ask, err)
		}
		if c := verifyWithJWKS(t, iss, resp.IDToken); c.AuthTime != fresh.AuthTime.Unix() || c.AuthTime < res.ReauthAt.Unix() {
			t.Errorf("%+v: auth_time = %d, want the fresh sign-in %d (after the demand %d)", ask, c.AuthTime, fresh.AuthTime.Unix(), res.ReauthAt.Unix())
		}
	}
}

// TestPromptNoneLoginRequired: prompt=none never sends the browser anywhere
// but back to the client, with login_required and the state, when only a
// sign-in would do.
func TestPromptNoneLoginRequired(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	iss, _ := w.replica(t, oidctest.NewKey(t), "vm-a")
	ctx := context.Background()
	p := newRP(orgA)
	for name, tc := range map[string]struct {
		maxAge string
		sess   oidcissuer.Session
	}{
		"no session":                     {"", oidcissuer.Session{}},
		"session too old":                {"60", oidcissuer.Session{AccountID: alice, AuthTime: start.Add(-2 * time.Minute)}},
		"unknown auth time with max_age": {"3600", oidcissuer.Session{AccountID: alice}},
		"max_age=0 on any one":           {"0", signedIn(alice)},
	} {
		r := p.authorize()
		r.Prompt, r.MaxAge = "none", tc.maxAge
		res := iss.Authorize(ctx, r, tc.sess)
		u, _ := url.Parse(res.Location)
		if res.Outcome != oidcissuer.OutcomeRedirect || u.Query().Get("error") != oidcissuer.ErrCodeLoginRequired ||
			u.Query().Get("state") != p.state || u.Query().Get("code") != "" {
			t.Errorf("%s: %+v, want a login_required redirect with state", name, res)
		}
	}
	// prompt=none on a session fresh enough issues silently, and so does
	// prompt=none with no max_age on a session of unknown authentication
	// time (nothing asked when the person authenticated).
	r := p.authorize()
	r.Prompt, r.MaxAge = "none", "600"
	codeFrom(t, p, iss.Authorize(ctx, r, signedIn(alice)))
	r = p.authorize()
	r.Prompt = "none"
	codeFrom(t, p, iss.Authorize(ctx, r, oidcissuer.Session{AccountID: alice}))
}

// TestPromptAndMaxAgeShapeRefused: unsupported prompt values, none combined
// with another value, and a malformed max_age are redirected back as
// invalid_request before any session is consulted.
func TestPromptAndMaxAgeShapeRefused(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	iss, _ := w.replica(t, oidctest.NewKey(t), "vm-a")
	p := newRP(orgA)
	for _, tc := range []struct{ prompt, maxAge, rule string }{
		{"consent", "", "prompt-supported"},
		{"select_account", "", "prompt-supported"},
		{"login create", "", "prompt-supported"},
		{"none login", "", "prompt-none-alone"},
		{"", "-5", "max-age-shape"},
		{"", "soon", "max-age-shape"},
	} {
		r := p.authorize()
		r.Prompt, r.MaxAge = tc.prompt, tc.maxAge
		res := iss.Authorize(context.Background(), r, signedIn(alice))
		u, _ := url.Parse(res.Location)
		if res.Err == nil || res.Err.RuleID != tc.rule || u.Query().Get("error") != oidcissuer.ErrCodeInvalidRequest {
			t.Errorf("prompt %q max_age %q: %+v, want invalid_request by %s", tc.prompt, tc.maxAge, res, tc.rule)
		}
	}
	if n := w.store.Codes(); n != 0 {
		t.Errorf("%d codes stored by refused requests", n)
	}
}

// TestDiscoveryAdvertisesAuthTimeAndPrompt: the metadata says what the
// issuer does.
func TestDiscoveryAdvertisesAuthTimeAndPrompt(t *testing.T) {
	t.Parallel()
	d := oidcissuer.DiscoveryFor(testIssuer)
	has := func(list []string, v string) bool {
		for _, x := range list {
			if x == v {
				return true
			}
		}
		return false
	}
	if !has(d.ClaimsSupported, "auth_time") {
		t.Errorf("claims_supported %v lacks auth_time", d.ClaimsSupported)
	}
	if len(d.PromptValuesSupported) != 2 || !has(d.PromptValuesSupported, "none") || !has(d.PromptValuesSupported, "login") {
		t.Errorf("prompt_values_supported = %v, want none and login", d.PromptValuesSupported)
	}
	// Since C2 the issuer signs amr for a session that used its passkey
	// second factor (and only then), so the metadata names it.
	if !has(d.ClaimsSupported, "amr") {
		t.Errorf("claims_supported %v lacks amr, which the issuer signs after a passkey second factor", d.ClaimsSupported)
	}
}

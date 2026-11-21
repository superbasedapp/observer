package api_test

import (
	"crypto/rsa"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/api"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudtestpg"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/jobs"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer/oidctest"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// oidc_reauth_test.go drives the platform OIDC issuer through the REAL portal
// (lane w9-issuer-authtime): the browser's portal session, its authentication
// time in Postgres (cloud 0083), the AuthKit start and callback against a fake
// AuthKit, and the issuer's authorize and token routes. The issuer's own
// store is the in-memory one (the store package's tests cover oidc_codes);
// what this proves is the wiring between the session and the issuer.

const reauthOrg = "0b5c3f1e-2d4a-4c6b-9e8f-1a2b3c4d5e6f"

type oidcPortal struct {
	*workosHarness
	issuer *oidctest.MemStore
	key    *rsa.PrivateKey
	client oidcissuer.Client
}

// newOIDCPortal is newWorkOSHarness with the platform OIDC issuer mounted on
// the portal origin.
func newOIDCPortal(t *testing.T) *oidcPortal {
	t.Helper()
	return newOIDCPortalWith(t, nil)
}

// newOIDCPortalWith is newOIDCPortal with a last say over the Options.
func newOIDCPortalWith(t *testing.T, edit func(*api.Options)) *oidcPortal {
	t.Helper()
	pool := cloudtestpg.NewDB(t)
	s := store.New(pool)
	apiStore := mustAPIStore(t, pool)
	s.SetDeletionJournal(mustJournal(t))
	apiStore.SetDeletionJournal(mustJournal(t))
	fake := newFakeWorkOS(t, testWorkOSSecret)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	base := "http://" + lis.Addr().String()
	key := oidctest.NewKey(t)
	ms := oidctest.NewMemStore()
	ms.SetKey(oidctest.ActiveKey(key, "vm", time.Now().Add(-time.Hour)))
	client, err := oidcissuer.ClientForOrg(reauthOrg, "acme", "superbased.app")
	if err != nil {
		t.Fatal(err)
	}
	ms.AddClient(client)
	signer, err := oidcissuer.NewLocalSigner(base+oidcissuer.IssuerPath, []*rsa.PrivateKey{key}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	iss, err := oidcissuer.New(oidcissuer.Config{Issuer: base + oidcissuer.IssuerPath, Store: ms, Signer: signer})
	if err != nil {
		t.Fatal(err)
	}
	opts := api.Options{
		Store:               apiStore,
		Queue:               jobs.NewPGQueue(apiStore),
		Verifier:            fakeWorkOSVerifier{},
		ExternalBaseURL:     base,
		RateLimit:           &api.RateLimitConfig{},
		Attestor:            admAttestor{verified: true},
		Credentials:         jobs.StaticCredentials{Key: "test-key"},
		PortalWorkOSEnabled: true,
		WorkOSClientID:      "client_test",
		WorkOSAPIKey:        testWorkOSSecret,
		WorkOSAuthorizeURL:  fake.srv.URL + "/authorize",
		WorkOSTokenURL:      fake.srv.URL + "/token",
		OIDCIssuer:          iss,
	}
	if edit != nil {
		edit(&opts)
	}
	handler := api.New(opts).Handler()
	srv := &httptest.Server{Listener: lis, Config: &http.Server{Handler: handler}}
	srv.Start()
	t.Cleanup(srv.Close)
	return &oidcPortal{
		workosHarness: &workosHarness{harness: &harness{srv: srv, store: s}, workos: fake},
		issuer:        ms, key: key, client: client,
	}
}

// rpRequest is a tenant's authorize request (PKCE S256, nonce), plus extra.
func (p *oidcPortal) rpRequest(extra url.Values) (url.Values, string) {
	verifier := strings.Repeat("v", 43)
	q := url.Values{
		"client_id": {p.client.ClientID}, "redirect_uri": {p.client.RedirectURIs[0]}, "response_type": {"code"},
		"scope": {"openid email"}, "state": {"rp-state"}, "nonce": {"rp-nonce"},
		"code_challenge": {oidcissuer.S256Challenge(verifier)}, "code_challenge_method": {"S256"},
	}
	for k, v := range extra {
		q[k] = v
	}
	return q, verifier
}

// follow GETs a same-origin path (or absolute URL) with the browser and
// returns the redirect target.
func (p *oidcPortal) follow(t *testing.T, hc *http.Client, target string) *url.URL {
	t.Helper()
	if strings.HasPrefix(target, "/") {
		target = p.srv.URL + target
	}
	resp, err := hc.Get(target)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("GET %s = %d %s, want a redirect", target, resp.StatusCode, readAll(resp))
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

// redeem exchanges the code the tenant callback carries and returns the
// verified claims.
func (p *oidcPortal) redeem(t *testing.T, cb *url.URL, verifier string) oidcissuer.Claims {
	t.Helper()
	if !strings.HasPrefix(cb.String(), p.client.RedirectURIs[0]+"?") || cb.Query().Get("code") == "" {
		t.Fatalf("authorize redirected to %s, want the tenant callback with a code", cb)
	}
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {cb.Query().Get("code")},
		"redirect_uri": {p.client.RedirectURIs[0]}, "client_id": {p.client.ClientID}, "code_verifier": {verifier},
	}
	resp, err := http.PostForm(p.srv.URL+oidcissuer.TokenPath, form)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token = %d %s", resp.StatusCode, readAll(resp))
	}
	var tr oidcissuer.TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		t.Fatal(err)
	}
	c, err := oidcissuer.VerifyRS256(tr.IDToken, oidcissuer.PublicJWK(&p.key.PublicKey))
	if err != nil {
		t.Fatalf("id_token: %v", err)
	}
	return c
}

// wantForcedStart asserts the issuer sent the browser to the portal's AuthKit
// start with reauth=1.
func wantForcedStart(t *testing.T, loc *url.URL) {
	t.Helper()
	if loc.Path != "/portal/auth/workos/start" || loc.Query().Get("reauth") != "1" ||
		!strings.HasPrefix(loc.Query().Get("return_to"), oidcissuer.AuthorizePath+"?") {
		t.Fatalf("issuer redirected to %s, want the AuthKit start with reauth=1 resuming the authorize request", loc)
	}
}

// TestOIDCStepUpThroughThePortal: an ordinary AuthKit sign-in gives a portal
// session whose authentication time is not known; a plain sign-in from it gets
// an id_token without auth_time; a step-up (prompt=login, max_age=0) is sent
// to a FORCED AuthKit sign-in, and the token issued after it carries that
// sign-in's time. A browser that drops reauth=1 from the start gets a session
// that still cannot answer the step-up.
func TestOIDCStepUpThroughThePortal(t *testing.T) {
	p := newOIDCPortal(t)
	const subject = "oidc-olive"
	hc, _, account := p.signIn(t, subject)
	p.issuer.SetMember(account, reauthOrg, oidcissuer.Member{
		IsMember: true, AccountStatus: "active", OrgStatus: "active",
		RailEnabled: true, Sub: "user_olive", Email: "olive@example.com", EmailVerified: true,
	})

	// 1. A plain sign-in from the ordinary session: issued, no auth_time.
	q, verifier := p.rpRequest(nil)
	c := p.redeem(t, p.follow(t, hc, oidcissuer.AuthorizePath+"?"+q.Encode()), verifier)
	if c.AuthTime != 0 || c.Sub != "user_olive" {
		t.Fatalf("plain sign-in claims = %+v, want sub user_olive and no auth_time", c)
	}

	// 2. A step-up from the same session: no code, a forced AuthKit start.
	q, verifier = p.rpRequest(url.Values{"prompt": {"login"}, "max_age": {"0"}})
	demanded := time.Now().Add(-time.Second)
	start := p.follow(t, hc, oidcissuer.AuthorizePath+"?"+q.Encode())
	wantForcedStart(t, start)

	// 3. The browser drops reauth=1: AuthKit is not forced, the new session
	// records no authentication time, and the resumed request is demanded
	// again rather than issued.
	stripped := start.Query()
	stripped.Del("reauth")
	state, resp := p.startFlow(t, hc, "?"+stripped.Encode())
	if aq := authorizeQuery(t, resp); aq.Get("prompt") != "" || aq.Get("max_age") != "" {
		t.Fatalf("a start without reauth forced AuthKit: %v", aq)
	}
	cb := p.callback(t, hc, newCode(subject), state)
	if cb.StatusCode != http.StatusSeeOther {
		t.Fatalf("callback = %d %s", cb.StatusCode, readAll(cb))
	}
	wantForcedStart(t, p.follow(t, hc, cb.Header.Get("Location")))

	// 4. The forced leg: AuthKit gets prompt=login max_age=0, the callback
	// records the authentication, and the resumed request issues a token
	// whose auth_time is that sign-in, after the demand.
	state, resp = p.startFlow(t, hc, "?"+start.RawQuery)
	if aq := authorizeQuery(t, resp); aq.Get("prompt") != "login" || aq.Get("max_age") != "0" {
		t.Fatalf("the forced start did not force AuthKit: %v", aq)
	}
	cb = p.callback(t, hc, newCode(subject), state)
	if cb.StatusCode != http.StatusSeeOther {
		t.Fatalf("callback = %d %s", cb.StatusCode, readAll(cb))
	}
	c = p.redeem(t, p.follow(t, hc, cb.Header.Get("Location")), verifier)
	if c.AuthTime < demanded.Unix() || c.AuthTime > time.Now().Unix()+1 {
		t.Fatalf("step-up auth_time = %d, want the forced sign-in (at or after %d)", c.AuthTime, demanded.Unix())
	}
}

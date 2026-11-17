package oidcissuer_test

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer/oidctest"
)

// issuer_test.go: conformance-style proofs of the issuer service over the
// in-memory store (the Postgres twin of the replica and atomicity proofs is
// in internal/cloudserver/store/oidc_test.go).

const (
	testIssuer = "https://app.example/oauth2"
	orgA       = "0b5c3f1e-2d4a-4c6b-9e8f-1a2b3c4d5e6f"
	orgB       = "1c6d4f2a-3e5b-4d7c-8f9a-2b3c4d5e6f70"
	alice      = "aaaaaaaa-0000-4000-8000-000000000001"
)

var start = time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)

// world is one issuer deployment: a shared store, a clock, and replicas.
type world struct {
	store *oidctest.MemStore
	clock *oidctest.Clock
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{store: oidctest.NewMemStore(), clock: oidctest.NewClock(start)}
	for _, org := range []string{orgA, orgB} {
		c, err := oidcissuer.ClientForOrg(org, slugOf(org), "superbased.app")
		if err != nil {
			t.Fatal(err)
		}
		w.store.AddClient(c)
	}
	w.store.SetMember(alice, orgA, member())
	w.store.SetMember(alice, orgB, member())
	return w
}

func slugOf(org string) string {
	if org == orgA {
		return "acme"
	}
	return "beta"
}

func member() oidcissuer.Member {
	return oidcissuer.Member{IsMember: true, AccountStatus: "active", OrgStatus: "active", RailEnabled: true, Sub: "user_alice", Email: "alice@example.com", EmailVerified: true}
}

// replica builds an issuer over the shared store with its own signer key
// (per-VM kids), registered active since a day ago.
func (w *world) replica(t *testing.T, key *rsa.PrivateKey, vm string) (*oidcissuer.Issuer, *oidcissuer.LocalSigner) {
	t.Helper()
	signer, err := oidcissuer.NewLocalSigner(testIssuer, []*rsa.PrivateKey{key}, w.clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	w.store.SetKey(oidctest.ActiveKey(key, vm, start.Add(-24*time.Hour)))
	iss, err := oidcissuer.New(oidcissuer.Config{Issuer: testIssuer, Store: w.store, Signer: signer, Now: w.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	return iss, signer
}

// signedIn is a portal session of account authenticated at start ("" is no
// session).
func signedIn(account string) oidcissuer.Session {
	return oidcissuer.Session{AccountID: account, AuthTime: start}
}

// rp is the relying party's half of one sign-in.
type rp struct {
	org, verifier, state, nonce string
}

func newRP(org string) rp {
	return rp{org: org, verifier: strings.Repeat("v", 50), state: "state-" + org[:4], nonce: "nonce-" + org[:4]}
}

func (p rp) redirect() string {
	return "https://" + slugOf(p.org) + ".superbased.app/auth/oidc/callback"
}

func (p rp) authorize() oidcissuer.AuthorizeRequest {
	return oidcissuer.AuthorizeRequest{
		ClientID: oidcissuer.ClientIDForOrg(p.org), RedirectURI: p.redirect(), ResponseType: "code",
		Scope: "openid email profile", State: p.state, Nonce: p.nonce,
		CodeChallenge: oidcissuer.S256Challenge(p.verifier), CodeChallengeMethod: "S256",
	}
}

func (p rp) token(code string) oidcissuer.TokenRequest {
	return oidcissuer.TokenRequest{
		GrantType: "authorization_code", Code: code, RedirectURI: p.redirect(),
		ClientID: oidcissuer.ClientIDForOrg(p.org), CodeVerifier: p.verifier,
	}
}

// codeFrom asserts a code redirect and returns the code.
func codeFrom(t *testing.T, p rp, res oidcissuer.AuthorizeResult) string {
	t.Helper()
	if res.Outcome != oidcissuer.OutcomeRedirect || res.Err != nil {
		t.Fatalf("authorize = %+v (err %v), want a code redirect", res, res.Err)
	}
	u, err := url.Parse(res.Location)
	if err != nil {
		t.Fatal(err)
	}
	if got := u.Scheme + "://" + u.Host + u.Path; got != p.redirect() {
		t.Fatalf("redirected to %s, want %s", got, p.redirect())
	}
	q := u.Query()
	if q.Get("state") != p.state || q.Get("iss") != testIssuer || q.Get("code") == "" {
		t.Fatalf("redirect query = %v", q)
	}
	return q.Get("code")
}

func wantGrantErr(t *testing.T, err error, code string) *oidcissuer.Error {
	t.Helper()
	var e *oidcissuer.Error
	if !errors.As(err, &e) || e.Code != code {
		t.Fatalf("err = %v, want %s", err, code)
	}
	return e
}

// verifyWithJWKS verifies token against the issuer's published JWKS.
func verifyWithJWKS(t *testing.T, iss *oidcissuer.Issuer, token string) oidcissuer.Claims {
	t.Helper()
	doc, err := iss.JWKS(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range doc.Keys {
		if c, err := oidcissuer.VerifyRS256(token, k); err == nil {
			return c
		}
	}
	t.Fatalf("token verifies under no published key (%d keys)", len(doc.Keys))
	return oidcissuer.Claims{}
}

func TestIssuerAuthorizeTokenWithPKCE(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	iss, _ := w.replica(t, oidctest.NewKey(t), "vm-a")
	ctx := context.Background()
	p := newRP(orgA)

	code := codeFrom(t, p, iss.Authorize(ctx, p.authorize(), oidcissuer.Session{AccountID: alice, AuthTime: start, AMR: []string{"pwd"}}))
	resp, err := iss.Token(ctx, p.token(code))
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if resp.TokenType != "Bearer" || resp.ExpiresIn != 300 {
		t.Errorf("response = %+v", resp)
	}
	c := verifyWithJWKS(t, iss, resp.IDToken)
	want := oidcissuer.Claims{
		Iss: testIssuer, Sub: "user_alice", Aud: "org:" + orgA, Iat: start.Unix(), Exp: start.Unix() + 300, AuthTime: start.Unix(),
		Jti: c.Jti, Nonce: p.nonce, Org: orgA, Email: "alice@example.com", EmailVerified: true, AMR: []string{"pwd"},
	}
	if gotJSON, wantJSON := mustJSON(t, c), mustJSON(t, want); gotJSON != wantJSON || c.Jti == "" {
		t.Errorf("claims = %s\nwant     %s", gotJSON, wantJSON)
	}
	issued := w.store.Issued()
	if len(issued) != 1 || issued[0].JTI != c.Jti || issued[0].AccountID != alice || issued[0].OrgID != orgA {
		t.Fatalf("issued = %+v", issued)
	}
	payload, ok := w.store.Mirror(c.Jti)
	if !ok || strings.Contains(string(payload), "alice@example.com") || !strings.Contains(string(payload), c.Jti) {
		t.Errorf("mirror payload = %s (ok %v): want the jti and no email", payload, ok)
	}
	if !w.store.SubSeen(orgA, "user_alice") {
		t.Error("org_sub_seen not recorded")
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestIssuerAuthorizeRefusals(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	iss, _ := w.replica(t, oidctest.NewKey(t), "vm-a")
	ctx := context.Background()
	p := newRP(orgA)

	cases := []struct {
		name    string
		mutate  func(r *oidcissuer.AuthorizeRequest)
		account string
		outcome oidcissuer.Outcome
		code    string
	}{
		{"redirect uri off by one character", func(r *oidcissuer.AuthorizeRequest) { r.RedirectURI += "x" }, alice, oidcissuer.OutcomeError, "invalid_request"},
		{"another org's redirect uri", func(r *oidcissuer.AuthorizeRequest) {
			r.RedirectURI = "https://beta.superbased.app/auth/oidc/callback"
		}, alice, oidcissuer.OutcomeError, "invalid_request"},
		{"unknown client", func(r *oidcissuer.AuthorizeRequest) {
			r.ClientID = "org:2d7e5a3b-4f6c-4e8d-9a0b-3c4d5e6f7081"
		}, alice, oidcissuer.OutcomeError, "invalid_client"},
		{"plain pkce", func(r *oidcissuer.AuthorizeRequest) {
			r.CodeChallengeMethod = "plain"
			r.CodeChallenge = p.verifier[:43]
		}, alice, oidcissuer.OutcomeRedirect, "invalid_request"},
		{"no pkce", func(r *oidcissuer.AuthorizeRequest) { r.CodeChallenge, r.CodeChallengeMethod = "", "" }, alice, oidcissuer.OutcomeRedirect, "invalid_request"},
		{"no openid scope", func(r *oidcissuer.AuthorizeRequest) { r.Scope = "email" }, alice, oidcissuer.OutcomeRedirect, "invalid_scope"},
		{"no session", func(*oidcissuer.AuthorizeRequest) {}, "", oidcissuer.OutcomeLogin, ""},
		{"not a member", func(*oidcissuer.AuthorizeRequest) {}, "bbbbbbbb-0000-4000-8000-000000000002", oidcissuer.OutcomeRedirect, "access_denied"},
	}
	for _, tc := range cases {
		r := p.authorize()
		tc.mutate(&r)
		res := iss.Authorize(ctx, r, signedIn(tc.account))
		if res.Outcome != tc.outcome {
			t.Errorf("%s: outcome %v, want %v (%+v)", tc.name, res.Outcome, tc.outcome, res.Err)
			continue
		}
		if tc.outcome == oidcissuer.OutcomeError && (res.Location != "" || res.Err == nil || res.Err.Code != tc.code) {
			t.Errorf("%s: %+v, want an in-place %s with no redirect", tc.name, res, tc.code)
		}
		if tc.outcome == oidcissuer.OutcomeRedirect {
			u, _ := url.Parse(res.Location)
			if u.Query().Get("error") != tc.code || u.Query().Get("code") != "" || u.Query().Get("state") != p.state {
				t.Errorf("%s: redirect %s, want error=%s with state and no code", tc.name, res.Location, tc.code)
			}
		}
	}
	if n := w.store.Codes(); n != 0 {
		t.Errorf("%d codes stored by refused requests", n)
	}

	// Org states after active, the opt-out, a suspended account.
	for _, m := range []func(*oidcissuer.Member){
		func(m *oidcissuer.Member) { m.OrgStatus = "suspended" },
		func(m *oidcissuer.Member) { m.OrgStatus = "provisioning" },
		func(m *oidcissuer.Member) { m.RailEnabled = false },
		func(m *oidcissuer.Member) { m.AccountStatus = "suspended" },
	} {
		mem := member()
		m(&mem)
		w.store.SetMember(alice, orgB, mem)
		q := newRP(orgB)
		res := iss.Authorize(ctx, q.authorize(), signedIn(alice))
		if u, _ := url.Parse(res.Location); res.Outcome != oidcissuer.OutcomeRedirect || u.Query().Get("error") != "access_denied" {
			t.Errorf("member %+v: %+v, want access_denied", mem, res)
		}
	}
}

func TestIssuerCodeSingleUseExpiryAndBinding(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	iss, _ := w.replica(t, oidctest.NewKey(t), "vm-a")
	ctx := context.Background()
	p := newRP(orgA)

	// Replay: the second redemption is refused.
	code := codeFrom(t, p, iss.Authorize(ctx, p.authorize(), signedIn(alice)))
	if _, err := iss.Token(ctx, p.token(code)); err != nil {
		t.Fatalf("first redemption: %v", err)
	}
	wantGrantErr(t, mustErr(iss.Token(ctx, p.token(code))), "invalid_grant")

	// Expiry: 60 seconds, then refused.
	code = codeFrom(t, p, iss.Authorize(ctx, p.authorize(), signedIn(alice)))
	w.clock.Advance(oidcissuer.CodeTTL)
	wantGrantErr(t, mustErr(iss.Token(ctx, p.token(code))), "invalid_grant")

	// A wrong verifier burns the code: the right one after it is refused.
	code = codeFrom(t, p, iss.Authorize(ctx, p.authorize(), signedIn(alice)))
	bad := p.token(code)
	bad.CodeVerifier = strings.Repeat("w", 50)
	if e := wantGrantErr(t, mustErr(iss.Token(ctx, bad)), "invalid_grant"); e.RuleID != "pkce-verifier" {
		t.Errorf("wrong verifier rule = %s", e.RuleID)
	}
	wantGrantErr(t, mustErr(iss.Token(ctx, p.token(code))), "invalid_grant")

	// Cross-org: a code minted for org A redeemed at org B's client.
	code = codeFrom(t, p, iss.Authorize(ctx, p.authorize(), signedIn(alice)))
	cross := newRP(orgB).token(code)
	cross.CodeVerifier = p.verifier
	if e := wantGrantErr(t, mustErr(iss.Token(ctx, cross)), "invalid_grant"); e.RuleID != "code-client" {
		t.Errorf("cross-org rule = %s", e.RuleID)
	}

	// Membership removed between authorize and token: no token.
	code = codeFrom(t, p, iss.Authorize(ctx, p.authorize(), signedIn(alice)))
	gone := member()
	gone.IsMember = false
	w.store.SetMember(alice, orgA, gone)
	wantGrantErr(t, mustErr(iss.Token(ctx, p.token(code))), "invalid_grant")

	if n := len(w.store.Issued()); n != 1 {
		t.Errorf("%d tokens recorded, want exactly the first", n)
	}
}

func mustErr(_ oidcissuer.TokenResponse, err error) error { return err }

// TestIssuerStartAndCallbackOnDifferentReplicas: authorize on replica A,
// token on replica B (its own signer and kid). Nothing lives in an Issuer.
func TestIssuerStartAndCallbackOnDifferentReplicas(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	a, _ := w.replica(t, oidctest.NewKey(t), "vm-a")
	b, signerB := w.replica(t, oidctest.NewKey(t), "vm-b")
	ctx := context.Background()
	p := newRP(orgA)

	code := codeFrom(t, p, a.Authorize(ctx, p.authorize(), signedIn(alice)))
	resp, err := b.Token(ctx, p.token(code))
	if err != nil {
		t.Fatalf("token on replica B: %v", err)
	}
	keys, _ := signerB.PublicKeys(ctx)
	if c, err := oidcissuer.VerifyRS256(resp.IDToken, keys[0].JWK); err != nil || c.Org != orgA {
		t.Fatalf("token not signed by replica B's own key: %v", err)
	}
	// Both VMs' kids are in the one JWKS, and either replica serves it.
	for _, iss := range []*oidcissuer.Issuer{a, b} {
		doc, err := iss.JWKS(ctx)
		if err != nil || len(doc.Keys) != 2 {
			t.Fatalf("JWKS = %+v, %v; want both VMs' keys", doc, err)
		}
		verifyWithJWKS(t, iss, resp.IDToken)
	}
	// And the code is spent for replica A too.
	wantGrantErr(t, mustErr(a.Token(ctx, p.token(code))), "invalid_grant")
}

// failingSigner is a signer outage.
type failingSigner struct{ keys []oidcissuer.PublicKey }

func (f failingSigner) Sign(context.Context, string, oidcissuer.Claims) (string, error) {
	return "", errors.New("signer socket: connection refused")
}

func (f failingSigner) PublicKeys(context.Context) ([]oidcissuer.PublicKey, error) {
	return f.keys, nil
}

// lyingSigner signs with a key other than the one it claims (kid confusion).
type lyingSigner struct {
	pub  []oidcissuer.PublicKey
	real *oidcissuer.LocalSigner
	kid  string
}

func (l lyingSigner) Sign(ctx context.Context, _ string, c oidcissuer.Claims) (string, error) {
	return l.real.Sign(ctx, l.kid, c)
}

func (l lyingSigner) PublicKeys(context.Context) ([]oidcissuer.PublicKey, error) { return l.pub, nil }

func TestIssuerNeverReturnsAnUnrecordedOrUnsignedToken(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	key := oidctest.NewKey(t)
	iss, signer := w.replica(t, key, "vm-a")
	ctx := context.Background()
	p := newRP(orgA)
	pubs, _ := signer.PublicKeys(ctx)

	// Signer outage: 503, no token, nothing recorded.
	down, err := oidcissuer.New(oidcissuer.Config{Issuer: testIssuer, Store: w.store, Signer: failingSigner{keys: pubs}, Now: w.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	code := codeFrom(t, p, down.Authorize(ctx, p.authorize(), signedIn(alice)))
	resp, err := down.Token(ctx, p.token(code))
	if e := wantGrantErr(t, err, "temporarily_unavailable"); e.Status != 503 || resp.IDToken != "" {
		t.Errorf("signer outage = %+v / %+v", e, resp)
	}

	// A signer that signs with a different key than the published kid: the
	// self-check refuses it.
	other := oidctest.NewKey(t)
	otherSigner, err := oidcissuer.NewLocalSigner(testIssuer, []*rsa.PrivateKey{other}, w.clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, _ := otherSigner.PublicKeys(ctx)
	liar, _ := oidcissuer.New(oidcissuer.Config{
		Issuer: testIssuer, Store: w.store, Now: w.clock.Now,
		Signer: lyingSigner{pub: pubs, real: otherSigner, kid: otherPub[0].KID},
	})
	code = codeFrom(t, p, liar.Authorize(ctx, p.authorize(), signedIn(alice)))
	if _, err := liar.Token(ctx, p.token(code)); err == nil {
		t.Error("a token signed under an unpublished key was returned")
	}

	// Audit before act: the mirror insert fails, so the sign-in fails.
	w.store.FailRecordIssuance(errors.New("insert oidc_audit_mirror: boom"))
	code = codeFrom(t, p, iss.Authorize(ctx, p.authorize(), signedIn(alice)))
	resp, err = iss.Token(ctx, p.token(code))
	if e := wantGrantErr(t, err, "temporarily_unavailable"); e.RuleID != "record-issuance" || resp.IDToken != "" {
		t.Errorf("mirror failure = %+v / %+v", e, resp)
	}
	if n := len(w.store.Issued()); n != 0 {
		t.Errorf("%d tokens recorded through failures", n)
	}
}

func TestIssuerKeyRotation(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	oldKey, newKey := oidctest.NewKey(t), oidctest.NewKey(t)
	ctx := context.Background()
	p := newRP(orgA)

	// The signer holds both keys; the old one is active, the new one only
	// reported (staged).
	signer, err := oidcissuer.NewLocalSigner(testIssuer, []*rsa.PrivateKey{oldKey, newKey}, w.clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	old := oidctest.ActiveKey(oldKey, "vm-a", start.Add(-30*24*time.Hour))
	w.store.SetKey(old)
	iss, err := oidcissuer.New(oidcissuer.Config{Issuer: testIssuer, Store: w.store, Signer: signer, Now: w.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	staged, err := iss.RegisterSignerKeys(ctx, "vm-a")
	if err != nil || len(staged) != 2 {
		t.Fatalf("RegisterSignerKeys = %v, %v", staged, err)
	}
	newKID := oidcissuer.Thumbprint(&newKey.PublicKey)
	doc, _ := iss.JWKS(ctx)
	if len(doc.Keys) != 1 || doc.Keys[0].Kid != old.KID {
		t.Fatalf("a staged key was published: %+v", doc.Keys)
	}

	// Promote: published now, usable after 24 hours. Until then the old key
	// signs.
	next := oidctest.ActiveKey(newKey, "vm-a", start.Add(24*time.Hour))
	w.store.SetKey(next)
	doc, _ = iss.JWKS(ctx)
	if len(doc.Keys) != 2 {
		t.Fatalf("promoted key not published before first use: %+v", doc.Keys)
	}
	code := codeFrom(t, p, iss.Authorize(ctx, p.authorize(), signedIn(alice)))
	resp, err := iss.Token(ctx, p.token(code))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := oidcissuer.VerifyRS256(resp.IDToken, old.JWK); err != nil {
		t.Fatalf("before not_before the old key must sign: %v", err)
	}
	oldToken := resp.IDToken

	// After not_before the new key signs; the old one retires and still
	// verifies the old token.
	w.clock.Advance(25 * time.Hour)
	old.Status = oidcissuer.KeyRetiring
	w.store.SetKey(old)
	code = codeFrom(t, p, iss.Authorize(ctx, p.authorize(), signedIn(alice)))
	resp, err = iss.Token(ctx, p.token(code))
	if err != nil {
		t.Fatal(err)
	}
	if c := verifyWithJWKS(t, iss, resp.IDToken); c.Org != orgA {
		t.Fatal("new token does not verify")
	}
	if _, err := oidcissuer.VerifyRS256(resp.IDToken, next.JWK); err != nil {
		t.Fatalf("after not_before the new key %s must sign: %v", newKID, err)
	}
	verifyWithJWKS(t, iss, oldToken) // retiring: still published

	// Retired: gone from the JWKS, so a token under it no longer verifies.
	old.Status = oidcissuer.KeyRetired
	w.store.SetKey(old)
	doc, _ = iss.JWKS(ctx)
	for _, k := range doc.Keys {
		if k.Kid == old.KID {
			t.Fatal("a retired key is still published")
		}
		if _, err := oidcissuer.VerifyRS256(oldToken, k); err == nil {
			t.Fatal("a token under a retired key still verifies against the JWKS")
		}
	}
}

func TestIssuerNoPublishedKeyIsUnavailable(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	key := oidctest.NewKey(t)
	signer, err := oidcissuer.NewLocalSigner(testIssuer, []*rsa.PrivateKey{key}, w.clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	iss, _ := oidcissuer.New(oidcissuer.Config{Issuer: testIssuer, Store: w.store, Signer: signer, Now: w.clock.Now})
	if _, err := iss.RegisterSignerKeys(context.Background(), "vm-a"); err != nil {
		t.Fatal(err)
	}
	p := newRP(orgA)
	code := codeFrom(t, p, iss.Authorize(context.Background(), p.authorize(), signedIn(alice)))
	_, err = iss.Token(context.Background(), p.token(code))
	if e := wantGrantErr(t, err, "temporarily_unavailable"); e.RuleID != "no-published-key" {
		t.Errorf("rule = %s", e.RuleID)
	}
}

func TestLocalSignerRefusesBadClaims(t *testing.T) {
	t.Parallel()
	clock := oidctest.NewClock(start)
	key := oidctest.NewKey(t)
	s, err := oidcissuer.NewLocalSigner(testIssuer, []*rsa.PrivateKey{key}, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	kid := oidcissuer.Thumbprint(&key.PublicKey)
	good := oidcissuer.Claims{
		Iss: testIssuer, Sub: "user_alice", Aud: "org:" + orgA, Iat: start.Unix(), Exp: start.Unix() + 300, AuthTime: start.Unix(),
		Jti: strings.Repeat("j", 32), Org: orgA, Email: "alice@example.com", EmailVerified: true,
	}
	ctx := context.Background()
	if tok, err := s.Sign(ctx, kid, good); err != nil || tok == "" {
		t.Fatalf("good claims refused: %v", err)
	}
	for name, mutate := range map[string]func(c *oidcissuer.Claims){
		"foreign issuer":          func(c *oidcissuer.Claims) { c.Iss = "https://evil.example/oauth2" },
		"another org's audience":  func(c *oidcissuer.Claims) { c.Aud = "org:" + orgB },
		"ten-minute token":        func(c *oidcissuer.Claims) { c.Exp = c.Iat + 600 },
		"no jti":                  func(c *oidcissuer.Claims) { c.Jti = "" },
		"pre-dated":               func(c *oidcissuer.Claims) { c.Iat -= 3600; c.Exp = c.Iat + 300 },
		"tenant host as audience": func(c *oidcissuer.Claims) { c.Aud = "https://acme.superbased.app" },
	} {
		c := good
		mutate(&c)
		if _, err := s.Sign(ctx, kid, c); !errors.Is(err, oidcissuer.ErrClaimsRefused) {
			t.Errorf("%s: Sign = %v, want ErrClaimsRefused", name, err)
		}
	}
	if _, err := s.Sign(ctx, "not-a-held-kid", good); !errors.Is(err, oidcissuer.ErrClaimsRefused) {
		t.Errorf("unknown kid: %v", err)
	}
	if _, err := oidcissuer.NewLocalSigner(testIssuer, []*rsa.PrivateKey{nil}, nil); err == nil {
		t.Error("a nil key was accepted")
	}
}

func TestDiscoveryDocument(t *testing.T) {
	t.Parallel()
	d := oidcissuer.DiscoveryFor(testIssuer)
	if d.Issuer != testIssuer || d.AuthorizationEndpoint != testIssuer+"/authorize" || d.TokenEndpoint != testIssuer+"/token" ||
		d.JWKSURI != testIssuer+"/jwks.json" {
		t.Errorf("endpoints = %+v", d)
	}
	if mustJSON(t, d.CodeChallengeMethodsSupported) != `["S256"]` || mustJSON(t, d.IDTokenSigningAlgValuesSupported) != `["RS256"]` ||
		mustJSON(t, d.ResponseTypesSupported) != `["code"]` || mustJSON(t, d.TokenEndpointAuthMethodsSupported) != `["none"]` {
		t.Errorf("capabilities = %+v", d)
	}
}

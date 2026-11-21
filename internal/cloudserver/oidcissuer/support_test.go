package oidcissuer_test

import (
	"crypto/rsa"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer/oidctest"
)

// support_test.go: the support path (M7a.2). A staff member's support code is
// written by the staff process's SupportAuthorizer and redeemed at the one
// token endpoint into a token carrying support: true, sub staff:<id>, no
// email, no amr; every refusal names its row.

const staffBob = "5f5e5d5c-5b5a-4958-8756-555453525150"

// supportWorld is a world with the support seam wired on both halves.
func supportWorld(t *testing.T) (*world, *oidctest.MemSupport, *oidcissuer.Issuer, *oidcissuer.SupportAuthorizer) {
	t.Helper()
	w := newWorld(t)
	sup := oidctest.NewMemSupport(w.store)
	sup.SetStaff(staffBob, true)
	sup.SetOrg(orgA, "active", true)
	sup.SetOrg(orgB, "active", true)
	key := oidctest.NewKey(t)
	signer, err := oidcissuer.NewLocalSigner(testIssuer, []*rsa.PrivateKey{key}, w.clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	w.store.SetKey(oidctest.ActiveKey(key, "vm-a", start.Add(-24*time.Hour)))
	iss, err := oidcissuer.New(oidcissuer.Config{
		Issuer: testIssuer, Store: w.store, Signer: signer, Now: w.clock.Now,
		Support: sup, SupportAuthorizeURL: "https://staff.example" + oidcissuer.SupportAuthorizePath,
	})
	if err != nil {
		t.Fatal(err)
	}
	authz, err := oidcissuer.NewSupportAuthorizer(oidcissuer.SupportAuthorizerConfig{Issuer: testIssuer, Store: sup, Now: w.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	return w, sup, iss, authz
}

func staffSession() oidcissuer.StaffSession {
	return oidcissuer.StaffSession{StaffID: staffBob, AssertedAt: start.Add(-5 * time.Minute)}
}

func TestSupportSignInEndToEnd(t *testing.T) {
	t.Parallel()
	_, sup, iss, authz := supportWorld(t)
	p := newRP(orgA)
	code := codeFrom(t, p, authz.Authorize(t.Context(), p.authorize(), staffSession()))
	resp, err := iss.Token(t.Context(), p.token(code))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := iss.JWKS(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	c, err := oidcissuer.VerifyRS256(resp.IDToken, keys.Keys[0])
	if err != nil {
		t.Fatal(err)
	}
	if !c.Support || c.Sub != "staff:"+staffBob || c.Email != "" || c.EmailVerified || len(c.AMR) != 0 ||
		c.Org != orgA || c.Nonce != p.nonce || c.AuthTime != staffSession().AssertedAt.Unix() {
		t.Fatalf("support claims = %+v", c)
	}
	if strings.Contains(resp.IDToken, "email") {
		t.Fatal("a support token must carry no email claim")
	}
	recs := sup.SupportIssued()
	if len(recs) != 1 || recs[0].JTI != c.Jti || recs[0].StaffID != staffBob || recs[0].OrgID != orgA {
		t.Fatalf("support issuance recorded %+v", recs)
	}
	// A code is single use.
	if _, err := iss.Token(t.Context(), p.token(code)); err == nil {
		t.Fatal("a support code redeemed twice")
	}
	if d := iss.Discovery(); d.SupportAuthorizationEndpoint != "https://staff.example/staff/oauth2/authorize" {
		t.Fatalf("discovery support endpoint %q", d.SupportAuthorizationEndpoint)
	}
}

// TestMemberPathNeverMintsASupportToken: a portal member's code yields a
// member token (support false) whatever its subject; only the staff
// authorizer writes a support code.
func TestMemberPathNeverMintsASupportToken(t *testing.T) {
	t.Parallel()
	w, _, iss, _ := supportWorld(t)
	p := newRP(orgA)
	code := codeFrom(t, p, iss.Authorize(t.Context(), p.authorize(), signedIn(alice)))
	resp, err := iss.Token(t.Context(), p.token(code))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(resp.IDToken, "support") {
		t.Fatalf("member token mentions support")
	}
	// A member whose provider subject looks like a staff subject is refused
	// by the signer's claim rules, never signed as one.
	m := member()
	m.Sub = "staff:" + staffBob
	w.store.SetMember(alice, orgA, m)
	code = codeFrom(t, p, iss.Authorize(t.Context(), p.authorize(), signedIn(alice)))
	if _, err := iss.Token(t.Context(), p.token(code)); err == nil {
		t.Fatal("a member with a staff-shaped subject was signed")
	}
}

func TestSupportAuthorizeRefusals(t *testing.T) {
	t.Parallel()
	_, _, _, authz := supportWorld(t)
	p := newRP(orgA)
	// An unknown client and a redirect URI off by one character are answered
	// in place, never redirected (the member path's own client rules).
	bad := p.authorize()
	bad.RedirectURI += "x"
	if res := authz.Authorize(t.Context(), bad, staffSession()); res.Outcome != oidcissuer.OutcomeError || res.Err.RuleID != "redirect-exact" {
		t.Fatalf("redirect mismatch: %+v", res)
	}
	// A request without PKCE is redirected back with invalid_request.
	noPKCE := p.authorize()
	noPKCE.CodeChallengeMethod = "plain"
	if res := authz.Authorize(t.Context(), noPKCE, staffSession()); res.Err == nil || res.Err.RuleID != "pkce-s256" {
		t.Fatalf("plain PKCE: %+v", res)
	}
	// A staff session without an assertion time, or a malformed id.
	for _, s := range []oidcissuer.StaffSession{{StaffID: staffBob}, {StaffID: "bob", AssertedAt: start}} {
		if res := authz.Authorize(t.Context(), p.authorize(), s); res.Outcome != oidcissuer.OutcomeError || res.Err.Status != 403 {
			t.Fatalf("staff session %+v: %+v", s, res)
		}
	}
	// max_age shorter than the assertion's age: assert again (in place).
	stale := p.authorize()
	stale.MaxAge = "60"
	if res := authz.Authorize(t.Context(), stale, staffSession()); res.Outcome != oidcissuer.OutcomeError || res.Err.Code != oidcissuer.ErrCodeLoginRequired {
		t.Fatalf("stale assertion: %+v", res)
	}
	// prompt=none with a stale assertion: login_required to the client.
	stale.Prompt = "none"
	res := authz.Authorize(t.Context(), stale, staffSession())
	if res.Outcome != oidcissuer.OutcomeRedirect || res.Err == nil || res.Err.Code != oidcissuer.ErrCodeLoginRequired {
		t.Fatalf("prompt=none stale: %+v", res)
	}
	if u, _ := url.Parse(res.Location); u.Query().Get("error") != oidcissuer.ErrCodeLoginRequired {
		t.Fatalf("prompt=none redirect %s", res.Location)
	}
}

func TestSupportTokenRechecks(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		rule  string
		apply func(*oidctest.MemSupport)
	}{
		{rule: "staff-active", apply: func(s *oidctest.MemSupport) { s.SetStaff(staffBob, false) }},
		{rule: "org-active", apply: func(s *oidctest.MemSupport) { s.SetOrg(orgA, "suspended", true) }},
		{rule: "rail-enabled", apply: func(s *oidctest.MemSupport) { s.SetOrg(orgA, "active", false) }},
	} {
		_, sup, iss, authz := supportWorld(t)
		p := newRP(orgA)
		code := codeFrom(t, p, authz.Authorize(t.Context(), p.authorize(), staffSession()))
		tc.apply(sup)
		_, err := iss.Token(t.Context(), p.token(code))
		if e := wantGrantErr(t, err, oidcissuer.ErrCodeInvalidGrant); e.RuleID != tc.rule {
			t.Errorf("%s: refused by %s", tc.rule, e.RuleID)
		}
		if len(sup.SupportIssued()) != 0 {
			t.Errorf("%s: a refused support token was recorded", tc.rule)
		}
	}
}

func TestSupportTokenBindingAndAudit(t *testing.T) {
	t.Parallel()
	_, sup, iss, authz := supportWorld(t)
	p := newRP(orgA)
	// A support code for org A redeemed at org B's client: invalid_grant.
	code := codeFrom(t, p, authz.Authorize(t.Context(), p.authorize(), staffSession()))
	other := newRP(orgB)
	tr := other.token(code)
	if _, err := iss.Token(t.Context(), tr); err == nil {
		t.Fatal("a support code crossed orgs")
	}
	// Audit before act: no record, no token.
	code = codeFrom(t, p, authz.Authorize(t.Context(), p.authorize(), staffSession()))
	sup.FailRecord(errors.New("disk full"))
	_, err := iss.Token(t.Context(), p.token(code))
	if e := wantGrantErr(t, err, oidcissuer.ErrCodeTemporarilyUnavailable); e.RuleID != "record-support-issuance" {
		t.Fatalf("record failure refused by %s", e.RuleID)
	}
}

// TestSupportCodeWithoutTheSupportSeam: a serve process built without the
// support seam answers a support code temporarily_unavailable, never a
// member token.
func TestSupportCodeWithoutTheSupportSeam(t *testing.T) {
	t.Parallel()
	w, _, _, authz := supportWorld(t)
	plain, _ := w.replica(t, oidctest.NewKey(t), "vm-b")
	p := newRP(orgA)
	code := codeFrom(t, p, authz.Authorize(t.Context(), p.authorize(), staffSession()))
	_, err := plain.Token(t.Context(), p.token(code))
	if e := wantGrantErr(t, err, oidcissuer.ErrCodeTemporarilyUnavailable); e.RuleID != "support-not-configured" {
		t.Fatalf("refused by %s", e.RuleID)
	}
}

func TestSupportAuthorizeURLValidation(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	signer, err := oidcissuer.NewLocalSigner(testIssuer, []*rsa.PrivateKey{oidctest.NewKey(t)}, w.clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		"http://staff.example/staff/oauth2/authorize",
		"https://staff.example/oauth2/authorize",
		"https://staff.example/staff/oauth2/authorize?x=1",
	} {
		if _, err := oidcissuer.New(oidcissuer.Config{Issuer: testIssuer, Store: w.store, Signer: signer, SupportAuthorizeURL: raw}); err == nil {
			t.Errorf("support authorize URL %q accepted", raw)
		}
	}
}

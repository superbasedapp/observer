package api

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer/oidctest"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/staffauth"
)

// staffsupport_internal_test.go: GET /staff/oauth2/authorize (M7a.2) over a
// real staff session: a fresh passkey assertion yields a support code at the
// tenant's registered callback; a stale one is refused by the authorization
// table before any code exists; a console without the support seam answers
// not_available. (TestStaffRoutesRefuseCustomerSession already walks this
// route with a customer cookie.)

const supportTestOrg = "0b5c3f1e-2d4a-4c6b-9e8f-1a2b3c4d5e6f"

func supportAuthorizeQuery(redirect string) string {
	q := url.Values{
		"client_id": {oidcissuer.ClientIDForOrg(supportTestOrg)}, "redirect_uri": {redirect}, "response_type": {"code"},
		"scope": {"openid"}, "state": {"st-1"}, "nonce": {"nn-1"},
		"code_challenge": {oidcissuer.S256Challenge(strings.Repeat("v", 50))}, "code_challenge_method": {"S256"},
	}
	return q.Encode()
}

func TestStaffSupportAuthorize(t *testing.T) {
	t.Parallel()
	h := newStaffHarness(t, StaffTestVerifier{}, "")
	mem := oidctest.NewMemStore()
	client, err := oidcissuer.ClientForOrg(supportTestOrg, "acme", "superbased.app")
	if err != nil {
		t.Fatal(err)
	}
	mem.AddClient(client)
	sup := oidctest.NewMemSupport(mem)

	auth := NewStaffTestAuthenticator(11)
	h.register(staffTestSupp, staffauth.RoleSupport, auth)
	cookie, _ := h.signIn(staffTestSupp, auth, nil)
	path := oidcissuer.SupportAuthorizePath + "?" + supportAuthorizeQuery(client.RedirectURIs[0])

	// Not configured: not_available, whatever the session.
	if rec := h.do(staffReq{method: "GET", path: path, cookies: []*http.Cookie{cookie}}); rec.Code != http.StatusNotImplemented {
		t.Fatalf("unconfigured = %d %s", rec.Code, rec.Body)
	}

	h.srv.staff.support, err = oidcissuer.NewSupportAuthorizer(oidcissuer.SupportAuthorizerConfig{
		Issuer: "https://app.example/oauth2", Store: sup, Now: h.clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := h.do(staffReq{method: "GET", path: path, cookies: []*http.Cookie{cookie}})
	if rec.Code != http.StatusFound {
		t.Fatalf("fresh support authorize = %d %s", rec.Code, rec.Body)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || loc.Scheme+"://"+loc.Host+loc.Path != client.RedirectURIs[0] || loc.Query().Get("code") == "" || loc.Query().Get("state") != "st-1" {
		t.Fatalf("redirected to %v (%v)", loc, err)
	}
	if mem.Codes() != 1 {
		t.Fatalf("codes stored = %d, want 1", mem.Codes())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("a support authorize answer must not be cached")
	}

	// Stale assertion: refused by the authorization table, no code written.
	h.clock.Advance(staffauth.FreshAssertionWindow + time.Second)
	rec = h.do(staffReq{method: "GET", path: path, cookies: []*http.Cookie{cookie}})
	if rec.Code != http.StatusForbidden || errCode(t, rec) != staffauth.CodeReauthRequired {
		t.Fatalf("stale support authorize = %d %s, want 403 reauth_required", rec.Code, rec.Body)
	}
	if mem.Codes() != 1 {
		t.Fatalf("a stale session wrote a code (codes %d)", mem.Codes())
	}

	// A redirect URI one character off is answered in place.
	cookie, _ = h.signIn(staffTestSupp, auth, cookie)
	bad := oidcissuer.SupportAuthorizePath + "?" + supportAuthorizeQuery(client.RedirectURIs[0]+"x")
	if rec := h.do(staffReq{method: "GET", path: bad, cookies: []*http.Cookie{cookie}}); rec.Code != http.StatusBadRequest {
		t.Fatalf("mismatched redirect = %d %s", rec.Code, rec.Body)
	}
}

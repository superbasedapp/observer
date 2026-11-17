package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/staffauth"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/staffauth/passkey"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/staffauth/passkey/passkeytest"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// staff_passkey_internal_test.go drives the four WebAuthn routes with the
// PRODUCTION verifier (staffauth/passkey, go-webauthn) and a software
// authenticator that produces real CBOR, COSE and signatures, over the
// in-memory staff store: the routes are live (no not_available), a
// discoverable passkey registered with an operator code signs in, a staff
// member holds two passkeys at once, and the counter and user-handle rules
// hold end to end. It also pins the process split (ruling A3): the customer
// handler mounts no staff route and the staff handler mounts nothing else.

// addCode mints another enrolment code for an existing staff member (the
// `observer-cloud staff enrol --staff-id` path).
func (m *memStaffStore) addCode(staffID, code string, expires time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.enrolments[memHash(code)] = &memEnrolment{staffID: staffID, expires: expires}
}

// registerPasskey runs register/begin and register/finish with a.
func (h *staffHarness) registerPasskey(code string, a *passkeytest.Authenticator) *httptest.ResponseRecorder {
	h.t.Helper()
	begin := h.do(staffReq{method: "POST", path: "/staff/auth/webauthn/register/begin", body: map[string]string{"enrolment_code": code}})
	if begin.Code != http.StatusOK {
		h.t.Fatalf("register/begin = %d %s", begin.Code, begin.Body)
	}
	var opts creationOptsBody
	if err := json.Unmarshal(begin.Body.Bytes(), &opts); err != nil {
		h.t.Fatal(err)
	}
	if opts.PublicKey.RP.ID != staffTestRPID || opts.PublicKey.AuthenticatorSelection.UserVerification != "required" ||
		opts.PublicKey.AuthenticatorSelection.ResidentKey != "required" || opts.PublicKey.Attestation != "none" {
		h.t.Fatalf("creation options = %+v", opts.PublicKey)
	}
	handle, err := base64.RawURLEncoding.DecodeString(opts.PublicKey.User.ID)
	if err != nil {
		h.t.Fatal(err)
	}
	cred, err := a.Register(passkeytest.Ceremony{Challenge: opts.PublicKey.Challenge, Origin: staffTestOrigin, RPID: opts.PublicKey.RP.ID}, handle)
	if err != nil {
		h.t.Fatal(err)
	}
	return h.do(staffReq{
		method: "POST", path: "/staff/auth/webauthn/register/finish",
		cookies: []*http.Cookie{cookieNamed(begin, staffCeremonyCookieSecure)},
		body:    map[string]any{"credential": json.RawMessage(cred), "label": "key"},
	})
}

// assertPasskey runs assert/begin and assert/finish with a, tampered by mod.
func (h *staffHarness) assertPasskey(a *passkeytest.Authenticator, mod func(*passkeytest.Ceremony)) *httptest.ResponseRecorder {
	h.t.Helper()
	begin := h.do(staffReq{method: "POST", path: "/staff/auth/webauthn/assert/begin"})
	if begin.Code != http.StatusOK {
		h.t.Fatalf("assert/begin = %d %s", begin.Code, begin.Body)
	}
	var opts requestOptsBody
	if err := json.Unmarshal(begin.Body.Bytes(), &opts); err != nil {
		h.t.Fatal(err)
	}
	if opts.PublicKey.UserVerification != "required" || len(opts.PublicKey.AllowCredentials) != 0 {
		h.t.Fatalf("request options = %+v", opts.PublicKey)
	}
	c := passkeytest.Ceremony{Challenge: opts.PublicKey.Challenge, Origin: staffTestOrigin, RPID: opts.PublicKey.RPID}
	if mod != nil {
		mod(&c)
	}
	cred, err := a.Assert(c)
	if err != nil {
		h.t.Fatal(err)
	}
	return h.do(staffReq{
		method: "POST", path: "/staff/auth/webauthn/assert/finish",
		cookies: []*http.Cookie{cookieNamed(begin, staffCeremonyCookieSecure)},
		body:    map[string]any{"credential": json.RawMessage(cred)},
	})
}

func newPasskey(t *testing.T, seed byte, alg passkeytest.Alg) *passkeytest.Authenticator {
	t.Helper()
	a, err := passkeytest.New(seed, alg)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestStaffPasskeyEndToEnd(t *testing.T) {
	t.Parallel()
	h := newStaffHarness(t, passkey.New(), "")
	exp := h.clock.Now().Add(30 * time.Minute)
	h.mem.addStaff(staffTestAdmin, staffauth.RoleAdmin, "code-primary", exp)
	h.mem.addCode(staffTestAdmin, "code-backup", exp)

	primary := newPasskey(t, 1, passkeytest.ES256)
	backup := newPasskey(t, 2, passkeytest.EdDSA)
	for _, r := range []struct {
		code string
		a    *passkeytest.Authenticator
	}{{"code-primary", primary}, {"code-backup", backup}} {
		if rec := h.registerPasskey(r.code, r.a); rec.Code != http.StatusCreated {
			t.Fatalf("register with %s = %d %s", r.code, rec.Code, rec.Body)
		}
	}
	// A spent code registers nothing more.
	if rec := h.registerPasskeyExpectBegin("code-primary"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("reused code = %d %s", rec.Code, rec.Body)
	}

	// Both passkeys sign the same staff member in.
	for _, a := range []*passkeytest.Authenticator{primary, backup} {
		rec := h.assertPasskey(a, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("assert = %d %s", rec.Code, rec.Body)
		}
		sess := cookieNamed(rec, staffCookieSecure)
		if sess == nil || sess.SameSite != http.SameSiteStrictMode {
			t.Fatalf("staff session cookie = %+v", sess)
		}
		me := h.do(staffReq{method: "GET", path: "/staff/api/me", cookies: []*http.Cookie{sess}})
		if me.Code != http.StatusOK || !strings.Contains(me.Body.String(), staffTestAdmin) {
			t.Fatalf("me = %d %s", me.Code, me.Body)
		}
	}

	// Refusals, each with one answer.
	zero := uint32(0)
	for name, mod := range map[string]func(*passkeytest.Ceremony){
		"replayed counter":                 func(c *passkeytest.Ceremony) { c.Counter = &zero },
		"no user verification":             func(c *passkeytest.Ceremony) { c.NoUserVerification = true },
		"another staff member's handle":    func(c *passkeytest.Ceremony) { c.UserHandle = store.StaffUserHandle(staffTestOps) },
		"no user handle":                   func(c *passkeytest.Ceremony) { c.OmitUserHandle = true },
		"another origin":                   func(c *passkeytest.Ceremony) { c.Origin = "https://acme.example" },
		"parent-domain relying-party hash": func(c *passkeytest.Ceremony) { c.RPID = "example" },
	} {
		rec := h.assertPasskey(primary, mod)
		if rec.Code != http.StatusUnauthorized || errCode(t, rec) != "webauthn_failed" {
			t.Errorf("%s: assert = %d %s, want 401 webauthn_failed", name, rec.Code, rec.Body)
		}
		if cookieNamed(rec, staffCookieSecure) != nil {
			t.Errorf("%s: a session cookie was set", name)
		}
	}
}

// registerPasskeyExpectBegin runs only register/begin, for a code expected
// to be refused there.
func (h *staffHarness) registerPasskeyExpectBegin(code string) *httptest.ResponseRecorder {
	h.t.Helper()
	return h.do(staffReq{method: "POST", path: "/staff/auth/webauthn/register/begin", body: map[string]string{"enrolment_code": code}})
}

// TestStaffRoutesAreLiveWithTheVerifier: with the production verifier wired
// none of the four routes answers not_available.
func TestStaffRoutesAreLiveWithTheVerifier(t *testing.T) {
	t.Parallel()
	h := newStaffHarness(t, passkey.New(), "")
	for _, p := range []string{
		"/staff/auth/webauthn/register/begin", "/staff/auth/webauthn/register/finish",
		"/staff/auth/webauthn/assert/begin", "/staff/auth/webauthn/assert/finish",
	} {
		rec := h.do(staffReq{method: "POST", path: p, body: map[string]string{"enrolment_code": "x"}})
		if errCode(t, rec) == "not_available" {
			t.Errorf("%s answered not_available with the verifier wired", p)
		}
	}
}

// TestCustomerHandlerMountsNoStaffRoute and TestStaffHandlerMountsOnlyStaff
// pin the process split (ruling A3).
func TestCustomerHandlerMountsNoStaffRoute(t *testing.T) {
	t.Parallel()
	h := newStaffHarness(t, passkey.New(), "")
	for _, rt := range staffRoutes {
		method, path := staffRoutePath(rt.pattern)
		req := httptest.NewRequest(method, staffTestOrigin+path, strings.NewReader("{}"))
		rec := httptest.NewRecorder()
		h.cust.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("customer handler %s = %d, want 404", rt.pattern, rec.Code)
		}
	}
}

func TestStaffHandlerMountsOnlyStaff(t *testing.T) {
	t.Parallel()
	h := newStaffHarness(t, passkey.New(), "")
	for _, rt := range []struct{ method, path string }{
		{"POST", "/portal/auth/login"},
		{"GET", "/portal/api/session"},
		{"GET", "/portal/api/overview"},
		{"POST", "/portal/api/consent"},
		{"GET", "/portal/auth/workos/start"},
		{"GET", "/v1/devices"},
		{"POST", "/v1/auth/exchange"},
		{"GET", "/.well-known/openid-configuration"},
		{"GET", "/oauth2/authorize"},
		{"POST", "/portal/webhooks/paddle"},
		{"GET", "/"},
	} {
		req := httptest.NewRequest(rt.method, staffTestOrigin+rt.path, strings.NewReader("{}"))
		rec := httptest.NewRecorder()
		h.staff.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("staff handler %s %s = %d, want 404", rt.method, rt.path, rec.Code)
		}
	}
}

// TestStaffDefaultHostAndRelyingParty: with nothing configured the staff
// console is https://staff.superbased.app, its relying-party id is that host
// (never the parent domain), and /staff is fenced to it.
func TestStaffDefaultHostAndRelyingParty(t *testing.T) {
	t.Parallel()
	empty := ""
	srv := New(Options{RateLimit: &RateLimitConfig{}, RootRedirectURL: &empty, StaffWebAuthn: passkey.New()})
	srv.staff.db = newMemStaffStore()
	if srv.staff.host != DefaultStaffHost || srv.staff.rpID != DefaultStaffHost || srv.staff.origin != DefaultStaffBaseURL || !srv.staff.secure {
		t.Fatalf("staff config = host %q rp %q origin %q secure %v", srv.staff.host, srv.staff.rpID, srv.staff.origin, srv.staff.secure)
	}
	h := srv.StaffHandler()
	for host, want := range map[string]int{
		"staff.superbased.app": http.StatusOK,
		"app.superbased.app":   http.StatusMisdirectedRequest,
		"superbased.app":       http.StatusMisdirectedRequest,
	} {
		req := httptest.NewRequest("POST", "https://"+host+"/staff/auth/webauthn/assert/begin", http.NoBody)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("assert/begin on %s = %d %s, want %d", host, rec.Code, rec.Body, want)
		}
		if want == http.StatusOK {
			var opts requestOptsBody
			if err := json.Unmarshal(rec.Body.Bytes(), &opts); err != nil || opts.PublicKey.RPID != DefaultStaffHost {
				t.Errorf("rpId = %q (%v), want %q", opts.PublicKey.RPID, err, DefaultStaffHost)
			}
		}
	}
}

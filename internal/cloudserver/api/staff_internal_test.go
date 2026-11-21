package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/staffauth"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// staff_internal_test.go drives the staff route group over the in-memory
// staff store (staff_memstore_test.go) and the hand-built authenticator
// (staff_fake_test.go), so the HTTP layer's rules run without Postgres:
// not_available without a verifier, the cookie shape, session fixation,
// CSRF and Origin on mutations, the authorization table, single-use
// ceremonies and codes, the counter rule, and the refusals between the staff
// and customer surfaces at the cookie level. The Postgres half
// (staff_test.go) repeats the refusals with real sessions on both sides.

const (
	staffTestOrigin = "https://app.example"
	staffTestRPID   = "app.example"
	staffTestAdmin  = "11111111-2222-4333-8444-555555555555"
	staffTestOps    = "22222222-3333-4444-8555-666666666666"
	staffTestSupp   = "33333333-4444-4555-8666-777777777777"
)

// staffClock is a settable clock (no sleeping in tests).
type staffClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *staffClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *staffClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// staffHarness serves the two surfaces the way production does: the staff
// handler (StaffHandler, the staff process) and the customer handler
// (Handler, serve), built from one Server so the cookie-level refusals
// between them are exercised with real cookies. do routes /staff to the
// staff handler and everything else to the customer handler.
type staffHarness struct {
	t     *testing.T
	srv   *Server
	staff http.Handler
	cust  http.Handler
	mem   *memStaffStore
	clock *staffClock
}

func newStaffHarness(t *testing.T, verifier staffauth.Verifier, portalHost string) *staffHarness {
	t.Helper()
	clock := &staffClock{now: time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)}
	empty := ""
	srv := New(Options{
		ExternalBaseURL:    staffTestOrigin,
		PortalBaseURL:      staffTestOrigin,
		PortalSecureCookie: true,
		PortalHost:         portalHost,
		RateLimit:          &RateLimitConfig{},
		RootRedirectURL:    &empty,
		Now:                clock.Now,
		StaffWebAuthn:      verifier,
		StaffBaseURL:       staffTestOrigin,
	})
	mem := newMemStaffStore()
	srv.staff.db = mem
	return &staffHarness{t: t, srv: srv, staff: srv.StaffHandler(), cust: srv.Handler(), mem: mem, clock: clock}
}

type staffReq struct {
	method, path string
	body         any
	cookies      []*http.Cookie
	headers      map[string]string
	host         string
}

func (h *staffHarness) do(r staffReq) *httptest.ResponseRecorder {
	h.t.Helper()
	var body io.Reader = http.NoBody
	if r.body != nil {
		b, err := json.Marshal(r.body)
		if err != nil {
			h.t.Fatal(err)
		}
		body = bytes.NewReader(b)
	}
	req := httptest.NewRequest(r.method, "https://app.example"+r.path, body)
	if r.host != "" {
		req.Host = r.host
	}
	for _, c := range r.cookies {
		req.AddCookie(c)
	}
	for k, v := range r.headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	if strings.HasPrefix(r.path, staffPathPrefix+"/") {
		h.staff.ServeHTTP(rec, req)
	} else {
		h.cust.ServeHTTP(rec, req)
	}
	return rec
}

func cookieNamed(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func errCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var e errorBody
	_ = json.Unmarshal(rec.Body.Bytes(), &e)
	return e.Code
}

type creationOptsBody struct {
	PublicKey staffauth.CreationOptions `json:"publicKey"`
}

type requestOptsBody struct {
	PublicKey staffauth.RequestOptions `json:"publicKey"`
}

// register enrols staffID with a fresh code and registers auth's passkey.
func (h *staffHarness) register(staffID string, role staffauth.Role, auth *StaffTestAuthenticator) {
	h.t.Helper()
	code := "code-" + staffID
	h.mem.addStaff(staffID, role, code, h.clock.Now().Add(30*time.Minute))
	begin := h.do(staffReq{method: "POST", path: "/staff/auth/webauthn/register/begin", body: map[string]string{"enrolment_code": code}})
	if begin.Code != http.StatusOK {
		h.t.Fatalf("register/begin = %d %s", begin.Code, begin.Body)
	}
	var opts creationOptsBody
	if err := json.Unmarshal(begin.Body.Bytes(), &opts); err != nil {
		h.t.Fatal(err)
	}
	cer := cookieNamed(begin, staffCeremonyCookieSecure)
	fin := h.do(staffReq{
		method: "POST", path: "/staff/auth/webauthn/register/finish", cookies: []*http.Cookie{cer},
		body: map[string]any{"credential": auth.Register(opts.PublicKey.Challenge, staffTestOrigin), "label": "laptop"},
	})
	if fin.Code != http.StatusCreated {
		h.t.Fatalf("register/finish = %d %s", fin.Code, fin.Body)
	}
}

// signIn asserts with auth and returns the session cookie and CSRF token.
func (h *staffHarness) signIn(staffID string, auth *StaffTestAuthenticator, prior *http.Cookie) (*http.Cookie, string) {
	h.t.Helper()
	rec := h.assert(staffID, auth, prior, 0)
	if rec.Code != http.StatusOK {
		h.t.Fatalf("assert/finish = %d %s", rec.Code, rec.Body)
	}
	var out struct {
		CSRF string `json:"csrf_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.CSRF == "" {
		h.t.Fatalf("assert/finish body %s: %v", rec.Body, err)
	}
	c := cookieNamed(rec, staffCookieSecure)
	if c == nil {
		h.t.Fatal("assert/finish set no staff cookie")
	}
	return c, out.CSRF
}

// assert runs one assertion; counter 0 means the authenticator's next value.
func (h *staffHarness) assert(staffID string, auth *StaffTestAuthenticator, prior *http.Cookie, counter uint32) *httptest.ResponseRecorder {
	h.t.Helper()
	begin := h.do(staffReq{method: "POST", path: "/staff/auth/webauthn/assert/begin"})
	if begin.Code != http.StatusOK {
		h.t.Fatalf("assert/begin = %d %s", begin.Code, begin.Body)
	}
	var opts requestOptsBody
	if err := json.Unmarshal(begin.Body.Bytes(), &opts); err != nil {
		h.t.Fatal(err)
	}
	if opts.PublicKey.RPID != staffTestRPID {
		h.t.Fatalf("rpId = %q, want %q", opts.PublicKey.RPID, staffTestRPID)
	}
	var cred json.RawMessage
	if counter == 0 {
		cred = auth.Assert(opts.PublicKey.Challenge, staffTestOrigin, staffTestRPID, store.StaffUserHandle(staffID))
	} else {
		cred = auth.AssertWithCounter(opts.PublicKey.Challenge, staffTestOrigin, staffTestRPID, store.StaffUserHandle(staffID), counter)
	}
	cookies := []*http.Cookie{cookieNamed(begin, staffCeremonyCookieSecure)}
	if prior != nil {
		cookies = append(cookies, prior)
	}
	return h.do(staffReq{method: "POST", path: "/staff/auth/webauthn/assert/finish", cookies: cookies, body: map[string]any{"credential": cred}})
}

func TestStaffWebAuthnRoutesAnswerNotAvailable(t *testing.T) {
	t.Parallel()
	h := newStaffHarness(t, nil, "")
	for _, p := range []string{
		"/staff/auth/webauthn/register/begin", "/staff/auth/webauthn/register/finish",
		"/staff/auth/webauthn/assert/begin", "/staff/auth/webauthn/assert/finish",
	} {
		rec := h.do(staffReq{method: "POST", path: p, body: map[string]string{"enrolment_code": "x"}})
		if rec.Code != http.StatusNotImplemented || errCode(t, rec) != "not_available" {
			t.Errorf("%s = %d %s, want 501 not_available", p, rec.Code, rec.Body)
		}
		if len(rec.Result().Cookies()) != 0 {
			t.Errorf("%s set a cookie while not available", p)
		}
	}
	if len(h.mem.ceremonies) != 0 {
		t.Errorf("not_available routes created %d ceremonies", len(h.mem.ceremonies))
	}
}

// TestStaffCookieScoping pins the staff and ceremony cookie attributes:
// __Host- name, host-only, Path=/, Secure, HttpOnly, SameSite=Strict.
func TestStaffCookieScoping(t *testing.T) {
	t.Parallel()
	h := newStaffHarness(t, StaffTestVerifier{}, "")
	auth := NewStaffTestAuthenticator(1)
	h.register(staffTestAdmin, staffauth.RoleAdmin, auth)
	begin := h.do(staffReq{method: "POST", path: "/staff/auth/webauthn/assert/begin"})
	cer := cookieNamed(begin, staffCeremonyCookieSecure)
	sess, _ := h.signIn(staffTestAdmin, auth, nil)
	for _, c := range []*http.Cookie{cer, sess} {
		if c == nil {
			t.Fatal("missing cookie")
		}
		if !strings.HasPrefix(c.Name, "__Host-") || c.Domain != "" || c.Path != "/" || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
			t.Errorf("cookie %s: domain=%q path=%q secure=%v httponly=%v samesite=%v", c.Name, c.Domain, c.Path, c.Secure, c.HttpOnly, c.SameSite)
		}
	}
	if sess.Name == portalCookieSecure || staffCookieSecure == portalCookieSecure || staffCookieDev == portalCookieDev {
		t.Fatal("the staff cookie shares a name with the customer cookie")
	}
	if cache := begin.Header().Get("Cache-Control"); cache != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cache)
	}
}

// staffSessionRoutes lists every route of the table that needs a session.
func staffSessionRoutes() []staffRoute {
	var out []staffRoute
	for _, r := range staffRoutes {
		if r.action != "" {
			out = append(out, r)
		}
	}
	return out
}

func staffRoutePath(pattern string) (string, string) {
	method, path, _ := strings.Cut(pattern, " ")
	path = strings.ReplaceAll(path, "{section}", "components")
	path = strings.ReplaceAll(path, "{key}", "codeintel")
	return method, path
}

// TestStaffRoutesRefuseCustomerSession: a customer portal cookie, with its
// CSRF header, authenticates no staff route.
func TestStaffRoutesRefuseCustomerSession(t *testing.T) {
	t.Parallel()
	h := newStaffHarness(t, StaffTestVerifier{}, "")
	customer := &http.Cookie{Name: portalCookieSecure, Value: "a-valid-looking-customer-session"}
	for _, rt := range staffSessionRoutes() {
		method, path := staffRoutePath(rt.pattern)
		rec := h.do(staffReq{
			method: method, path: path, cookies: []*http.Cookie{customer},
			headers: map[string]string{headerCSRF: "customer-csrf"},
			body:    map[string]any{"value": map[string]string{"reach": "off"}, "reason": "r"},
		})
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s with a customer cookie = %d %s, want 401", rt.pattern, rec.Code, rec.Body)
		}
	}
}

// TestCustomerRoutesRefuseStaffSession: a valid staff session, with its CSRF
// header, authenticates no customer or device route.
func TestCustomerRoutesRefuseStaffSession(t *testing.T) {
	t.Parallel()
	h := newStaffHarness(t, StaffTestVerifier{}, "")
	auth := NewStaffTestAuthenticator(2)
	h.register(staffTestAdmin, staffauth.RoleAdmin, auth)
	sess, csrf := h.signIn(staffTestAdmin, auth, nil)
	// The session is valid on the staff surface...
	if rec := h.do(staffReq{method: "GET", path: "/staff/api/me", cookies: []*http.Cookie{sess}}); rec.Code != http.StatusOK {
		t.Fatalf("staff me = %d %s", rec.Code, rec.Body)
	}
	// ...and nothing on the customer or device surface.
	for _, rt := range []struct{ method, path string }{
		{"GET", "/portal/api/session"},
		{"GET", "/portal/api/overview"},
		{"GET", "/portal/api/me/orgs"},
		{"GET", "/portal/api/devices"},
		{"POST", "/portal/api/consent"},
		{"POST", "/portal/auth/logout"},
		{"POST", "/portal/api/billing/checkout"},
		{"POST", "/portal/api/deletion-requests"},
		// The device routes (/v1) audit through the real store, so they are
		// in the Postgres half (staff_test.go).
	} {
		rec := h.do(staffReq{
			method: rt.method, path: rt.path, cookies: []*http.Cookie{sess},
			headers: map[string]string{headerStaffCSRF: csrf, headerCSRF: csrf},
			body:    map[string]any{},
		})
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s with a staff session = %d %s, want 401", rt.method, rt.path, rec.Code, rec.Body)
		}
	}
}

func TestStaffMutationCSRFAndOrigin(t *testing.T) {
	t.Parallel()
	h := newStaffHarness(t, StaffTestVerifier{}, "")
	auth := NewStaffTestAuthenticator(3)
	h.register(staffTestOps, staffauth.RoleOps, auth)
	sess, csrf := h.signIn(staffTestOps, auth, nil)
	body := map[string]any{"value": map[string]string{"reach": "off"}, "reason": "incident 7"}
	cases := []struct {
		name    string
		headers map[string]string
		want    int
		code    string
	}{
		{"no CSRF header", nil, http.StatusForbidden, "csrf_failed"},
		{"wrong CSRF token", map[string]string{headerStaffCSRF: "nope"}, http.StatusForbidden, "csrf_failed"},
		{"token under the customer header", map[string]string{headerCSRF: csrf}, http.StatusForbidden, "csrf_failed"},
		{"foreign Origin", map[string]string{headerStaffCSRF: csrf, "Origin": "https://evil.example"}, http.StatusForbidden, "origin_mismatch"},
		{"valid", map[string]string{headerStaffCSRF: csrf, "Origin": staffTestOrigin}, http.StatusOK, ""},
	}
	for _, c := range cases {
		rec := h.do(staffReq{method: "PUT", path: "/staff/api/availability/components/codeintel", cookies: []*http.Cookie{sess}, headers: c.headers, body: body})
		if rec.Code != c.want || (c.code != "" && errCode(t, rec) != c.code) {
			t.Errorf("%s: %d %s, want %d %s", c.name, rec.Code, rec.Body, c.want, c.code)
		}
	}
	if n := len(h.mem.inputs); n != 1 {
		t.Fatalf("inputs written = %d, want 1 (only the valid request)", n)
	}
	// A GET needs no CSRF.
	if rec := h.do(staffReq{method: "GET", path: "/staff/api/availability", cookies: []*http.Cookie{sess}}); rec.Code != http.StatusOK {
		t.Fatalf("GET availability = %d", rec.Code)
	}
	// A reason is required.
	rec := h.do(staffReq{
		method: "PUT", path: "/staff/api/availability/components/codeintel", cookies: []*http.Cookie{sess},
		headers: map[string]string{headerStaffCSRF: csrf}, body: map[string]any{"value": map[string]string{}, "reason": "  "},
	})
	if rec.Code != http.StatusBadRequest || errCode(t, rec) != "reason_required" {
		t.Fatalf("blank reason = %d %s", rec.Code, rec.Body)
	}
}

// TestStaffSessionFixation: a cookie value the browser held before the
// assertion (planted or a prior session) is never promoted; the assertion
// mints a new value and revokes the old.
func TestStaffSessionFixation(t *testing.T) {
	t.Parallel()
	h := newStaffHarness(t, StaffTestVerifier{}, "")
	auth := NewStaffTestAuthenticator(4)
	h.register(staffTestAdmin, staffauth.RoleAdmin, auth)

	planted := &http.Cookie{Name: staffCookieSecure, Value: "attacker-chosen-value"}
	first, _ := h.signIn(staffTestAdmin, auth, planted)
	if first.Value == planted.Value {
		t.Fatal("the planted cookie value was adopted as the session")
	}
	if rec := h.do(staffReq{method: "GET", path: "/staff/api/me", cookies: []*http.Cookie{planted}}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("planted value = %d, want 401", rec.Code)
	}
	second, _ := h.signIn(staffTestAdmin, auth, first)
	if second.Value == first.Value {
		t.Fatal("re-assertion reused the session value")
	}
	if rec := h.do(staffReq{method: "GET", path: "/staff/api/me", cookies: []*http.Cookie{first}}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("prior session after re-assertion = %d, want 401 (revoked)", rec.Code)
	}
	if rec := h.do(staffReq{method: "GET", path: "/staff/api/me", cookies: []*http.Cookie{second}}); rec.Code != http.StatusOK {
		t.Fatalf("new session = %d, want 200", rec.Code)
	}
}

func TestStaffAuthorizationTableOnRoutes(t *testing.T) {
	t.Parallel()
	h := newStaffHarness(t, StaffTestVerifier{}, "")
	supportAuth, opsAuth := NewStaffTestAuthenticator(5), NewStaffTestAuthenticator(6)
	h.register(staffTestSupp, staffauth.RoleSupport, supportAuth)
	h.register(staffTestOps, staffauth.RoleOps, opsAuth)
	body := map[string]any{"value": map[string]string{"ingest": "pause"}, "reason": "incident 9"}
	put := func(c *http.Cookie, csrf string) *httptest.ResponseRecorder {
		return h.do(staffReq{method: "PUT", path: "/staff/api/availability/org_controls/org-1", cookies: []*http.Cookie{c}, headers: map[string]string{headerStaffCSRF: csrf}, body: body})
	}

	supp, suppCSRF := h.signIn(staffTestSupp, supportAuth, nil)
	if rec := put(supp, suppCSRF); rec.Code != http.StatusForbidden || errCode(t, rec) != staffauth.CodeForbiddenRole {
		t.Fatalf("support write = %d %s, want 403 forbidden_role", rec.Code, rec.Body)
	}
	ops, opsCSRF := h.signIn(staffTestOps, opsAuth, nil)
	h.clock.Advance(staffauth.FreshAssertionWindow + time.Second)
	if rec := put(ops, opsCSRF); rec.Code != http.StatusForbidden || errCode(t, rec) != staffauth.CodeReauthRequired {
		t.Fatalf("stale ops write = %d %s, want 403 reauth_required", rec.Code, rec.Body)
	}
	ops, opsCSRF = h.signIn(staffTestOps, opsAuth, ops)
	if rec := put(ops, opsCSRF); rec.Code != http.StatusOK {
		t.Fatalf("fresh ops write = %d %s", rec.Code, rec.Body)
	}
	refused := 0
	for _, a := range h.mem.actions {
		if a.Verb == string(staffauth.VerbActionRefused) && a.Result == "refused" {
			refused++
		}
	}
	if refused != 2 {
		t.Fatalf("refusals logged = %d, want 2", refused)
	}
}

func TestStaffEnrolmentCodeIsSingleUseOverHTTP(t *testing.T) {
	t.Parallel()
	h := newStaffHarness(t, StaffTestVerifier{}, "")
	code := "code-single"
	h.mem.addStaff(staffTestAdmin, staffauth.RoleAdmin, code, h.clock.Now().Add(30*time.Minute))
	begin := func() (*http.Cookie, string) {
		rec := h.do(staffReq{method: "POST", path: "/staff/auth/webauthn/register/begin", body: map[string]string{"enrolment_code": code}})
		if rec.Code != http.StatusOK {
			return nil, ""
		}
		var opts creationOptsBody
		_ = json.Unmarshal(rec.Body.Bytes(), &opts)
		return cookieNamed(rec, staffCeremonyCookieSecure), opts.PublicKey.Challenge
	}
	finish := func(c *http.Cookie, challenge string, auth *StaffTestAuthenticator) *httptest.ResponseRecorder {
		return h.do(staffReq{method: "POST", path: "/staff/auth/webauthn/register/finish", cookies: []*http.Cookie{c}, body: map[string]any{"credential": auth.Register(challenge, staffTestOrigin)}})
	}
	// Two ceremonies started from one code: the first finish spends it.
	c1, ch1 := begin()
	c2, ch2 := begin()
	if c1 == nil || c2 == nil {
		t.Fatal("begin refused a fresh code")
	}
	if rec := finish(c1, ch1, NewStaffTestAuthenticator(7)); rec.Code != http.StatusCreated {
		t.Fatalf("first finish = %d %s", rec.Code, rec.Body)
	}
	if rec := finish(c2, ch2, NewStaffTestAuthenticator(8)); rec.Code != http.StatusUnauthorized || errCode(t, rec) != "enrolment_invalid" {
		t.Fatalf("second finish = %d %s, want 401 enrolment_invalid", rec.Code, rec.Body)
	}
	if c, _ := begin(); c != nil {
		t.Fatal("a spent code started a new ceremony")
	}
	// An expired code is refused too.
	h.mem.addStaff(staffTestOps, staffauth.RoleOps, "code-expired", h.clock.Now().Add(time.Minute))
	h.clock.Advance(2 * time.Minute)
	rec := h.do(staffReq{method: "POST", path: "/staff/auth/webauthn/register/begin", body: map[string]string{"enrolment_code": "code-expired"}})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expired code = %d, want 401", rec.Code)
	}
}

func TestStaffAssertionRefusals(t *testing.T) {
	t.Parallel()
	h := newStaffHarness(t, StaffTestVerifier{}, "")
	auth := NewStaffTestAuthenticator(9)
	h.register(staffTestAdmin, staffauth.RoleAdmin, auth)
	h.signIn(staffTestAdmin, auth, nil) // counter now 1

	// The counter must move forward.
	if rec := h.assert(staffTestAdmin, auth, nil, 1); rec.Code != http.StatusUnauthorized || errCode(t, rec) != "webauthn_failed" {
		t.Fatalf("repeated counter = %d %s, want 401", rec.Code, rec.Body)
	}
	// An unregistered passkey gets the same answer.
	if rec := h.assert(staffTestAdmin, NewStaffTestAuthenticator(10), nil, 0); rec.Code != http.StatusUnauthorized || errCode(t, rec) != "webauthn_failed" {
		t.Fatalf("unknown passkey = %d %s, want 401", rec.Code, rec.Body)
	}
	// A ceremony answers once.
	begin := h.do(staffReq{method: "POST", path: "/staff/auth/webauthn/assert/begin"})
	var opts requestOptsBody
	_ = json.Unmarshal(begin.Body.Bytes(), &opts)
	cer := cookieNamed(begin, staffCeremonyCookieSecure)
	cred := auth.Assert(opts.PublicKey.Challenge, staffTestOrigin, staffTestRPID, store.StaffUserHandle(staffTestAdmin))
	first := h.do(staffReq{method: "POST", path: "/staff/auth/webauthn/assert/finish", cookies: []*http.Cookie{cer}, body: map[string]any{"credential": cred}})
	if first.Code != http.StatusOK {
		t.Fatalf("first finish = %d %s", first.Code, first.Body)
	}
	replay := h.do(staffReq{method: "POST", path: "/staff/auth/webauthn/assert/finish", cookies: []*http.Cookie{cer}, body: map[string]any{"credential": cred}})
	if replay.Code != http.StatusBadRequest || errCode(t, replay) != "ceremony_invalid" {
		t.Fatalf("replayed ceremony = %d %s, want 400 ceremony_invalid", replay.Code, replay.Body)
	}
	// No ceremony cookie at all.
	if rec := h.do(staffReq{method: "POST", path: "/staff/auth/webauthn/assert/finish", body: map[string]any{"credential": cred}}); rec.Code != http.StatusBadRequest || errCode(t, rec) != "ceremony_missing" {
		t.Fatalf("no ceremony = %d %s", rec.Code, rec.Body)
	}
	// An assertion for another origin does not verify.
	begin = h.do(staffReq{method: "POST", path: "/staff/auth/webauthn/assert/begin"})
	_ = json.Unmarshal(begin.Body.Bytes(), &opts)
	wrong := auth.Assert(opts.PublicKey.Challenge, "https://evil.example", staffTestRPID, store.StaffUserHandle(staffTestAdmin))
	if rec := h.do(staffReq{method: "POST", path: "/staff/auth/webauthn/assert/finish", cookies: []*http.Cookie{cookieNamed(begin, staffCeremonyCookieSecure)}, body: map[string]any{"credential": wrong}}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("foreign origin assertion = %d %s", rec.Code, rec.Body)
	}
}

func TestStaffSignOut(t *testing.T) {
	t.Parallel()
	h := newStaffHarness(t, StaffTestVerifier{}, "")
	auth := NewStaffTestAuthenticator(11)
	h.register(staffTestAdmin, staffauth.RoleAdmin, auth)
	sess, csrf := h.signIn(staffTestAdmin, auth, nil)
	if rec := h.do(staffReq{method: "POST", path: "/staff/auth/logout", cookies: []*http.Cookie{sess}}); rec.Code != http.StatusForbidden {
		t.Fatalf("logout without CSRF = %d, want 403", rec.Code)
	}
	rec := h.do(staffReq{method: "POST", path: "/staff/auth/logout", cookies: []*http.Cookie{sess}, headers: map[string]string{headerStaffCSRF: csrf}})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("logout = %d %s", rec.Code, rec.Body)
	}
	if c := cookieNamed(rec, staffCookieSecure); c == nil || c.MaxAge >= 0 {
		t.Fatal("logout did not delete the staff cookie")
	}
	if rec := h.do(staffReq{method: "GET", path: "/staff/api/me", cookies: []*http.Cookie{sess}}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("after logout = %d, want 401", rec.Code)
	}
}

func TestStaffRoutesHonourTheCanonicalHost(t *testing.T) {
	t.Parallel()
	h := newStaffHarness(t, StaffTestVerifier{}, "app.example")
	if rec := h.do(staffReq{method: "POST", path: "/staff/auth/webauthn/assert/begin", host: "other.example"}); rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("staff route on another host = %d, want 421", rec.Code)
	}
	if rec := h.do(staffReq{method: "POST", path: "/staff/auth/webauthn/assert/begin", host: "app.example"}); rec.Code != http.StatusOK {
		t.Fatalf("staff route on its host = %d, want 200", rec.Code)
	}
}

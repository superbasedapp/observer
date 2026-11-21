package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/api"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudtestpg"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/identity"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/staffauth"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// staff_test.go is the Postgres half of the staff console's proof (M6.8):
// real customer and staff sessions on one server, each refused by every
// route of the other surface, including with the cookie VALUES swapped
// between the two cookie names; and the operator-enrolled bootstrap through
// registration, assertion and a logged availability change. Needs Postgres
// (cloudtestpg; SKIPPED loudly without SBCI_TEST_PG_DSN).

const (
	staffPGOrigin = "https://app.example"
	staffPGRPID   = "app.example"
)

// staffPGHarness runs the two processes of ruling A3 against one database:
// the customer serve handler over an sbci_api store, and the staff process's
// handler (StaffHandler) over an sbci_staff store. do sends /staff to the
// staff handler and everything else to the customer handler.
type staffPGHarness struct {
	t      *testing.T
	cust   http.Handler
	staffH http.Handler
	app    *store.Store
}

func newStaffPGHarness(t *testing.T) *staffPGHarness {
	t.Helper()
	return newStaffPGHarnessWith(t, api.StaffTestVerifier{})
}

func newStaffPGHarnessWith(t *testing.T, verifier staffauth.Verifier) *staffPGHarness {
	t.Helper()
	pool := cloudtestpg.NewDB(t)
	app := store.New(pool)
	app.SetDeletionJournal(mustJournal(t))
	apiStore := mustAPIStore(t, pool)
	apiStore.SetDeletionJournal(mustJournal(t))
	staffStore, err := store.NewForRole(pool, store.RoleStaff)
	if err != nil {
		t.Fatal(err)
	}
	empty := ""
	cust := api.New(api.Options{
		Store:              apiStore,
		Verifier:           identity.NewDevAuth(),
		ExternalBaseURL:    staffPGOrigin,
		PortalBaseURL:      staffPGOrigin,
		PortalSecureCookie: true,
		RateLimit:          &api.RateLimitConfig{},
		RootRedirectURL:    &empty,
	}).Handler()
	staff := api.New(api.Options{
		Store:           staffStore,
		RateLimit:       &api.RateLimitConfig{},
		RootRedirectURL: &empty,
		StaffWebAuthn:   verifier,
		StaffBaseURL:    staffPGOrigin,
	}).StaffHandler()
	return &staffPGHarness{t: t, cust: cust, staffH: staff, app: app}
}

func (h *staffPGHarness) do(method, path string, body any, cookies []*http.Cookie, headers map[string]string) *httptest.ResponseRecorder {
	h.t.Helper()
	var rd io.Reader = http.NoBody
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			h.t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, staffPGOrigin+path, rd)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	if strings.HasPrefix(path, "/staff/") {
		h.staffH.ServeHTTP(rec, req)
	} else {
		h.cust.ServeHTTP(rec, req)
	}
	return rec
}

func recCookie(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// customer signs a customer in through the dev-auth portal login.
func (h *staffPGHarness) customer(subject string) (*http.Cookie, string) {
	h.t.Helper()
	rec := h.do("POST", "/portal/auth/login", map[string]string{"broker_token": "dev:" + subject}, nil, nil)
	if rec.Code != http.StatusOK {
		h.t.Fatalf("portal login = %d %s", rec.Code, rec.Body)
	}
	var lr struct {
		CSRF string `json:"csrf_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &lr); err != nil {
		h.t.Fatal(err)
	}
	c := recCookie(rec, "__Host-sbci")
	if c == nil {
		h.t.Fatal("portal login set no __Host-sbci cookie")
	}
	return c, lr.CSRF
}

// staff enrols a staff member through the operator path, registers auth's
// passkey with the one-time code over HTTP, and signs in.
func (h *staffPGHarness) staff(role staffauth.Role, auth *api.StaffTestAuthenticator) (string, string, *http.Cookie, string) {
	h.t.Helper()
	e, err := h.app.EnrolStaff(context.Background(), store.EnrolStaffInput{DisplayName: "Ops", Role: role, Reason: "bootstrap", Now: time.Now()})
	if err != nil {
		h.t.Fatalf("EnrolStaff: %v", err)
	}
	begin := h.do("POST", "/staff/auth/webauthn/register/begin", map[string]string{"enrolment_code": e.RawCode}, nil, nil)
	if begin.Code != http.StatusOK {
		h.t.Fatalf("register/begin = %d %s", begin.Code, begin.Body)
	}
	var co struct {
		PublicKey staffauth.CreationOptions `json:"publicKey"`
	}
	if err := json.Unmarshal(begin.Body.Bytes(), &co); err != nil {
		h.t.Fatal(err)
	}
	fin := h.do("POST", "/staff/auth/webauthn/register/finish",
		map[string]any{"credential": auth.Register(co.PublicKey.Challenge, staffPGOrigin)},
		[]*http.Cookie{recCookie(begin, "__Host-sbci-staff-ceremony")}, nil)
	if fin.Code != http.StatusCreated {
		h.t.Fatalf("register/finish = %d %s", fin.Code, fin.Body)
	}
	sess, csrf := h.signIn(e.Staff.StaffID, auth)
	return e.Staff.StaffID, e.RawCode, sess, csrf
}

func (h *staffPGHarness) signIn(staffID string, auth *api.StaffTestAuthenticator) (*http.Cookie, string) {
	h.t.Helper()
	begin := h.do("POST", "/staff/auth/webauthn/assert/begin", nil, nil, nil)
	var ro struct {
		PublicKey staffauth.RequestOptions `json:"publicKey"`
	}
	if err := json.Unmarshal(begin.Body.Bytes(), &ro); err != nil {
		h.t.Fatal(err)
	}
	fin := h.do("POST", "/staff/auth/webauthn/assert/finish",
		map[string]any{"credential": auth.Assert(ro.PublicKey.Challenge, staffPGOrigin, staffPGRPID, store.StaffUserHandle(staffID))},
		[]*http.Cookie{recCookie(begin, "__Host-sbci-staff-ceremony")}, nil)
	if fin.Code != http.StatusOK {
		h.t.Fatalf("assert/finish = %d %s", fin.Code, fin.Body)
	}
	var out struct {
		CSRF string `json:"csrf_token"`
	}
	if err := json.Unmarshal(fin.Body.Bytes(), &out); err != nil {
		h.t.Fatal(err)
	}
	return recCookie(fin, "__Host-sbci-staff"), out.CSRF
}

// staffSessionRoutePaths is every staff route that needs a session.
var staffSessionRoutePaths = []struct{ method, path string }{
	{"POST", "/staff/auth/logout"},
	{"GET", "/staff/api/me"},
	{"GET", "/staff/api/log"},
	{"GET", "/staff/api/availability"},
	{"PUT", "/staff/api/availability/components/codeintel"},
	{"DELETE", "/staff/api/availability/components/codeintel"},
	{"GET", "/staff/api/team-allowlist"},
	{"POST", "/staff/api/team-allowlist"},
	{"DELETE", "/staff/api/team-allowlist/00000000-0000-0000-0000-000000000000"},
}

// customerRoutePaths samples the customer portal and device surfaces.
var customerRoutePaths = []struct{ method, path string }{
	{"GET", "/portal/api/session"},
	{"GET", "/portal/api/overview"},
	{"GET", "/portal/api/devices"},
	{"GET", "/portal/api/me/orgs"},
	{"GET", "/portal/api/billing"},
	{"POST", "/portal/api/consent"},
	{"POST", "/portal/api/billing/checkout"},
	{"POST", "/portal/api/deletion-requests"},
	{"POST", "/portal/auth/logout"},
	{"GET", "/v1/devices"},
	{"GET", "/v1/usage"},
	{"POST", "/v1/logout"},
}

func TestStaffAndCustomerSurfacesRefuseEachOther(t *testing.T) {
	t.Parallel()
	h := newStaffPGHarness(t)
	cust, custCSRF := h.customer("staff-refusal-customer")
	_, _, staff, staffCSRF := h.staff(staffauth.RoleAdmin, api.NewStaffTestAuthenticator(31))

	// Each credential works on its own surface.
	if rec := h.do("GET", "/portal/api/session", nil, []*http.Cookie{cust}, nil); rec.Code != http.StatusOK {
		t.Fatalf("customer on its own surface = %d %s", rec.Code, rec.Body)
	}
	if rec := h.do("GET", "/staff/api/me", nil, []*http.Cookie{staff}, nil); rec.Code != http.StatusOK {
		t.Fatalf("staff on its own surface = %d %s", rec.Code, rec.Body)
	}

	body := map[string]any{"value": map[string]string{"reach": "off"}, "reason": "probe"}
	both := map[string]string{"X-SBCI-CSRF": custCSRF, "X-SBCI-Staff-CSRF": custCSRF}
	custAsStaff := &http.Cookie{Name: "__Host-sbci-staff", Value: cust.Value}
	for _, rt := range staffSessionRoutePaths {
		for name, c := range map[string]*http.Cookie{"customer cookie": cust, "customer value under the staff name": custAsStaff} {
			if rec := h.do(rt.method, rt.path, body, []*http.Cookie{c}, both); rec.Code != http.StatusUnauthorized {
				t.Errorf("%s %s with a %s = %d %s, want 401", rt.method, rt.path, name, rec.Code, rec.Body)
			}
		}
	}

	staffHeaders := map[string]string{"X-SBCI-CSRF": staffCSRF, "X-SBCI-Staff-CSRF": staffCSRF}
	staffAsCustomer := &http.Cookie{Name: "__Host-sbci", Value: staff.Value}
	for _, rt := range customerRoutePaths {
		for name, c := range map[string]*http.Cookie{"staff cookie": staff, "staff value under the customer name": staffAsCustomer} {
			rec := h.do(rt.method, rt.path, map[string]any{}, []*http.Cookie{c}, staffHeaders)
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("%s %s with a %s = %d %s, want 401", rt.method, rt.path, name, rec.Code, rec.Body)
			}
		}
	}

	// Neither session was disturbed by the other's probes.
	if rec := h.do("GET", "/staff/api/me", nil, []*http.Cookie{staff}, nil); rec.Code != http.StatusOK {
		t.Fatalf("staff session after probes = %d", rec.Code)
	}
	if rec := h.do("GET", "/portal/api/session", nil, []*http.Cookie{cust}, nil); rec.Code != http.StatusOK {
		t.Fatalf("customer session after probes = %d", rec.Code)
	}
}

func TestStaffBootstrapAndAvailabilityWithPostgres(t *testing.T) {
	t.Parallel()
	h := newStaffPGHarness(t)
	auth := api.NewStaffTestAuthenticator(32)
	staffID, code, sess, csrf := h.staff(staffauth.RoleOps, auth)

	// The bootstrap code is spent.
	if rec := h.do("POST", "/staff/auth/webauthn/register/begin", map[string]string{"enrolment_code": code}, nil, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("reused enrolment code = %d %s, want 401", rec.Code, rec.Body)
	}

	put := h.do("PUT", "/staff/api/availability/org_controls/org-42",
		map[string]any{"value": map[string]string{"ingest": "pause"}, "reason": "incident 42"},
		[]*http.Cookie{sess}, map[string]string{"X-SBCI-Staff-CSRF": csrf})
	if put.Code != http.StatusOK {
		t.Fatalf("PUT availability = %d %s", put.Code, put.Body)
	}
	list := h.do("GET", "/staff/api/availability", nil, []*http.Cookie{sess}, nil)
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), `"ingest":"pause"`) || !strings.Contains(list.Body.String(), staffauth.Actor(staffID)) {
		t.Fatalf("GET availability = %d %s", list.Code, list.Body)
	}
	log := h.do("GET", "/staff/api/log?limit=50", nil, []*http.Cookie{sess}, nil)
	for _, verb := range []string{"staff.created", "enrolment.minted", "credential.registered", "session.started", "availability.set"} {
		if !strings.Contains(log.Body.String(), `"verb":"`+verb+`"`) {
			t.Errorf("log lacks %s: %s", verb, log.Body)
		}
	}
	// A planted value never becomes a session; a second sign-in mints its own
	// value, and signing one session out leaves the other.
	planted := &http.Cookie{Name: "__Host-sbci-staff", Value: "planted"}
	if rec := h.do("GET", "/staff/api/me", nil, []*http.Cookie{planted}, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("planted cookie = %d", rec.Code)
	}
	again, _ := h.signIn(staffID, auth)
	if again.Value == sess.Value {
		t.Fatal("re-assertion reused the session value")
	}
	out := h.do("POST", "/staff/auth/logout", nil, []*http.Cookie{sess}, map[string]string{"X-SBCI-Staff-CSRF": csrf})
	if out.Code != http.StatusNoContent {
		t.Fatalf("logout = %d %s", out.Code, out.Body)
	}
	if rec := h.do("GET", "/staff/api/me", nil, []*http.Cookie{again}, nil); rec.Code != http.StatusOK {
		t.Fatalf("the second session after the first signed out = %d", rec.Code)
	}
}

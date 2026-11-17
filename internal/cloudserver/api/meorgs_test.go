package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	"github.com/marmutapp/superbased-observer/internal/platformcontract"
)

type fakeOrgLister struct{ orgs []store.MyOrg }

func (f fakeOrgLister) ListMyOrgs(context.Context, string) ([]store.MyOrg, error) {
	return f.orgs, nil
}

func myOrg(slug string, st platformcontract.TenantState) store.MyOrg {
	return store.MyOrg{
		Org:         store.Org{OrgID: "id-" + slug, Slug: slug, DisplayName: slug, Kind: "team", Status: st},
		ConsoleRole: "owner",
	}
}

func newMyOrgsServer(orgs ...store.MyOrg) *Server {
	return &Server{
		portalBaseURL: "https://app.example.test",
		tenantDomain:  "example.test",
		orgLister:     fakeOrgLister{orgs: orgs},
	}
}

func getMyOrgs(s *Server, origin string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/portal/api/me/orgs", nil)
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	rec := httptest.NewRecorder()
	s.handlePortalMyOrgs(rec, req)
	return rec
}

func TestMyOrgsCORSTable(t *testing.T) {
	t.Parallel()
	s := newMyOrgsServer(
		myOrg("acme", platformcontract.StateActive),
		myOrg("suspended-co", platformcontract.StateSuspended),
		myOrg("www", platformcontract.StateActive),
		myOrg("demo", platformcontract.StateActive),
	)
	cases := []struct {
		name       string
		origin     string
		wantStatus int
		wantACAO   string
	}{
		{"no origin", "", 200, ""},
		{"portal origin itself", "https://app.example.test", 200, ""},
		{"member tenant", "https://acme.example.test", 200, "https://acme.example.test"},
		{"unknown slug", "https://nope.example.test", 403, ""},
		{"non-member evil subdomain", "https://evil.example.test", 403, ""},
		{"suspended tenant", "https://suspended-co.example.test", 403, ""},
		{"www", "https://www.example.test", 403, ""},
		{"demo", "https://demo.example.test", 403, ""},
		{"pages origin", "https://acme.pages.dev", 403, ""},
		{"http scheme", "http://acme.example.test", 403, ""},
		{"trailing dot", "https://acme.example.test.", 403, ""},
		{"uppercase host", "https://ACME.example.test", 403, ""},
		{"port", "https://acme.example.test:8443", 403, ""},
		{"path", "https://acme.example.test/x", 403, ""},
		{"prefix of tenant", "https://acme.example.test.evil.com", 403, ""},
		{"suffix lookalike", "https://xacme.example.test", 403, ""},
		{"parent domain", "https://example.test", 403, ""},
		{"nested label", "https://a.acme.example.test", 403, ""},
		{"null origin", "null", 403, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec := getMyOrgs(s, tc.origin)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if got := rec.Header().Get("Access-Control-Allow-Origin"); got != tc.wantACAO {
				t.Errorf("ACAO = %q, want %q", got, tc.wantACAO)
			}
			creds := rec.Header().Get("Access-Control-Allow-Credentials")
			if (tc.wantACAO != "") != (creds == "true") {
				t.Errorf("credentials header %q inconsistent with ACAO %q", creds, tc.wantACAO)
			}
			if rec.Header().Get("Vary") != "Origin" {
				t.Errorf("Vary = %q, want Origin", rec.Header().Get("Vary"))
			}
			if rec.Header().Get("Cache-Control") != "no-store" {
				t.Errorf("Cache-Control = %q", rec.Header().Get("Cache-Control"))
			}
		})
	}
}

func TestMyOrgsEmptyTenantDomainFailsClosed(t *testing.T) {
	t.Parallel()
	s := newMyOrgsServer(myOrg("acme", platformcontract.StateActive))
	s.tenantDomain = ""
	if rec := getMyOrgs(s, "https://acme.example.test"); rec.Code != 403 || rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("got %d acao=%q", rec.Code, rec.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestMyOrgsBody(t *testing.T) {
	t.Parallel()
	s := newMyOrgsServer(myOrg("acme", platformcontract.StateActive))
	rec := getMyOrgs(s, "")
	var got []map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0]["slug"] != "acme" || got[0]["console_role"] != "owner" || got[0]["org_id"] != "id-acme" {
		t.Fatalf("body = %v", got)
	}
	if len(got[0]) != 6 {
		t.Errorf("unexpected fields: %v", got[0])
	}
}

func TestMyOrgsPreflight(t *testing.T) {
	t.Parallel()
	s := newMyOrgsServer()
	cases := []struct {
		name, origin, method, headers string
		wantStatus                    int
		wantACAO                      string
	}{
		{"tenant shape GET", "https://acme.example.test", "GET", "", 204, "https://acme.example.test"},
		{"bad origin", "https://evil.com", "GET", "", 403, ""},
		{"reserved label", "https://www.example.test", "GET", "", 403, ""},
		{"POST requested", "https://acme.example.test", "POST", "", 403, ""},
		{"custom header requested", "https://acme.example.test", "GET", "x-sbci-csrf", 403, ""},
		{"no origin", "", "GET", "", 403, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodOptions, "/portal/api/me/orgs", nil)
			req.Header.Set("Origin", tc.origin)
			req.Header.Set("Access-Control-Request-Method", tc.method)
			if tc.headers != "" {
				req.Header.Set("Access-Control-Request-Headers", tc.headers)
			}
			rec := httptest.NewRecorder()
			s.handleMyOrgsPreflight(rec, req)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if got := rec.Header().Get("Access-Control-Allow-Origin"); got != tc.wantACAO {
				t.Errorf("ACAO = %q, want %q", got, tc.wantACAO)
			}
			if tc.wantStatus == 204 && rec.Header().Get("Access-Control-Allow-Methods") != "GET" {
				t.Errorf("methods = %q", rec.Header().Get("Access-Control-Allow-Methods"))
			}
		})
	}
}

// TestMyOrgsRouteIsReadOnlyAndCookieGated pins the route table: no mutating
// verb is routed, and a GET without the session cookie is a 401 with no CORS
// headers. A cross-origin state change elsewhere is stopped by portalAuth's
// CSRF check, which this route does not touch.
func TestMyOrgsRouteIsReadOnlyAndCookieGated(t *testing.T) {
	t.Parallel()
	noRedirect := ""
	h := New(Options{RateLimit: &RateLimitConfig{}, RootRedirectURL: &noRedirect, TenantDomain: "Example.Test"}).Handler()
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		req := httptest.NewRequest(method, "/portal/api/me/orgs", nil)
		req.Header.Set("Origin", "https://acme.example.test")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: status = %d, want 405", method, rec.Code)
		}
		if rec.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("%s: unexpected CORS header", method)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/portal/api/me/orgs", nil)
	req.Header.Set("Origin", "https://acme.example.test")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized || rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("cookieless GET: status = %d acao=%q", rec.Code, rec.Header().Get("Access-Control-Allow-Origin"))
	}
}

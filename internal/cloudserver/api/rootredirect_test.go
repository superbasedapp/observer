package api

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// newRootRedirectServer builds a handler-only Server for the root-redirect
// tests: no Store, matching the nil-Store pattern edge_test.go's
// TestRateLimitBackendErrorBlocksAuthAndJobRoutes already uses for
// mux-shape tests that never touch a handler needing the store. RateLimit is
// the all-zero disabled config so the unauthenticated routes this test
// exercises are never throttled.
func newRootRedirectServer(t *testing.T, rootRedirectURL *string) http.Handler {
	t.Helper()
	return New(Options{
		Logger:          slog.Default(),
		RateLimit:       &RateLimitConfig{},
		RootRedirectURL: rootRedirectURL,
	}).Handler()
}

// strPtr is a small helper so table rows can express "explicitly set to this
// string" (including "") versus "leave nil, resolve from the environment".
func strPtr(s string) *string { return &s }

// TestRootRedirectRoutes is the table-driven core of the "/" behavior: GET
// and HEAD 302 to the configured target with the SAME middleware chain
// (canonical-host fence + security headers) as every other route, POST pins
// whatever net/http's ServeMux does for a path-matched-but-method-mismatched
// pattern (405, per the live check against this exact registration), and an
// unrelated path stays a plain 404.
func TestRootRedirectRoutes(t *testing.T) {
	const target = "https://superbased.app/"
	h := newRootRedirectServer(t, strPtr(target))

	cases := []struct {
		name         string
		method       string
		path         string
		wantStatus   int
		wantLocation string
		wantBody     bool // GET carries an HTML body; HEAD/POST/404 do not
	}{
		{name: "GET / redirects", method: http.MethodGet, path: "/", wantStatus: http.StatusFound, wantLocation: target, wantBody: true},
		{name: "HEAD / redirects with no body", method: http.MethodHead, path: "/", wantStatus: http.StatusFound, wantLocation: target, wantBody: false},
		{name: "POST / is refused", method: http.MethodPost, path: "/", wantStatus: http.StatusMethodNotAllowed},
		{name: "GET /nope stays 404", method: http.MethodGet, path: "/nope", wantStatus: http.StatusNotFound},
		// The checkout-domain review's four conventional pages (2026-09-14
		// provisional approval mail): each redirects to the same path under
		// the root target; trailing-slash and nested variants stay 404, and
		// POST is refused like "/".
		{name: "GET /terms redirects", method: http.MethodGet, path: "/terms", wantStatus: http.StatusFound, wantLocation: target + "terms", wantBody: true},
		{name: "GET /privacy redirects", method: http.MethodGet, path: "/privacy", wantStatus: http.StatusFound, wantLocation: target + "privacy", wantBody: true},
		{name: "GET /refund-policy redirects", method: http.MethodGet, path: "/refund-policy", wantStatus: http.StatusFound, wantLocation: target + "refund-policy", wantBody: true},
		{name: "GET /pricing redirects", method: http.MethodGet, path: "/pricing", wantStatus: http.StatusFound, wantLocation: target + "pricing", wantBody: true},
		{name: "HEAD /terms redirects with no body", method: http.MethodHead, path: "/terms", wantStatus: http.StatusFound, wantLocation: target + "terms", wantBody: false},
		{name: "POST /terms is refused", method: http.MethodPost, path: "/terms", wantStatus: http.StatusMethodNotAllowed},
		{name: "GET /terms/ stays 404", method: http.MethodGet, path: "/terms/", wantStatus: http.StatusNotFound},
		{name: "GET /pricing/x stays 404", method: http.MethodGet, path: "/pricing/x", wantStatus: http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, "http://example.test"+tc.path, nil)
			rw := httptest.NewRecorder()
			h.ServeHTTP(rw, r)
			if rw.Code != tc.wantStatus {
				t.Fatalf("status=%d, want %d (body=%q)", rw.Code, tc.wantStatus, rw.Body.String())
			}
			if tc.wantLocation != "" {
				if got := rw.Header().Get("Location"); got != tc.wantLocation {
					t.Errorf("Location=%q, want %q", got, tc.wantLocation)
				}
			}
			if tc.wantStatus == http.StatusFound {
				hasBody := rw.Body.Len() > 0
				if hasBody != tc.wantBody {
					t.Errorf("body present=%v, want %v (body=%q)", hasBody, tc.wantBody, rw.Body.String())
				}
			}
			// The redirect (and every other response) must sit behind the same
			// middleware chain as /portal/: securityHeaders wraps the whole mux
			// unconditionally, so the fixed header set must be present here too.
			assertSecurityHeaders(t, rw.Header())
		})
	}
}

// TestRootRedirectDisabledByEmptyEnv proves an explicit empty
// Options.RootRedirectURL (the construction-time equivalent of
// SBCI_ROOT_REDIRECT_URL="") disables the route entirely: "/" falls through
// to the mux's ordinary 404, exactly as it did before this route existed.
func TestRootRedirectDisabledByEmptyEnv(t *testing.T) {
	h := newRootRedirectServer(t, strPtr(""))
	// Disabling the one target disables the marketing paths with it.
	for _, path := range append([]string{"/"}, marketingRedirectPaths...) {
		r := httptest.NewRequest(http.MethodGet, "http://example.test"+path, nil)
		rw := httptest.NewRecorder()
		h.ServeHTTP(rw, r)
		if rw.Code != http.StatusNotFound {
			t.Fatalf("%s: status=%d, want 404 (disabled redirect)", path, rw.Code)
		}
		// The security-headers middleware still applies to the 404 — disabling
		// the redirect must not disable anything else in the chain.
		assertSecurityHeaders(t, rw.Header())
	}
}

// TestMarketingRedirectTarget pins the join: the base's trailing slash is
// optional and never doubled, and a base carrying its own path keeps it.
func TestMarketingRedirectTarget(t *testing.T) {
	cases := []struct{ base, path, want string }{
		{"https://superbased.app/", "/terms", "https://superbased.app/terms"},
		{"https://superbased.app", "/privacy", "https://superbased.app/privacy"},
		{"http://localhost:8080/site/", "/pricing", "http://localhost:8080/site/pricing"},
	}
	for _, tc := range cases {
		if got := marketingRedirectTarget(tc.base, tc.path); got != tc.want {
			t.Errorf("marketingRedirectTarget(%q, %q) = %q, want %q", tc.base, tc.path, got, tc.want)
		}
	}
}

// TestRootRedirectDefaultsFromEnv proves the nil-Options fallback: with no
// RootRedirectURL supplied and SBCI_ROOT_REDIRECT_URL unset, "/" redirects to
// defaultRootRedirectURL.
func TestRootRedirectDefaultsFromEnv(t *testing.T) {
	unsetEnvForTest(t, rootRedirectEnvVar)
	h := newRootRedirectServer(t, nil)
	r := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, r)
	if rw.Code != http.StatusFound {
		t.Fatalf("status=%d, want 302", rw.Code)
	}
	if got := rw.Header().Get("Location"); got != defaultRootRedirectURL {
		t.Errorf("Location=%q, want default %q", got, defaultRootRedirectURL)
	}
}

// TestRootRedirectMalformedURLRejectedAtConstruction is a fast, no-database
// unit test of validateRootRedirectURL itself: every malformed shape a
// misconfigured SBCI_ROOT_REDIRECT_URL could take is rejected with an error,
// while "" (disabled) and well-formed absolute http(s) URLs pass through
// unchanged.
func TestRootRedirectMalformedURLRejectedAtConstruction(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		wantErr bool
		want    string
	}{
		{name: "empty disables", raw: "", wantErr: false, want: ""},
		{name: "trims whitespace around empty", raw: "   ", wantErr: false, want: ""},
		{name: "valid https", raw: "https://superbased.app/", wantErr: false, want: "https://superbased.app/"},
		{name: "valid http", raw: "http://localhost:8080/", wantErr: false, want: "http://localhost:8080/"},
		{name: "relative path rejected", raw: "/not-absolute", wantErr: true},
		{name: "scheme-less host rejected", raw: "superbased.app", wantErr: true},
		{name: "unsupported scheme rejected", raw: "ftp://superbased.app/", wantErr: true},
		{name: "no host rejected", raw: "https:///path-only", wantErr: true},
		{name: "control character rejected", raw: "https://superbased.app/\x7f", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := validateRootRedirectURL(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("validateRootRedirectURL(%q) = %q, <nil>; want an error", tc.raw, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateRootRedirectURL(%q) unexpected error: %v", tc.raw, err)
			}
			if got != tc.want {
				t.Errorf("validateRootRedirectURL(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

// TestRootRedirectFailsClosedOnMalformedOption proves the end-to-end
// fail-closed contract: constructing a Server with a malformed
// Options.RootRedirectURL never panics and never serves a broken redirect —
// New disables the route (logging the rejection) and "/" answers 404, the
// same safe posture as an explicitly disabled redirect.
func TestRootRedirectFailsClosedOnMalformedOption(t *testing.T) {
	h := newRootRedirectServer(t, strPtr("not a url \x7f"))
	r := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, r)
	if rw.Code != http.StatusNotFound {
		t.Fatalf("status=%d, want 404 (malformed target fails closed)", rw.Code)
	}
}

// unsetEnvForTest removes an environment variable for the duration of the
// test, restoring whatever value (or absence) preceded it. t.Setenv cannot
// express "absent" (only "set to a value"), and TestRootRedirectDefaultsFromEnv
// specifically needs SBCI_ROOT_REDIRECT_URL to be absent rather than empty, so
// rootRedirectURLFromEnv exercises its os.LookupEnv "unset" branch.
func unsetEnvForTest(t *testing.T, key string) {
	t.Helper()
	if prev, had := os.LookupEnv(key); had {
		t.Cleanup(func() { _ = os.Setenv(key, prev) })
	}
	_ = os.Unsetenv(key)
}

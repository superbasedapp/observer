package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	clouddb "github.com/marmutapp/superbased-observer/internal/cloudserver/db"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudtestpg"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// wantSecurityHeaders is the fixed set every response must carry (gap 3.3).
// HSTS is checked separately (it is conditional on portalSecureCookie).
var wantSecurityHeaders = map[string]string{
	"X-Content-Type-Options": "nosniff",
	"Referrer-Policy":        "strict-origin-when-cross-origin",
	"X-Frame-Options":        "DENY",
	"Permissions-Policy":     `camera=(), microphone=(), geolocation=(), payment=(self "https://*.paddle.com")`,
	"Content-Security-Policy": "default-src 'self'; " +
		"script-src 'self' https://cdn.paddle.com; " +
		"frame-src https://buy.paddle.com https://sandbox-buy.paddle.com; " +
		"connect-src 'self' https://*.paddle.com; " +
		"img-src 'self' data: https://*.paddle.com; " +
		"style-src 'self' 'unsafe-inline'; " +
		"font-src 'self' data:; " +
		"frame-ancestors 'none'; " +
		"base-uri 'self'; " +
		"form-action 'self' https://*.paddle.com; " +
		"object-src 'none'",
}

func assertSecurityHeaders(t *testing.T, h http.Header) {
	t.Helper()
	for name, want := range wantSecurityHeaders {
		got := h.Get(name)
		if got != want {
			t.Errorf("header %s = %q, want %q", name, got, want)
		}
	}
}

// TestSecurityHeadersMiddlewareSetsFixedSet is a fast, no-database unit test
// of securityHeaders itself: every header is present on whatever the wrapped
// handler answers, for both 2xx and error statuses, mirroring
// TestEdgeHealthProbeBypassesEdgeFence's white-box &Server{} style.
func TestSecurityHeadersMiddlewareSetsFixedSet(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusNotFound, http.StatusInternalServerError} {
		s := &Server{log: slog.Default(), portalSecureCookie: true}
		h := s.securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
		}))
		r := httptest.NewRequest(http.MethodGet, "http://example.test/anything", nil)
		rw := httptest.NewRecorder()
		h.ServeHTTP(rw, r)
		if rw.Code != status {
			t.Fatalf("status=%d, want %d", rw.Code, status)
		}
		assertSecurityHeaders(t, rw.Header())
		if got := rw.Header().Get("Strict-Transport-Security"); got != "max-age=63072000; includeSubDomains" {
			t.Errorf("HSTS = %q, want the fixed max-age=63072000; includeSubDomains value", got)
		}
	}
}

// TestSecurityHeadersHSTSAbsentWhenInsecureCookie proves HSTS is gated on
// portalSecureCookie — emitting it over a plain-http local/dev deployment
// would tell a browser to upgrade a host that cannot serve https, breaking it
// outright. Every OTHER header still applies unconditionally.
func TestSecurityHeadersHSTSAbsentWhenInsecureCookie(t *testing.T) {
	s := &Server{log: slog.Default(), portalSecureCookie: false}
	h := s.securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest(http.MethodGet, "http://example.test/anything", nil)
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, r)
	if got := rw.Header().Get("Strict-Transport-Security"); got != "" {
		t.Errorf("HSTS present with portalSecureCookie=false: %q, want absent", got)
	}
	assertSecurityHeaders(t, rw.Header())
}

// TestSecurityHeadersOnCoreRoutes proves securityHeaders wraps the WHOLE mux
// in Handler() (server.go) — not just handlers that happen to call it
// individually — by hitting the four route classes named in gap 3.3:
// /healthz, the portal SPA catch-all, a /portal/api/* route, and a webhook.
// None of these need to SUCCEED (an unconfigured webhook 501s, an
// unauthenticated portal API route 401s) — the point is that every response,
// regardless of status or which handler produced it, carries the same fixed
// header set. /healthz specifically requires a live store (it pings the
// pool), hence the throwaway Postgres; skips gracefully when SBCI_TEST_PG_DSN
// is unset (cloudtestpg.NewDB).
func TestSecurityHeadersOnCoreRoutes(t *testing.T) {
	pool := cloudtestpg.NewDB(t)
	s := store.New(pool)

	spaStub := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html></html>"))
	})

	h := New(Options{
		Store:              s,
		Logger:             slog.Default(),
		RateLimit:          &RateLimitConfig{}, // disabled: this test is not about rate limiting
		PortalSPA:          spaStub,
		PortalSecureCookie: true,
		// PaddleWebhookSecret left empty on purpose — the webhook answers its
		// honest 501 without touching the store, which is exactly the shape
		// this test wants to probe (headers on a non-2xx response too).
	}).Handler()

	cases := []struct {
		name       string
		method     string
		path       string
		wantStatus int
	}{
		{"healthz", http.MethodGet, "/healthz", http.StatusOK},
		{"portal SPA catch-all", http.MethodGet, "/portal/", http.StatusOK},
		{"portal API route, unauthenticated", http.MethodGet, "/portal/api/session", http.StatusUnauthorized},
		{"paddle webhook, unconfigured", http.MethodPost, "/portal/webhooks/paddle", http.StatusNotImplemented},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, "http://example.test"+tc.path, nil)
			rw := httptest.NewRecorder()
			h.ServeHTTP(rw, r)
			if rw.Code != tc.wantStatus {
				t.Fatalf("%s %s: status=%d, want %d", tc.method, tc.path, rw.Code, tc.wantStatus)
			}
			assertSecurityHeaders(t, rw.Header())
			if got := rw.Header().Get("Strict-Transport-Security"); got == "" {
				t.Errorf("%s %s: HSTS absent with portalSecureCookie=true", tc.method, tc.path)
			}
		})
	}
}

// TestHealthzReportsSchemaVersion proves GET /healthz's "schema" object
// (gap owed by the schema-check CLI: db.MaxEmbeddedVersion + clouddb.Version
// against the SAME store pool, so the two can never disagree about "what
// schema does this binary expect") reports embedded==deployed==true against
// a database cloudtestpg.NewDB has just migrated to head, and that the
// db_unreachable 503 path is unaffected. Skips gracefully when
// SBCI_TEST_PG_DSN is unset (cloudtestpg.NewDB).
func TestHealthzReportsSchemaVersion(t *testing.T) {
	pool := cloudtestpg.NewDB(t)
	s := store.New(pool)

	h := New(Options{Store: s, Logger: slog.Default(), RateLimit: &RateLimitConfig{}}).Handler()

	r := httptest.NewRequest(http.MethodGet, "http://example.test/healthz", nil)
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, r)
	if rw.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rw.Code)
	}
	var body struct {
		Status string `json:"status"`
		Schema struct {
			Embedded int  `json:"embedded"`
			Deployed int  `json:"deployed"`
			OK       bool `json:"ok"`
		} `json:"schema"`
	}
	if err := json.Unmarshal(rw.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode healthz body: %v (body: %s)", err, rw.Body.String())
	}
	wantEmbedded, err := clouddb.MaxEmbeddedVersion()
	if err != nil {
		t.Fatalf("MaxEmbeddedVersion: %v", err)
	}
	if body.Schema.Embedded != wantEmbedded {
		t.Fatalf("schema.embedded=%d, want %d", body.Schema.Embedded, wantEmbedded)
	}
	if body.Schema.Deployed != wantEmbedded {
		t.Fatalf("schema.deployed=%d on a freshly-migrated-to-head database, want %d", body.Schema.Deployed, wantEmbedded)
	}
	if !body.Schema.OK {
		t.Fatalf("schema.ok=false on a matching embedded/deployed pair, want true")
	}
}

// TestSecurityHeadersCSPHasNoDuplicateDirectives is a cheap structural check
// on the CSP builder: every directive name in cspDirectives appears exactly
// once in the built string, so a future edit that accidentally duplicates a
// row is caught here rather than shipping a CSP a browser silently
// resolves by picking the first occurrence.
func TestSecurityHeadersCSPHasNoDuplicateDirectives(t *testing.T) {
	seen := map[string]bool{}
	for _, d := range cspDirectives {
		if seen[d.name] {
			t.Fatalf("directive %q appears more than once in cspDirectives", d.name)
		}
		seen[d.name] = true
	}
	built := buildCSP()
	for _, d := range cspDirectives {
		if strings.Count(built, d.name+" ") != 1 {
			t.Fatalf("built CSP does not contain exactly one %q directive: %s", d.name, built)
		}
	}
}

// TestSecurityHeadersCSPFrameSrcTightenedToDocumentedHosts pins the
// 2026-09-12 tightening: frame-src carries exactly the two documented Paddle
// hosted-checkout hosts (production buy.paddle.com, sandbox
// sandbox-buy.paddle.com) and no longer the broader https://*.paddle.com
// hedge, while script-src keeps loading Paddle.js from cdn.paddle.com.
func TestSecurityHeadersCSPFrameSrcTightenedToDocumentedHosts(t *testing.T) {
	var frameSrc, scriptSrc string
	for _, d := range cspDirectives {
		switch d.name {
		case "frame-src":
			frameSrc = d.value
		case "script-src":
			scriptSrc = d.value
		}
	}

	const wantFrameSrc = "https://buy.paddle.com https://sandbox-buy.paddle.com"
	if frameSrc != wantFrameSrc {
		t.Errorf("frame-src = %q, want %q", frameSrc, wantFrameSrc)
	}
	if strings.Contains(frameSrc, "*.paddle.com") {
		t.Errorf("frame-src still contains the *.paddle.com wildcard: %q", frameSrc)
	}
	if !strings.Contains(scriptSrc, "cdn.paddle.com") {
		t.Errorf("script-src no longer contains cdn.paddle.com: %q", scriptSrc)
	}
}

package dashboard

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBrowserGuard(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// loopbackPred is the loopback single-user predicate (the default bind).
	// allowlistPred is a remote-exposed Host allow-list (never "allow any").
	loopbackPred := hostIsLoopback
	allowlistPred := hostAllowlistPredicate([]string{"obs.example:8080", "10.0.0.5:8081"})

	tests := []struct {
		name   string
		pred   func(string) bool
		method string
		host   string
		origin string
		want   int
	}{
		// Loopback bind — DNS-rebind + CSRF posture (unchanged).
		{"loopback GET same host", loopbackPred, http.MethodGet, "127.0.0.1:8081", "", http.StatusOK},
		{"loopback GET localhost", loopbackPred, http.MethodGet, "localhost:8081", "", http.StatusOK},
		{"loopback GET rebound attacker host", loopbackPred, http.MethodGet, "evil.com", "", http.StatusForbidden},
		{"loopback POST no origin (curl)", loopbackPred, http.MethodPost, "127.0.0.1:8081", "", http.StatusOK},
		{"loopback POST same-origin", loopbackPred, http.MethodPost, "127.0.0.1:8081", "http://127.0.0.1:8081", http.StatusOK},
		{"loopback POST cross-origin (CSRF)", loopbackPred, http.MethodPost, "127.0.0.1:8081", "https://evil.com", http.StatusForbidden},
		{"loopback POST null origin", loopbackPred, http.MethodPost, "127.0.0.1:8081", "null", http.StatusForbidden},

		// Remote-exposed bind — the dashboard.go:494 relaxation is GONE: a Host
		// not on the allow-list is rejected even on a non-loopback bind.
		{"remote GET allowed host", allowlistPred, http.MethodGet, "obs.example:8080", "", http.StatusOK},
		{"remote GET unlisted host", allowlistPred, http.MethodGet, "attacker.example", "", http.StatusForbidden},
		{"remote GET rebound loopback", allowlistPred, http.MethodGet, "127.0.0.1:8080", "", http.StatusForbidden},
		{"remote POST same allowed origin", allowlistPred, http.MethodPost, "obs.example:8080", "https://obs.example:8080", http.StatusOK},
		{"remote POST cross-origin", allowlistPred, http.MethodPost, "obs.example:8080", "https://evil.com", http.StatusForbidden},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := browserGuard(next, tc.pred)
			req := httptest.NewRequest(tc.method, "/api/admin/restart", nil)
			req.Host = tc.host
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Errorf("code=%d, want %d", rec.Code, tc.want)
			}
		})
	}

	// A nil predicate rejects everything (defensive).
	h := browserGuard(next, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "127.0.0.1:8080"
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("nil predicate allowed a request: %d", rec.Code)
	}
}

// TestOriginIsOwnRows pins the same-origin rule table (adversarial review
// 2026-09-29, C1): the Origin must match scheme + host + port of the
// daemon's own listener, not just the hostname, so a page on ANY other
// localhost port is cross-origin. One case per rule row, plus the aliases
// and front-end shapes legitimate clients use.
func TestOriginIsOwnRows(t *testing.T) {
	loopback := hostIsLoopback
	allow := hostAllowlistPredicate([]string{"obs.example:8080", "box.tail1.ts.net"})
	cases := []struct {
		name   string
		pred   func(string) bool
		host   string
		tls    bool
		origin string
		fail   string // "" = own origin
	}{
		// Loopback direct listener.
		{"same origin", loopback, "127.0.0.1:8820", false, "http://127.0.0.1:8820", ""},
		{"localhost alias, same port", loopback, "127.0.0.1:8820", false, "http://localhost:8820", ""},
		{"[::1] alias, same port", loopback, "localhost:8820", false, "http://[::1]:8820", ""},
		{"Referer path form", loopback, "localhost:8820", false, "http://localhost:8820/sessions?x=1", ""},
		{"other localhost port (the C1 hole)", loopback, "localhost:8820", false, "http://localhost:5173", "same port"},
		{"other loopback-alias port", loopback, "127.0.0.1:8820", false, "http://localhost:3000", "same port"},
		{"default port origin vs explicit port", loopback, "localhost:8820", false, "http://localhost", "same port"},
		{"https origin on the plaintext loopback port 443 vs 8820", loopback, "localhost:8820", false, "https://localhost", "same port"},
		{"127.0.0.2 is not an alias", loopback, "127.0.0.1:8820", false, "http://127.0.0.2:8820", "same host, or a loopback alias of the same listener"},
		{"cross-site", loopback, "127.0.0.1:8820", false, "https://evil.com", "origin host is an allowed Host"},
		{"null", loopback, "127.0.0.1:8820", false, "null", "an opaque (null) origin"},
		{"extension scheme", loopback, "127.0.0.1:8820", false, "vscode-webview://abc123", "an http(s) origin (not null, file:, or an extension scheme)"},
		{"file scheme", loopback, "127.0.0.1:8820", false, "file:///tmp/x.html", "an origin without a host (unparseable, file:)"},
		{"http origin on a TLS listener", loopback, "localhost:8443", true, "http://localhost:8443", "scheme matches the listener"},
		{"https origin on a TLS listener", loopback, "localhost:8443", true, "https://localhost:8443", ""},
		// Remote-exposed (allow-listed Host; TLS may be terminated in front).
		{"remote explicit port", allow, "obs.example:8080", false, "https://obs.example:8080", ""},
		{"remote other port", allow, "obs.example:8080", false, "https://obs.example:9090", "same port"},
		{"tailscale serve: https origin, Host without port", allow, "box.tail1.ts.net", false, "https://box.tail1.ts.net", ""},
		{"tailscale serve: other port on the tailnet host", allow, "box.tail1.ts.net", false, "https://box.tail1.ts.net:8443", "same port"},
		{"remote: allowed but different host", allow, "obs.example:8080", false, "https://box.tail1.ts.net:8080", "same host, or a loopback alias of the same listener"},
		// The Vite dev proxy rewrites its own Origin to the proxy target and
		// changeOrigin sets Host to the target: same origin at the daemon.
		{"vite dev proxy rewrite", loopback, "localhost:8820", false, "http://localhost:8820", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/x", nil)
			req.Host = tc.host
			req.TLS = nil
			if tc.tls {
				req.TLS = &tls.ConnectionState{}
			}
			if got := originFailure(tc.origin, req, tc.pred); got != tc.fail {
				t.Fatalf("originFailure(%q, Host %q) = %q, want %q", tc.origin, tc.host, got, tc.fail)
			}
		})
	}
}

// TestBrowserGuardOriginPortAndClients drives the whole guard: a POST and a
// WebSocket upgrade from another localhost port are refused; the SPA itself,
// a Referer-only same-origin request, and a no-Origin client (curl, the CLI,
// the VS Code extension host's fetch) pass; GETs are not Origin-checked.
func TestBrowserGuardOriginPortAndClients(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := browserGuard(next, hostIsLoopback)
	cases := []struct {
		name    string
		method  string
		ws      bool
		origin  string
		referer string
		want    int
	}{
		{"SPA POST", http.MethodPost, false, "http://127.0.0.1:8820", "", http.StatusOK},
		{"no Origin client (CLI / extension host)", http.MethodPost, false, "", "", http.StatusOK},
		{"Referer-only same origin", http.MethodDelete, false, "", "http://127.0.0.1:8820/terminal", http.StatusOK},
		{"POST from another localhost port", http.MethodPost, false, "http://localhost:5173", "", http.StatusForbidden},
		{"Referer-only from another localhost port", http.MethodPut, false, "", "http://127.0.0.1:3000/", http.StatusForbidden},
		{"WS upgrade from another localhost port", http.MethodGet, true, "http://127.0.0.1:9999", "", http.StatusForbidden},
		{"WS upgrade same origin", http.MethodGet, true, "http://localhost:8820", "", http.StatusOK},
		{"GET from another port is not Origin-checked", http.MethodGet, false, "http://localhost:5173", "", http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/api/admin/restart", nil)
			req.Host = "127.0.0.1:8820"
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if tc.referer != "" {
				req.Header.Set("Referer", tc.referer)
			}
			if tc.ws {
				req.Header.Set("Upgrade", "websocket")
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("code=%d, want %d", rec.Code, tc.want)
			}
		})
	}
}

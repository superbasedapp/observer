// secheaders.go — the security-response-header middleware (gap 3.3). It
// wraps the WHOLE mux in Handler() so every response — /healthz, every
// /portal/* UI/API route, and the two webhooks — carries the same set of
// browser-defensive headers. There is no per-route opt-out: a header that
// only some responses carry is a header a future route can forget.
//
// Sources consulted for the Paddle-specific CSP entries (2026-09-11):
//   - https://developer.paddle.com/paddle-js/about/include-paddlejs — the
//     ONLY documented script host is https://cdn.paddle.com/paddle/v2/paddle.js
//     ("Always load Paddle.js directly from https://cdn.paddle.com/"); no
//     other script host is ever needed.
//   - https://developer.paddle.com/paddle-js/methods/paddle-environment-set —
//     Paddle.Environment.set() accepts exactly "sandbox" | "production" (never
//     "live" — the server's own SBCI_PADDLE_ENV vocabulary is a superset used
//     nowhere in this file).
//   - Paddle's Checkout overlay iframe is served from the widely-documented
//     hosted-checkout domains buy.paddle.com (production) and
//     sandbox-buy.paddle.com (sandbox); frame-src allows exactly these two
//     hosts, kept both regardless of deployment environment (the go-live
//     checklist's planned tightening is now done, see the dated line below).
//   - 2026-09-12: live-observed on staging - overlay iframe host
//     sandbox-buy.paddle.com, script host cdn.paddle.com, no CSP violation;
//     frame-src tightened from the *.paddle.com hedge to the two documented
//     hosts.
//   - 2026-09-17: live-observed in PRODUCTION (cloud.superbased.app) - three
//     blocks caused by our own policy, all from Paddle.js v2 itself rather
//     than anything the portal directly loads: (1) Paddle.js injects its own
//     stylesheet from https://cdn.paddle.com/paddle/v2/assets/css/paddle.css,
//     blocked by style-src; (2) with ProfitWell Retain enabled on the Paddle
//     account, Paddle.js loads https://public.profitwell.com/js/profitwell.js,
//     blocked by script-src; (3) the overlay's "Contact support" affordance
//     navigates the checkout iframe to a Paddle host other than
//     buy.paddle.com/sandbox-buy.paddle.com, which frame-src rejected outright
//     ("This content is blocked"). Fixes: style-src gains cdn.paddle.com;
//     script-src gains public.profitwell.com; connect-src gains
//     *.profitwell.com (ProfitWell's script reports back to its own API —
//     this host is best-effort, not from a Paddle doc, since Retain's network
//     footprint isn't itself documented); and frame-src is widened back to
//     the *.paddle.com hedge, REVERSING the 2026-09-12 tightening above — the
//     overlay itself needs to navigate across Paddle's own subdomains, so
//     enumerating hosts one violation at a time is a losing game. The two
//     explicit hosts are kept alongside the wildcard for documentation value.
package api

import (
	"net/http"
	"strings"
)

// contentSecurityPolicy is built ONCE (not per-request) from a table so a
// future directive addition is a data-table row, not a growing string
// concatenation (CLAUDE.md #5). It must keep the built SPA working: Vite
// emits no inline <script> and no inline <style> (verified against
// webcloud/dist/index.html — fonts and CSS are separate hashed files under
// /portal/assets/), and 'unsafe-inline' on style-src is the one documented
// allowance for framer-motion/recharts, which set inline style ATTRIBUTES
// (not <style> blocks) at runtime.
var cspDirectives = []struct {
	name  string
	value string
}{
	{"default-src", "'self'"},
	{"script-src", "'self' https://cdn.paddle.com https://public.profitwell.com"},
	{"frame-src", "https://buy.paddle.com https://sandbox-buy.paddle.com https://*.paddle.com"},
	{"connect-src", "'self' https://*.paddle.com https://*.profitwell.com"},
	{"img-src", "'self' data: https://*.paddle.com"},
	{"style-src", "'self' 'unsafe-inline' https://cdn.paddle.com"},
	{"font-src", "'self' data:"},
	{"frame-ancestors", "'none'"},
	{"base-uri", "'self'"},
	{"form-action", "'self' https://*.paddle.com"},
	{"object-src", "'none'"},
}

func buildCSP() string {
	parts := make([]string, 0, len(cspDirectives))
	for _, d := range cspDirectives {
		parts = append(parts, d.name+" "+d.value)
	}
	return strings.Join(parts, "; ")
}

// csp is computed once at package init — it never varies per request or per
// deployment (the Paddle hosts are fixed regardless of sandbox/live, and the
// portal serves no other third-party origin).
var csp = buildCSP()

// securityHeaders sets the fixed set of browser-defensive response headers on
// every response the mux serves (JSON API responses included — harmless
// there, and one code path is simpler than an API/UI split). HSTS is
// conditional on portalSecureCookie: emitting Strict-Transport-Security over
// a plain-http local/dev deployment would tell a browser to upgrade a host
// that cannot serve https, breaking it outright.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		if s.portalSecureCookie {
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Permissions-Policy", `camera=(), microphone=(), geolocation=(), payment=(self "https://*.paddle.com")`)
		h.Set("Content-Security-Policy", csp)
		next.ServeHTTP(w, r)
	})
}

// Package api: rootredirect.go answers the bare "/" path — and the four
// policy/pricing paths a checkout-domain reviewer fetches by convention —
// on this server's own origin with a redirect to the marketing site.
//
// Paddle's checkout-domain review fetches the domain root and, live-observed
// 2026-09-13 against cloud.superbased.app, treats a 404 there as "your
// website is offline" and fails the review — even though /portal/,
// /portal/billing, /healthz and /v1/* all already answer correctly. The
// marketing site (superbased.app) carries the pricing/terms/privacy/refund
// pages a checkout-domain reviewer looks for, so sending the bare root there
// fixes the review without touching any other route on this server.
//
// The same review then (2026-09-14, provisional approval of
// cloud.superbased.app) fetched /terms, /privacy, /refund-policy and
// /pricing ON THE CHECKOUT DOMAIN ITSELF and reported every one as
// inaccessible (all four were 404 here; the marketing site serves them at
// the same paths). marketingRedirectPaths is the table of those paths; each
// 302s to the same path under the root-redirect base, so the ONE configured
// target (SBCI_ROOT_REDIRECT_URL) governs all five redirects and disabling
// it disables all of them together.
package api

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// defaultRootRedirectURL is the "/" redirect target used when
// SBCI_ROOT_REDIRECT_URL is unset and Options.RootRedirectURL is nil.
const defaultRootRedirectURL = "https://superbased.app/"

// rootRedirectEnvVar is the environment variable that overrides
// defaultRootRedirectURL. Unset ⇒ the default applies; set to an explicit
// empty string ⇒ the redirect is disabled and "/" stays 404.
const rootRedirectEnvVar = "SBCI_ROOT_REDIRECT_URL"

// rootRedirectURLFromEnv resolves SBCI_ROOT_REDIRECT_URL. It distinguishes
// "unset" (falls back to defaultRootRedirectURL) from "set to empty" (the
// operator's explicit opt-out, returned as "" so the caller disables the
// route) using os.LookupEnv rather than os.Getenv.
func rootRedirectURLFromEnv() string {
	v, ok := os.LookupEnv(rootRedirectEnvVar)
	if !ok {
		return defaultRootRedirectURL
	}
	return strings.TrimSpace(v)
}

// validateRootRedirectURL checks raw is either empty (redirect disabled) or
// an absolute http(s) URL with a host. It exists so a malformed
// SBCI_ROOT_REDIRECT_URL / Options.RootRedirectURL fails loud at
// construction (New logs and disables the route) instead of the server
// silently issuing a broken redirect for every request to "/".
func validateRootRedirectURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%s %q is not a valid URL: %w", rootRedirectEnvVar, raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("%s %q must be an absolute http or https URL", rootRedirectEnvVar, raw)
	}
	if u.Host == "" {
		return "", fmt.Errorf("%s %q has no host", rootRedirectEnvVar, raw)
	}
	return raw, nil
}

// marketingRedirectPaths are the exact paths (no trailing slash, GET/HEAD
// only) that redirect to the same path under the root-redirect base. They
// are the pages a checkout-domain review fetches on the checkout domain by
// convention; the marketing site serves each at the identical path.
var marketingRedirectPaths = []string{
	"/terms",
	"/privacy",
	"/refund-policy",
	"/pricing",
}

// marketingRedirectTarget joins one of marketingRedirectPaths onto base
// (the validated root-redirect URL, with or without its trailing slash).
func marketingRedirectTarget(base, path string) string {
	return strings.TrimSuffix(base, "/") + path
}

// handleMarketingRedirect answers one of marketingRedirectPaths with a 302
// to the same path under s.rootRedirectURL. r.URL.Path is always one of the
// table's exact entries because mountRootRedirect registers each as an
// exact-match pattern, so the target is never derived from arbitrary input.
func (s *Server) handleMarketingRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, marketingRedirectTarget(s.rootRedirectURL, r.URL.Path), http.StatusFound)
}

// handleRoot answers the bare "/" with a 302 redirect to s.rootRedirectURL.
// It is registered only when that target is non-empty (see
// mountRootRedirect), so a disabled redirect never reaches this handler and
// mountRootRedirect never registers a pattern that would call it with an
// empty target.
func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, s.rootRedirectURL, http.StatusFound)
}

// mountRootRedirect registers the exact-match "/" route and the
// marketingRedirectPaths routes on mux when a redirect target is configured. The single "GET /{$}" pattern also serves
// HEAD (net/http's ServeMux matches a HEAD request against a GET pattern
// when no HEAD-specific pattern is registered, and http.Redirect already
// omits the response body for HEAD); every other method on "/" and every
// other path are left alone, so they fall through to the mux's ordinary
// 404/405 handling exactly as before this route existed. Each marketing
// path is registered the same way ("GET /terms" matches exactly "/terms";
// "/terms/" and "/terms/x" stay 404). A disabled target
// (s.rootRedirectURL == "") registers nothing, leaving "/" and the four
// paths at their pre-existing 404.
func (s *Server) mountRootRedirect(mux *http.ServeMux) {
	if s.rootRedirectURL == "" {
		return
	}
	mux.HandleFunc("GET /{$}", s.handleRoot)
	for _, p := range marketingRedirectPaths {
		mux.HandleFunc("GET "+p, s.handleMarketingRedirect)
	}
}

// Package api: rootredirect.go answers the bare "/" path and the four
// policy/pricing paths a checkout-domain reviewer fetches by convention.
//
// THE BARE ROOT goes to the portal (operator ruling "Go to the portal",
// D-830, T-946): "/" answers a same-origin 302 to /portal/ whenever this
// server mounts the portal SPA, so a person who types cloud.superbased.app
// lands on the sign-in page instead of the marketing site. Paddle's
// checkout-domain review (live-observed 2026-09-13) fails a 404 at the root;
// a 302 to a page that answers 200 passes it the same way the old redirect
// to superbased.app did. A server built WITHOUT the portal SPA (tests, an
// API-only replica) keeps the older behaviour: "/" redirects to the
// configured marketing base, or stays 404 when that is disabled.
//
// THE FOUR POLICY PATHS are unchanged. The same review (2026-09-14,
// provisional approval of cloud.superbased.app) fetched /terms, /privacy,
// /refund-policy and /pricing ON THE CHECKOUT DOMAIN ITSELF and reported every
// one as inaccessible while they were 404 here; the marketing site serves them
// at the same paths. marketingRedirectPaths is the table of those paths; each
// 302s to the same path under the root-redirect base (SBCI_ROOT_REDIRECT_URL),
// and disabling that base disables all four together.
package api

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// defaultRootRedirectURL is the marketing base the policy paths redirect
// under (and "/" too on a server without the portal SPA) when
// SBCI_ROOT_REDIRECT_URL is unset and Options.RootRedirectURL is nil.
const defaultRootRedirectURL = "https://superbased.app/"

// rootRedirectEnvVar is the environment variable that overrides
// defaultRootRedirectURL. Unset means the default applies; set to an explicit
// empty string disables the marketing redirects (the policy paths go back to
// 404; "/" still goes to the portal when the SPA is mounted).
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
	http.Redirect(w, r, marketingRedirectTarget(s.rootRedirectURL, r.URL.Path), http.StatusFound) //nolint:gosec // G710: the path is one exact entry of the fixed redirect table
}

// portalRootPath is where "/" sends a visitor when this server mounts the
// portal SPA: a same-origin path, so the redirect never leaves the host the
// request arrived on and the canonical-host fence still applies to it.
const portalRootPath = "/portal/"

// rootTarget is one row of the "/" decision table: the first row whose
// condition holds supplies the redirect target. An empty target means "/" is
// not registered and stays 404.
type rootTarget struct {
	name   string
	when   func(s *Server) bool
	target func(s *Server) string
}

// rootTargets is the ordered "/" decision table, walked top-down by
// rootRedirectTarget.
var rootTargets = []rootTarget{
	{
		name:   "portal mounted",
		when:   func(s *Server) bool { return s.portalSPA != nil },
		target: func(*Server) string { return portalRootPath },
	},
	{
		name:   "marketing base configured",
		when:   func(s *Server) bool { return s.rootRedirectURL != "" },
		target: func(s *Server) string { return s.rootRedirectURL },
	},
}

// rootRedirectTarget resolves where "/" redirects to from rootTargets, or ""
// when no row applies (the route is then not registered at all).
func (s *Server) rootRedirectTarget() string {
	for _, row := range rootTargets {
		if row.when(s) {
			return row.target(s)
		}
	}
	return ""
}

// mountRootRedirect registers the exact-match "/" route (when
// rootRedirectTarget names a target) and the marketingRedirectPaths routes
// (when a marketing base is configured) on mux. The single "GET /{$}" pattern
// also serves HEAD (net/http's ServeMux matches a HEAD request against a GET
// pattern when no HEAD-specific pattern is registered, and http.Redirect
// already omits the response body for HEAD); every other method on "/" and
// every other path are left alone, so they fall through to the mux's ordinary
// 404/405 handling. Each marketing path is registered the same way ("GET
// /terms" matches exactly "/terms"; "/terms/" and "/terms/x" stay 404).
func (s *Server) mountRootRedirect(mux *http.ServeMux) {
	if target := s.rootRedirectTarget(); target != "" {
		mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target, http.StatusFound)
		})
	}
	if s.rootRedirectURL == "" {
		return
	}
	for _, p := range marketingRedirectPaths {
		mux.HandleFunc("GET "+p, s.handleMarketingRedirect)
	}
}

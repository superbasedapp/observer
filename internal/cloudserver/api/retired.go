package api

import (
	"fmt"
	"net/http"
	"strings"
)

// retired.go is the personal-plane retirement switch (managed-SaaS
// individuals workstream D-IND-7; plan 06 9.4, 9.5; plan 07 M9.3;
// docs/security.md IND-3).
//
// SBCI_PERSONAL_PLANE (Options.PersonalPlane) is "serving" (the default) or
// "retired". While serving, nothing here changes a single answer. Once the
// operator turns it to retired (after E3 plus one release), the old personal
// plane's job, result, structural, community, preview-confirmation and usage
// routes, device and portal, answer 410 moved_to_org_plane with upgrade
// guidance; sign-in, devices, logout, consents, deletion, export, the org
// discovery routes and every org, billing, privacy, session and consent
// portal route keep serving. The console reads the mode from the
// personal_plane field of GET /portal/api/session and GET
// /portal/api/auth-config and hides the legacy links.
//
// The decision is ONE table, personalPlaneRoutes, keyed by the exact ServeMux
// pattern a request matches (so /portal/api/sessions/browser, a different
// pattern, is never confused with /portal/api/sessions). A wrapper around the
// mux looks the matched pattern up, so the handlers themselves carry no mode
// branch. retired_test.go has one case per row in both modes, and a
// structural test that every registered /v1 and /portal/api route is a row,
// so a new route must be classified before it can land.

// Personal-plane modes (SBCI_PERSONAL_PLANE).
const (
	PersonalPlaneServing = "serving"
	PersonalPlaneRetired = "retired"
)

// ParsePersonalPlane reads an SBCI_PERSONAL_PLANE value: empty is serving;
// anything but serving or retired is an error (serve refuses to start).
func ParsePersonalPlane(raw string) (string, error) {
	switch v := strings.TrimSpace(raw); v {
	case "", PersonalPlaneServing:
		return PersonalPlaneServing, nil
	case PersonalPlaneRetired:
		return PersonalPlaneRetired, nil
	default:
		return "", fmt.Errorf("cloudserver/api: personal plane mode %q is not %q or %q", v, PersonalPlaneServing, PersonalPlaneRetired)
	}
}

// movedToOrgPlaneCode is the 410's error code.
const movedToOrgPlaneCode = "moved_to_org_plane"

// movedToOrgPlaneMessage is the upgrade guidance a v1.38 node or an old
// console page shows the user (cloudclient prints the whole body).
const movedToOrgPlaneMessage = "This part of superbased Cloud moved to your personal organization. " +
	"Update Observer to 1.39 or later and run \"observer connect\"; " +
	"your results moved to your personal organization."

// movedToOrgPlaneDocs is where the guidance points.
const movedToOrgPlaneDocs = "https://superbased.app/docs/getting-started/install"

// movedToOrgPlaneJSON is the 410 body: the writeErr shape (error, code) plus
// the guidance and a docs link.
type movedToOrgPlaneJSON struct {
	Error   string `json:"error"`
	Code    string `json:"code"`
	Message string `json:"message"`
	Docs    string `json:"docs"`
}

// writeMovedToOrgPlane answers a retired route.
func writeMovedToOrgPlane(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusGone, movedToOrgPlaneJSON{
		Error: movedToOrgPlaneCode, Code: movedToOrgPlaneCode,
		Message: movedToOrgPlaneMessage, Docs: movedToOrgPlaneDocs,
	})
}

// routeFate is what retirement does to a route.
type routeFate int

const (
	// routeKept serves in both modes.
	routeKept routeFate = iota + 1
	// routeRetired answers 410 moved_to_org_plane once retired.
	routeRetired
)

// personalPlaneRoute is one row: a registered ServeMux pattern and its fate.
type personalPlaneRoute struct {
	pattern string
	fate    routeFate
}

// personalPlaneRoutes classifies every /v1 and /portal/api route. Patterns
// are the exact strings the mux registers.
var personalPlaneRoutes = []personalPlaneRoute{
	// --- device: the personal plane (retired) ---
	{"POST /v1/jobs", routeRetired},
	{"GET /v1/jobs/{id}", routeRetired},
	{"POST /v1/intelligence/jobs", routeRetired},
	{"GET /v1/intelligence/jobs/{id}", routeRetired},
	{"POST /v1/structural-insights", routeRetired},
	{"GET /v1/results", routeRetired},
	{"PATCH /v1/results/{id}/correction", routeRetired},
	{"GET /v1/community/percentile", routeRetired},
	{"POST /v1/community/contribution", routeRetired},
	{"POST /v1/consents/preview-confirmation", routeRetired},
	{"GET /v1/usage", routeRetired},

	// --- device: kept ---
	{"GET /v1/auth/nonce", routeKept},
	{"POST /v1/auth/exchange", routeKept},
	{"GET /v1/devices", routeKept},
	{"DELETE /v1/devices/{id}", routeKept},
	{"GET /v1/consents", routeKept},
	{"PUT /v1/consents", routeKept},
	{"POST /v1/logout", routeKept},
	{"POST /v1/deletion-requests", routeKept},
	{"POST /v1/export", routeKept},
	{"GET /v1/exports/{id}", routeKept},
	{"GET /v1/orgs", routeKept},
	{"POST /v1/orgs/personal:ensure", routeKept},
	// Getting started v2: the connect flow (connect.go).
	{"POST /v1/connect/requests", routeKept},
	{"GET /v1/connect/requests/{id}", routeKept},

	// --- portal: the personal plane (retired) ---
	{"GET /portal/api/overview", routeRetired},
	{"GET /portal/api/usage", routeRetired},
	{"GET /portal/api/digests", routeRetired},
	{"GET /portal/api/insights", routeRetired},
	{"GET /portal/api/community", routeRetired},
	{"GET /portal/api/community/metrics", routeRetired},
	{"GET /portal/api/sessions", routeRetired},
	{"GET /portal/api/sessions/{id}", routeRetired},
	{"POST /portal/api/results/{id}/correction", routeRetired},

	// --- portal: kept (sign-in session and factors, devices, browser
	// sessions, consents and grants, orgs, billing, deletion, export) ---
	{"GET /portal/api/auth-config", routeKept},
	{"GET /portal/api/session", routeKept},
	{"GET /portal/api/devices", routeKept},
	{"DELETE /portal/api/devices/{id}", routeKept},
	{"GET /portal/api/sessions/browser", routeKept},
	{"POST /portal/api/sessions/browser/revoke-all", routeKept},
	{"GET /portal/api/consents", routeKept},
	{"GET /portal/api/consent", routeKept},
	{"POST /portal/api/consent", routeKept},
	{"GET /portal/api/grants", routeKept},
	{"GET /portal/api/me/orgs", routeKept},
	{"OPTIONS /portal/api/me/orgs", routeKept},
	{"GET /portal/api/orgs", routeKept},
	{"POST /portal/api/orgs", routeKept},
	{"POST /portal/api/orgs/personal", routeKept},
	{"GET /portal/api/orgs/slug-availability", routeKept},
	{"GET /portal/api/orgs/{id}", routeKept},
	{"PATCH /portal/api/orgs/{id}", routeKept},
	{"GET /portal/api/orgs/{id}/billing", routeKept},
	{"POST /portal/api/orgs/{id}/billing/checkout", routeKept},
	{"GET /portal/api/billing", routeKept},
	{"POST /portal/api/billing/checkout", routeKept},
	{"POST /portal/api/deletion-requests", routeKept},
	{"POST /portal/api/exports", routeKept},
	{"GET /portal/api/exports", routeKept},
	{"GET /portal/api/exports/{id}/download", routeKept},
	// org deletion, its account precheck and the billing self-service portal
	{"GET /portal/api/orgs/{id}/deletion", routeKept},
	{"POST /portal/api/orgs/{id}/deletion", routeKept},
	{"DELETE /portal/api/orgs/{id}/deletion", routeKept},
	{"GET /portal/api/account/deletion-precheck", routeKept},
	{"POST /portal/api/orgs/{id}/billing/portal-session", routeKept},
	{"POST /portal/api/billing/portal-session", routeKept},
	// sign-in factors (passkeys, recovery codes) and the org's sign-in policy
	{"GET /portal/api/mfa", routeKept},
	{"POST /portal/api/mfa/passkeys/register/begin", routeKept},
	{"POST /portal/api/mfa/passkeys/register/finish", routeKept},
	{"DELETE /portal/api/mfa/passkeys/{id}", routeKept},
	{"POST /portal/api/mfa/recovery-codes", routeKept},
	{"POST /portal/api/mfa/assert/begin", routeKept},
	{"POST /portal/api/mfa/assert/finish", routeKept},
	{"POST /portal/api/mfa/recover", routeKept},
	{"POST /portal/api/mfa/devices/approve", routeKept},
	{"GET /portal/api/orgs/{id}/signin-policy", routeKept},
	{"PUT /portal/api/orgs/{id}/signin-policy", routeKept},
	// Getting started v2: the console side of the connect flow (portal_connect.go)
	{"GET /portal/api/connect/requests/{id}", routeKept},
	{"POST /portal/api/connect/lookup", routeKept},
	{"POST /portal/api/connect/requests/{id}/approve", routeKept},
	{"POST /portal/api/connect/requests/{id}/decline", routeKept},
	{"GET /portal/api/connect/machines", routeKept},
}

// retiredPatterns is the set of routeRetired patterns.
var retiredPatterns = func() map[string]bool {
	m := make(map[string]bool)
	for _, r := range personalPlaneRoutes {
		if r.fate == routeRetired {
			m[r.pattern] = true
		}
	}
	return m
}()

// personalPlaneRetired reports whether this server runs retired.
func (s *Server) personalPlaneRetired() bool { return s.personalPlane == PersonalPlaneRetired }

// retirePersonalPlane wraps mux: while retired, a request whose matched
// pattern is a retired row answers 410 before any handler (and so before
// authentication: the guidance is public, and an old node whose token still
// works gets the same answer as one whose token does not). While serving it
// is mux itself.
func (s *Server) retirePersonalPlane(mux *http.ServeMux) http.Handler {
	if !s.personalPlaneRetired() {
		return mux
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, pattern := mux.Handler(r); retiredPatterns[pattern] {
			writeMovedToOrgPlane(w)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

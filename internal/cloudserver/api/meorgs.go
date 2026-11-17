package api

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	"github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// GET /portal/api/me/orgs (M6.6; plan 06 5.4 as amended by the M6.0 design
// A3/A4): the console org chooser that tenant dashboards, running in the
// browser on <slug>.superbased.app, call to learn which orgs the signed-in
// user belongs to.
//
// Decisions, each pinned by meorgs_test.go:
//
//   - Served under /portal/api (cookie BFF, portal canonical host), not /v1
//     (the bearer + proof-of-possession device surface).
//   - The session cookie is SameSite=Lax (operator ruling A7a,
//     portalCookieSameSite in portal.go) and host-only (__Host-): the tenant
//     hosts are same-site with the portal, so a credentialed fetch from them
//     carries it. No Domain attribute; the controls are the exact-origin CORS
//     rule here and portalAuth's CSRF and Origin checks on every mutation.
//   - It is a read-only GET, so it needs no CSRF token; every state-changing
//     portal route already goes through portalAuth, the single owner of the
//     double-submit X-SBCI-CSRF check, and this change adds none.
//   - CORS is an exact-origin allow rule, evaluated per request (see
//     tenantOriginSlug), never a wildcard and never a reflection.

// myOrgLister is the store read this route needs.
type myOrgLister interface {
	ListMyOrgs(ctx context.Context, accountID string) ([]store.MyOrg, error)
}

// tenantSlugPattern matches the host label of a tenant origin: the org slug
// grammar (lowercase letters, digits, hyphen, 3 to 40). Matching is on the raw,
// case-sensitive Origin string, so upper case, ports, trailing dots and paths
// all fail before any lookup.
var tenantSlugPattern = regexp.MustCompile(`^[a-z0-9-]{3,40}$`)

// reservedTenantLabels are host labels that are never a tenant, whatever the
// registry says (plan 06 5.4: never www, demo, or the Pages origin).
func reservedTenantLabel(label string) bool {
	switch label {
	case "www", "demo", "app", "cloud", "api", "admin":
		return true
	}
	return false
}

// tenantOriginSlug returns the slug named by origin when origin has exactly
// the shape https://<slug>.<tenantDomain>, else "". tenantDomain must be
// non-empty and already normalized.
func tenantOriginSlug(origin, tenantDomain string) string {
	if tenantDomain == "" {
		return ""
	}
	rest, ok := strings.CutPrefix(origin, "https://")
	if !ok {
		return ""
	}
	slug, ok := strings.CutSuffix(rest, "."+tenantDomain)
	if !ok || !tenantSlugPattern.MatchString(slug) {
		return ""
	}
	if reservedTenantLabel(slug) {
		return ""
	}
	return slug
}

// myOrgJSON is one row of the response. No billing data.
type myOrgJSON struct {
	OrgID       string `json:"org_id"`
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name"`
	Kind        string `json:"kind"`
	Status      string `json:"status"`
	ConsoleRole string `json:"console_role"`
}

// corsDecision is the outcome of the origin rules.
type corsDecision int

const (
	corsNone    corsDecision = iota // no Origin header: not a CORS request
	corsSame                        // the portal's own origin: allowed, no CORS headers needed
	corsAllowed                     // an exact tenant origin the caller belongs to
	corsDenied                      // any other Origin: refused
)

// decideMyOrgsOrigin walks the origin rules top-down for one request.
func (s *Server) decideMyOrgsOrigin(origin string, orgs []store.MyOrg) corsDecision {
	switch {
	case origin == "":
		return corsNone
	case s.portalBaseURL != "" && origin == s.portalBaseURL:
		return corsSame
	}
	slug := tenantOriginSlug(origin, s.tenantDomain)
	if slug == "" {
		return corsDenied
	}
	for _, o := range orgs {
		if o.Slug == slug && o.Status == platformcontract.StateActive {
			return corsAllowed
		}
	}
	return corsDenied
}

func (s *Server) handlePortalMyOrgs(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Add("Vary", "Origin")
	h.Set("Cache-Control", "no-store")
	p, _ := portalPrincipalFrom(r.Context())
	if s.orgLister == nil {
		writeErr(w, http.StatusServiceUnavailable, "unavailable", "org registry not available")
		return
	}
	orgs, err := s.orgLister.ListMyOrgs(r.Context(), p.AccountID)
	if err != nil {
		if s.log != nil {
			s.log.Error("cloudserver/api: list my orgs", "err", fmt.Errorf("api.handlePortalMyOrgs: %w", err))
		}
		writeErr(w, http.StatusInternalServerError, "internal", "could not list orgs")
		return
	}
	origin := r.Header.Get("Origin")
	switch s.decideMyOrgsOrigin(origin, orgs) {
	case corsDenied:
		writeErr(w, http.StatusForbidden, "origin_not_allowed", "origin not allowed")
		return
	case corsAllowed:
		h.Set("Access-Control-Allow-Origin", origin)
		h.Set("Access-Control-Allow-Credentials", "true")
	case corsNone, corsSame:
	}
	out := make([]myOrgJSON, 0, len(orgs))
	for _, o := range orgs {
		out = append(out, myOrgJSON{
			OrgID: o.OrgID, Slug: o.Slug, DisplayName: o.DisplayName,
			Kind: string(o.Kind), Status: string(o.Status), ConsoleRole: string(o.ConsoleRole),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// handleMyOrgsPreflight answers the CORS preflight. A preflight carries no
// cookie, so it cannot be checked against the caller's memberships; it is
// answered on the origin SHAPE alone and discloses nothing (no data, no
// membership signal). The real GET re-checks membership and refuses an origin
// the caller does not belong to. Only GET is granted, with no request
// headers, so a plain credentialed GET needs no preflight at all; this keeps
// a stricter client from failing opaquely.
func (s *Server) handleMyOrgsPreflight(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Add("Vary", "Origin")
	h.Add("Vary", "Access-Control-Request-Method")
	h.Add("Vary", "Access-Control-Request-Headers")
	origin := r.Header.Get("Origin")
	if tenantOriginSlug(origin, s.tenantDomain) == "" ||
		r.Header.Get("Access-Control-Request-Method") != http.MethodGet ||
		strings.TrimSpace(r.Header.Get("Access-Control-Request-Headers")) != "" {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	h.Set("Access-Control-Allow-Origin", origin)
	h.Set("Access-Control-Allow-Credentials", "true")
	h.Set("Access-Control-Allow-Methods", http.MethodGet)
	h.Set("Access-Control-Max-Age", "600")
	w.WriteHeader(http.StatusNoContent)
}

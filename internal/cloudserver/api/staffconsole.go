package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/staffauth"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// staffconsole.go is the staff console's UI window (managed-SaaS plan 07
// M6.8; lane w17/staff-console): the org registry reads the screens need
// (cloud migration 0133), the issued availability envelope, a feature probe
// the UI keys optional screens on, the SPA itself, and the staff host's own
// Content-Security-Policy. Every route here is a READ: the console's writes
// stay the availability routes of staffapi.go, each behind a fresh passkey
// assertion, the staff CSRF header and a required reason, logged in
// staff_actions in the same transaction.

// staffConsoleStore is the read seam the console screens use. The production
// store (store.Store) implements it; a store that does not (the route-level
// test fakes of the older staff tests) answers the routes not_available.
type staffConsoleStore interface {
	ListStaffOrgs(ctx context.Context) ([]store.StaffOrg, error)
	StaffOrgDetail(ctx context.Context, orgID string) (store.StaffOrgDetail, error)
	StaffAvailabilityDocument(ctx context.Context) (store.StaffSignedDoc, error)
	ListStaffActionsFiltered(ctx context.Context, f store.StaffActionFilter) ([]store.StaffAction, error)
}

// staffConsole returns the console read seam, or answers 501 and false.
func (s *Server) staffConsole(w http.ResponseWriter) (staffConsoleStore, bool) {
	cs, ok := s.staff.db.(staffConsoleStore)
	if !ok {
		writeErr(w, http.StatusNotImplemented, "not_available", "this staff console store has no org reads")
		return nil, false
	}
	return cs, true
}

// staffFeature is one optional console surface: on when its route is in the
// staff route table (and, for need, when the server is configured for it).
// The UI renders a screen only when its feature is on, so a coordinating lane
// lights a screen up by adding its route row; it edits nothing here unless it
// picks a different path, in which case it changes the one pattern below.
type staffFeature struct {
	name    string
	pattern string
	need    func(*Server) bool
}

// staffFeatures is THE feature table.
var staffFeatures = []staffFeature{
	{name: "orgs", pattern: "GET /staff/api/orgs", need: (*Server).hasStaffConsoleStore},
	{name: "availability_document", pattern: "GET /staff/api/availability/document", need: (*Server).hasStaffConsoleStore},
	{name: "support_signin", pattern: "GET " + oidcissuer.SupportAuthorizePath, need: func(s *Server) bool { return s.staff.support != nil }},
	// w17/portal-guardrails: the team-creation allow-list (read, then PUT and
	// DELETE /staff/api/team-allowlist/{key}).
	{name: "team_allowlist", pattern: "GET /staff/api/team-allowlist"},
	// w17/deletion-purge: a cross-org deletion queue view. One org's deletion
	// request is already in GET /staff/api/orgs/{id}.
	{name: "deletion_queue", pattern: "GET /staff/api/deletions"},
	// A staff plan grant write. Plan grants are operator-only CLI by W15-D13
	// (cloud 0095); until a ruling adds this route the console shows the
	// grant history and prepares the `observer-cloud grant-plan org` command.
	{name: "plan_grant_write", pattern: "POST /staff/api/orgs/{id}/plan-grant"},
}

func (s *Server) hasStaffConsoleStore() bool {
	_, ok := s.staff.db.(staffConsoleStore)
	return ok
}

// staffRouteMounted reports whether pattern was mounted from the staff route
// table (mountStaff records the set; reading staffRoutes here would be an
// initialization cycle through the table's own handlers).
func (s *Server) staffRouteMounted(pattern string) bool {
	return s.staff.mounted[pattern]
}

func (s *Server) handleStaffFeatures(w http.ResponseWriter, r *http.Request) {
	p, _ := staffPrincipalFrom(r.Context())
	features := make(map[string]bool, len(staffFeatures))
	for _, f := range staffFeatures {
		features[f.name] = s.staffRouteMounted(f.pattern) && (f.need == nil || f.need(s))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"features":               features,
		"capabilities":           staffauth.Capabilities(p.Role),
		"fresh_window_seconds":   int(staffauth.FreshAssertionWindow / time.Second),
		"max_reason_characters":  staffauth.MaxReasonRunes,
		"availability_sections":  staffauth.KnownSections,
		"availability_key_regex": `^[A-Za-z0-9._:-]{1,128}$`,
	})
}

func (s *Server) handleStaffOrgs(w http.ResponseWriter, r *http.Request) {
	cs, ok := s.staffConsole(w)
	if !ok {
		return
	}
	orgs, err := cs.ListStaffOrgs(r.Context())
	if err != nil {
		s.log.Error("cloudserver/api: staff orgs", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not read the orgs")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"orgs": orgs})
}

func (s *Server) handleStaffOrg(w http.ResponseWriter, r *http.Request) {
	cs, ok := s.staffConsole(w)
	if !ok {
		return
	}
	d, err := cs.StaffOrgDetail(r.Context(), r.PathValue("id"))
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, "not_found", "no such org")
		return
	case err != nil:
		s.log.Error("cloudserver/api: staff org", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not read the org")
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) handleStaffAvailabilityDocument(w http.ResponseWriter, r *http.Request) {
	cs, ok := s.staffConsole(w)
	if !ok {
		return
	}
	doc, err := cs.StaffAvailabilityDocument(r.Context())
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeJSON(w, http.StatusOK, map[string]any{"document": nil})
		return
	case err != nil:
		s.log.Error("cloudserver/api: staff availability document", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not read the availability envelope")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"document": doc})
}

// staffLogFilter reads the log's optional filters (org, verb, actor, before).
// ok is false (and the response written) for a malformed value; filtered
// reports whether any filter is present.
func staffLogFilter(w http.ResponseWriter, r *http.Request, limit int) (f store.StaffActionFilter, filtered, ok bool) {
	q := r.URL.Query()
	f = store.StaffActionFilter{Limit: limit, OrgID: q.Get("org"), Verb: q.Get("verb"), Actor: q.Get("actor")}
	if v := q.Get("before"); v != "" {
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", "before must be an RFC 3339 time")
			return f, false, false
		}
		f.Before = t
	}
	for _, v := range []string{f.OrgID, f.Verb, f.Actor} {
		if len(v) > 300 {
			writeErr(w, http.StatusBadRequest, "bad_request", "a filter value is too long")
			return f, false, false
		}
	}
	filtered = strings.TrimSpace(f.OrgID+f.Verb+f.Actor) != "" || !f.Before.IsZero()
	return f, filtered, true
}

// staffAPIPrefixes are the staff paths the SPA never answers: an unknown API
// path is a 404, not the app's HTML.
var staffAPIPrefixes = []string{"/staff/api/", "/staff/auth/", "/staff/oauth2/"}

// mountStaffSPA serves the staff console's own SPA (webcloud's staff build,
// webcloud.StaffHandler) under /staff/, and redirects / and /staff to it.
// Without a StaffSPA option nothing is mounted (the API-only posture).
func (s *Server) mountStaffSPA(mux *http.ServeMux) {
	if s.staff.spa == nil {
		return
	}
	spa := http.StripPrefix("/staff", s.staff.spa)
	mux.Handle("GET /staff/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, p := range staffAPIPrefixes {
			if strings.HasPrefix(r.URL.Path, p) {
				writeErr(w, http.StatusNotFound, "not_found", "no such staff route")
				return
			}
		}
		spa.ServeHTTP(w, r)
	}))
	redirect := http.RedirectHandler("/staff/", http.StatusFound)
	mux.Handle("GET /staff", redirect)
	mux.Handle("GET /{$}", redirect)
}

// staffCSP is the staff host's Content-Security-Policy: same-origin only. The
// customer policy (secheaders.go) allows Paddle's hosts, which the staff
// console never loads; this one replaces it on every staff response.
var staffCSP = strings.Join([]string{
	"default-src 'self'",
	"script-src 'self'",
	"connect-src 'self'",
	"img-src 'self' data:",
	"style-src 'self' 'unsafe-inline'",
	"font-src 'self' data:",
	"frame-src 'none'",
	"frame-ancestors 'none'",
	"base-uri 'self'",
	"form-action 'self'",
	"object-src 'none'",
}, "; ")

// staffSecurityHeaders overrides the customer CSP with staffCSP. It runs
// inside securityHeaders, so every other header is the customer handler's.
func staffSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", staffCSP)
		next.ServeHTTP(w, r)
	})
}

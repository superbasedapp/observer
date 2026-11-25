package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/staffauth"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// The staff console (managed-SaaS M6.8; design
// docs/plans/managed-saas/m6.0-control-plane-design-2026-11-13.md 3.5, 3.6,
// 4.9; operator rulings A2 and A3 of 2026-11-13) is a route group of its own
// under /staff, served by its own process on its own host
// (DefaultStaffHost, staff.superbased.app), with:
//
//   - its own handler (StaffHandler), which mounts the staff routes and
//     nothing else; the customer handler (Handler) mounts no staff route;
//   - its own session cookie (__Host-sbci-staff), minted ONLY by a verified
//     WebAuthn assertion, host-only, Secure, HttpOnly, SameSite=Strict;
//   - its own CSRF header (X-SBCI-Staff-CSRF) on every mutation, and an exact
//     Origin check;
//   - its own middleware (staffAuth), which reads only the staff cookie, so a
//     customer portal session never authenticates a staff route, and
//     portalAuth reads only the customer cookie, so a staff session never
//     authenticates a customer route;
//   - its own database login and role (the staff process connects as
//     sbci_staff_svc, the only member of sbci_staff, which holds grants on
//     the staff tables only).
//
// WebAuthn verification sits behind staffauth.Verifier; the staff process
// wires staffauth/passkey (go-webauthn). A server with no verifier answers
// 501 not_available on the four /staff/auth/webauthn/* routes, and no staff
// session can exist there.

const (
	// staffCookieSecure is the staff session cookie on an https origin.
	staffCookieSecure = "__Host-sbci-staff"
	// staffCookieDev is the plain-http dev fallback (see portalCookieDev).
	staffCookieDev = "sbci_staff_session"
	// staffCeremonyCookieSecure carries a WebAuthn ceremony between its begin
	// and finish requests.
	staffCeremonyCookieSecure = "__Host-sbci-staff-ceremony"
	// staffCeremonyCookieDev is its plain-http dev fallback.
	staffCeremonyCookieDev = "sbci_staff_ceremony"

	// headerStaffCSRF is the staff double-submit CSRF header. It is not the
	// portal's X-SBCI-CSRF: the two surfaces share no credential of any kind.
	headerStaffCSRF = "X-SBCI-Staff-CSRF"

	// staffPathPrefix is the staff route group.
	staffPathPrefix = "/staff"

	// staffWebAuthnTimeout is the timeout the options ask the browser for.
	staffWebAuthnTimeout = 2 * time.Minute
)

// staffStore is the slice of the store the staff routes use, so the HTTP
// layer is testable without Postgres (staff_internal_test.go).
type staffStore interface {
	BeginStaffRegistration(ctx context.Context, rawCode, rawCeremony string, challenge []byte, now time.Time) (store.StaffRegistrationStart, error)
	BeginStaffAssertion(ctx context.Context, rawCeremony string, challenge []byte, now time.Time) error
	ConsumeStaffCeremony(ctx context.Context, rawCeremony string, kind store.StaffCeremonyKind, now time.Time) (store.StaffCeremony, error)
	RegisterStaffCredential(ctx context.Context, c store.StaffCeremony, cred staffauth.NewCredential, label string, now time.Time) error
	StaffCredentialForAssertion(ctx context.Context, credentialID []byte) (staffauth.StoredCredential, store.StaffUser, error)
	StartStaffSession(ctx context.Context, in store.StartStaffSessionInput) (store.StaffSession, error)
	IntrospectStaffSession(ctx context.Context, rawSession string, now time.Time, idleTTL time.Duration) (store.StaffPrincipal, error)
	EndStaffSession(ctx context.Context, staffID, rawSession string, now time.Time) error
	RecordStaffRefusal(ctx context.Context, staffID string, action staffauth.Action, code string, now time.Time) error
	ListStaffActions(ctx context.Context, limit int) ([]store.StaffAction, error)
	ListAvailabilityInputs(ctx context.Context) ([]store.AvailabilityInputRow, error)
	SetAvailabilityInput(ctx context.Context, staffID string, in staffauth.AvailabilityInput, reason string, now time.Time) error
	DeleteAvailabilityInput(ctx context.Context, staffID string, section staffauth.Section, key, reason string, now time.Time) error
}

// staffConfig is the staff console's resolved configuration.
type staffConfig struct {
	db       staffStore
	verifier staffauth.Verifier
	// host is the normalized canonical host of /staff ("" unenforced).
	host string
	// origin is the exact staff origin a WebAuthn clientDataJSON must carry,
	// and rpID its host name (the WebAuthn relying-party id).
	origin string
	rpID   string
	// secure selects the __Host- cookie names and the Secure attribute.
	secure     bool
	sessionTTL time.Duration
	idleTTL    time.Duration
	// random is the challenge and ceremony-token source.
	random io.Reader
	// support writes support codes (staffsupport.go); nil answers the
	// support authorize route not_available.
	support *oidcissuer.SupportAuthorizer
	// spa serves the staff console's SPA under /staff/ (staffconsole.go);
	// nil mounts no UI.
	spa http.Handler
	// mounted is the set of staff route patterns mountStaff registered (the
	// feature probe's source).
	mounted map[string]bool
}

// DefaultStaffHost is the staff console's own host (operator ruling A3,
// 2026-11-13): a name of its own, decided before any passkey is enrolled,
// because a passkey is bound to its relying-party id and moving the console
// later would invalidate every credential. It is also the relying-party id,
// never the parent domain, so a staff passkey is unusable on any sibling
// (tenant or portal) subdomain.
const DefaultStaffHost = "staff.superbased.app"

// DefaultStaffBaseURL is the staff console's default origin.
const DefaultStaffBaseURL = "https://" + DefaultStaffHost

// initStaff resolves the staff configuration from o. The origin defaults to
// DefaultStaffBaseURL (never the portal's: the staff console is served by
// its own process on its own host), the relying-party id is the origin's
// host, and the canonical host defaults to it as well.
func (s *Server) initStaff(o Options) {
	c := staffConfig{
		verifier:   o.StaffWebAuthn,
		host:       NormalizeHost(o.StaffHost),
		origin:     strings.TrimRight(strings.TrimSpace(o.StaffBaseURL), "/"),
		sessionTTL: o.StaffSessionTTL,
		idleTTL:    o.StaffSessionIdleTTL,
		random:     rand.Reader,
	}
	if o.Store != nil {
		c.db = o.Store
	}
	if c.verifier == nil {
		c.verifier = staffauth.Unavailable{}
	}
	if c.origin == "" {
		c.origin = DefaultStaffBaseURL
	}
	if u, err := url.Parse(c.origin); err == nil {
		c.rpID = strings.ToLower(u.Hostname())
		// The __Host- cookie names and Secure follow the staff origin's own
		// scheme: https everywhere but a loopback dev run.
		c.secure = u.Scheme == "https"
	}
	if c.host == "" {
		c.host = c.rpID
	}
	if c.sessionTTL <= 0 {
		c.sessionTTL = store.DefaultStaffSessionTTL
	}
	if c.idleTTL <= 0 {
		c.idleTTL = store.DefaultStaffSessionIdleTTL
	}
	c.support = s.staffSupportAuthorizer(o)
	c.spa = o.StaffSPA
	s.staff = c
}

// staffRoute is one row of the staff route table.
type staffRoute struct {
	pattern string
	// action is the authorization row a session route is checked against;
	// empty for the pre-session WebAuthn routes.
	action staffauth.Action
	// noCSRF exempts a session mutation from the CSRF header (sign-out
	// only; the Origin check still applies).
	noCSRF  bool
	handler func(*Server) http.HandlerFunc
}

// staffRoutes is THE staff route table. Pre-session routes (no action) are
// the WebAuthn ceremonies; every other route runs behind staffAuth with its
// action.
var staffRoutes = []staffRoute{
	{pattern: "POST /staff/auth/webauthn/register/begin", handler: func(s *Server) http.HandlerFunc { return s.handleStaffRegisterBegin }},
	{pattern: "POST /staff/auth/webauthn/register/finish", handler: func(s *Server) http.HandlerFunc { return s.handleStaffRegisterFinish }},
	{pattern: "POST /staff/auth/webauthn/assert/begin", handler: func(s *Server) http.HandlerFunc { return s.handleStaffAssertBegin }},
	{pattern: "POST /staff/auth/webauthn/assert/finish", handler: func(s *Server) http.HandlerFunc { return s.handleStaffAssertFinish }},
	// Sign-out needs no CSRF token (SC-5): the token lives only in a tab's
	// memory, so after a reload the button could never end the session. The
	// Origin check and the SameSite=Strict cookie still apply; a forged
	// sign-out only signs a staff member out.
	{pattern: "POST /staff/auth/logout", action: staffauth.ActionSignOut, noCSRF: true, handler: func(s *Server) http.HandlerFunc { return s.handleStaffLogout }},
	{pattern: "GET /staff/api/me", action: staffauth.ActionReadSelf, handler: func(s *Server) http.HandlerFunc { return s.handleStaffMe }},
	{pattern: "GET /staff/api/log", action: staffauth.ActionReadLog, handler: func(s *Server) http.HandlerFunc { return s.handleStaffLog }},
	{pattern: "GET /staff/api/availability", action: staffauth.ActionReadAvailability, handler: func(s *Server) http.HandlerFunc { return s.handleStaffAvailabilityList }},
	{pattern: "PUT /staff/api/availability/{section}/{key}", action: staffauth.ActionWriteAvailability, handler: func(s *Server) http.HandlerFunc { return s.handleStaffAvailabilitySet }},
	{pattern: "DELETE /staff/api/availability/{section}/{key}", action: staffauth.ActionWriteAvailability, handler: func(s *Server) http.HandlerFunc { return s.handleStaffAvailabilityDelete }},
	{pattern: "GET /staff/api/deletions", action: staffauth.ActionReadDeletions, handler: func(s *Server) http.HandlerFunc { return s.handleStaffDeletions }},
	{pattern: "GET /staff/api/team-allowlist", action: staffauth.ActionReadTeamAllowlist, handler: func(s *Server) http.HandlerFunc { return s.handleStaffTeamAllowlistList }},
	{pattern: "POST /staff/api/team-allowlist", action: staffauth.ActionWriteTeamAllowlist, handler: func(s *Server) http.HandlerFunc { return s.handleStaffTeamAllowlistAdd }},
	{pattern: "DELETE /staff/api/team-allowlist/{id}", action: staffauth.ActionWriteTeamAllowlist, handler: func(s *Server) http.HandlerFunc { return s.handleStaffTeamAllowlistRemove }},
	{pattern: "GET " + oidcissuer.SupportAuthorizePath, action: staffauth.ActionSupportSignIn, handler: func(s *Server) http.HandlerFunc { return s.handleStaffSupportAuthorize }},
	// The console screens' reads (staffconsole.go, cloud 0133).
	{pattern: "GET /staff/api/features", action: staffauth.ActionReadSelf, handler: func(s *Server) http.HandlerFunc { return s.handleStaffFeatures }},
	{pattern: "GET /staff/api/orgs", action: staffauth.ActionReadOrgs, handler: func(s *Server) http.HandlerFunc { return s.handleStaffOrgs }},
	{pattern: "GET /staff/api/orgs/{id}", action: staffauth.ActionReadOrgs, handler: func(s *Server) http.HandlerFunc { return s.handleStaffOrg }},
	{pattern: "GET /staff/api/availability/document", action: staffauth.ActionReadAvailability, handler: func(s *Server) http.HandlerFunc { return s.handleStaffAvailabilityDocument }},
	// The issue step and the per-org components (staffavail.go, cloud 0154).
	{pattern: "GET /staff/api/availability/preview", action: staffauth.ActionReadAvailability, handler: func(s *Server) http.HandlerFunc { return s.handleStaffAvailabilityPreview }},
	{pattern: "POST /staff/api/availability/issue", action: staffauth.ActionIssueAvailability, handler: func(s *Server) http.HandlerFunc { return s.handleStaffAvailabilityIssue }},
	{pattern: "POST /staff/api/availability/issue/{id}/cancel", action: staffauth.ActionIssueAvailability, handler: func(s *Server) http.HandlerFunc { return s.handleStaffAvailabilityIssueCancel }},
	{pattern: "GET /staff/api/orgs/{id}/components", action: staffauth.ActionReadOrgs, handler: func(s *Server) http.HandlerFunc { return s.handleStaffOrgComponents }},
	{pattern: "PUT /staff/api/orgs/{id}/components/{component}", action: staffauth.ActionWriteAvailability, handler: func(s *Server) http.HandlerFunc { return s.handleStaffOrgComponentSet }},
}

// StaffHandler returns the staff process's handler: the staff route group,
// the staff console's own SPA when Options.StaffSPA is set, and a
// database-only health probe, and nothing else (no portal, device, OIDC or
// webhook route). The canonical-host fence binds /staff to the staff host;
// the edge and security-header wrappers are the customer handler's own, with
// the staff host's same-origin Content-Security-Policy in place of the
// customer one (staffconsole.go).
func (s *Server) StaffHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleStaffHealthz)
	s.mountStaff(mux)
	s.mountStaffSPA(mux)
	return s.securityHeaders(staffSecurityHeaders(s.enforceTrustedEdge(enforceHostRules(s.staffHostRules(), mux))))
}

// handleStaffHealthz is the staff process's probe: the database answers.
// It reports nothing else (no schema or route coverage: the staff login
// reads no customer table).
func (s *Server) handleStaffHealthz(w http.ResponseWriter, r *http.Request) {
	if s.store == nil || s.store.Pool().Ping(r.Context()) != nil {
		writeErr(w, http.StatusServiceUnavailable, "db_unreachable", "database unreachable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "surface": "staff"})
}

// mountStaff registers the staff route group. Every route answers
// Cache-Control: no-store. The pre-session WebAuthn ceremonies are rate
// limited per client IP. A session route is limited per staff member once
// the session resolves (the per-account budget), and per IP only when it
// carries no staff cookie or a cookie that does not resolve (SC-2: the
// anonymous per-IP budget used to count every signed-in read, so ordinary
// navigation hit 429).
func (s *Server) mountStaff(mux *http.ServeMux) {
	s.staff.mounted = make(map[string]bool, len(staffRoutes))
	for _, rt := range staffRoutes {
		s.staff.mounted[rt.pattern] = true
		var h http.Handler = rt.handler(s)
		if rt.action != "" {
			h = s.staffAuth(rt.action, rt.noCSRF, h)
			h = s.rateLimitIPWithoutStaffCookie(h)
		} else {
			h = s.rateLimitIP(h)
		}
		mux.Handle(rt.pattern, staffNoStore(h))
	}
}

// rateLimitIPWithoutStaffCookie applies the per-IP limit to a session route
// called with no staff cookie (staffAuth charges the IP for a cookie that
// does not resolve).
func (s *Server) rateLimitIPWithoutStaffCookie(next http.Handler) http.Handler {
	limited := s.rateLimitIP(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie(s.staffCookieName()); err == nil && c.Value != "" {
			next.ServeHTTP(w, r)
			return
		}
		limited.ServeHTTP(w, r)
	})
}

// allowStaffMember applies the per-staff-member limit (the per-account
// budget, SBCI_RATELIMIT_ACCOUNT, default 240 a minute) to a resolved
// session, before its CSRF and authorization checks, so a signed-in member
// cannot write refusal rows without bound either. It answers 429 (or 503
// when the limiter cannot answer) and false when the request must stop.
func (s *Server) allowStaffMember(w http.ResponseWriter, r *http.Request, staffID string) bool {
	if s.rl == nil || s.rl.account == nil || s.rl.account.limit <= 0 {
		return true
	}
	allowed, retry, err := s.rl.account.allowContext(r.Context(), "staff:"+staffID)
	if err != nil {
		s.log.Error("cloudserver/api: staff rate limiter", "err", err)
		writeRateLimitUnavailable(w)
		return false
	}
	if !allowed {
		writeRateLimited(w, retry)
		return false
	}
	return true
}

// chargeIP counts one request against the client IP's budget and reports
// whether it is still within it (a resolve failure counts as within: the
// caller answers 401 anyway).
func (s *Server) chargeIP(r *http.Request) bool {
	if s.rl == nil || s.rl.ip == nil || s.rl.ip.limit <= 0 {
		return true
	}
	key, err := rateLimitKey(r)
	if err != nil {
		return true
	}
	ok, _, err := s.rl.ip.allowContext(r.Context(), key)
	return err != nil || ok
}

// staffNoStore marks a staff response uncacheable.
func staffNoStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// staffCookieName and staffCeremonyCookieName follow the deployment's scheme,
// like portalCookieName.
func (s *Server) staffCookieName() string {
	if s.staff.secure {
		return staffCookieSecure
	}
	return staffCookieDev
}

func (s *Server) staffCeremonyCookieName() string {
	if s.staff.secure {
		return staffCeremonyCookieSecure
	}
	return staffCeremonyCookieDev
}

// setStaffCookie writes a host-only (no Domain), Path=/, HttpOnly,
// SameSite=Strict cookie; Secure whenever the __Host- name is used. maxAge
// below zero deletes it.
func (s *Server) setStaffCookie(w http.ResponseWriter, name, value string, expires time.Time, maxAge int) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: HttpOnly and SameSite=Strict; Secure follows the deployment (always on with the __Host- name)
		Name:     name,
		Value:    value,
		Path:     "/",
		Expires:  expires,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   s.staff.secure,
		SameSite: http.SameSiteStrictMode,
	})
}

// staffPrincipalKey carries the resolved staff principal.
const staffPrincipalKey ctxKey = 7

// staffPrincipal is a resolved staff session.
type staffPrincipal struct {
	store.StaffPrincipal
	// Raw is the session cookie value, so sign-out revokes exactly it.
	Raw string
}

func staffPrincipalFrom(ctx context.Context) (staffPrincipal, bool) {
	p, ok := ctx.Value(staffPrincipalKey).(staffPrincipal)
	return p, ok
}

// staffAuth is the staff session middleware. It reads ONLY the staff cookie
// (never the portal's), checks the staff CSRF header and the request Origin
// on every non-GET, and applies the staffauth authorization table for
// action. A refusal by the table is logged in staff_actions.
func (s *Server) staffAuth(action staffauth.Action, noCSRF bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if s.staff.db == nil {
			writeErr(w, http.StatusServiceUnavailable, "staff_unavailable", "the staff console has no store")
			return
		}
		c, err := r.Cookie(s.staffCookieName())
		if err != nil || c.Value == "" {
			writeErr(w, http.StatusUnauthorized, "unauthorized", "not signed in to the staff console")
			return
		}
		now := s.now()
		p, err := s.staff.db.IntrospectStaffSession(ctx, c.Value, now, s.staff.idleTTL)
		if err != nil {
			if !errors.Is(err, store.ErrStaffSessionInvalid) {
				s.log.Error("cloudserver/api: staff session", "err", err)
			}
			s.setStaffCookie(w, s.staffCookieName(), "", time.Time{}, -1)
			// A cookie that does not resolve is charged to the client IP
			// (it skipped the per-IP limit for carrying a cookie).
			if !s.chargeIP(r) {
				writeErr(w, http.StatusTooManyRequests, "rate_limited", "rate limit exceeded; retry later")
				return
			}
			writeErr(w, http.StatusUnauthorized, "unauthorized", "staff session expired or invalid")
			return
		}
		if !s.allowStaffMember(w, r, p.StaffID) {
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if origin := r.Header.Get("Origin"); origin != "" && origin != s.staff.origin {
				writeErr(w, http.StatusForbidden, "origin_mismatch", "cross-origin staff request refused")
				return
			}
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && !noCSRF {
			presented := csrfHash(r.Header.Get(headerStaffCSRF))
			if p.CSRFHash == "" || subtle.ConstantTimeCompare([]byte(presented), []byte(p.CSRFHash)) != 1 {
				writeErr(w, http.StatusForbidden, "csrf_failed", "missing or invalid staff CSRF token")
				return
			}
		}
		if d := staffauth.Authorize(p.Role, action, p.AssertedAt, now); !d.Allowed {
			if err := s.staff.db.RecordStaffRefusal(ctx, p.StaffID, action, d.Code, now); err != nil {
				s.log.Warn("cloudserver/api: staff refusal log", "err", err)
			}
			writeErr(w, http.StatusForbidden, d.Code, "this staff action is refused: "+d.Code)
			return
		}
		ctx = context.WithValue(ctx, staffPrincipalKey, staffPrincipal{StaffPrincipal: p, Raw: c.Value})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// staffToken returns a fresh 32-byte random token, base64url.
func (s *Server) staffToken() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(s.staff.random, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

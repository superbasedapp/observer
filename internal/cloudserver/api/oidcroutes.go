package api

import (
	"errors"
	"net/http"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer/oidchttp"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// The platform OIDC issuer's routes (managed-SaaS M6.2; design
// docs/plans/managed-saas/m6.0-control-plane-design-2026-11-13.md 4.4, A5).
//
// The issuer lives on the PORTAL origin at oidcissuer.IssuerPath: authorize
// must see the browser's portal session, and that cookie (__Host-sbci) is
// host-only, so no other host can serve authorize. One canonical-host row
// (canonicalhost.go) binds /oauth2 to the portal host, and one return_to row
// (portalauth.go) lets a sign-in started by authorize come back to it.
//
// Every decision is the issuer's (internal/cloudserver/oidcissuer); the
// handlers are internal/cloudserver/oidcissuer/oidchttp. This file only
// mounts them and hands authorize the session's account id.

// initOIDC builds the handler when an issuer is configured. The issuer's
// identifier must be exactly the portal origin plus IssuerPath (the tenants
// pin it, and discovery must be served where the identifier says); any other
// value leaves the routes unmounted and logs why, rather than serving a
// discovery document whose issuer the tenants would refuse.
func (s *Server) initOIDC(iss *oidcissuer.Issuer) {
	if iss == nil {
		return
	}
	if want := s.portalBaseURL + oidcissuer.IssuerPath; iss.Identifier() != want {
		s.log.Error("cloudserver/api: OIDC issuer identifier does not match the portal origin; the /oauth2 routes stay off",
			"issuer", iss.Identifier(), "want", want)
		return
	}
	h, err := oidchttp.New(iss, oidchttp.Options{Logger: s.log})
	if err != nil {
		s.log.Error("cloudserver/api: OIDC handler", "err", err)
		return
	}
	s.oidc = h
}

// oidcSession is the issuer's view of the browser's portal session: the
// account, and when the person authenticated to establish the session (its
// authenticated_at, recorded only by a sign-in that was a fresh primary
// authentication: a forced AuthKit leg or the dev-auth login), which the
// issuer signs as auth_time and checks against prompt and max_age. A session
// whose authentication time is not known carries a zero AuthTime: the issuer
// signs no auth_time for it and answers any freshness request with a forced
// sign-in. No session is a zero Session. ok is false only when a session
// exists but cannot be read (a store fault): the caller answers 503 rather
// than letting the issuer treat the session as signed out.
//
// amr is what the session's passkey second factor proved (C2, portalmfa.go):
// "hwk" or "swk" with "mfa" after a passkey, nothing otherwise. AuthKit's own
// sign-in reports no multi-factor signal (its code exchange returns the
// primary authentication_method only), so a session without a passkey
// carries no amr. SecondFactorPending stops the issuer for an account whose
// passkey this session has not used.
func (s *Server) oidcSession(r *http.Request) (oidcissuer.Session, bool) {
	p, signedIn := s.optionalPortalPrincipal(r)
	if !signedIn {
		return oidcissuer.Session{}, true
	}
	at, err := s.store.BrowserSessionAuthTime(r.Context(), p.AccountID, p.SessionID)
	if errors.Is(err, store.ErrNotFound) {
		// Revoked between the introspection and this read: signed out.
		return oidcissuer.Session{}, true
	}
	if err != nil {
		s.log.Error("cloudserver/api: OIDC authorize: session authentication time", "err", err)
		return oidcissuer.Session{}, false
	}
	sf, err := s.store.PortalSecondFactorState(r.Context(), p.AccountID, p.SessionID)
	if errors.Is(err, store.ErrNotFound) {
		return oidcissuer.Session{}, true
	}
	if err != nil {
		s.log.Error("cloudserver/api: OIDC authorize: session second factor", "err", err)
		return oidcissuer.Session{}, false
	}
	return oidcissuer.Session{AccountID: p.AccountID, AuthTime: at, AMR: sf.AMR, SecondFactorPending: sf.Pending()}, true
}

// mountOIDC registers the four issuer routes when an issuer is configured.
// All four carry the per-IP cap of the other unauthenticated bootstrap
// endpoints; authorize resolves the portal session itself (a missing session
// is a redirect to sign-in, not a 401), which is a GET with no side effect on
// the session, so the CSRF check is not skipped by not using portalAuth.
func (s *Server) mountOIDC(mux *http.ServeMux) {
	if s.oidc == nil {
		return
	}
	mux.Handle("GET "+oidcissuer.DiscoveryPath, s.rateLimitIP(http.HandlerFunc(s.oidc.Discovery)))
	mux.Handle("GET "+oidcissuer.JWKSPath, s.rateLimitIP(http.HandlerFunc(s.oidc.JWKS)))
	mux.Handle("GET "+oidcissuer.AuthorizePath, s.rateLimitIP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, ok := s.oidcSession(r)
		if !ok {
			w.Header().Set("Cache-Control", "no-store")
			writeErr(w, http.StatusServiceUnavailable, oidcissuer.ErrCodeTemporarilyUnavailable, "sign-in is temporarily unavailable")
			return
		}
		s.oidc.Authorize(w, r, sess)
	})))
	mux.Handle("POST "+oidcissuer.TokenPath, s.rateLimitIP(http.HandlerFunc(s.oidc.Token)))
}

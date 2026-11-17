package dashboard

import (
	"context"
	"fmt"
	"net/http"

	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
)

// remoteExposedCtxKey marks a request context as having arrived through the
// remote-exposed authorization chain (remoteAuthz). It is the LISTENER-
// PROVENANCE flag §4.4 requires for the execute tier: resolved AT THE BOUNDARY
// from which handler chain served the request, NEVER read from a client-
// controlled request field. The owner-trusted direct loopback handler
// (browserGuard(s.Handler())) never runs remoteAuthz, so the marker is absent
// there — a loopback request is owner-local, a remote request is remote-exposed.
type remoteExposedCtxKey struct{}

// withRemoteExposed stamps the remote-exposed provenance marker on ctx.
func withRemoteExposed(ctx context.Context) context.Context {
	return context.WithValue(ctx, remoteExposedCtxKey{}, true)
}

// remoteExposedFromContext reports whether the request arrived through the
// remote-exposed authz chain. Used by the /ws/launch bridge to refuse the
// owner-local writer path and require the §4.δ conjunction (AcquireWriterRemote)
// for a remote principal.
func remoteExposedFromContext(ctx context.Context) bool {
	v, _ := ctx.Value(remoteExposedCtxKey{}).(bool)
	return v
}

// remoteExposureAllowed enforces the plan §4.6 atomic-safety rule for a bind
// address: a non-loopback bind is permitted ONLY when a non-nil
// RemoteController reports Ready(). It returns a descriptive error otherwise so
// the CLI and ListenAndServe both refuse with an actionable message rather than
// silently exposing an unauthenticated surface. A loopback bind always
// returns nil — the local single-user path is behaviourally unchanged.
func remoteExposureAllowed(addr string, rc RemoteController) error {
	if hostIsLoopback(hostnameOnly(addr)) {
		return nil
	}
	if rc != nil && rc.Ready() {
		return nil
	}
	return fmt.Errorf(
		"refusing to bind the dashboard to non-loopback address %q: remote exposure requires the [remote] "+
			"security substrate (authentication, route-capability registry, Host allow-list, rate limiting), "+
			"which is not active. Bind a loopback address (127.0.0.1) for local use, or enable remote access "+
			"once [remote] is configured. This closes the unauthenticated-RCE hole of a bare non-loopback bind",
		addr,
	)
}

// CheckRemoteBind is the exported preflight the CLI runs before printing a
// "listening on …" banner, so `observer dashboard --addr 0.0.0.0:8080` refuses
// with a clear message instead of appearing to start. It is the same §4.6
// predicate ListenAndServe enforces as a backstop. Pass the RemoteController
// the server will run with (nil pre-Phase-2, when no remote listener is wired).
func CheckRemoteBind(addr string, rc RemoteController) error {
	return remoteExposureAllowed(addr, rc)
}

// guardedHandler wraps the mux with the request-time browser + remote guards
// for the given bind address. The loopback single-user path is byte-identical
// to before: browserGuard with a loopback Host predicate. When a ready
// RemoteController is present AND the bind is non-loopback (only reachable once
// remoteExposureAllowed has permitted it, plan §4.6), it uses the
// remote-exposed handler with the Host allow-list + capability authorization.
func (s *Server) guardedHandler(addr string) http.Handler {
	var h http.Handler
	if rc := s.opts.Remote; rc != nil && rc.Ready() && !hostIsLoopback(hostnameOnly(addr)) {
		// The remote handler does not go through Handler, so it takes the
		// database identity guard here (db_identity_guard.go, L-125).
		h = s.dbIdentityGuard(s.remoteGuardedHandler(rc))
	} else {
		// Handler carries the database identity guard itself.
		h = browserGuard(s.Handler(), hostIsLoopback)
	}
	// The caller check rides outside the route guards, so it covers every
	// route of both handlers by construction (caller_guard.go).
	h = s.callerGuard(h)
	if s.opts.ReadCaches {
		h = costRowCacheMiddleware(h)
	}
	// Execute-tier hardening headers + CSP ride the OUTERMOST wrapper so they
	// apply to every response on both the loopback and the deliberately-armed
	// remote direct bind (plan §8.1 item 7).
	return securityHeaders(h)
}

// costRowCacheMiddleware marks safe (GET/HEAD) requests so the cost engine
// may answer their row loads from its short-lived shared cache
// (cost.WithRowCache). Mutating requests are never marked: a handler that
// writes and then reads back must see its own write.
func costRowCacheMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			r = r.WithContext(cost.WithRowCache(r.Context()))
		}
		next.ServeHTTP(w, r)
	})
}

// remoteGuardedHandler builds the handler chain for a remotely-exposed bind
// (plan §4.5/§4.6). Outer→inner:
//   - browserGuard with the controller's Host allow-list + Origin/CSRF check
//     (never "allow any Host").
//   - remoteAuthz: resolve the matched route's required capability from the
//     registry and compare to the request's granted principal; deny (fail
//     closed) on an unclassified route or insufficient capability.
//   - the mux (built with the controller's own /api/remote/* routes mounted).
func (s *Server) remoteGuardedHandler(rc RemoteController) http.Handler {
	mux, capMap, sections := s.registerRoutes(rc)
	authz := s.remoteAuthz(mux, capMap, rc)
	// Admin-controlled Plane B (spec §3.5): the governance guard wraps the
	// authz chain on THIS branch too. Both branches of guardedHandler get it
	// — a governed section must be refused identically whether the request
	// arrived on the owner-trusted loopback listener or a paired remote one.
	return browserGuard(s.analyticsInvalidateOnWrite(s.governanceGuard(mux, sections, authz)), hostAllowlistPredicate(rc.AllowedHosts()))
}

// requiredCapability maps a route's registered base capability + the request
// method to the capability a principal must hold (plan §4.1/§4.2, method-aware):
//   - Public: no auth for any method.
//   - View: safe methods (GET/HEAD/OPTIONS) need View; unsafe methods
//     (POST/PUT/DELETE/PATCH) auto-escalate to Execute.
//   - Execute: every method needs Execute (the terminal PTY bridge).
//   - Unclassified: fail closed — returns (CapabilityUnclassified, false),
//     signalling the caller to DENY outright.
func requiredCapability(base Capability, method string) (Capability, bool) {
	switch base {
	case CapabilityPublic:
		return CapabilityPublic, true
	case CapabilityExecute:
		return CapabilityExecute, true
	case CapabilityView:
		switch method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			return CapabilityView, true
		default:
			return CapabilityExecute, true
		}
	case CapabilityLocal:
		// Local is owner-local-only and never remotely grantable — fail closed
		// (plan §A). remoteAuthz refuses a Local route BEFORE reaching here; this
		// is the defense-in-depth backstop if that early branch is ever skipped.
		return CapabilityUnclassified, false
	default:
		return CapabilityUnclassified, false
	}
}

// remoteAuthz is the deny-by-default authorization middleware for a
// remotely-exposed bind. It resolves the matched route pattern via the mux
// (reusing ServeMux's own matching), looks up its capability, computes the
// method-aware requirement, and admits only a principal whose granted
// capability is >= the requirement. Unclassified routes and insufficient
// principals get 403/401. Every decision is audited (metadata only).
func (s *Server) remoteAuthz(mux *http.ServeMux, capMap map[string]Capability, rc RemoteController) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, pattern := mux.Handler(r)
		base, known := capMap[pattern]
		if !known {
			base = CapabilityUnclassified
		}
		// Local routes are owner-local-only (plan §A): refuse on every
		// remotely-exposed listener BEFORE resolving the principal, so no
		// single-use execute capability is ever consumed on a refused request —
		// the exact early-refusal ordering used for funnel_execute_refused. The
		// direct owner-trusted loopback listener never runs remoteAuthz, so
		// Local routes stay fully reachable locally.
		if base == CapabilityLocal {
			s.auditRemote(r, rc, CapabilityPublic, pattern, "deny", "local_route_refused")
			http.Error(w, "forbidden: route is reachable only from the local dashboard", http.StatusForbidden)
			return
		}
		required, ok := requiredCapability(base, r.Method)
		if !ok {
			// Unclassified route — fail closed. Do NOT resolve the principal
			// (which would consume a single-use execute capability on a route
			// we are refusing regardless).
			s.auditRemote(r, rc, CapabilityPublic, pattern, "deny", "unclassified route")
			http.Error(w, "forbidden: route not authorized for remote access", http.StatusForbidden)
			return
		}
		if pattern == "/api/terminal/launch" && r.Method == http.MethodPost && rc.AllowTerminal() {
			required = CapabilityView
		}
		// Funnel (public-internet) requests are refused for execute-tier routes
		// outright, BEFORE resolving the principal (plan §9 — funnel is not a
		// supported transport; defence-in-depth over the capability check, and a
		// refused request must never consume a single-use capability). The
		// funnel marker is captured on the dedicated backend socket only.
		if required == CapabilityExecute && funnelFromContext(r.Context()) {
			s.auditRemote(r, rc, CapabilityPublic, pattern, "deny", "funnel_execute_refused")
			http.Error(w, "forbidden: execute routes are not reachable over tailscale funnel", http.StatusForbidden)
			return
		}
		granted := rc.Principal(r)
		if granted < required {
			decision := http.StatusForbidden
			msg := "forbidden: insufficient capability"
			detail := required.String()
			if granted == CapabilityPublic {
				// Anonymous hitting a protected route → 401 (authenticate).
				decision = http.StatusUnauthorized
				msg = "unauthorized: authentication required"
				// Record WHICH KIND of anonymous this is. Principal collapses
				// four different worlds into CapabilityPublic — no cookie was
				// sent at all, an unknown session, an expired session, a failed
				// CSRF check — and they have opposite fixes: "the browser threw
				// the credential away" is a cookie-attribute problem, while "the
				// server refused a credential the browser still had" is a
				// session-lifecycle problem.
				//
				// Not knowing which cost two days on the 2026-07-25 mobile-401:
				// it was "fixed" by widening the session TTL, but the credential
				// was a cookie the browser had already discarded, so no TTL
				// could have rescued it and the defect survived the fix. The
				// discriminator goes on the row that is ALREADY written, so it
				// costs no extra audit volume on a hot auth path.
				if sessionCookie(r) == "" {
					detail += " no_cookie"
				} else {
					detail += " cookie_rejected"
				}
			}
			s.auditRemote(r, rc, granted, pattern, "deny", detail)
			http.Error(w, msg, decision)
			return
		}
		s.auditRemote(r, rc, granted, pattern, "allow", required.String())
		// Stamp the remote-exposed provenance marker so downstream handlers (the
		// /ws/launch writer bridge) resolve listener provenance from the boundary
		// — never from a client-controlled request field (§4.4). The owner-local
		// loopback handler never reaches here, so it never carries the marker.
		mux.ServeHTTP(w, r.WithContext(withRemoteExposed(r.Context())))
	})
}

// auditRemote records one remote-access decision through the injected audit
// sink (metadata only; never secrets). Best-effort — an audit failure never
// blocks a request. Nil sink (the default) is a no-op.
func (s *Server) auditRemote(r *http.Request, rc RemoteController, granted Capability, route, decision, detail string) {
	if s.opts.RemoteAudit == nil {
		return
	}
	// On the tailnet-serve backend the forwarded tailnet login is captured into
	// the request context (audit only — never an auth channel here). Append it
	// so `observer remote status` shows which tailnet identity reached a route.
	// The direct owner-trusted listener never captures it, so it is empty there.
	if user := tailnetUserFromContext(r.Context()); user != "" {
		if detail == "" {
			detail = "tailnet:" + user
		} else {
			detail = detail + " tailnet:" + user
		}
	}
	s.opts.RemoteAudit(RemoteAuditRecord{
		Kind:       "http_request",
		Principal:  granted.String(),
		RemoteAddr: hostnameOnly(r.RemoteAddr),
		Route:      route,
		Decision:   decision,
		Detail:     detail,
	})
}

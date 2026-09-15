package api

import (
	"net"
	"net/http"
	"strings"
)

// Canonical-host enforcement (plan §2 R5 / §3 W1 "Origin"). The portal
// (app.superbased.app) and the device API are two ORIGINS served by one
// process. R5 binds them: a /portal/* request must arrive on the portal host and
// a /v1/* request on the API host, so a credential minted for one origin can
// never be replayed against the other by aiming a request at the wrong name.
//
// It is a HOST check, not an auth check — the mutual credential rejection
// between the two surfaces is structural (the /v1 middleware demands a bearer +
// proof-of-possession a browser cannot mint; the portal middleware demands a
// cookie a device never holds) and is pinned by its own tests. This middleware
// is the second, coarser fence in front of that.
//
// Both hosts are OPTIONAL. Empty ⇒ enforcement off for that surface, which is
// exactly the single-host staging/dev deployment: unset both and the server
// behaves byte-identically to before this landed. /healthz is deliberately
// host-agnostic in every configuration — a probe hitting the container's own
// address must not be refused for not knowing the public name.

// hostRule binds one path prefix to the canonical host that serves it. A rule
// with an empty host is inert (that surface is unenforced).
type hostRule struct {
	// prefix is matched as an exact path OR as a path segment prefix, so
	// "/portal" covers both "/portal" and "/portal/anything" while never
	// matching an unrelated "/portalish".
	prefix string
	host   string
}

// normalizeHost reduces a Host header (or a configured host) to its comparable
// form: lowercased, port stripped, IPv6 brackets removed, trailing root dot
// dropped. Comparing anything less normalized would make `App.Example:443` and
// `app.example` spuriously different hosts.
func normalizeHost(h string) string {
	h = strings.TrimSpace(h)
	if h == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.Trim(h, "[]")
	h = strings.TrimSuffix(h, ".")
	return strings.ToLower(h)
}

// canonicalHostRules is the ordered rule table this deployment enforces. It is
// built once per Handler() call from the already-normalized configured hosts.
func (s *Server) canonicalHostRules() []hostRule {
	return []hostRule{
		{prefix: "/portal", host: s.portalHost},
		{prefix: "/v1", host: s.apiHost},
	}
}

// matches reports whether path falls under this rule's prefix.
func (r hostRule) matches(path string) bool {
	return path == r.prefix || strings.HasPrefix(path, r.prefix+"/")
}

// enforceCanonicalHost wraps the mux with the R5 host fence. With neither host
// configured it returns next unchanged, so the unenforced deployment pays
// nothing — not even a closure per request.
func (s *Server) enforceCanonicalHost(next http.Handler) http.Handler {
	rules := s.canonicalHostRules()
	active := make([]hostRule, 0, len(rules))
	for _, r := range rules {
		if r.host != "" {
			active = append(active, r)
		}
	}
	if len(active) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := normalizeHost(r.Host)
		for _, rule := range active {
			if !rule.matches(r.URL.Path) {
				continue
			}
			if got != rule.host {
				// 421 Misdirected Request is the precise status: the request is
				// well-formed and may be perfectly valid — just not at this name.
				writeErr(w, http.StatusMisdirectedRequest, "wrong_host",
					"this path is served only on "+rule.host)
				return
			}
			break
		}
		next.ServeHTTP(w, r)
	})
}

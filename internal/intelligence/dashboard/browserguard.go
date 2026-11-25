package dashboard

import (
	"net"
	"net/http"
	"net/url"
	"strings"
)

// browserGuard defends the dashboard's loopback single-user deployment against
// two attacks that need no network access, only a web page the operator
// visits: CSRF (a malicious page drives a no-preflight POST to a state-changing
// endpoint — restart, config write, tool launch) and DNS rebinding (an attacker
// domain re-pointed at 127.0.0.1 becomes same-origin with the dashboard). It
// wraps the mux at ListenAndServe, where the bind address is known:
//   - unsafe methods (POST/PUT/DELETE/PATCH): the Origin (or Referer) header,
//     when present, must be same-host as the request Host, else 403. A
//     browser always sends Origin on a cross-origin POST, so this blocks CSRF;
//     non-browser clients (curl, the VS Code extension) send no Origin and are
//     unaffected.
//   - on a loopback bind (the default), EVERY request's Host header must name a
//     loopback host, else 403 — this defeats DNS rebinding, whose request
//     carries the attacker's own Host. A deliberately non-loopback bind can't
//     know its intended external host, so the Host allow-list is relaxed there
//     (start-up emits a WARN); the Origin/CSRF check still applies.
func browserGuard(next http.Handler, hostAllowed func(host string) bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqHost := hostnameOnly(r.Host)
		// Host allow-list (DNS-rebind defense). On a loopback bind the predicate
		// admits any loopback host; on a remote bind it admits ONLY the
		// configured/trusted hosts — NEVER "allow any Host" (plan §4.5, the
		// dashboard.go:494 relaxation fix). A nil predicate (defensive) rejects.
		if hostAllowed == nil || !hostAllowed(reqHost) {
			http.Error(w, "forbidden: unrecognized Host header", http.StatusForbidden)
			return
		}
		// The Origin/CSRF check applies to unsafe methods AND to WebSocket
		// upgrades (plan §4.5 — enforce Origin on WS upgrades too, the
		// CVE-2018-14732 class), in addition to coder/websocket.Accept's own
		// cross-origin reject.
		if isUnsafeMethod(r.Method) || isWebSocketUpgrade(r) {
			// CSRF / cross-origin: the Origin (or Referer), when present, must
			// be the daemon's OWN origin - scheme + host + port - not merely a
			// same hostname: every other localhost port is a different origin
			// (a dev server, another local app), and a hostname-only check
			// would let a page there drive this API. A "null" opaque origin is
			// treated as cross-origin. No Origin/Referer (curl, the CLI, the
			// VS Code extension host) passes: a browser always sends Origin on
			// an unsafe cross-origin request.
			if raw := requestOrigin(r); raw != "" && !originIsOwn(raw, r, hostAllowed) {
				http.Error(w, "forbidden: cross-origin request", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// isWebSocketUpgrade reports whether r is a WebSocket upgrade handshake:
// "websocket" as any token of any Upgrade header line, matched without
// case, the way coder/websocket's Accept reads it (an exact match on the
// first line alone let "Upgrade: h2c, websocket", or a second Upgrade line,
// pass as a plain GET and then upgrade; callerid fixes-1, H1).
func isWebSocketUpgrade(r *http.Request) bool {
	for _, line := range r.Header.Values("Upgrade") {
		for _, token := range strings.Split(line, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "websocket") {
				return true
			}
		}
	}
	return false
}

// hostAllowlistPredicate returns a Host-allow predicate for a remotely-exposed
// bind (plan §4.5): a request Host is allowed only if it case-insensitively
// matches one of the explicit allow-list entries (the configured bind address +
// [remote].trusted_hosts). Never admits an arbitrary Host.
func hostAllowlistPredicate(allowed []string) func(string) bool {
	set := make(map[string]struct{}, len(allowed))
	for _, h := range allowed {
		if hn := strings.ToLower(hostnameOnly(strings.TrimSpace(h))); hn != "" {
			set[hn] = struct{}{}
		}
	}
	return func(host string) bool {
		_, ok := set[strings.ToLower(host)]
		return ok
	}
}

// hostnameOnly strips the port (and IPv6 brackets) from a host[:port] value,
// returning the bare hostname/IP. It tolerates a missing port.
func hostnameOnly(hostport string) string {
	if hostport == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return strings.Trim(hostport, "[]")
}

// hostIsLoopback reports whether host is a loopback name or IP (localhost,
// 127.0.0.0/8, ::1).
func hostIsLoopback(host string) bool {
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// requestOrigin returns the request's Origin header, or its Referer as a
// fallback; empty when neither is present (a non-browser client).
func requestOrigin(r *http.Request) string {
	if o := r.Header.Get("Origin"); o != "" {
		return o
	}
	return r.Header.Get("Referer")
}

// loopbackAliases are the spellings of the local machine a browser may use
// for the daemon's own listener: the SAME port under another of these names
// is the same daemon (the SPA, the VS Code webview iframe at 127.0.0.1 and a
// `localhost` bookmark all reach it). Any other 127/8 address is not an
// alias: another process may hold that port there.
var loopbackAliases = map[string]bool{"localhost": true, "127.0.0.1": true, "::1": true}

// originCheck is one row of the same-origin rule table: an Origin is the
// daemon's own only when every row passes. Rows are walked top-down; the
// first failing row names why (tests pin one case per row).
type originCheck struct {
	name string
	ok   func(o parsedOrigin) bool
}

// parsedOrigin is the Origin/Referer and request facts the rows read.
type parsedOrigin struct {
	scheme      string // origin scheme (lower-case)
	host        string // origin hostname (lower-case, no brackets)
	authority   string // origin host:port with the scheme's default port elided
	reqHost     string // request Host hostname (lower-case)
	reqAuth     string // request Host host:port, default port (of scheme) elided
	reqTLS      bool   // the request arrived over TLS on this listener
	hostAllowed func(string) bool
}

var originChecks = []originCheck{
	{"an http(s) origin (not null, file:, or an extension scheme)", func(o parsedOrigin) bool {
		return (o.scheme == "http" || o.scheme == "https") && o.host != ""
	}},
	// A TLS listener's own origin is https. A plaintext listener may sit
	// behind a TLS terminator (tailscale serve, a reverse proxy), so its
	// public origin can be https; the port row below still binds it.
	{"scheme matches the listener", func(o parsedOrigin) bool {
		return !o.reqTLS || o.scheme == "https"
	}},
	{"origin host is an allowed Host", func(o parsedOrigin) bool {
		return o.hostAllowed(o.host)
	}},
	{"same host, or a loopback alias of the same listener", func(o parsedOrigin) bool {
		return o.host == o.reqHost || (loopbackAliases[o.host] && loopbackAliases[o.reqHost])
	}},
	{"same port", func(o parsedOrigin) bool {
		return portOf(o.authority) == portOf(o.reqAuth)
	}},
}

// originIsOwn reports whether raw (an Origin or Referer value) is the origin
// the browser used to reach THIS daemon: scheme, host and port, compared
// against the request's own Host (already vetted by the Host allow-list), so
// a port forward or a TLS-terminating front end keeps working while any
// other origin on the same machine - a different localhost port - does not.
func originIsOwn(raw string, r *http.Request, hostAllowed func(string) bool) bool {
	return originFailure(raw, r, hostAllowed) == ""
}

// originFailure is originIsOwn's table walk: "" when raw is the daemon's own
// origin, else the name of the first rule it fails.
func originFailure(raw string, r *http.Request, hostAllowed func(string) bool) string {
	if raw == "null" {
		return "an opaque (null) origin"
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "an origin without a host (unparseable, file:)"
	}
	scheme := strings.ToLower(u.Scheme)
	o := parsedOrigin{
		scheme:      scheme,
		host:        strings.ToLower(u.Hostname()),
		authority:   withPort(u.Host, scheme),
		reqHost:     strings.ToLower(hostnameOnly(r.Host)),
		reqAuth:     withPort(r.Host, scheme),
		reqTLS:      r.TLS != nil,
		hostAllowed: hostAllowed,
	}
	for _, c := range originChecks {
		if !c.ok(o) {
			return c.name
		}
	}
	return ""
}

// withPort returns hostport with an explicit port, filling the scheme's
// default (80 for http, 443 for https) when it carries none. The request
// Host of a same-origin request omits exactly the default port of the
// scheme the browser used, which is the origin's scheme.
func withPort(hostport, scheme string) string {
	if _, _, err := net.SplitHostPort(hostport); err == nil {
		return hostport
	}
	port := "80"
	if scheme == "https" {
		port = "443"
	}
	return net.JoinHostPort(strings.Trim(hostport, "[]"), port)
}

// portOf returns the port of a host:port value ("" when it has none).
func portOf(hostport string) string {
	_, p, err := net.SplitHostPort(hostport)
	if err != nil {
		return ""
	}
	return p
}

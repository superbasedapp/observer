package hostguard

import "net"

// IsLoopbackHost reports whether an HTTP Host header value targets loopback.
//
// It is the DNS-rebinding / cross-origin defense every loopback-bound ingest
// listener applies on top of its loopback BIND: a bind stops a remote socket,
// but it does not stop a page the developer's own browser loaded from
// evil.example (whose A record it re-points at 127.0.0.1) from POSTing to the
// listener with `Host: evil.example`. Comparing the Host header against the
// loopback vocabulary is what rejects that request, because the attacker
// controls the name, not the header the browser must send for it.
//
// The rules, deliberately narrow:
//
//   - An EMPTY host (HTTP/1.0 with no Host header) is loopback: the request
//     already reached a loopback-bound listener and carries no name to check.
//   - A bare "localhost" is loopback.
//   - Any other name is NOT loopback, even one that currently resolves to
//     127.0.0.1 — resolution is the attacker's input, so this never calls the
//     resolver.
//   - An IP host must parse and be in a loopback range (127/8, ::1).
//
// A "host:port" value is split first; a value that does not split is used
// whole, so a bare "localhost" or "127.0.0.1" works with or without a port.
//
// IPv6 needs one extra step. RFC 7230 lets a Host header carry a bracketed
// literal WITHOUT a port ("[::1]"), and that form defeats both of the steps
// above: net.SplitHostPort rejects it for having no port, so the brackets are
// never stripped, and net.ParseIP then rejects "[::1]" because ParseIP does not
// accept brackets. Without the explicit unwrap below a bare bracketed loopback
// literal would be judged NON-loopback and refused — a false positive against a
// perfectly legitimate local client.
func IsLoopbackHost(host string) bool {
	if host == "" {
		return true
	}
	h := host
	if hostOnly, _, err := net.SplitHostPort(host); err == nil {
		h = hostOnly
	} else if len(h) >= 2 && h[0] == '[' && h[len(h)-1] == ']' {
		// A bracketed IPv6 literal with no port — see the doc comment.
		h = h[1 : len(h)-1]
	}
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

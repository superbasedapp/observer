package proxy

import (
	"net/http"
	"net/url"
	"strings"
)

// Browser-provenance guard (security review 2026-09-27, SR27-B1).
//
// The proxy is a loopback API endpoint for CLI / SDK / editor clients. None of
// those send an Origin or Sec-Fetch-* header: those are set by a BROWSER, and a
// browser request can only reach 127.0.0.1:8820 because a web page the
// developer happens to have open told it to. That matters because the proxy
// can ADD a credential the page does not have - the org gateway's virtual key
// in AI-Gateway mode, or an operator key from a routing key_pool - so a
// no-preflight `text/plain` POST from any website would spend the developer's
// (or the org's) credential, and a DNS-rebound page (Host: rebind.evil:8820)
// could also read the answer.
//
// The rules below are an ORDERED table walked top-down (CLAUDE.md #5); the
// first row that matches refuses the request. Non-browser clients match no row
// and pass unchanged. An Origin with a non-web scheme (an Electron / desktop
// renderer: app://, vscode-file://, file://) is not something a web page can
// forge, so it passes; the opaque "null" origin CAN be produced by any page
// (a sandboxed iframe), so it is refused.

// browserRefusal is one row of the provenance table.
type browserRefusal struct {
	// name identifies the row in tests and in the refusal body.
	name string
	// match reports whether the row refuses r. hostCheck is whether the
	// Host header must name a loopback host (see Proxy.requireLoopbackHost).
	match func(r *http.Request, hostCheck bool) bool
}

// browserRefusals is the ordered provenance table.
var browserRefusals = []browserRefusal{
	{
		// DNS rebinding: a page on an attacker domain that re-resolves to
		// 127.0.0.1 still sends its own name as Host. Only enforced when the
		// listener is bound to loopback (a deliberately exposed bind is
		// reachable by name/IP from the network anyway).
		name: "non_loopback_host",
		match: func(r *http.Request, hostCheck bool) bool {
			return hostCheck && !hostIsLoopback(hostnameOnly(r.Host))
		},
	},
	{
		// The opaque origin: sandboxed iframes, data: URLs. Any page can mint it.
		name: "opaque_origin",
		match: func(r *http.Request, _ bool) bool {
			return strings.EqualFold(strings.TrimSpace(r.Header.Get("Origin")), "null")
		},
	},
	{
		// A web page (http/https origin) that is not itself on loopback.
		name: "cross_origin_web_page",
		match: func(r *http.Request, _ bool) bool {
			origin := strings.TrimSpace(r.Header.Get("Origin"))
			if origin == "" || strings.EqualFold(origin, "null") {
				return false
			}
			u, err := url.Parse(origin)
			if err != nil {
				return true // an unparseable Origin is not a client we serve
			}
			switch strings.ToLower(u.Scheme) {
			case "http", "https":
				return !hostIsLoopback(u.Hostname())
			default:
				return false // desktop / editor renderer scheme
			}
		},
	},
	{
		// A cross-site request that carries no Origin (a no-cors GET/HEAD, an
		// <img>/<script> subresource, a navigation). Only browsers send
		// Sec-Fetch-Site.
		name: "cross_site_fetch",
		match: func(r *http.Request, _ bool) bool {
			return r.Header.Get("Origin") == "" &&
				strings.EqualFold(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")), "cross-site")
		},
	},
}

// browserProvenanceRefusal returns the name of the first provenance row that
// refuses r, or "" when the request may proceed.
func browserProvenanceRefusal(r *http.Request, hostCheck bool) string {
	for _, row := range browserRefusals {
		if row.match(r, hostCheck) {
			return row.name
		}
	}
	return ""
}

// writeBrowserRefusal answers a refused browser request. No CORS headers are
// set, so a cross-origin page can neither read this answer nor pass a preflight.
func writeBrowserRefusal(w http.ResponseWriter, reason string) {
	http.Error(w, "forbidden: the observer proxy does not accept browser requests from other origins ("+reason+")", http.StatusForbidden)
}

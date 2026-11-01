package proxy

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// routelanes.go: node-local ROUTE LANES (lane P1, managed route maintenance).
//
// On a managed node the daemon routes a coding agent whose provider is a
// third-party OpenAI-compatible host (Qwen Code on OpenRouter, a Kimi Code
// custom provider) through the proxy by rewriting the tool's base URL to
// http://127.0.0.1:<port>/up/<id>/<the provider's own path>. When the host is
// one of the registry's built-in agent lanes (Options.AgentUpstreams) that
// lane is used. Otherwise the route needs a lane of its own: a route lane,
// whose id always starts with RouteLanePrefix and whose upstream is the exact
// host root the tool talked to before. The routes and their lanes are owned by
// the route-provenance file (internal/proxyroute); the daemon installs them
// here at start, before the listener accepts, and when it writes a new one.
//
// Precedence: an id carrying RouteLanePrefix resolves to its route lane
// FIRST, because the route was written to reach exactly the host it records;
// every other id resolves as before ([proxy.upstreams] / gateway.providers,
// then the built-in agent lanes) and a route lane can never answer for it. A
// route lane is a coding-agent lane (it only selects the upstream; parsing is
// by path shape).

// RouteLanePrefix starts every route lane id.
const RouteLanePrefix = "route-"

// SetRouteLanes atomically replaces the node-local route lanes. All or
// nothing: an id without RouteLanePrefix, or an upstream that does not parse
// as an https host root, leaves the previous set serving and is returned as
// an error. A nil or empty map clears them.
func (p *Proxy) SetRouteLanes(lanes map[string]string) error {
	next := map[string]*url.URL{}
	ids := make([]string, 0, len(lanes))
	for id := range lanes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if !strings.HasPrefix(id, RouteLanePrefix) || len(id) == len(RouteLanePrefix) || strings.ContainsAny(id, "/?#") {
			return fmt.Errorf("proxy.SetRouteLanes: %q is not a route lane id", id)
		}
		u, err := parseUpstream("route_lane:"+id, lanes[id], "")
		if err != nil {
			return fmt.Errorf("proxy.SetRouteLanes: %w", err)
		}
		if u.Scheme != "https" {
			return fmt.Errorf("proxy.SetRouteLanes: route lane %q must use https", id)
		}
		next[id] = u
	}
	p.routeLanes.Store(&next)
	return nil
}

// ResolvableLanes is the set of `/up/<id>/` ids this proxy resolves now
// (Lanes, as a set), for a caller that must not route a tool at a lane that
// would be refused.
func (p *Proxy) ResolvableLanes() map[string]bool {
	out := map[string]bool{}
	for _, id := range p.Lanes().Lanes {
		out[id] = true
	}
	return out
}

// routeLane returns the route lane for id, or nil.
func (p *Proxy) routeLane(id string) *url.URL {
	if !strings.HasPrefix(id, RouteLanePrefix) {
		return nil
	}
	m := p.routeLanes.Load()
	if m == nil {
		return nil
	}
	return (*m)[id]
}

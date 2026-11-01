package proxy

import (
	"encoding/json"
	"net"
	"net/http"
	"sort"
)

// lanesPath is the proxy's local lane-introspection endpoint (T-308). A
// launcher asks the RUNNING daemon which `/up/<id>/` lanes it can route
// before it starts a vendor tool on one, instead of resolving only the
// config file and the registry's built-ins: an org-distributed
// gateway.providers lane table (installed live through SetLaneTable /
// SetRoutingSnapshot) exists nowhere in config. It shares healthz's "/-/"
// prefix, which no provider path or lane address can produce.
const lanesPath = "/-/lanes"

// LaneInfo is the /-/lanes body. Lanes are lane IDS only, never upstream
// URLs: a launcher needs to know whether a lane resolves, not where it
// points, and an id list discloses nothing a lane address does not already
// carry.
type LaneInfo struct {
	// Lanes is every id `/up/<id>/` resolves on this proxy right now: the
	// live hosted lane table (config [proxy.upstreams] or the org's
	// gateway.providers table, whichever is installed) plus the coding-agent
	// lanes (registry built-ins under [proxy.agent_upstreams]). Sorted,
	// deduplicated.
	Lanes []string `json:"lanes"`
	// AutoDefaultLane is the live table's default lane for the virtual
	// "auto" lane ("" when none is set).
	AutoDefaultLane string `json:"auto_default_lane,omitempty"`
}

// Lanes returns the lane ids this proxy resolves right now (LaneInfo's
// contract), from ONE lane snapshot.
func (p *Proxy) Lanes() LaneInfo {
	t := p.laneSnapshot()
	seen := map[string]bool{}
	var ids []string
	add := func(id string) {
		if id == "" || seen[id] {
			return
		}
		seen[id] = true
		ids = append(ids, id)
	}
	for id, u := range t.upstreams {
		if u != nil {
			add(id)
		}
	}
	for id, u := range p.agentUpstreams {
		if u != nil {
			add(id)
		}
	}
	if m := p.routeLanes.Load(); m != nil {
		for id, u := range *m {
			if u != nil {
				add(id)
			}
		}
	}
	if len(t.upstreams) > 0 {
		add(autoLaneID)
	}
	sort.Strings(ids)
	if ids == nil {
		ids = []string{}
	}
	return LaneInfo{Lanes: ids, AutoDefaultLane: t.autoDefault}
}

// serveLanes answers GET /-/lanes with the LaneInfo JSON; any other method
// is 405. Like healthz it never touches an upstream or records a turn.
func (p *Proxy) serveLanes(w http.ResponseWriter, r *http.Request) {
	// Loopback peers only: a proxy bound beyond loopback (a hosted gateway)
	// must not list its lanes to the network. A launcher always asks
	// 127.0.0.1.
	if !loopbackPeer(r.RemoteAddr) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(p.Lanes())
}

// loopbackPeer reports whether remoteAddr (host:port) is a loopback address.
func loopbackPeer(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

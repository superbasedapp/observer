//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"sort"
	"sync/atomic"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/proxyroute"
	"github.com/marmutapp/superbased-observer/internal/routeprov"
)

// sandbox_provider_hosts.go is the one seam that lists the extra model
// provider hosts a sandboxed run's provider block refuses beside the closed
// list (sandboxvocab.ModelProviderHosts), lane FU8, ledger OSH-43 (sweep
// E4). Three sources, each read where its owner keeps it:
//
//   - the config: [proxy.upstreams], [proxy.agent_upstreams] and the
//     [proxy.org_route] bootstrap (proxyUpstreamHosts);
//   - the recorded route lanes: the third-party-provider lanes the managed
//     daemon wrote, read from the route-provenance file, the one owner of
//     which lanes exist (proxyroute.Registrar.RouteLanes);
//   - the live lane table: the daemon proxy's /up/<id> lanes, which the
//     signed gateway.providers family installs without touching the config
//     file, and the org-route primary and fallbacks it installs with them.
//
// The live source exists only inside the daemon (bindSandboxLiveProviderHosts
// from `observer start`); a CLI launch reads the first two.

// sandboxLiveProviderSource returns the live lane table's upstream base URLs.
type sandboxLiveProviderSource func() []string

// sandboxLiveProviderHosts is the daemon's live source; nil outside it.
var sandboxLiveProviderHosts atomic.Pointer[sandboxLiveProviderSource]

// sandboxRouteLaneRoots reads the recorded route lanes' upstream roots for
// the proxy on port. A var so tests never read the real home's provenance.
var sandboxRouteLaneRoots = func(port int) []string {
	if port <= 0 || port > 65535 {
		port = defaultSandboxProxyPort
	}
	reg, err := proxyroute.NewRegistrar(proxyroute.RegisterOptions{ProxyPort: port, Writer: routeprov.WriterManaged})
	if err != nil {
		return nil
	}
	lanes, err := reg.RouteLanes()
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(lanes))
	for _, root := range lanes {
		out = append(out, root)
	}
	return out
}

// sandboxLaneTableSource is the part of the daemon proxy the live source
// reads.
type sandboxLaneTableSource interface {
	LaneTable() (upstreams map[string]string, autoDefaultLane string)
}

// sandboxOrgRouteSource is the optional org-route read (*proxy.Proxy has
// it; the inert stand-in does not).
type sandboxOrgRouteSource interface {
	OrgRoute() (mode, primary string, fallbacks []string, generation uint64)
}

// bindSandboxLiveProviderHosts binds the live source to the daemon's proxy.
// A nil proxy clears it.
func bindSandboxLiveProviderHosts(p sandboxLaneTableSource) {
	if p == nil {
		sandboxLiveProviderHosts.Store(nil)
		return
	}
	src := sandboxLiveProviderSource(func() []string {
		lanes, _ := p.LaneTable()
		out := make([]string, 0, len(lanes)+2)
		for _, u := range lanes {
			out = append(out, u)
		}
		if or, ok := p.(sandboxOrgRouteSource); ok {
			if _, primary, fallbacks, _ := or.OrgRoute(); primary != "" {
				out = append(out, primary)
				out = append(out, fallbacks...)
			}
		}
		return out
	})
	sandboxLiveProviderHosts.Store(&src)
}

// sandboxDynamicProviderHosts lists the hosts of the recorded route lanes
// and the live lane table, read now.
func sandboxDynamicProviderHosts(port int) []string {
	var urls []string
	urls = append(urls, sandboxRouteLaneRoots(port)...)
	if src := sandboxLiveProviderHosts.Load(); src != nil && *src != nil {
		urls = append(urls, (*src)()...)
	}
	return providerHostsOfURLs(urls)
}

// sandboxProviderHosts is every extra provider host, from every source,
// sorted and deduplicated: the one seam the provider block and the refusal
// advisor read.
func sandboxProviderHosts(p config.ProxyConfig) []string {
	return mergeProviderHosts(proxyUpstreamHosts(p), sandboxDynamicProviderHosts(p.Port))
}

// mergeProviderHosts returns the sorted, deduplicated union.
func mergeProviderHosts(lists ...[]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range lists {
		for _, h := range l {
			if h != "" && !seen[h] {
				seen[h] = true
				out = append(out, h)
			}
		}
	}
	sort.Strings(out)
	return out
}

// providerHostList is the run's extra provider hosts at launch: the
// config's snapshot taken when the runtime was built (providerHosts) and
// the dynamic sources read now, so a lane the organization installs after
// the runtime was built is refused from the next launch on.
func (r *sandboxRuntime) providerHostList() []string {
	return mergeProviderHosts(r.providerHosts, sandboxDynamicProviderHosts(r.proxyPort))
}

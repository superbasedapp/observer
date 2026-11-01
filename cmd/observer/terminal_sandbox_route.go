//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/proxyroute"
)

// terminal_sandbox_route.go decides whether a sandboxed launch will actually
// be proxy-routed (lane sbx-p1a2, audit finding P-006 (2)). The inner
// `observer <verb>` launcher picks the route at run time; the sandbox has to
// know the same answer at prepare time, because it decides the capture level
// (C3 versus C6) and whether the egress gateway refuses the model-provider
// hosts. Reading the registry row alone was wrong: a build without
// capture.proxy, a node whose proxy is off, a conditional (gated) route and
// a tool the operator deliberately points at another provider (the inner
// claude launcher honours a third-party route and launches direct) all run
// unrouted, and blocking the provider hosts there only produces 403s and a
// false "full" claim.
//
// Lane sbx-p2 (decision log P-017 (a)): the third-party check now reads the
// tool's EFFECTIVE route over the run's workspace directory, through the same
// resolver the inner launcher uses (every settings scope it honours: managed,
// the operator's own --settings, project-local, project and user), so a
// project-scoped third-party route is seen as one. The resolver is picked by
// the route's capability shape (sandboxEffectiveRouteReaders, keyed on the
// RouteKind and env var), never by the tool name.

// sandboxRouteInput is the capability-shaped facts of one launch's route.
type sandboxRouteInput struct {
	// HasRoute: the tool's registry row carries a proxy route.
	HasRoute bool
	// Gated: the route is conditional (ProxyRoute.Gate): the launcher
	// applies it only when the environment holds the developer's own
	// provider credential, which the daemon cannot see at prepare time.
	Gated bool
	// ProxyServing: this node serves the API proxy (proxyServingReason is
	// empty: capture.proxy compiled in and active, [proxy].enabled on) and,
	// on the CLI path, the proxy answers now (P-017 (b)).
	ProxyServing bool
	// PersistedElsewhere: the tool's own persisted config points it at a
	// host other than Observer (proxyroute.RouteDrifted), which the inner
	// launcher honours as the operator's deliberate choice.
	PersistedElsewhere bool
	// EffectiveThirdParty: the tool's effective route over the workspace
	// (any settings scope the inner launcher reads) points at a host other
	// than Observer, so the inner launcher launches direct.
	EffectiveThirdParty bool
	// EffectiveUnknown: the effective route could not be read (the
	// operator's own --settings is unreadable); the inner launcher refuses
	// or launches without proving the route, so no full claim is made.
	EffectiveUnknown bool
}

// sandboxRouteRule is one row of the ordered route table.
type sandboxRouteRule struct {
	id       string
	unrouted func(sandboxRouteInput) bool
}

// sandboxRouteRules is walked top-down; the first row that holds makes the
// launch unrouted and names why. No row holding means routed.
var sandboxRouteRules = []sandboxRouteRule{
	{"no-route", func(in sandboxRouteInput) bool { return !in.HasRoute }},
	{"proxy-not-serving", func(in sandboxRouteInput) bool { return !in.ProxyServing }},
	{"route-gated", func(in sandboxRouteInput) bool { return in.Gated }},
	{"persisted-elsewhere", func(in sandboxRouteInput) bool { return in.PersistedElsewhere }},
	{"effective-third-party", func(in sandboxRouteInput) bool { return in.EffectiveThirdParty }},
	{"effective-unknown", func(in sandboxRouteInput) bool { return in.EffectiveUnknown }},
}

// decideSandboxRoute returns whether the launch is proxy-routed and, when
// it is not, the id of the rule that said so.
func decideSandboxRoute(in sandboxRouteInput) (bool, string) {
	for _, r := range sandboxRouteRules {
		if r.unrouted(in) {
			return false, r.id
		}
	}
	return true, ""
}

// effectiveRouteClass is what an effective-route reader found.
type effectiveRouteClass int

const (
	// effectiveRouteOurs: no scope routes elsewhere (no route, an Observer
	// route, or an empty value the launcher re-pins to the proxy).
	effectiveRouteOurs effectiveRouteClass = iota
	// effectiveRouteThirdParty: a scope routes to another host.
	effectiveRouteThirdParty
	// effectiveRouteUnknown: a scope could not be read.
	effectiveRouteUnknown
)

// effectiveRouteReader reads one route mechanism's effective route for a
// launch running in dir with the tool's own args.
type effectiveRouteReader func(proxyURL, dir string, args []string) effectiveRouteClass

// effectiveRouteKey is the capability shape a reader is chosen by.
type effectiveRouteKey struct {
	kind   integration.RouteKind
	envVar string
}

// sandboxEffectiveRouteReaders maps a route's capability shape to the
// resolver its inner launcher uses. A route shape with no row has no
// settings scopes beyond what InspectRoutes already reads.
var sandboxEffectiveRouteReaders = map[effectiveRouteKey]effectiveRouteReader{
	// The settings-file env route (Claude Code's ANTHROPIC_BASE_URL across
	// managed, --settings, local, project and user scopes).
	{integration.RouteEnvSettings, "ANTHROPIC_BASE_URL"}: func(proxyURL, dir string, args []string) effectiveRouteClass {
		res := resolveClaudeEffectiveRoute(proxyURL, dir, args)
		switch {
		case res.cliUnreadable, res.userUnreadable != "":
			return effectiveRouteUnknown
		case res.class == claudeRouteThirdParty:
			return effectiveRouteThirdParty
		}
		return effectiveRouteOurs
	},
}

// readEffectiveRoute is the default effective-route seam of a runtime.
func readEffectiveRoute(spec integration.Capability, proxyURL, dir string, args []string) effectiveRouteClass {
	if spec.Proxy == nil {
		return effectiveRouteOurs
	}
	read, ok := sandboxEffectiveRouteReaders[effectiveRouteKey{spec.Proxy.Kind, spec.Proxy.EnvVar}]
	if !ok {
		return effectiveRouteOurs
	}
	return read(proxyURL, dir, args)
}

// launchRouted answers decideSandboxRoute for tool on this runtime, for a
// launch running in dir with the tool's own args. The persisted-route and
// effective-route inspections run only when the earlier rows leave the
// launch routed.
func (r *sandboxRuntime) launchRouted(tool, dir string, args []string) (bool, string) {
	spec, _ := integration.For(tool)
	in := sandboxRouteInput{
		HasRoute:     spec.Proxy != nil,
		Gated:        spec.Proxy != nil && spec.Proxy.Gate != nil,
		ProxyServing: r.proxyServing,
	}
	if routed, rule := decideSandboxRoute(in); !routed {
		return false, rule
	}
	if r.inspectRoutes != nil {
		for _, st := range r.inspectRoutes() {
			if st.Tool == tool && st.State == proxyroute.RouteDrifted {
				in.PersistedElsewhere = true
				break
			}
		}
	}
	if r.effectiveRoute != nil {
		switch r.effectiveRoute(spec, resolveProxyURL(r.proxyPort, ""), dir, args) {
		case effectiveRouteThirdParty:
			in.EffectiveThirdParty = true
		case effectiveRouteUnknown:
			in.EffectiveUnknown = true
		}
	}
	return decideSandboxRoute(in)
}

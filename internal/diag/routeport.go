package diag

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/proxyroute"
	"github.com/marmutapp/superbased-observer/internal/remedy"
)

// checkRoutePort flags a persisted proxy route that points at a loopback
// port other than [proxy].port (U9, lane FIX-UPGRADE). `observer init`
// treats any loopback route as already set, so after a port change the
// route keeps the old port and every routed request fails to connect; only
// a forced route rewrite moves it. The fix names that exact command.
func checkRoutePort(homeDir string, cfg config.Config) Check {
	const name = "proxy.route_port"
	want := cfg.Proxy.Port
	if want <= 0 {
		return Check{Name: name, Status: StatusOK, Message: "[proxy].port is not set: route ports not compared"}
	}
	ports := proxyroute.ObserverRoutePorts(homeDir)
	var tools []string
	for tool, p := range ports {
		if p != want {
			tools = append(tools, tool)
		}
	}
	if len(tools) == 0 {
		if len(ports) == 0 {
			return Check{Name: name, Status: StatusOK, Message: "no tool routes through a local Observer proxy"}
		}
		return Check{Name: name, Status: StatusOK, Message: fmt.Sprintf("every local proxy route uses [proxy].port %d", want)}
	}
	sort.Strings(tools)
	var details, fixes []string
	var rems []remedy.Remediation
	for _, tool := range tools {
		details = append(details, fmt.Sprintf("%s routes to port %d", tool, ports[tool]))
		r := remedy.Of(remedy.InitToolRoute, tool)
		cmd := remedy.Command(r)
		if strings.Contains(cmd, "--all") {
			// No per-tool selector: a forced --all would rewrite every
			// tool's route, so point at the dashboard control instead.
			fixes = append(fixes, fmt.Sprintf("%s: set its route again from Settings > Connected tools", tool))
			continue
		}
		fixes = append(fixes, fmt.Sprintf("`%s --proxy-port %d --force`", cmd, want))
		rems = append(rems, r)
	}
	return Check{
		Name: name, Status: StatusWarn,
		Message: fmt.Sprintf("%d route(s) point at another port than [proxy].port %d, so their requests do not reach this proxy - fix with %s (turn the route off in any live session first)",
			len(tools), want, strings.Join(fixes, "; ")),
		Details:      details,
		Remediations: rems,
	}
}

// routedThroughLane reports whether tool's persisted route on homeDir ("" =
// the running user's home) is a third-party-provider route lane.
func routedThroughLane(tool, homeDir string) bool {
	if homeDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return false
		}
		homeDir = home
	}
	return proxyroute.LaneRoutedTools(homeDir)[tool]
}

// checkRouteHost flags a persisted proxy route that points at another host
// than an Observer proxy (T-903, RETEST5 F2): its requests bypass this proxy,
// and on a managed node whose routes are maintained the organization sees it
// as route drift, which the daemon never overwrites. A tool on its own
// third-party provider that a managed node would carry through a route lane
// is only a warning where routes are maintained; elsewhere it is the
// developer's setup and reads OK. Only the tool name is printed, never the
// configured URL.
//
// The node's component selection (sel, the one route maintenance acts on) is
// read through proxyroute's own drift table, never a second copy of it: a
// tool the policy did not select is never routed by route maintenance, so
// its host is never route drift and the row names it "not selected by
// policy" (T-915, D-770); with the route writer component not active the
// node keeps no routes at all, and the row says "routing is switched off by
// policy" naming the installed tools (D-771). Neither raises the status.
//
// A route whose file Observer cannot name (proxyroute.RouteUnknown: a
// relocation variable holds a relative path) is named with its variable and
// raises the status to a warning (withUnknownRoutes, R-188 F6).
func checkRouteHost(homeDir string, sel proxyroute.Selection) Check {
	routes := proxyroute.InspectRoutes(homeDir)
	return withUnknownRoutes(routeHostCheck(homeDir, routes, sel), routes)
}

// withUnknownRoutes adds the routes whose file Observer cannot name
// (proxyroute.RouteUnknown) to c: the tool reads a relative relocation
// variable against its own working directory, so Observer read no route
// there and reports none as present. Only the tool and the variable name
// are printed, never the value. A route file that cannot be named raises an
// OK check to a warning.
func withUnknownRoutes(c Check, routes []proxyroute.RouteStatus) Check {
	var tools []string
	for _, st := range routes {
		if st.State != proxyroute.RouteUnknown {
			continue
		}
		tools = append(tools, st.Tool)
		if st.UnresolvedBy != "" {
			c.Details = append(c.Details, st.Tool+": its route file is unknown because "+st.UnresolvedBy+" is set to a relative path, which the tool reads against its own working directory; Observer read and wrote no route for it (set an absolute path)")
			continue
		}
		c.Details = append(c.Details, st.Tool+": its route file has no path on this OS; Observer read no route for it")
	}
	if len(tools) == 0 {
		return c
	}
	sort.Strings(tools)
	c.Message += "; route file unknown, so not read: " + strings.Join(tools, ", ")
	if c.Status == StatusOK {
		c.Status = StatusWarn
	}
	return c
}

// routeHostCheck is checkRouteHost over inspected routes.
func routeHostCheck(homeDir string, routes []proxyroute.RouteStatus, sel proxyroute.Selection) Check {
	const name = "proxy.route_host"
	maintained := proxyroute.ManagedRoutesMaintained(homeDir)
	read := proxyroute.DriftPolicy{Mode: proxyroute.DriftModeMaintained, Selection: sel}
	if proxyroute.RoutingSwitchedOff(read) {
		return routingOffRouteHost(name, routes, read)
	}
	notSelected := map[string]bool{}
	for _, tool := range proxyroute.UnselectedTools(routes, read) {
		notSelected[tool] = true
	}
	var bypass, lane, unselected []string
	for _, st := range routes {
		if st.State != proxyroute.RouteDrifted {
			continue
		}
		if notSelected[st.Tool] {
			unselected = append(unselected, st.Tool)
			continue
		}
		if st.LaneWritable {
			lane = append(lane, st.Tool)
			continue
		}
		bypass = append(bypass, st.Tool)
	}
	sort.Strings(bypass)
	sort.Strings(lane)
	sort.Strings(unselected)
	var unselectedNote string
	var unselectedDetails []string
	if len(unselected) > 0 {
		unselectedNote = "not selected by policy: " + strings.Join(unselected, ", ") +
			" (installed and talking to another host, but Observer does not route a tool the policy did not select, so this is not route drift)"
		for _, tool := range unselected {
			unselectedDetails = append(unselectedDetails, tool+" is not selected by policy; Observer does not route it, so its host is not route drift")
		}
	}
	if len(bypass) == 0 && len(lane) == 0 {
		if unselectedNote != "" {
			return Check{Name: name, Status: StatusOK, Message: "no tool Observer routes points at another host; " + unselectedNote, Details: unselectedDetails}
		}
		return Check{Name: name, Status: StatusOK, Message: "no tool routes to another host than an Observer proxy"}
	}
	var details, fixes []string
	var rems []remedy.Remediation
	for _, tool := range bypass {
		details = append(details, tool+" routes to another host, not to this Observer proxy")
		r := remedy.Of(remedy.InitToolRoute, tool)
		cmd := remedy.Command(r)
		if strings.Contains(cmd, "--all") {
			fixes = append(fixes, tool+": set its route again from Settings > Connected tools")
			continue
		}
		fixes = append(fixes, "`"+cmd+" --force`")
		rems = append(rems, r)
	}
	for _, tool := range lane {
		details = append(details, tool+" talks to its own provider directly; a managed node that keeps routes carries it through a proxy route lane to the same provider")
	}
	status := StatusWarn
	if len(bypass) == 0 && !maintained {
		status = StatusOK
	}
	all := append(append([]string(nil), bypass...), lane...)
	sort.Strings(all)
	msg := fmt.Sprintf("%d route(s) point at another host than an Observer proxy, so their requests bypass it: %s", len(all), strings.Join(all, ", "))
	if maintained {
		msg += "; this node keeps routes for your organization, which sees this as route drift (another host is never overwritten)"
	}
	if len(fixes) > 0 {
		msg += " - if that host is not intended, fix with " + strings.Join(fixes, "; ") + " (turn the route off in any live session first)"
	}
	if unselectedNote != "" {
		msg += "; " + unselectedNote
		details = append(details, unselectedDetails...)
	}
	return Check{Name: name, Status: status, Message: msg, Details: details, Remediations: rems}
}

// routingOffRouteHost is proxy.route_host on a node whose route writer
// component is not active (D-771): Observer keeps no AI tool routes there, so
// no route is drift, wherever it points. It names the installed tools (the
// ones RoutingOffTools reads) and, per tool on another host, says why that is
// not drift. Always OK: it is the policy's choice, not a defect.
func routingOffRouteHost(name string, routes []proxyroute.RouteStatus, read proxyroute.DriftPolicy) Check {
	msg := "routing is switched off by policy on this machine (the proxy routing component is not active): Observer keeps no AI tool routes, so no route is drift"
	if tools := proxyroute.RoutingOffTools(routes, read); len(tools) > 0 {
		msg += "; installed: " + strings.Join(tools, ", ")
	}
	var details []string
	for _, st := range routes {
		if st.State == proxyroute.RouteDrifted {
			details = append(details, st.Tool+" talks to another host; routing is switched off by policy, so this is not route drift")
		}
	}
	sort.Strings(details)
	return Check{Name: name, Status: StatusOK, Message: msg, Details: details}
}

package diag

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/routeattest"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// route.observed: per-surface proxy traffic truth (surface-gap arc Wave 1,
// findings OBS-2, CX-6 and CLI-11; docs/audits/surface-settings-precedence-
// gap-review-2026-10-25.md section 3.2). It replaced the "proxy routing gap"
// check, which knew two tools by name, compared a day of actions against a
// day of API turns per provider, warned only at zero and blamed every gap
// on a down proxy. This check reads no settings file and names no tool: it
// counts SESSIONS per (tool, surface, surface_host) group in the node store
// (store.RouteObservedSince), judges each group with
// routeattest.AttestSurfaces against the registry's per-surface route facts
// (Capability.RouteSurfaces), and warns only on an observed bypass of a
// routable surface (SurfaceVerdict.ObservedBypass). It does not filter on
// Capability.Proxy, so probe_required tools are judged too.

// routeObservedName is the check's id.
const routeObservedName = "route.observed"

// checkRouteObserved runs route.observed over the sessions that started in
// the routeattest.ObservedWindow before now. A nil policy judges against
// the registry (routeattest.RegistrySurfacePolicy).
func checkRouteObserved(ctx context.Context, database *sql.DB, now time.Time, policy routeattest.SurfacePolicy) Check {
	if database == nil {
		return Check{Name: routeObservedName, Status: StatusFail, Message: "no database handle"}
	}
	rows, err := store.New(database).RouteObservedSince(ctx, now.Add(-routeattest.ObservedWindow))
	if err != nil {
		return Check{Name: routeObservedName, Status: StatusFail, Message: "query sessions: " + err.Error()}
	}
	if len(rows) == 0 {
		return Check{
			Name: routeObservedName, Status: StatusOK,
			Message: fmt.Sprintf("no sessions recorded in the %dd window - nothing to judge", int(routeattest.ObservedWindow/(24*time.Hour))),
		}
	}
	return routeObservedReport(ObservedSurfaceVerdicts(rows, policy))
}

// ObservedSurfaceVerdicts judges the store's session groups the way
// route.observed does: each declared surface of a tool with sessions is
// added as unobserved (routeattest.WithDeclaredSurfaces), then every group
// goes through routeattest.AttestSurfaces. A nil policy judges against the
// registry. The managed-integrity report (OBS-6) calls it too, so the doctor
// and the organization judge one node the same way.
func ObservedSurfaceVerdicts(rows []store.RouteObservedRow, policy routeattest.SurfacePolicy) []routeattest.SurfaceVerdict {
	return routeattest.AttestSurfaces(observedTraffic(rows), policy)
}

// observedTraffic turns the store's session groups into AttestSurfaces
// input, with routeattest.WithDeclaredSurfaces adding an unobserved group
// for each declared surface of a tool this node has sessions for.
func observedTraffic(rows []store.RouteObservedRow) []routeattest.SurfaceTraffic {
	out := make([]routeattest.SurfaceTraffic, 0, len(rows))
	for _, r := range rows {
		out = append(out, routeattest.SurfaceTraffic{
			Tool: r.Tool, Kind: r.Surface, Host: r.SurfaceHost,
			Sessions: r.Sessions, ProxiedSessions: r.ProxiedSessions,
		})
	}
	return routeattest.WithDeclaredSurfaces(out)
}

// surfaceLabel names a session group as tool/kind[ (host)].
func surfaceLabel(v routeattest.SurfaceVerdict) string {
	kind := v.Kind
	if kind == "" {
		kind = "unstamped"
	}
	label := v.Tool + "/" + kind
	if v.Host != "" {
		label += " (" + v.Host + ")"
	}
	return label
}

// routeObservedReport folds the verdicts into one check: WARN when any
// routable surface was observed bypassing the proxy or a row was invalid,
// OK otherwise. Every verdict is a detail line, so a bypass of a surface
// that is not yet routable (reported, never warned) is still visible.
func routeObservedReport(verdicts []routeattest.SurfaceVerdict) Check {
	var bypassed, invalid []string
	counts := map[routeattest.SurfaceState]int{}
	details := make([]string, 0, len(verdicts)+2)
	for _, v := range verdicts {
		counts[v.State]++
		line := fmt.Sprintf("%s: %s - %s", surfaceLabel(v), v.State, v.Reason)
		switch {
		case v.ObservedBypass():
			bypassed = append(bypassed, surfaceLabel(v))
			line += " [routable surface: bypass]"
		case v.State == routeattest.SurfaceInvalidInput:
			invalid = append(invalid, surfaceLabel(v))
		}
		details = append(details, line)
	}
	summary := stateSummary(counts)
	if len(bypassed) > 0 || len(invalid) > 0 {
		var msg []string
		if len(bypassed) > 0 {
			msg = append(msg, fmt.Sprintf("%d routable surface(s) ran sessions that never reached this machine's proxy: %s", len(bypassed), strings.Join(bypassed, ", ")))
			details = append(details,
				"a bypassed surface either is not routed (its own config or the app ignores the route) or ran while the proxy was down; route that surface, or launch it through the observer wrapper, then check again")
		}
		if len(invalid) > 0 {
			msg = append(msg, fmt.Sprintf("%d session group(s) had invalid counts: %s", len(invalid), strings.Join(invalid, ", ")))
		}
		return Check{Name: routeObservedName, Status: StatusWarn, Message: strings.Join(msg, "; ") + " (" + summary + ")", Details: details}
	}
	return Check{Name: routeObservedName, Status: StatusOK, Message: "no observed bypass of a routable surface (" + summary + ")", Details: details}
}

// stateSummary renders the per-state counts in rule-table order, with the
// window, e.g. "7d: 2 attested, 1 unknown_measurability".
func stateSummary(counts map[routeattest.SurfaceState]int) string {
	order := []routeattest.SurfaceState{
		routeattest.SurfaceInvalidInput, routeattest.SurfaceUnknownSurface, routeattest.SurfaceExempt,
		routeattest.SurfaceUnobserved, routeattest.SurfaceUnknownMeasurability, routeattest.SurfaceNotMeasurable,
		routeattest.SurfaceBypassSuspect, routeattest.SurfacePartial, routeattest.SurfaceAttested,
	}
	var parts []string
	for _, st := range order {
		if n := counts[st]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, st))
		}
	}
	return fmt.Sprintf("last %dd: %s", int(routeattest.ObservedWindow/(24*time.Hour)), strings.Join(parts, ", "))
}

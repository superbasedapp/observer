package diag

import (
	"fmt"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/proxyroute"
	"github.com/marmutapp/superbased-observer/internal/remedy"
)

// checkRecordedRoutes reports, per route the route-provenance file says
// Observer wrote or confirmed, whether that route is still in its config file
// (surface-gap FU-77, the doctor half of audit finding 3). A tool that writes
// its whole settings file back from memory while it runs (Cline's
// globalState.json) can drop Observer's member after a successful write, and
// nothing else notices: the tool simply stops reaching the proxy.
//
// The reading is proxyroute.RecordedRoutes, which dispatches on each tool's
// route shape (the reader Leave uses), never on a tool name. No record means
// no row. Only the tool, the config path and the setting name are printed,
// never the configured value.
//
// Named "<tool>.proxy.route_recorded" so `observer doctor cline` and
// `observer doctor proxy` both scope to it; an unreadable provenance file is
// the one "proxy.route_recorded" row.
func checkRecordedRoutes(homeDir string) []Check {
	const name = "proxy.route_recorded"
	routes, err := proxyroute.RecordedRoutes(homeDir)
	if err != nil {
		return []Check{{
			Name: name, Status: StatusWarn,
			Message: "the route-provenance file could not be read, so the proxy routes Observer wrote cannot be checked: " + err.Error(),
		}}
	}
	out := make([]Check, 0, len(routes))
	for _, rr := range routes {
		out = append(out, recordedRouteCheck(rr))
	}
	return out
}

// recordedRouteCheck renders one recorded route.
func recordedRouteCheck(rr proxyroute.RecordedRoute) Check {
	name := rr.Tool + ".proxy.route_recorded"
	setting := rr.Setting
	if setting == "" {
		setting = "the proxy route"
	}
	details := []string{fmt.Sprintf("%s: %s in %s, recorded as written by %s", rr.Tool, setting, rr.ConfigPath, writerOrUnknown(string(rr.Writer)))}
	switch rr.State {
	case proxyroute.RecordedRoutePresent:
		return Check{
			Name: name, Status: StatusOK, Details: details,
			Message: fmt.Sprintf("the proxy route Observer wrote is still in %s", rr.ConfigPath),
		}
	case proxyroute.RecordedRouteConfigGone:
		return Check{
			Name: name, Status: StatusOK, Details: details,
			Message: fmt.Sprintf("%s, where Observer wrote the proxy route, is gone (the tool may no longer be installed here), so there is no route to check", rr.ConfigPath),
		}
	case proxyroute.RecordedRouteUnreadable:
		why := "unknown error"
		if rr.Err != nil {
			why = rr.Err.Error()
		}
		return Check{
			Name: name, Status: StatusWarn, Details: details,
			Message: fmt.Sprintf("%s could not be read, so the proxy route Observer wrote there cannot be checked: %s", rr.ConfigPath, why),
		}
	case proxyroute.RecordedRouteMissing:
		fix, rems := recordedRouteFix(rr.Tool)
		return Check{
			Name: name, Status: StatusWarn, Details: details, Remediations: rems,
			Message: fmt.Sprintf("the proxy route Observer wrote (%s) is gone from %s, so %s's requests no longer reach the Observer proxy; a tool that writes its whole settings file back while it runs can drop it - with %s closed, set the route again with %s; if you removed it on purpose, ignore this",
				setting, rr.ConfigPath, rr.Tool, rr.Tool, fix),
		}
	case proxyroute.RecordedRouteChanged:
		return Check{
			Name: name, Status: StatusWarn, Details: details,
			Message: fmt.Sprintf("the proxy route Observer wrote (%s) in %s now holds another value, so %s's requests may not reach this Observer proxy; Observer does not overwrite a value it did not write - if the change is not intended, set it back in %s's own settings and then set the route from Settings > Connected tools",
				setting, rr.ConfigPath, rr.Tool, rr.Tool),
		}
	}
	return Check{Name: name, Status: StatusOK, Details: details, Message: "recorded route state not classified"}
}

// recordedRouteFix is the sentence and structured fix that writes tool's
// route again: the per-tool route command when one exists, the dashboard
// control otherwise (a forced --all would rewrite every tool's route).
func recordedRouteFix(tool string) (string, []remedy.Remediation) {
	r := remedy.Of(remedy.InitToolRoute, tool)
	cmd := remedy.Command(r)
	if strings.Contains(cmd, "--all") {
		return "Settings > Connected tools", nil
	}
	return "`" + cmd + "` (or from Settings > Connected tools)", []remedy.Remediation{r}
}

// writerOrUnknown names a provenance writer, "unknown" for the zero value.
func writerOrUnknown(w string) string {
	if w == "" {
		return "unknown"
	}
	return w
}

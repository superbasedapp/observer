package diag

import (
	"fmt"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/proxyroute"
)

// checkRouteHold reports proxy routes a safe stop or restart took off and has
// not put back (lane sr-restart): `observer service stop` leaves them off
// until `observer service start`, and an interrupted `observer service
// restart` leaves them in the route hold journal. The AI tools keep working
// against their providers directly, but nothing they send reaches the proxy,
// so the doctor says so and names the command that puts them back. No hold
// means no row. Only the tool and the config path are printed, never the
// route value (it can carry the proxy client token).
func checkRouteHold(homeDir string) []Check {
	const name = "proxy.route_hold"
	h, err := proxyroute.PendingRouteHoldAt(homeDir)
	if err != nil {
		return []Check{{
			Name: name, Status: StatusWarn,
			Message: "the route hold journal could not be read, so whether a stop or restart left proxy routes off is unknown: " + err.Error(),
		}}
	}
	if h.Empty() {
		return nil
	}
	details := make([]string, 0, len(h.Routes))
	tools := make([]string, 0, len(h.Routes))
	for _, r := range h.Routes {
		details = append(details, fmt.Sprintf("%s: %s, off since %s", r.Tool, r.ConfigPath, r.HeldAt))
		tools = append(tools, r.Tool)
	}
	return []Check{{
		Name: name, Status: StatusWarn, Details: details,
		Message: fmt.Sprintf("%d proxy route(s) are off because a stop or restart took them off and has not put them back (%s), so those tools reach their providers directly and bypass the proxy; "+
			"the daemon puts them back itself once its proxy on :%d serves, so start it (`observer start`, or `observer service start` where a service manager runs it). "+
			"If a daemon on :%d is already serving, `observer service start` puts them back now",
			len(h.Routes), strings.Join(tools, ", "), h.Port, h.Port),
	}}
}

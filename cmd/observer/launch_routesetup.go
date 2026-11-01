package main

import (
	"os"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/proxyroute"
)

// routeSetupMissingConfig is the New Terminal picker's next step for a tool
// whose proxy route lives in the tool's OWN config file, when that file does
// not exist yet (T-685). Without it the picker said nothing and the launcher
// only printed "no crush.json found - launching unproxied" once the terminal
// was open. Observer never writes a provider or a key, so the first step is
// the developer's; the route itself is then added by Observer's writer.
const routeSetupMissingConfig = "This tool's own config file is not on this machine yet, so it starts without the Observer proxy route. " +
	"Set up a provider in the tool first (its own setup, with your key); then run `observer init` or start it again from here, and Observer adds the proxy route itself (it never reads or writes the key)."

// routeSetupInspect reads the persisted route posture of every inspectable
// tool; a variable so tests never read the real home directory.
var routeSetupInspect = func() []proxyroute.RouteStatus {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	return proxyroute.InspectRoutes(home)
}

// routeSetupPreflight returns the picker's route-setup sentence for tool, or
// "" when there is nothing to set up. It dispatches on capability shape: a
// tool whose route is applied by a config-lane writer (registry ProxyProbe)
// and whose config artifact is absent. A present config with no route is
// not reported here: the launcher or init adds the route on their own.
func routeSetupPreflight(tool string) string {
	capability, ok := integration.For(tool)
	if !ok || capability.ProxyProbe == nil {
		return ""
	}
	if capability.ProxyProbe.LiveGate.Waiting() {
		// DEC-12: the writer is switched off, so "Observer adds the route"
		// would not be true yet.
		return ""
	}
	for _, status := range routeSetupInspect() {
		if status.Tool != tool {
			continue
		}
		if status.State == proxyroute.RouteAbsent && !status.ArtifactPresent {
			return routeSetupMissingConfig
		}
		return ""
	}
	return ""
}

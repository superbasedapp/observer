package proxyroute

import (
	"errors"
	"io/fs"
	"os"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// The live-check gate on route writers (surface-gap decision DEC-12,
// integration.ProxyRoute.LiveGate): a writer that is built but waits on a
// live check refuses here before it reads the tool's file, whoever calls it
// (`observer init`, the dashboard, route maintenance). Callers skip a gated
// writer on their own too; this is the backstop.

// runLiveGatedRouteWriters lets this package's tests run a gated writer's
// real logic. Production code never sets it: switching a writer on is a
// registry change (clearing the route's LiveGate), never a flag.
var runLiveGatedRouteWriters = false

// routeLiveGateFor is the registry lookup (a variable so tests can gate a
// synthetic tool).
var routeLiveGateFor = integration.RouteLiveGate

// LiveGateSkipPrefix starts the SkipReason of a gated writer's refusal.
const LiveGateSkipPrefix = "not written: "

// liveGateRefusal returns the refusal for tool when its route writer waits on
// a live check, and ok=false when the writer may run. path is the file the
// writer would edit ("" when it could not be named): only its existence is
// checked, never its contents, so an absent file still reads as the benign
// ConfigMissing skip and a present one carries the gate in SkipReason.
func (r *Registrar) liveGateRefusal(tool, path string) (RegistrationResult, bool) {
	return r.refuseGated(routeLiveGateFor(tool), tool, path)
}

// defaultLiveGateFor is the default-provider writer's registry lookup (a
// variable for tests, like routeLiveGateFor).
var defaultLiveGateFor = integration.DefaultProviderLiveGate

// defaultLiveGateRefusal is liveGateRefusal for a default-provider writer
// (integration.ProxyRoute.PersistedDefault).
func (r *Registrar) defaultLiveGateRefusal(tool, path string) (RegistrationResult, bool) {
	return r.refuseGated(defaultLiveGateFor(tool), tool, path)
}

// refuseGated is the shared refusal for gate g.
func (r *Registrar) refuseGated(g integration.LiveGate, tool, path string) (RegistrationResult, bool) {
	if !g.Waiting() || runLiveGatedRouteWriters {
		return RegistrationResult{}, false
	}
	res := RegistrationResult{Tool: tool, ConfigPath: path, DryRun: r.opts.DryRun}
	if path == "" {
		res.ConfigMissing = true
		return res, true
	}
	if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) { //nolint:gosec // G703: existence check of the tool's own config path, never read
		res.ConfigMissing = true
		return res, true
	}
	res.SkipReason = LiveGateSkipPrefix + g.Text()
	return res, true
}

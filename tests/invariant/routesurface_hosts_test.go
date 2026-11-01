package invariant

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestRouteSurfaceHostsShipVerbatim is the producer-side drift guard for the
// registry's per-surface route table (integration.RouteSurfaceHosts, surface-
// gap arc Wave 0.1), in the shape of TestPlatformSurfaceHostsShipVerbatim: a
// host the registry declares must cross the org wire as itself, never coarsen
// to "other". A failure means the new host needs a reviewed entry in
// internal/store/orgpush.go's knownSurfaceHosts. The allowlist is never
// derived from the registry; only this test links the two.
func TestRouteSurfaceHostsShipVerbatim(t *testing.T) {
	for _, h := range integration.RouteSurfaceHosts() {
		if !store.SurfaceHostShipsVerbatim(h) {
			t.Errorf("registry route-surface host %q would ship to the org as \"other\"", h)
		}
	}
}

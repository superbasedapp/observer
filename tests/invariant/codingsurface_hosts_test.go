package invariant

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/platform/zedhost"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestCodingSurfaceHostsShipVerbatim is the producer-side drift guard for the
// registry's coding-surface rows (integration.CodingSurfaces, surface-gap
// lane w8-registry) and the Zed host vocabulary: every host token they name
// crosses the org wire as itself, never coarsened to "other". A failure means
// the token needs a reviewed entry in internal/store/orgpush.go's
// knownSurfaceHosts; the allowlist is never derived from the registry.
func TestCodingSurfaceHostsShipVerbatim(t *testing.T) {
	hosts := []string{zedhost.Host}
	for _, s := range integration.CodingSurfaces() {
		if s.Host != "" {
			hosts = append(hosts, s.Host)
		}
	}
	for _, h := range hosts {
		if !store.SurfaceHostShipsVerbatim(h) {
			t.Errorf("coding-surface host %q would ship to the org as \"other\"", h)
		}
	}
}

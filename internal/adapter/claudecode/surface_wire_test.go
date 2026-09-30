package claudecode

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestClaudeSurfaceHostsShipVerbatim is the producer-side drift guard for the
// org wire's closed surface_host vocabulary (store.knownSurfaceHosts, PRIV-2).
// Every host this adapter can mint must cross to the org as itself; a missing
// row coarsens it to "other", which is exactly how `claude -p` sessions read
// `sdk · cli` on the node but `sdk · other` on the org (MCP audit #4c,
// 2026-09-27). A failure here means: review the new token and add it to the
// list in internal/store/orgpush.go, never widen the gate.
func TestClaudeSurfaceHostsShipVerbatim(t *testing.T) {
	entrypoints := []string{"sdk", "sdk-ts", "sdk-py", "sdk-cli"}
	for ep := range claudeEntrypointSurface {
		entrypoints = append(entrypoints, ep)
	}
	for _, ep := range entrypoints {
		t.Run(ep, func(t *testing.T) {
			_, host, ok := resolveClaudeSurface(ep)
			if !ok {
				t.Fatalf("resolveClaudeSurface(%q) not ok", ep)
			}
			if !store.SurfaceHostShipsVerbatim(host) {
				t.Errorf("entrypoint %q -> host %q would ship to the org as \"other\"", ep, host)
			}
		})
	}
}

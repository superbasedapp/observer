package routeattest

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestRouteSurfaceToolsAreWireLabels holds the managed-integrity
// UnroutedSurfaces vocabulary (orgcontract, OBS-6) and the registry's
// per-surface route facts together: every surface a registry tool declares
// in Capability.RouteSurfaces can be judged an observed bypass, so its
// "tool/kind" label must cross the wire. A tool or kind the closed
// vocabulary refuses would let a managed node report a bypassed surface as
// clean. Widen orgcontract's unroutedSurfaceTools when this fails.
func TestRouteSurfaceToolsAreWireLabels(t *testing.T) {
	t.Parallel()
	for _, tool := range integration.Tools() {
		c, ok := integration.For(tool)
		if !ok {
			continue
		}
		for _, sr := range c.RouteSurfaces {
			if label, ok := orgcontract.UnroutedSurfaceLabel(tool, sr.Kind); !ok {
				t.Errorf("%s declares route surface %q but %q is not an orgcontract UnroutedSurfaces label", tool, sr.Kind, label)
			}
		}
	}
}

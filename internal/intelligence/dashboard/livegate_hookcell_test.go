package dashboard

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// TestHookCellLiveGate: a hook writer that waits on a live check (DEC-12)
// is never dry-run by the dashboard; the cell says why in the shared
// wording.
func TestHookCellLiveGate(t *testing.T) {
	c := integration.Capability{
		Tool: "synthetic",
		Hook: integration.HookSpec{Mechanism: integration.HookClaudeSettings, AutoWired: true, LiveGate: "LC18"},
	}
	kind, detail := hookCellFor(c)
	if kind != hookCellUnprobed {
		t.Fatalf("kind = %v, want unprobed (never run)", kind)
	}
	if !strings.Contains(detail, "built, waiting on live check LC18") {
		t.Errorf("detail = %q, want the DEC-12 wording", detail)
	}
	c.Hook.LiveGate = ""
	if kind, _ := hookCellFor(c); kind != hookCellProbe {
		t.Errorf("ungated: kind = %v, want a probe", kind)
	}
}

package diag

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/hook"
)

func TestLiveGatedChecks(t *testing.T) {
	got := liveGatedChecks([]hook.LiveGate{{Target: "claude-code-wsl", LiveCheck: "WSL-4"}})
	if len(got) != 1 {
		t.Fatalf("got %d checks", len(got))
	}
	c := got[0]
	if c.Name != "claude-code-wsl.hooks.live_gate" || c.Status != StatusWarn {
		t.Errorf("check = %+v", c)
	}
	if !strings.Contains(c.Message, "built, waiting on live check WSL-4") {
		t.Errorf("message %q lacks the gate wording", c.Message)
	}
	if len(liveGatedChecks(nil)) != 0 {
		t.Error("no gated target must yield no row")
	}
}

// TestCheckCrossOSLiveGatedSandboxed pins that a pinned home reports
// nothing (cross-OS detection is off there).
func TestCheckCrossOSLiveGatedSandboxed(t *testing.T) {
	if got := checkCrossOSLiveGated(t.TempDir(), "/x/observer"); len(got) != 0 {
		t.Errorf("sandboxed run reported %+v", got)
	}
}

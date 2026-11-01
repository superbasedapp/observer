package integration

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/platform/winshim"
)

// TestMCPWindowsStdioGrounded pins the grounded native-Windows stdio launch
// form per client (T-923, live-checked 2026-10-20; see the row comments) and
// that every other row stays at the honest zero value until someone grounds
// it. A new value here needs its grounding in the row comment.
func TestMCPWindowsStdioGrounded(t *testing.T) {
	want := map[string]winshim.Launch{
		"claude-code": winshim.LaunchCmdShell,
		"codex":       winshim.LaunchCmdExtension,
	}
	for _, c := range Capabilities() {
		if c.MCP == nil {
			continue
		}
		if got, exp := c.MCP.WindowsStdio, want[c.Tool]; got != exp {
			t.Errorf("%s: MCP.WindowsStdio = %v, want %v", c.Tool, got, exp)
		}
	}
	for tool := range want {
		if c, ok := For(tool); !ok || c.MCP == nil {
			t.Errorf("%s: no MCP target row to carry WindowsStdio", tool)
		}
	}
}

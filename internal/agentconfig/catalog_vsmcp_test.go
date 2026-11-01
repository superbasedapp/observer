package agentconfig

import "testing"

// TestVisualStudioMCPRowCarriesNoCopilotSetting (lane w8-writers audit
// item 1): Visual Studio's user .mcp.json has its own shape, so VS Code
// Copilot's servers setting keeps no user-scope file (an L1 / L2 fan-out or
// an org policy never lands in Visual Studio's file), and no setting row
// points at it.
func TestVisualStudioMCPRowCarriesNoCopilotSetting(t *testing.T) {
	if got := userFileFor("copilot/servers"); got != "" {
		t.Errorf("copilot/servers user file = %q, want none", got)
	}
	for _, r := range Catalog() {
		if r.FileID == "copilot/visual-studio-mcp" {
			t.Errorf("setting %s points at Visual Studio's MCP file", r.ID)
		}
	}
	var found bool
	for _, f := range Files() {
		if f.ID == "copilot/visual-studio-user-mcp" {
			found = true
			if f.WriteNeeds != PrivNever {
				t.Errorf("WriteNeeds = %v, want PrivNever (only the gated MCP writer targets it)", f.WriteNeeds)
			}
		}
	}
	if !found {
		t.Fatal("no copilot/visual-studio-user-mcp row")
	}
}

package main

import (
	"slices"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestInitNeverOffersAToolThatWritesNothing (fix round 1): `observer init`
// lists, accepts and selects only tools with a hook, MCP or persisted-route
// writer. custom-agent has none (the developer's own code), so it must not
// appear in the --tool list, must be refused by --tool, and must drop out
// of an --all selection even if something reported it installed.
func TestInitNeverOffersAToolThatWritesNothing(t *testing.T) {
	if slices.Contains(initSelectableTools(), models.ToolCustomAgent) {
		t.Fatal("observer init lists custom-agent, which it cannot wire")
	}
	for _, tool := range initSelectableTools() {
		if !autoInitSupported(tool) {
			t.Errorf("observer init lists %q, which has no hook, MCP or route writer", tool)
		}
	}
	if _, err := resolveInitToolFlag([]string{models.ToolCustomAgent}); err == nil {
		t.Fatal("--tool custom-agent was accepted")
	}
	got := selectToolsForInit(true, nil, []string{models.ToolCustomAgent, models.ToolClaudeCode})
	for _, tool := range got {
		if !autoInitSupported(tool) {
			t.Errorf("--all selected %q, which init cannot wire (got %v)", tool, got)
		}
	}
}

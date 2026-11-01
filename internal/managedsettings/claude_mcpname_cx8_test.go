package managedsettings

import (
	"encoding/json"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestClaudeMCPNameIsTheSharedConstant pins surface-gap CX-8's Claude half:
// the opt-in managed-mcp.json pin names Observer's server with the one
// shared constant the per-node writer (mcpregister) uses, so a managed node
// never carries two Observer servers under different names.
func TestClaudeMCPNameIsTheSharedConstant(t *testing.T) {
	if MCPServerName != models.ObserverMCPServerName {
		t.Fatalf("MCPServerName = %q, want models.ObserverMCPServerName %q", MCPServerName, models.ObserverMCPServerName)
	}
	arts, err := GenerateClaudeCode(ClaudeCodeOptions{IncludeMCP: true, ExclusiveMCP: true})
	if err != nil {
		t.Fatalf("GenerateClaudeCode: %v", err)
	}
	var doc struct {
		MCPServers map[string]any `json:"mcpServers"`
	}
	if err := json.Unmarshal(arts.ManagedMCPJSON, &doc); err != nil {
		t.Fatalf("decode managed-mcp.json: %v", err)
	}
	if _, ok := doc.MCPServers[models.ObserverMCPServerName]; !ok || len(doc.MCPServers) != 1 {
		t.Fatalf("managed-mcp.json servers = %v, want exactly %q", doc.MCPServers, models.ObserverMCPServerName)
	}
}

//go:build !sbo_omit_agentaccess_relay

package mcpregister

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/BurntSushi/toml"
)

// TestUnregisterClaudeRoundTrip verifies install→uninstall removes the
// observer entry and cleans up mcpServers when empty.
func TestUnregisterClaudeRoundTrip(t *testing.T) {
	t.Parallel()
	// A provenance record says Observer created the file (MACUSER merge
	// M2: with no record a removal never deletes it).
	r, home := newProvenanceRegistrar(t)
	path := filepath.Join(home, ".claude.json")

	if res := r.Register("claude-code"); res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	res := r.Unregister("claude-code")
	if res.Error != nil {
		t.Fatalf("Unregister: %v", res.Error)
	}
	if !res.Removed {
		t.Errorf("expected Removed=true: %+v", res)
	}
	// File is now empty of useful keys → should be removed.
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		body, _ := os.ReadFile(path)
		t.Errorf(".claude.json should be gone after round-trip, got: %s", body)
	}
}

// TestUnregisterPreservesOtherMCPServers verifies that other MCP servers
// under mcpServers survive uninstall.
func TestUnregisterPreservesOtherMCPServers(t *testing.T) {
	t.Parallel()
	r, home := newRegistrar(t, false)
	path := filepath.Join(home, ".claude.json")

	prior := `{
  "feedbackSurveyState": {"shown": true},
  "mcpServers": {
    "other-server": {"command": "/opt/other", "args": ["serve"]}
  }
}`
	if err := os.WriteFile(path, []byte(prior), 0o644); err != nil {
		t.Fatal(err)
	}
	if res := r.Register("claude-code"); res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	if res := r.Unregister("claude-code"); res.Error != nil {
		t.Fatalf("Unregister: %v", res.Error)
	}

	body, _ := os.ReadFile(path)
	var top map[string]any
	if err := json.Unmarshal(body, &top); err != nil {
		t.Fatalf("post-uninstall parse: %v\n%s", err, body)
	}
	if _, ok := top["feedbackSurveyState"]; !ok {
		t.Errorf("feedbackSurveyState was clobbered: %v", top)
	}
	servers, ok := top["mcpServers"].(map[string]any)
	if !ok {
		t.Fatalf("mcpServers lost: %v", top)
	}
	if _, ok := servers["other-server"]; !ok {
		t.Errorf("other-server lost: %v", servers)
	}
	if _, ok := servers[ServerName]; ok {
		t.Errorf("observer entry still present: %v", servers)
	}
}

// TestUnregisterCursorRoundTrip verifies cursor MCP uninstall works the
// same shape as Claude's JSON path.
func TestUnregisterCursorRoundTrip(t *testing.T) {
	t.Parallel()
	r, home := newProvenanceRegistrar(t) // the record decides (M2)
	path := filepath.Join(home, ".cursor", "mcp.json")

	if res := r.Register("cursor"); res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	if res := r.Unregister("cursor"); res.Error != nil {
		t.Fatalf("Unregister: %v", res.Error)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("cursor mcp.json should be gone after round-trip")
	}
}

// TestUnregisterCodexTOMLPreservesNeighbors verifies the TOML path keeps
// sibling [mcp_servers.*] entries after the observer entry is removed.
func TestUnregisterCodexTOMLPreservesNeighbors(t *testing.T) {
	t.Parallel()
	r, home := newRegistrar(t, false)
	dir := filepath.Join(home, ".codex")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.toml")

	// Pre-seed with model + one unrelated mcp_server.
	prior := "model = \"o4-mini\"\n\n[mcp_servers.other]\ncommand = \"/opt/other\"\nargs = [\"serve\"]\n"
	if err := os.WriteFile(path, []byte(prior), 0o644); err != nil {
		t.Fatal(err)
	}

	if res := r.Register("codex"); res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	if res := r.Unregister("codex"); res.Error != nil {
		t.Fatalf("Unregister: %v", res.Error)
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var root map[string]any
	if err := toml.Unmarshal(body, &root); err != nil {
		t.Fatalf("parse: %v\n%s", err, body)
	}
	if root["model"] != "o4-mini" {
		t.Errorf("model key lost: %v", root["model"])
	}
	servers, ok := root["mcp_servers"].(map[string]any)
	if !ok {
		t.Fatalf("mcp_servers lost:\n%s", body)
	}
	if _, ok := servers["other"]; !ok {
		t.Errorf("other server lost: %v", servers)
	}
	if _, ok := servers[ServerName]; ok {
		t.Errorf("observer entry still present: %v", servers)
	}
}

// TestUnregisterClaudeMissingFile verifies the skip path for a missing config.
func TestUnregisterClaudeMissingFile(t *testing.T) {
	t.Parallel()
	r, _ := newRegistrar(t, false)
	res := r.Unregister("claude-code")
	if res.Error != nil {
		t.Fatalf("Unregister: %v", res.Error)
	}
	if !res.Skipped {
		t.Errorf("expected Skipped=true: %+v", res)
	}
	if res.Removed {
		t.Errorf("Removed should be false: %+v", res)
	}
}

// TestUnregisterClaudeNotInstalled verifies skip when file exists but has
// no observer entry.
func TestUnregisterClaudeNotInstalled(t *testing.T) {
	t.Parallel()
	r, home := newRegistrar(t, false)
	path := filepath.Join(home, ".claude.json")
	prior := `{"mcpServers":{"other-server":{"command":"/opt/other","args":["serve"]}}}`
	if err := os.WriteFile(path, []byte(prior), 0o644); err != nil {
		t.Fatal(err)
	}
	res := r.Unregister("claude-code")
	if res.Error != nil {
		t.Fatalf("Unregister: %v", res.Error)
	}
	if !res.Skipped {
		t.Errorf("expected Skipped=true when observer entry absent: %+v", res)
	}
}

// TestUnregisterUnknownTool verifies the error path.
func TestUnregisterUnknownToolMCP(t *testing.T) {
	t.Parallel()
	r, _ := newRegistrar(t, false)
	res := r.Unregister("nonexistent")
	if res.Error == nil {
		t.Fatal("expected error for unknown tool")
	}
}

// TestUnregisterClaudeDryRun verifies --dry-run doesn't modify the file.
func TestUnregisterClaudeDryRun(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	r, err := NewRegistrar(RegisterOptions{
		BinaryPath: "/usr/local/bin/observer",
		HomeDir:    home,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res := r.Register("claude-code"); res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}

	path := filepath.Join(home, ".claude.json")
	pre, _ := os.ReadFile(path)

	// Swap to dry-run via fresh registrar (opts are immutable via NewRegistrar).
	rDry, err := NewRegistrar(RegisterOptions{
		BinaryPath: "/usr/local/bin/observer",
		HomeDir:    home,
		DryRun:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	res := rDry.Unregister("claude-code")
	if res.Error != nil {
		t.Fatalf("Unregister: %v", res.Error)
	}
	if !res.Removed {
		t.Errorf("dry-run should still report Removed=true: %+v", res)
	}
	post, _ := os.ReadFile(path)
	if string(pre) != string(post) {
		t.Errorf("dry-run mutated file:\nbefore:\n%s\nafter:\n%s", pre, post)
	}
}

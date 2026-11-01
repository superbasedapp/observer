package mcpregister

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/BurntSushi/toml"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestServerNameIsTheSharedConstant pins CX-8 on the per-node side: the
// Codex and Claude Code writers register Observer's server under
// models.ObserverMCPServerName, the same constant the Rail B generators in
// internal/managedsettings pin (TestCodexMCPNameIsTheSharedConstant there).
func TestServerNameIsTheSharedConstant(t *testing.T) {
	if ServerName != models.ObserverMCPServerName {
		t.Fatalf("ServerName = %q, want models.ObserverMCPServerName %q", ServerName, models.ObserverMCPServerName)
	}
	home := t.TempDir()
	r, err := NewRegistrar(RegisterOptions{BinaryPath: "/usr/local/bin/observer", HomeDir: home})
	if err != nil {
		t.Fatalf("NewRegistrar: %v", err)
	}
	for _, tc := range []struct {
		tool    string
		servers func(t *testing.T, path string) map[string]any
	}{
		{"codex", func(t *testing.T, path string) map[string]any {
			var root map[string]any
			body, _ := os.ReadFile(path)
			if err := toml.Unmarshal(body, &root); err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			m, _ := root["mcp_servers"].(map[string]any)
			return m
		}},
		{"claude-code", func(t *testing.T, path string) map[string]any {
			var root map[string]any
			body, _ := os.ReadFile(path)
			if err := json.Unmarshal(body, &root); err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			m, _ := root["mcpServers"].(map[string]any)
			return m
		}},
	} {
		t.Run(tc.tool, func(t *testing.T) {
			if tc.tool == "codex" {
				if err := os.MkdirAll(filepath.Join(home, ".codex"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			res := r.Register(tc.tool)
			if res.Error != nil {
				t.Fatalf("Register(%s): %v", tc.tool, res.Error)
			}
			servers := tc.servers(t, res.ConfigPath)
			if _, ok := servers[models.ObserverMCPServerName]; !ok || len(servers) != 1 {
				t.Errorf("%s: servers = %v, want exactly %q", tc.tool, servers, models.ObserverMCPServerName)
			}
		})
	}
}

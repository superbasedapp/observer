package diag

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCheckCodexProviderRouteFollowsCodexHome pins CX-4 for codex.proxy_route:
// with CODEX_HOME set (through the injected getenv), the check reads the
// relocated config.toml, and its profile overlays beside it, not
// <home>/.codex. The old check hard-coded <home>/.codex and reported a
// relocated, routed codex as "not set up".
func TestCheckCodexProviderRouteFollowsCodexHome(t *testing.T) {
	const routed = "model_provider = \"openai-observer\"\n[model_providers.openai-observer]\nname = \"x\"\nbase_url = \"http://127.0.0.1:8820/v1\"\n"
	home := t.TempDir()
	moved := filepath.Join(t.TempDir(), "codex-home")
	if err := os.MkdirAll(moved, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(moved, "config.toml"), []byte(routed), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(moved, "work.config.toml"), []byte("model_provider = \"amazon-bedrock\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name       string
		getenv     func(string) string
		wantMsg    string
		wantConfig string
	}{
		{"relocated", func(k string) string {
			if k == "CODEX_HOME" {
				return moved
			}
			return ""
		}, "proxy-exact", filepath.Join(moved, "config.toml")},
		{"no env reads the home", nil, "not set up", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := checkCodexProviderRoute(home, tc.getenv, "")
			if !strings.Contains(c.Message, tc.wantMsg) {
				t.Errorf("Message = %q, want %q", c.Message, tc.wantMsg)
			}
			if tc.wantConfig == "" {
				return
			}
			joined := strings.Join(c.Details, "\n")
			if !strings.Contains(joined, "config: "+tc.wantConfig) || !strings.Contains(joined, `profile "work"`) {
				t.Errorf("Details = %v, want the relocated config and its overlay", c.Details)
			}
		})
	}
}

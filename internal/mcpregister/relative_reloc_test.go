package mcpregister

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRelativeRelocationRefusesMCPWriters pins R-188 F6 for the MCP
// registrar over the shared locate table: a relocation variable holding a
// relative path (CLAUDE_CONFIG_DIR, CODEX_HOME, CLINE_DIR) makes Register
// and Unregister refuse naming the variable, and nothing is written to the
// vendor default under the home, which the client does not read. Before the
// fix locate fell back to that default and the registrar wrote it.
func TestRelativeRelocationRefusesMCPWriters(t *testing.T) {
	const rel = "observer-r188-rel"
	cases := []struct {
		tool, env string
		install   []string // the install signal directory under the home
		def       []string // the vendor default MCP file under the home
	}{
		{"claude-code", "CLAUDE_CONFIG_DIR", []string{".claude"}, []string{".claude.json"}},
		{"codex", "CODEX_HOME", []string{".codex"}, []string{".codex", "config.toml"}},
		{"cline", "CLINE_DIR", []string{".cline", "data"}, []string{".cline", "data", "settings", "cline_mcp_settings.json"}},
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			home := t.TempDir()
			if err := os.MkdirAll(filepath.Join(append([]string{home}, tc.install...)...), 0o755); err != nil {
				t.Fatal(err)
			}
			r, err := NewRegistrar(RegisterOptions{
				BinaryPath: "/usr/local/bin/observer", HomeDir: home,
				Getenv: func(k string) string {
					if k == tc.env {
						return rel
					}
					return ""
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			def := filepath.Join(append([]string{home}, tc.def...)...)
			res := r.Register(tc.tool)
			if res.Error == nil || !strings.Contains(res.Error.Error(), tc.env) || res.ConfigPath != "" || res.Added {
				t.Errorf("Register = %+v, want a refusal naming %s and no file", res, tc.env)
			}
			if _, err := os.Stat(def); err == nil {
				t.Errorf("Register wrote the vendor default %s", def)
			}
			un := r.Unregister(tc.tool)
			if un.Error == nil || !strings.Contains(un.Error.Error(), tc.env) || un.ConfigPath != "" {
				t.Errorf("Unregister = %+v, want a refusal naming %s and no file", un, tc.env)
			}
			if _, err := os.Stat(rel); err == nil {
				t.Errorf("the relative %s was created in the test's working directory", rel)
			}
		})
	}
}

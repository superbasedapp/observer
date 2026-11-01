package mcpregister

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// TestRelocatedConfigHomes pins CC-8 and CX-4 for the MCP registrar: with
// CLAUDE_CONFIG_DIR or CODEX_HOME set (through the injected Getenv, the
// production os.Getenv), the install probe and the write follow the
// relocated home that the agentconfig rule names. The old registrar
// hard-coded ~/.claude and ~/.codex, so a relocated profile was neither
// detected nor written. CLAUDE_CONFIG_DIR also moves ~/.claude.json to
// $CLAUDE_CONFIG_DIR/.claude.json (CC-8, grounded by the MAC-4 macOS run
// and the Windows rerun D3), so the claude-code MCP file follows it.
func TestRelocatedConfigHomes(t *testing.T) {
	cases := []struct {
		name string
		tool string
		env  string
		// file is the MCP file Register writes, relative to the relocated
		// dir (rel=true) or to the home.
		file []string
		rel  bool
	}{
		{"CODEX_HOME moves the codex config", "codex", "CODEX_HOME", []string{"config.toml"}, true},
		{"CLAUDE_CONFIG_DIR moves the claude-code MCP file", "claude-code", "CLAUDE_CONFIG_DIR", []string{".claude.json"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			moved := filepath.Join(t.TempDir(), "profile")
			if err := os.MkdirAll(moved, 0o755); err != nil {
				t.Fatal(err)
			}
			env := map[string]string{tc.env: moved}
			r, err := NewRegistrar(RegisterOptions{
				BinaryPath: "/usr/local/bin/observer", HomeDir: home,
				Getenv: func(k string) string { return env[k] },
			})
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(r.Installed(), tc.tool) {
				t.Fatalf("Installed() = %v: the relocated %s home is not detected", r.Installed(), tc.env)
			}
			want := filepath.Join(append([]string{home}, tc.file...)...)
			if tc.rel {
				want = filepath.Join(append([]string{moved}, tc.file...)...)
			}
			res := r.Register(tc.tool)
			if res.Error != nil || !res.Added || res.ConfigPath != want {
				t.Fatalf("Register = %+v, want Added at %s", res, want)
			}
			if _, err := os.Stat(want); err != nil {
				t.Errorf("not written: %v", err)
			}
			if tc.rel {
				for _, def := range []string{".codex", ".claude.json"} {
					if _, err := os.Stat(filepath.Join(home, def)); err == nil {
						t.Errorf("the default %s was written despite the relocation", def)
					}
				}
			}
			ures := r.Unregister(tc.tool)
			if ures.Error != nil || !ures.Removed || ures.ConfigPath != want {
				t.Errorf("Unregister = %+v, want Removed at %s", ures, want)
			}
		})
	}
}

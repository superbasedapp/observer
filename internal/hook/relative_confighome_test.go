package hook

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestRelativeConfigHomeRefusesHookWriters pins R-188 F6 for the native
// Claude Code and Codex hook writers and the Claude Code status line: a
// CLAUDE_CONFIG_DIR or CODEX_HOME holding a relative path (which the tool
// reads against its own working directory) is a refusal naming the
// variable, and nothing is written to ~/.claude or ~/.codex instead. The
// install probe still lists the tool when the default home exists, so its
// writer runs and the refusal is reported. Before the fix every one of these
// writers wrote the vendor default.
func TestRelativeConfigHomeRefusesHookWriters(t *testing.T) {
	t.Parallel()
	const rel = "observer-r188-rel"
	cases := []struct {
		name, tool, env string
		files           [][]string // files under the home that must not appear
		act             func(r *Registry) (configPath string, err error)
	}{
		{"claude hooks", "claude-code", "CLAUDE_CONFIG_DIR", [][]string{{".claude", "settings.json"}}, func(r *Registry) (string, error) {
			res := r.Register("claude-code")
			return res.ConfigPath, res.Error
		}},
		{"claude statusline", "claude-code", "CLAUDE_CONFIG_DIR", [][]string{{".claude", "settings.json"}}, func(r *Registry) (string, error) {
			res := r.RegisterClaudeCodeStatusline()
			return res.ConfigPath, res.Error
		}},
		{"claude hooks unregister", "claude-code", "CLAUDE_CONFIG_DIR", [][]string{{".claude", "settings.json"}}, func(r *Registry) (string, error) {
			res := r.Unregister("claude-code")
			return res.ConfigPath, res.Error
		}},
		{"claude statusline unregister", "claude-code", "CLAUDE_CONFIG_DIR", [][]string{{".claude", "settings.json"}}, func(r *Registry) (string, error) {
			res := r.UnregisterClaudeCodeStatusline()
			return res.ConfigPath, res.Error
		}},
		{"codex hooks", "codex", "CODEX_HOME", [][]string{{".codex", "hooks.json"}, {".codex", "config.toml"}}, func(r *Registry) (string, error) {
			res := r.Register("codex")
			return res.ConfigPath, res.Error
		}},
		{"codex hooks unregister", "codex", "CODEX_HOME", [][]string{{".codex", "hooks.json"}, {".codex", "config.toml"}}, func(r *Registry) (string, error) {
			res := r.Unregister("codex")
			return res.ConfigPath, res.Error
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			home := t.TempDir()
			for _, d := range []string{".claude", ".codex"} {
				if err := os.MkdirAll(filepath.Join(home, d), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			r, err := NewRegistry(Options{
				BinaryPath:    "/opt/observer/bin/observer",
				HomeDir:       home,
				ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
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
			if !slices.Contains(r.Installed(), tc.tool) {
				t.Errorf("Installed() = %v, want %s listed so its refusal is reported", r.Installed(), tc.tool)
			}
			path, err := tc.act(r)
			if err == nil || !strings.Contains(err.Error(), tc.env) {
				t.Errorf("got %v, want a refusal naming %s", err, tc.env)
			}
			if path != "" {
				t.Errorf("ConfigPath %q, want no file named", path)
			}
			for _, f := range tc.files {
				if p := filepath.Join(append([]string{home}, f...)...); r188PathExists(p) {
					t.Errorf("%s was written under the vendor default home", p)
				}
			}
			if r188PathExists(rel) {
				t.Errorf("the relative %s was created in the test's working directory", rel)
			}
		})
	}
}

// r188PathExists reports whether p exists.
func r188PathExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

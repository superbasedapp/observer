package hook

import (
	"os"
	"path/filepath"
	"testing"
)

// The local settings-file writers' output, byte for byte (lane HOOKS,
// SBXD-6). The pure pieces the hosted box seed shares with them
// (claudeCodeHookCommand, genericSettingsHookCommand, encodeSettingsJSON,
// boxseed.go) were extracted from these writers; these goldens were
// recorded from the writers BEFORE the extraction, so a change to what a
// local registration writes fails here. UPDATE_HOOK_GOLDEN=1 rewrites them
// (only for a deliberate change to the local writers).

func TestLocalSettingsWritersGolden(t *testing.T) {
	cases := []struct {
		tool, rel, golden string
		seed              string
	}{
		{"claude-code", ".claude/settings.json", "claude-code-fresh.json", ""},
		{"claude-code", ".claude/settings.json", "claude-code-merge.json", `{"model":"opus","hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/opt/acme/audit","timeout":30}]}]},"zeta":1}`},
		{"qwen-code", ".qwen/settings.json", "qwen-code-fresh.json", ""},
		{"qoder", ".qoder/settings.json", "qoder-fresh.json", ""},
		{"gemini-cli", ".gemini/settings.json", "gemini-cli-fresh.json", ""},
	}
	for _, c := range cases {
		t.Run(c.golden, func(t *testing.T) {
			home := t.TempDir()
			p := filepath.Join(home, filepath.FromSlash(c.rel))
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if c.seed != "" {
				if err := os.WriteFile(p, []byte(c.seed), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			reg, err := NewRegistry(Options{
				BinaryPath:    "/usr/local/bin/observer",
				HomeDir:       home,
				Force:         true,
				ConfigPath:    "/home/u/.observer/config.toml",
				ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
			})
			if err != nil {
				t.Fatalf("NewRegistry: %v", err)
			}
			if res := reg.Register(c.tool); res.Error != nil {
				t.Fatalf("Register(%s): %v", c.tool, res.Error)
			}
			got, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			gp := filepath.Join("testdata", "hookrender", c.golden)
			if os.Getenv("UPDATE_HOOK_GOLDEN") == "1" {
				if err := os.MkdirAll(filepath.Dir(gp), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(gp, got, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(gp)
			if err != nil {
				t.Fatalf("read golden: %v (UPDATE_HOOK_GOLDEN=1 records it)", err)
			}
			if string(got) != string(want) {
				t.Fatalf("%s writer output changed:\n got: %s\nwant: %s", c.tool, got, want)
			}
		})
	}
}

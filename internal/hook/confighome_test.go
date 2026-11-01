package hook

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
)

// TestConfigHomeArtifactsResolve pins that the config-home artifacts
// resolve through their agentconfig rows (the fallback in
// configArtifactPath is unreachable).
func TestConfigHomeArtifactsResolve(t *testing.T) {
	t.Parallel()
	for _, id := range []string{claudeSettingsArtifact, codexHooksArtifact} {
		got, err := agentconfig.ResolveArtifact(id, agentconfig.PathEnv{GOOS: runtime.GOOS, Home: "/h"})
		if err != nil || got.Status != agentconfig.PathResolved {
			t.Errorf("%s = %+v, %v", id, got, err)
		}
	}
}

// TestRelocatedConfigHomesHooks pins CC-8 and CX-4 for the native hook
// writers, the Claude Code status line writer (the S-21 Claude part) and
// the install probe: with CLAUDE_CONFIG_DIR or CODEX_HOME set through
// Options.Getenv, each writes the relocated file and the default home is
// left alone; with no Getenv the default home is used. The old writers
// hard-coded ~/.claude and ~/.codex.
func TestRelocatedConfigHomesHooks(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		tool    string
		env     string
		file    string
		write   func(r *Registry) RegistrationResult
		relocOn bool
	}{
		{"claude hooks relocated", "claude-code", "CLAUDE_CONFIG_DIR", "settings.json", func(r *Registry) RegistrationResult { return r.Register("claude-code") }, true},
		{"claude statusline relocated", "claude-code", "CLAUDE_CONFIG_DIR", "settings.json", (*Registry).RegisterClaudeCodeStatusline, true},
		{"codex hooks relocated", "codex", "CODEX_HOME", "hooks.json", func(r *Registry) RegistrationResult { return r.Register("codex") }, true},
		{"claude hooks, no env", "claude-code", "CLAUDE_CONFIG_DIR", "settings.json", func(r *Registry) RegistrationResult { return r.Register("claude-code") }, false},
		{"codex hooks, no env", "codex", "CODEX_HOME", "hooks.json", func(r *Registry) RegistrationResult { return r.Register("codex") }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			home := t.TempDir()
			moved := filepath.Join(t.TempDir(), "profile")
			if err := os.MkdirAll(moved, 0o755); err != nil {
				t.Fatal(err)
			}
			opts := Options{
				BinaryPath:    "/opt/observer/bin/observer",
				HomeDir:       home,
				ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
			}
			wantDir := filepath.Join(home, map[string]string{"claude-code": ".claude", "codex": ".codex"}[tc.tool])
			if tc.relocOn {
				opts.Getenv = func(k string) string {
					if k == tc.env {
						return moved
					}
					return ""
				}
				wantDir = moved
			} else if err := os.MkdirAll(wantDir, 0o755); err != nil {
				t.Fatal(err)
			}
			r, err := NewRegistry(opts)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(r.Installed(), tc.tool) {
				t.Errorf("Installed() = %v, want %s from %s", r.Installed(), tc.tool, wantDir)
			}
			res := tc.write(r)
			want := filepath.Join(wantDir, tc.file)
			if res.Error != nil || res.ConfigPath != want {
				t.Fatalf("write = %+v, want %s", res, want)
			}
			if _, err := os.Stat(want); err != nil {
				t.Errorf("not written: %v", err)
			}
			if tc.relocOn {
				for _, d := range []string{".claude", ".codex"} {
					if _, err := os.Stat(filepath.Join(home, d)); err == nil {
						t.Errorf("the default home's %s was written", d)
					}
				}
			}
		})
	}
}

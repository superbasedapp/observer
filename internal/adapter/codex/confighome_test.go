package codex

import (
	"path/filepath"
	"testing"
)

// TestWatchPathsCodexHomeThroughTheArtifactRule pins CX-4 for capture: the
// Codex watch root follows CODEX_HOME through the agentconfig rule on
// codex/user-config (the rule the hook, MCP and route writers follow), read
// through the injected getenv. An absolute value is the single CLI root (the
// established behaviour); a relative value is refused by the rule, so the
// per-home defaults stay instead of a root relative to the daemon's working
// directory.
func TestWatchPathsCodexHomeThroughTheArtifactRule(t *testing.T) {
	t.Parallel()
	abs := filepath.Join(t.TempDir(), "codex-home")
	cases := []struct {
		name   string
		value  string
		single string
	}{
		{"absolute", abs, filepath.Join(abs, "sessions")},
		{"relative refused", filepath.Join("rel", "codex"), ""},
		{"unset", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a := New()
			a.getenv = func(k string) string {
				if k == "CODEX_HOME" {
					return tc.value
				}
				return ""
			}
			paths := a.WatchPaths()
			if tc.single != "" {
				if len(paths) != 1 || paths[0] != tc.single {
					t.Errorf("WatchPaths = %v, want exactly [%s]", paths, tc.single)
				}
				return
			}
			if len(paths) == 0 {
				t.Fatal("no roots")
			}
			for _, p := range paths {
				if filepath.Base(filepath.Dir(p)) != ".codex" {
					t.Errorf("root %q is not a per-home .codex/sessions default", p)
				}
			}
		})
	}
}

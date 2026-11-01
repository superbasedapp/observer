package claudecode

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// TestWatchPathsFollowsClaudeConfigDir pins CC-8 for capture: a relocated
// Claude Code profile (CLAUDE_CONFIG_DIR, through the agentconfig rule on
// claude-code/user-settings) adds its projects dir to the watch roots, after
// the default per-home roots, which stay. A relative value is refused by the
// rule (the daemon cannot place it). The old WatchPaths watched only
// ~/.claude/projects.
func TestWatchPathsFollowsClaudeConfigDir(t *testing.T) {
	t.Parallel()
	moved := filepath.Join(t.TempDir(), "claude-work")
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("UserHomeDir unavailable")
	}
	native := filepath.Join(home, ".claude", "projects")
	cases := []struct {
		name      string
		value     string
		wantExtra string
	}{
		{"absolute profile", moved, filepath.Join(moved, "projects")},
		{"unset", "", ""},
		{"relative value refused", filepath.Join("rel", "claude"), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a := New()
			a.getenv = func(k string) string {
				if k == "CLAUDE_CONFIG_DIR" {
					return tc.value
				}
				return ""
			}
			paths := a.WatchPaths()
			if len(paths) == 0 || paths[0] != native {
				t.Fatalf("WatchPaths = %v, want the native default first", paths)
			}
			hasExtra := tc.wantExtra != "" && slices.Contains(paths, tc.wantExtra)
			if tc.wantExtra != "" && !hasExtra {
				t.Errorf("WatchPaths = %v, want %s", paths, tc.wantExtra)
			}
			if tc.wantExtra == "" && slices.ContainsFunc(paths, func(p string) bool { return filepath.Base(filepath.Dir(p)) != ".claude" }) {
				t.Errorf("WatchPaths = %v, want only <home>/.claude/projects roots", paths)
			}
			if a.IsSessionFile(filepath.Join(moved, "projects", "p", "s.jsonl")) != (tc.wantExtra != "") {
				t.Errorf("IsSessionFile under the profile = %v", !(tc.wantExtra != ""))
			}
		})
	}
}

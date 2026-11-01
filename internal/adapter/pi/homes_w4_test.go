package pi

import (
	"path/filepath"
	"slices"
	"testing"
)

// TestWatchRootsFollowPiAgentDir (S-17 / CLI-4, lane w4-homes-b): PI_CODING_AGENT_DIR moves
// the tool's home, so the adapter watches the relocated session subtree
// beside the per-home defaults. Red before: the roots were per-home only.
func TestWatchRootsFollowPiAgentDir(t *testing.T) {
	alt := filepath.Join(t.TempDir(), "relocated")
	t.Setenv("PI_CODING_AGENT_DIR", alt)
	got := defaultRoots()
	for _, want := range []string{filepath.Join(alt, "sessions")} {
		if !slices.Contains(got, want) {
			t.Errorf("roots = %v, want %s", got, want)
		}
	}
}

package copilotcli

import (
	"path/filepath"
	"slices"
	"testing"
)

// TestWatchRootsFollowCopilotHome (S-17 / CLI-4, lane w4-homes-b): COPILOT_HOME moves
// the tool's home, so the adapter watches the relocated session subtree
// beside the per-home defaults. Red before: the roots were per-home only.
func TestWatchRootsFollowCopilotHome(t *testing.T) {
	alt := filepath.Join(t.TempDir(), "relocated")
	t.Setenv("COPILOT_HOME", alt)
	got := (&Adapter{}).WatchPaths()
	for _, want := range []string{filepath.Join(alt, "session-state"), filepath.Join(alt, "logs")} {
		if !slices.Contains(got, want) {
			t.Errorf("roots = %v, want %s", got, want)
		}
	}
}

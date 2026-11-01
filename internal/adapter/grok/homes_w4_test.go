package grok

import (
	"path/filepath"
	"slices"
	"testing"
)

// TestWatchRootsFollowGrokHome (S-17 / CLI-4, lane w4-homes-b): GROK_HOME moves
// the tool's home, so the adapter watches the relocated session subtree
// beside the per-home defaults. Red before: the roots were per-home only.
func TestWatchRootsFollowGrokHome(t *testing.T) {
	alt := filepath.Join(t.TempDir(), "relocated")
	t.Setenv("GROK_HOME", alt)
	got := defaultRoots()
	for _, want := range []string{filepath.Join(alt, "sessions"), filepath.Join(alt, "logs")} {
		if !slices.Contains(got, want) {
			t.Errorf("roots = %v, want %s", got, want)
		}
	}
}

package store

import "testing"

// TestWorktreeSightingKey (lane LEFT-SEC milestone 2): the per-checkout
// sighting path splits back into its key and path; anything else is no
// worktree sighting.
func TestWorktreeSightingKey(t *testing.T) {
	p := WorktreeSightingPath("/tmp/wt", "pkg/a.go")
	key, rel, ok := SplitWorktreeSighting(p)
	if !ok || key != WorktreeSightingKey("/tmp/wt") || rel != "pkg/a.go" {
		t.Fatalf("split %q: %q %q %v", p, key, rel, ok)
	}
	if WorktreeSightingKey("/tmp/wt/") != WorktreeSightingKey("/tmp/wt") {
		t.Fatal("the key is not of the cleaned path")
	}
	for _, bad := range []string{"pkg/a.go", "[worktree:abc]/x", "[worktree:0123456789abcdef]", "[worktree:0123456789abcdef]/", "[external]/x"} {
		if _, _, ok := SplitWorktreeSighting(bad); ok {
			t.Errorf("%q split as a worktree sighting", bad)
		}
	}
}

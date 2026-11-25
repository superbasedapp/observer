package invariant

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// Helpers shared across the invariant suites. They live here rather than in
// a topical test file, so removing one suite never breaks the others.

// repoRoot walks up from the test's working directory until it finds the
// go.mod, so the guard works regardless of where `go test` is invoked.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("repoRoot: go.mod not found above %s", dir)
		}
		dir = parent
	}
}

// uniqueSorted returns the distinct strings of xs in sorted order.
func uniqueSorted(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

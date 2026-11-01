package publictree

import (
	"os"
	"path/filepath"
	"testing"
)

// Marker is the module-relative directory whose absence marks the public
// tree. scripts/release.sh lists it in PRIVATE_ONLY_PATHS, and the private
// tree cannot build its org server without it.
const Marker = "cmd/observer-org"

// In reports whether root, a module root, is the stripped public tree.
func In(root string) bool {
	st, err := os.Stat(filepath.Join(root, filepath.FromSlash(Marker)))
	return err != nil || !st.IsDir()
}

// RepoRoot walks up from the test's working directory to the directory
// holding go.mod, failing t when there is none.
func RepoRoot(t testing.TB) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("publictree.RepoRoot: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("publictree.RepoRoot: go.mod not found above the working directory")
		}
		dir = parent
	}
}

// SkipAt skips t when root is the public tree, naming what the public tree
// does not carry.
func SkipAt(t testing.TB, root, what string) {
	t.Helper()
	if In(root) {
		t.Skipf("public tree: %s is private-only (scripts/release.sh PRIVATE_ONLY_PATHS)", what)
	}
}

// Skip is SkipAt for the module that holds the test's working directory.
func Skip(t testing.TB, what string) {
	t.Helper()
	SkipAt(t, RepoRoot(t), what)
}

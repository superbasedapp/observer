package sandbox

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestGitDirExecParents (Linux live re-check 3, D2): the folders between a
// git dir and each protected execution-state path, derived from the table,
// parents first, so every row pins each one and a renamed folder cannot
// carry a read-only overlay away.
func TestGitDirExecParents(t *testing.T) {
	g := filepath.Join("/w", ".git")
	got := GitDirExecParents(g)
	want := []string{filepath.Join(g, "info"), filepath.Join(g, "objects"), filepath.Join(g, "objects", "info")}
	if !slices.Equal(got, want) {
		t.Fatalf("parents %q, want %q", got, want)
	}
	// Every table row's folders are covered, whatever row is added later.
	for _, pp := range WorkspaceExecState {
		rel := strings.TrimPrefix(filepath.ToSlash(pp.Rel), ".git/")
		for dir := filepath.Dir(filepath.Join(g, rel)); dir != g; dir = filepath.Dir(dir) {
			if !slices.Contains(got, dir) {
				t.Errorf("%s: the folder %s is not pinned", pp.Rel, dir)
			}
		}
	}
}

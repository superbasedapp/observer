package git

import (
	"context"
	"path/filepath"
	"testing"
)

// TestLinkedCommonDir: a linked worktree names its main repository's .git;
// the main checkout and a non-repository name nothing.
func TestLinkedCommonDir(t *testing.T) {
	repo := initRepo(t)
	wt := filepath.Join(t.TempDir(), "wt")
	if err := WorktreeAdd(context.Background(), repo, wt, "feature/c", "HEAD"); err != nil {
		t.Fatalf("WorktreeAdd: %v", err)
	}
	got, ok := LinkedCommonDir(wt)
	if !ok || got != filepath.Join(realPath(t, repo), ".git") {
		t.Fatalf("LinkedCommonDir(worktree) = %q %v", got, ok)
	}
	if _, ok := LinkedCommonDir(repo); ok {
		t.Error("the main checkout reads as a linked worktree")
	}
	if _, ok := LinkedCommonDir(t.TempDir()); ok {
		t.Error("a non-repository reads as a linked worktree")
	}
}

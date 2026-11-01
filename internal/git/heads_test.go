package git

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestLatestHeadWrite: the newest HEAD write of the main checkout and its
// linked worktrees, read from any directory of either; a directory outside
// git cannot be answered.
func TestLatestHeadWrite(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	run := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	repo := t.TempDir()
	run(repo, "init", "-q")
	if err := os.WriteFile(filepath.Join(repo, "a"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	run(repo, "add", "a")
	run(repo, "commit", "-q", "-m", "one")
	wt := filepath.Join(t.TempDir(), "wt")
	run(repo, "worktree", "add", "-q", "-b", "f", wt)

	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(filepath.Join(repo, ".git", "HEAD"), old, old); err != nil {
		t.Fatal(err)
	}
	newer := time.Now().Add(-time.Minute).Truncate(time.Second)
	wtHead := filepath.Join(repo, ".git", "worktrees", "wt", "HEAD")
	if err := os.Chtimes(wtHead, newer, newer); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{repo, wt} {
		got, ok := LatestHeadWrite(dir)
		if !ok || !got.Equal(newer) {
			t.Fatalf("LatestHeadWrite(%s) = %v %v, want the worktree's %v", dir, got, ok, newer)
		}
	}
	if _, ok := LatestHeadWrite(t.TempDir()); ok {
		t.Fatal("a directory outside git was answered")
	}
}

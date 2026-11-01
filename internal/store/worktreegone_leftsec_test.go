package store

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/git"
)

// TestWorktreeSightingGone (lane LEFT-SEC audit F1): a worktree sighting is
// provably gone only from a whole listing with no entry mapping to its key.
// Each partial shape (unreadable gitdir, checkout off disk, past the cap)
// keeps it, as does a live or pointed checkout with the key.
func TestWorktreeSightingGone(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	ctx := context.Background()
	root := t.TempDir()
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", root, "-c", "user.email=t@example.com", "-c", "user.name=t", "-c", "commit.gpgsign=false"}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	run("init", "-q")
	if err := os.WriteFile(filepath.Join(root, "README"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run("add", "README")
	run("commit", "-qm", "first")
	parent := t.TempDir()
	if r, err := filepath.EvalSymlinks(parent); err == nil {
		parent = r
	}
	wt, other := filepath.Join(parent, "wt"), filepath.Join(parent, "other")
	for i, w := range []string{wt, other} {
		if err := git.WorktreeAdd(ctx, root, w, "gone/"+string(rune('a'+i)), "HEAD"); err != nil {
			t.Fatal(err)
		}
	}
	key := WorktreeSightingKey(wt)
	if WorktreeSightingGone(root, key) {
		t.Fatal("a live worktree read as gone")
	}
	if worktreeSightingGone(root, WorktreeSightingKey(filepath.Join(parent, "never")), 1) {
		t.Error("a listing cut at its cap closed an unknown key")
	}
	odd := filepath.Join(root, ".git", "worktrees", "odd")
	if err := os.MkdirAll(filepath.Join(odd, "gitdir"), 0o700); err != nil {
		t.Fatal(err)
	}
	if WorktreeSightingGone(root, WorktreeSightingKey(filepath.Join(parent, "never"))) {
		t.Error("an unreadable gitdir closed an unknown key")
	}
	if err := os.RemoveAll(odd); err != nil {
		t.Fatal(err)
	}
	if !WorktreeSightingGone(root, WorktreeSightingKey(filepath.Join(parent, "never"))) {
		t.Error("a whole listing without the key kept it")
	}
	if err := os.RemoveAll(wt); err != nil {
		t.Fatal(err)
	}
	if WorktreeSightingGone(root, key) {
		t.Error("a checkout off disk (not yet pruned) read as gone")
	}
	run("worktree", "prune")
	if !WorktreeSightingGone(root, key) {
		t.Error("a pruned worktree did not read as gone")
	}
	if WorktreeSightingGone(root, WorktreeSightingKey(other)) {
		t.Error("the other live worktree read as gone")
	}
}

package git

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestListLinkedWorktreesComplete (lane LEFT-SEC audit F1): the listing is
// Complete only when every admin entry was read whole; an unreadable gitdir,
// a checkout off disk, entries left past the cap and a missing `.git` each
// make it partial.
func TestListLinkedWorktreesComplete(t *testing.T) {
	ctx := context.Background()
	repo := initRepo(t)
	mainRoot := realPath(t, repo)
	if l := ListLinkedWorktrees(mainRoot, 10); !l.Complete || len(l.Checkouts) != 0 {
		t.Fatalf("no worktrees: %+v, want complete and empty", l)
	}
	a := filepath.Join(t.TempDir(), "a")
	b := filepath.Join(t.TempDir(), "b")
	for i, w := range []string{a, b} {
		if err := WorktreeAdd(ctx, repo, w, "lsc/"+string(rune('a'+i)), "HEAD"); err != nil {
			t.Fatal(err)
		}
	}
	l := ListLinkedWorktrees(mainRoot, 10)
	if !l.Complete || len(l.Checkouts) != 2 || len(l.Pointed) != 2 {
		t.Fatalf("two live worktrees: %+v", l)
	}
	if l := ListLinkedWorktrees(mainRoot, 1); l.Complete || len(l.Checkouts) != 1 {
		t.Errorf("cap 1 over two worktrees: %+v, want partial", l)
	}
	if l := ListLinkedWorktrees(filepath.Join(t.TempDir(), "nogit"), 10); l.Complete {
		t.Errorf("a folder without .git read as complete: %+v", l)
	}

	// An unreadable gitdir (a directory where git's file belongs).
	odd := filepath.Join(mainRoot, ".git", "worktrees", "odd")
	if err := os.MkdirAll(filepath.Join(odd, "gitdir"), 0o700); err != nil {
		t.Fatal(err)
	}
	if l := ListLinkedWorktrees(mainRoot, 10); l.Complete || len(l.Checkouts) != 2 {
		t.Errorf("unreadable gitdir: %+v, want partial with both checkouts", l)
	}
	if err := os.RemoveAll(odd); err != nil {
		t.Fatal(err)
	}

	// A checkout off disk (removed without `git worktree prune`).
	if err := os.RemoveAll(b); err != nil {
		t.Fatal(err)
	}
	if l := ListLinkedWorktrees(mainRoot, 10); l.Complete || len(l.Checkouts) != 1 {
		t.Errorf("checkout off disk: %+v, want partial", l)
	}
	runOrFail(t, repo, "worktree", "prune")
	if l := ListLinkedWorktrees(mainRoot, 10); !l.Complete || len(l.Checkouts) != 1 {
		t.Errorf("after prune: %+v, want complete with one", l)
	}
}

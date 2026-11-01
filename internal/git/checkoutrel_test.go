package git

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestCheckoutRelativePath: a file has the same project-relative path in
// the main checkout and in every linked worktree of the project, in or
// out of tree, absolute or relative-path (lane shr-worktree2, PT-39).
func TestCheckoutRelativePath(t *testing.T) {
	ctx := context.Background()
	repo := mainWithRemotes(t)
	mainRoot := realPath(t, repo)
	outOfTree := filepath.Join(t.TempDir(), "wt")
	inTree := filepath.Join(repo, ".worktrees", "x")
	relOut := filepath.Join(t.TempDir(), "relwt")
	for _, w := range []struct{ dir, branch string }{
		{outOfTree, "p/out"}, {inTree, "p/in"}, {relOut, "p/rel"},
	} {
		if err := WorktreeAdd(ctx, repo, w.dir, w.branch, "HEAD"); err != nil {
			t.Fatalf("WorktreeAdd %s: %v", w.dir, err)
		}
	}
	relativize(t, relOut, true, true)

	other := mainWithRemotes(t)
	otherWT := filepath.Join(t.TempDir(), "otherwt")
	if err := WorktreeAdd(ctx, other, otherWT, "o/wt", "HEAD"); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{repo, outOfTree, inTree, relOut, otherWT} {
		writeFile(t, filepath.Join(d, "pkg", "a.go"), "package pkg\n")
	}

	cases := []struct {
		name, root, target, want string
	}{
		{"main checkout", mainRoot, filepath.Join(repo, "pkg", "a.go"), "pkg/a.go"},
		{"out-of-tree worktree", mainRoot, filepath.Join(outOfTree, "pkg", "a.go"), "pkg/a.go"},
		{"in-tree worktree", mainRoot, filepath.Join(inTree, "pkg", "a.go"), "pkg/a.go"},
		{"relative-path worktree", mainRoot, filepath.Join(relOut, "pkg", "a.go"), "pkg/a.go"},
		{"not yet written in a worktree", mainRoot, filepath.Join(inTree, "pkg", "new.go"), "pkg/new.go"},
		{"worktree top level", mainRoot, inTree, "."},
		{"unresolved root spelling", repo, filepath.Join(outOfTree, "pkg", "a.go"), "pkg/a.go"},
		// Another project's worktree, and a relative target, read exactly
		// as RelativePath reads them.
		{"another project's worktree", mainRoot, filepath.Join(otherWT, "pkg", "a.go"), RelativePath(mainRoot, filepath.Join(otherWT, "pkg", "a.go"))},
		{"relative target", mainRoot, "pkg/a.go", RelativePath(mainRoot, "pkg/a.go")},
		{"empty root", "", filepath.Join(inTree, "pkg", "a.go"), RelativePath("", filepath.Join(inTree, "pkg", "a.go"))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := CheckoutRelativePath(c.root, c.target); got != c.want {
				t.Errorf("CheckoutRelativePath(%q, %q) = %q, want %q", c.root, c.target, got, c.want)
			}
		})
	}
	// Before the seam the worktree paths split from the main checkout's.
	if got := RelativePath(mainRoot, filepath.Join(inTree, "pkg", "a.go")); got != ".worktrees/x/pkg/a.go" {
		t.Errorf("RelativePath in-tree = %q (the split the seam removes)", got)
	}
	if _, err := os.Stat(filepath.Join(mainRoot, ".worktrees", "x", ".git")); err != nil {
		t.Fatal(err)
	}
}

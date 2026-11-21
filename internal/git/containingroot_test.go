package git

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestContainingRootTarget: a stored root inside a git working tree, but not
// its project root, belongs under the tree's project root (the main
// repository for anything inside a linked worktree); a removed folder is
// judged by its nearest existing ancestor and reported gone; a project root
// itself, a nested repository's own root, a root inside no tree and a
// relative root are left alone.
func TestContainingRootTarget(t *testing.T) {
	ctx := context.Background()
	repo := initRepo(t)
	mainRoot := realPath(t, repo)
	wt := filepath.Join(repo, ".claude", "worktrees", "wt")
	if err := WorktreeAdd(ctx, repo, wt, "contain/wt", "HEAD"); err != nil {
		t.Fatalf("WorktreeAdd: %v", err)
	}
	nested := filepath.Join(repo, "vendor", "other")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	runOrFail(t, nested, "init", "-q")
	for _, d := range []string{filepath.Join(repo, "web", "src"), filepath.Join(wt, "web"), filepath.Join(nested, "pkg")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	outside := t.TempDir()
	cases := []struct {
		name       string
		root, want string
		gone, ok   bool
	}{
		{"main repository subdirectory", realPath(t, filepath.Join(repo, "web", "src")), mainRoot, false, true},
		{"linked worktree top level", realPath(t, wt), mainRoot, false, true},
		{"linked worktree subdirectory", realPath(t, filepath.Join(wt, "web")), mainRoot, false, true},
		{"removed worktree folder", filepath.Join(mainRoot, ".claude", "worktrees", "removed", "web"), mainRoot, true, true},
		{"nested repository subdirectory", realPath(t, filepath.Join(nested, "pkg")), realPath(t, nested), false, true},
		{"main repository itself", mainRoot, "", false, false},
		{"nested repository itself", realPath(t, nested), "", false, false},
		{"inside no working tree", realPath(t, outside), "", false, false},
		{"gone and inside no working tree", filepath.Join(realPath(t, outside), "gone", "deeper"), "", false, false},
		{"relative", "web", "", false, false},
		{"empty", "", "", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, gone, ok := ContainingRootTarget(tc.root)
			if ok != tc.ok || got != tc.want || gone != tc.gone {
				t.Errorf("ContainingRootTarget(%q) = %q gone=%v ok=%v, want %q gone=%v ok=%v", tc.root, got, gone, ok, tc.want, tc.gone, tc.ok)
			}
		})
	}
}

package git

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

// TestPointerValue: the worktree pointer files git writes (`commondir`,
// the admin directory's `gitdir`) are read in this host's flavor. Git for
// Windows writes `D:/repo/...`; a daemon inside WSL reads `/mnt/d/repo/...`
// (live 2026-11-07: without this every Windows-created worktree failed the
// back-pointer check and became a project of its own). Relative and native
// values pass through unchanged, trimmed.
func TestPointerValue(t *testing.T) {
	cases := []struct {
		name, raw, posix, windows string
	}{
		{"windows drive pointer", "D:/repo/.claude/worktrees/wt/.git\n", "/mnt/d/repo/.claude/worktrees/wt/.git", "D:/repo/.claude/worktrees/wt/.git"},
		{"relative commondir", "../..\n", "../..", "../.."},
		{"native posix pointer", "  /home/u/repo/wt/.git \n", "/home/u/repo/wt/.git", "/home/u/repo/wt/.git"},
		{"empty", "\n", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := tc.posix
			if runtime.GOOS == "windows" {
				want = tc.windows
			}
			if got := pointerValue(tc.raw); got != want {
				t.Fatalf("pointerValue(%q) = %q, want %q", tc.raw, got, want)
			}
		})
	}
}

// fileURI spells an absolute path as a file URI: a foreign spelling the
// host translator rewrites to the same native path on every OS, so a test
// can write a pointer that only resolves through the translation.
func fileURI(p string) string {
	if runtime.GOOS == "windows" {
		return "file:///" + filepath.ToSlash(p)
	}
	return "file://" + p
}

// TestLinkedWorktree_ForeignSpelledPointers: a worktree whose `commondir`
// and back pointer are written in a foreign spelling (as Git for Windows
// writes them, read by a WSL daemon) still folds onto the main repository's
// project, and the main repository's worktree listing still finds it. Before
// the translation both pointers were refused and the worktree resolved to
// its own folder.
func TestLinkedWorktree_ForeignSpelledPointers(t *testing.T) {
	ctx := context.Background()
	repo := mainWithRemotes(t)
	wt := filepath.Join(t.TempDir(), "wt")
	if err := WorktreeAdd(ctx, repo, wt, "foreign/wt", "HEAD"); err != nil {
		t.Fatalf("WorktreeAdd: %v", err)
	}
	admin := realPath(t, filepath.Join(repo, ".git", "worktrees", "wt"))
	common := realPath(t, filepath.Join(repo, ".git"))
	gitFile := filepath.Join(realPath(t, wt), ".git")
	writes := map[string]string{
		filepath.Join(admin, "gitdir"):    fileURI(gitFile) + "\n",
		filepath.Join(admin, "commondir"): fileURI(common) + "\n",
	}
	for path, body := range writes {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	wantResolved(t, wt, realPath(t, repo), realPath(t, wt), true)

	listing := ListLinkedWorktrees(realPath(t, repo), 10)
	if !listing.Complete || !slices.Contains(listing.Checkouts, realPath(t, wt)) {
		t.Fatalf("ListLinkedWorktrees = %+v, want a complete listing holding %s", listing, realPath(t, wt))
	}
}

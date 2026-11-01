package store

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/git"
)

// worktreeFixture builds a real repository with one commit and an origin
// remote, plus a linked worktree outside it (`git init` then `git checkout
// -b`, never `git init -b`, so it runs on git 2.25).
func worktreeFixture(t *testing.T) (repo, wt string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git binary not available")
	}
	repo = t.TempDir()
	run := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	run(repo, "init")
	run(repo, "checkout", "-b", "main")
	run(repo, "remote", "add", "origin", "git@github.com:Acme/Widget.git")
	if err := os.WriteFile(filepath.Join(repo, "README.md"), []byte("# w\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run(repo, "add", "-A")
	run(repo, "commit", "-m", "init")
	wt = filepath.Join(t.TempDir(), "wt")
	if err := git.WorktreeAdd(context.Background(), repo, wt, "feature/wt", "HEAD"); err != nil {
		t.Fatalf("WorktreeAdd: %v", err)
	}
	return repo, wt
}

// TestRootCommitCache_LinkedWorktreeHitsMainProject: a linked worktree's
// session resolves to the main repository's projects row (F0-14), so the
// lazy root-commit exec runs on the main top level and the cached value is
// found from the worktree too.
func TestRootCommitCache_LinkedWorktreeHitsMainProject(t *testing.T) {
	t.Parallel()
	repo, wt := worktreeFixture(t)
	ctx := context.Background()
	s, _ := newTestStore(t)

	mainID, err := git.ResolveIdentity(repo, git.IdentityOptions{})
	if err != nil {
		t.Fatal(err)
	}
	wtID, err := git.ResolveIdentity(wt, git.IdentityOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if wtID.Root != mainID.Root {
		t.Fatalf("worktree Root = %q, want the main project %q", wtID.Root, mainID.Root)
	}

	mainPID, err := s.UpsertProjectWithIdentity(ctx, mainID.Root, mainID.Remote, ProjectIdentity{})
	if err != nil {
		t.Fatal(err)
	}

	var ranIn []string
	s.SetRootCommitResolver(func(ctx context.Context, root string) (string, error) {
		ranIn = append(ranIn, root)
		return git.DefaultRootCommit(ctx, root)
	})
	// The worktree's first batch: the same projects row, and the lazy exec
	// runs once, on the main top level.
	wtPID, err := s.UpsertProjectWithIdentity(ctx, wtID.Root, wtID.Remote, ProjectIdentity{})
	if err != nil {
		t.Fatal(err)
	}
	if wtPID != mainPID {
		t.Fatalf("worktree projects row %d, want the main project's %d", wtPID, mainPID)
	}
	s.maybeRunLazyRootCommit(ctx, wtID.Root)
	if len(ranIn) != 1 || ranIn[0] != mainID.Root {
		t.Fatalf("root-commit exec ran in %v, want once in %q", ranIn, mainID.Root)
	}
	needs, err := s.RootCommitNeedsCheck(ctx, wtID.Root)
	if err != nil || needs {
		t.Fatalf("RootCommitNeedsCheck(worktree) = %v, %v; want a cache hit", needs, err)
	}
	needs, err = s.RootCommitNeedsCheck(ctx, mainID.Root)
	if err != nil || needs {
		t.Fatalf("RootCommitNeedsCheck(main) = %v, %v; want a cache hit", needs, err)
	}
	want, err := git.DefaultRootCommit(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}
	var got string
	if err := s.db.QueryRowContext(ctx, `SELECT root_commit_sha FROM projects WHERE id = ?`, mainPID).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("cached root commit = %q, want the main repository's %q", got, want)
	}
}

package secquickscan

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestHistoryPrunableWorktreeSkipped (lane SEC-P4 decision 4, SECP-18): a
// linked worktree whose checkout was deleted but not pruned no longer makes
// every check unknown: its config is skipped for the push URLs and the
// default push remote, and a commit only its HEAD holds is still held.
func TestHistoryPrunableWorktreeSkipped(t *testing.T) {
	git, code := realGit(t)
	repo := t.TempDir()
	gitT(t, repo, "init", "-q")
	gitT(t, repo, "symbolic-ref", "HEAD", "refs/heads/main")
	commitFile(t, repo, "a", "one")
	gitT(t, repo, "remote", "add", "origin", t.TempDir())
	gitT(t, repo, "config", "branch.main.remote", "origin")
	gitT(t, repo, "config", "extensions.worktreeConfig", "true")
	wt := filepath.Join(t.TempDir(), "wt")
	gitT(t, repo, "worktree", "add", "-q", "--detach", wt)
	held := commitFile(t, wt, "b", "only on the worktree")
	if err := os.RemoveAll(wt); err != nil {
		t.Fatal(err)
	}
	if wts := parseWorktrees(gitT(t, repo, "worktree", "list", "--porcelain")); len(wts) != 2 || !wts[1].prunable {
		t.Fatalf("parse = %+v, want the second worktree prunable", wts)
	}
	h := HistoryChecker{Git: git, ExitCode: code}
	ctx := context.Background()
	if remote, ok := h.DefaultPushRemote(ctx, repo); !ok || remote != "origin" {
		t.Fatalf("default push remote = %q %v, want origin (the prunable worktree skipped)", remote, ok)
	}
	if got := h.Check(ctx, repo, held); got != HistoryUnpushed {
		t.Fatalf("a commit the prunable worktree's HEAD holds: %s, want unpushed", got)
	}
}

// TestParseWorktreesPrunable: both porcelain spellings of the prunable
// line are read.
func TestParseWorktreesPrunable(t *testing.T) {
	out := "worktree /r\nHEAD " + repeat40("0a") + "\nbranch refs/heads/main\n\nworktree /w\nHEAD " + repeat40("0b") + "\ndetached\nprunable gitdir file points to non-existent location\n\nworktree /x\nprunable\n"
	wts := parseWorktrees(out)
	if len(wts) != 3 || wts[0].prunable || !wts[1].prunable || !wts[2].prunable {
		t.Fatalf("parse = %+v", wts)
	}
}

func repeat40(pair string) string {
	b := make([]byte, 0, 40)
	for len(b) < 40 {
		b = append(b, pair...)
	}
	return string(b)
}

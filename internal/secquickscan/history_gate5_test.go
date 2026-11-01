package secquickscan

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// realGit is a GitFunc over the installed git (tests only).
func realGit(t *testing.T) (GitFunc, func(error) (int, bool)) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	run := func(ctx context.Context, dir string, maxBytes int, timeout time.Duration, args ...string) ([]byte, bool, error) {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, "git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_NO_LAZY_FETCH=1")
		var out bytes.Buffer
		cmd.Stdout = &out
		err := cmd.Run()
		b := out.Bytes()
		if len(b) > maxBytes {
			return b[:maxBytes], true, err
		}
		return b, false, err
	}
	code := func(err error) (int, bool) {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode(), true
		}
		return 0, false
	}
	return run, code
}

// gitT runs git in dir (fixture setup).
func gitT(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func commitFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	gitT(t, dir, "add", name)
	gitT(t, dir, "commit", "-q", "-m", body)
	return gitT(t, dir, "rev-parse", "HEAD")
}

// TestHistoryCheckerReflogHold (lane SEC-GATE5 milestone 2, SECP-18): a
// commit an amend or a reset left reachable only through a reflog entry,
// whether it is the entry or an ancestor of one, stays held; once the
// reflog no longer reaches it, it is held as dangling until `git gc
// --prune=now` removes the object, then it is gone.
func TestHistoryCheckerReflogHold(t *testing.T) {
	git, code := realGit(t)
	repo := t.TempDir()
	gitT(t, repo, "init", "-q")
	commitFile(t, repo, "a", "one")
	secret := commitFile(t, repo, "b", "two")
	tip := commitFile(t, repo, "c", "three")
	h := HistoryChecker{Git: git, ExitCode: code}
	ctx := context.Background()
	if got := h.Check(ctx, repo, secret); got != HistoryUnpushed {
		t.Fatalf("on the branch: %s, want unpushed", got)
	}
	gitT(t, repo, "reset", "-q", "--hard", "HEAD~2")
	f := h.Facts(ctx, repo, secret)
	if got := DecideHistory(f); got != HistoryUnpushed || !f.Reflog {
		t.Fatalf("after a reset, an ancestor of a reflog entry: %s (%+v), want unpushed by reflog", got, f)
	}
	if got := h.Check(ctx, repo, tip); got != HistoryUnpushed {
		t.Fatalf("after a reset, a reflog entry itself: %s, want unpushed", got)
	}
	gitT(t, repo, "reflog", "expire", "--expire-unreachable=now", "--all")
	// Nothing reaches it but the object is still there: a push by its id
	// still sends it, so it stays held as dangling until git prunes it
	// (lane SEC-P4 decision 5; it read gone before).
	if v := h.Inspect(ctx, repo, secret); v.State != HistoryUnpushed || v.Reason != HistoryReasonDangling {
		t.Fatalf("after the reflog expired: %+v, want unpushed (dangling)", v)
	}
	gitT(t, repo, "gc", "-q", "--prune=now")
	if got := h.Check(ctx, repo, secret); got != HistoryGone {
		t.Fatalf("after git gc --prune=now: %s, want gone", got)
	}

	// An amend leaves the old commit in HEAD's reflog.
	amended := commitFile(t, repo, "d", "four")
	gitT(t, repo, "commit", "-q", "--amend", "-m", "four amended")
	if got := h.Check(ctx, repo, amended); got != HistoryUnpushed {
		t.Fatalf("after an amend: %s, want unpushed", got)
	}
}

// TestDefaultPushRemoteWorktreeConfig (lane SEC-GATE5 milestone 2,
// SECP-18): with extensions.worktreeConfig set, a linked worktree's own
// config.worktree decides where a plain push from it goes; without the
// extension the main config does.
func TestDefaultPushRemoteWorktreeConfig(t *testing.T) {
	git, code := realGit(t)
	repo := t.TempDir()
	gitT(t, repo, "init", "-q")
	commitFile(t, repo, "a", "one")
	main := strings.TrimPrefix(gitT(t, repo, "symbolic-ref", "HEAD"), "refs/heads/")
	gitT(t, repo, "remote", "add", "origin", "https://example.invalid/o.git")
	gitT(t, repo, "remote", "add", "fork", "https://example.invalid/f.git")
	gitT(t, repo, "config", "remote.pushDefault", "origin")
	wt := filepath.Join(t.TempDir(), "wt")
	gitT(t, repo, "worktree", "add", "-q", "-b", "feature", wt)
	h := HistoryChecker{Git: git, ExitCode: code}
	ctx := context.Background()
	if got, ok := h.DefaultPushRemote(ctx, repo); !ok || got != "origin" {
		t.Fatalf("both worktrees on remote.pushDefault: %q %v, want origin", got, ok)
	}
	gitT(t, repo, "config", "extensions.worktreeConfig", "true")
	gitT(t, wt, "config", "--worktree", "branch.feature.pushRemote", "fork")
	if got, ok := h.DefaultPushRemote(ctx, repo); !ok || got != "" {
		t.Fatalf("the worktree pushes to fork, main to origin: %q %v, want no agreed default", got, ok)
	}
	gitT(t, repo, "config", "--worktree", "branch."+main+".pushRemote", "fork")
	if got, ok := h.DefaultPushRemote(ctx, repo); !ok || got != "fork" {
		t.Fatalf("both worktrees push to fork through config.worktree: %q %v, want fork", got, ok)
	}
	// A pushurl set only in the worktree's config.worktree is read too:
	// that remote is never credited.
	gitT(t, wt, "config", "--worktree", "remote.fork.pushurl", "https://example.invalid/elsewhere.git")
	differs, ok := h.pushDiffers(ctx, repo, []string{"origin", "fork"})
	if !ok || !differs["fork"] || differs["origin"] {
		t.Fatalf("push differs = %v %v, want fork only", differs, ok)
	}
}

package git

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// worktree.go — mutation helpers for the Agent Arena's per-candidate git
// worktrees (plan: docs/plans/agent-arena-terminal-multi-harness-2026-08-22.md
// §2a). Unlike the rest of this package, these shell out to the real git
// binary (precedent: internal/gitview) because worktree plumbing has no
// pure-file equivalent. The main repository is never touched by a run: each
// candidate diverges from HEAD inside its own linked worktree.

// Worktree describes a linked worktree created for an arena candidate.
type Worktree struct {
	// Path is the absolute path of the worktree checkout.
	Path string
	// Branch is the arena branch checked out in the worktree.
	Branch string
}

func runGit(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// IsDirty reports whether the repository at repoRoot has uncommitted
// changes (staged or unstaged, including untracked files).
func IsDirty(ctx context.Context, repoRoot string) (bool, error) {
	out, err := runGit(ctx, repoRoot, "status", "--porcelain")
	if err != nil {
		return false, fmt.Errorf("git.IsDirty: %w", err)
	}
	return strings.TrimSpace(out) != "", nil
}

// HeadSHA returns the commit SHA currently checked out at repoRoot.
func HeadSHA(ctx context.Context, repoRoot string) (string, error) {
	out, err := runGit(ctx, repoRoot, "rev-parse", "HEAD")
	if err != nil {
		return "", fmt.Errorf("git.HeadSHA: %w", err)
	}
	return strings.TrimSpace(out), nil
}

// CurrentBranch returns the checked-out branch name, or "" on a detached
// HEAD.
func CurrentBranch(ctx context.Context, repoRoot string) (string, error) {
	out, err := runGit(ctx, repoRoot, "rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		return "", fmt.Errorf("git.CurrentBranch: %w", err)
	}
	branch := strings.TrimSpace(out)
	if branch == "HEAD" {
		return "", nil
	}
	return branch, nil
}

// CommitMessage returns the full commit message of sha.
func CommitMessage(ctx context.Context, repoRoot, sha string) (string, error) {
	out, err := runGit(ctx, repoRoot, "log", "-1", "--format=%B", sha)
	if err != nil {
		return "", fmt.Errorf("git.CommitMessage: %w", err)
	}
	return out, nil
}

// AmendCommitMessage rewrites the CURRENT HEAD's message to msg (keeping
// author/committer identity and content untouched) and returns the new SHA.
func AmendCommitMessage(ctx context.Context, repoRoot, msg string) (string, error) {
	out, err := runGit(ctx, repoRoot, "commit", "--amend", "-m", msg)
	if err != nil {
		return "", fmt.Errorf("git.AmendCommitMessage: %w: %s", err, strings.TrimSpace(out))
	}
	return HeadSHA(ctx, repoRoot)
}

// IsAncestor reports whether ancestor is reachable from descendant. A false
// result is a clean git exit status 1; malformed refs and repository failures
// are returned as errors.
func IsAncestor(ctx context.Context, repoRoot, ancestor, descendant string) (bool, error) {
	if ancestor == "" || descendant == "" {
		return false, fmt.Errorf("git.IsAncestor: ancestor and descendant required")
	}
	cmd := exec.CommandContext(ctx, "git", "merge-base", "--is-ancestor", ancestor, descendant)
	cmd.Dir = repoRoot
	out, err := cmd.CombinedOutput()
	if err == nil {
		return true, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode() == 1 {
		return false, nil
	}
	return false, fmt.Errorf("git.IsAncestor: %w: %s", err, strings.TrimSpace(string(out)))
}

// TreesEqual reports whether two commits resolve to the same tree object.
func TreesEqual(ctx context.Context, repoRoot, a, b string) (bool, error) {
	if a == "" || b == "" {
		return false, fmt.Errorf("git.TreesEqual: both revisions required")
	}
	aTree, err := runGit(ctx, repoRoot, "rev-parse", a+"^{tree}")
	if err != nil {
		return false, fmt.Errorf("git.TreesEqual: %w", err)
	}
	bTree, err := runGit(ctx, repoRoot, "rev-parse", b+"^{tree}")
	if err != nil {
		return false, fmt.Errorf("git.TreesEqual: %w", err)
	}
	return strings.TrimSpace(aTree) == strings.TrimSpace(bTree), nil
}

// ResetHard restores a clean Arena keep target to an exact pre-operation
// commit when a land completed but its provenance/database finalization did
// not. Callers must first prove that HEAD is still the commit they created.
func ResetHard(ctx context.Context, repoRoot, revision string) error {
	if revision == "" {
		return fmt.Errorf("git.ResetHard: revision required")
	}
	if _, err := runGit(ctx, repoRoot, "reset", "--hard", revision); err != nil {
		return fmt.Errorf("git.ResetHard: %w", err)
	}
	return nil
}

// WorktreeAdd creates a linked worktree at path with a new branch branching
// from startPoint. The caller owns cleanup via WorktreeRemove.
func WorktreeAdd(ctx context.Context, repoRoot, path, branch, startPoint string) error {
	if path == "" || branch == "" || startPoint == "" {
		return fmt.Errorf("git.WorktreeAdd: path, branch and startPoint are required")
	}
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("git.WorktreeAdd: path already exists: %s", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("git.WorktreeAdd: inspect path: %w", err)
	}
	exists, err := localBranchExists(ctx, repoRoot, branch)
	if err != nil {
		return fmt.Errorf("git.WorktreeAdd: %w", err)
	}
	if exists {
		return fmt.Errorf("git.WorktreeAdd: branch already exists: %s", branch)
	}
	if _, err := runGit(ctx, repoRoot, "worktree", "add", "-b", branch, path, startPoint); err != nil {
		cleanupCtx := context.WithoutCancel(ctx)
		_ = WorktreeRemove(cleanupCtx, repoRoot, path)
		_ = os.RemoveAll(path)
		_ = DeleteBranch(cleanupCtx, repoRoot, branch)
		return fmt.Errorf("git.WorktreeAdd: %w", err)
	}
	return nil
}

func localBranchExists(ctx context.Context, repoRoot, branch string) (bool, error) {
	//nolint:gosec // G204: fixed git argv; branch is interpolated into a ref NAME argument (not a flag position) and show-ref only reads refs
	cmd := exec.CommandContext(ctx, "git", "show-ref", "--verify", "--quiet", "refs/heads/"+branch)
	cmd.Dir = repoRoot
	err := cmd.Run()
	if err == nil {
		return true, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode() == 1 {
		return false, nil
	}
	return false, fmt.Errorf("git branch existence: %w", err)
}

// WorktreeRemove detaches and deletes the linked worktree at path from the
// repository at repoRoot. Force is used deliberately: arena candidates may
// leave uncommitted scratch behind, and the run's verdict already lives in
// the store — nothing in the worktree is precious once removed.
func WorktreeRemove(ctx context.Context, repoRoot, path string) error {
	if path == "" {
		return fmt.Errorf("git.WorktreeRemove: path required")
	}
	if _, err := runGit(ctx, repoRoot, "worktree", "remove", "--force", path); err != nil {
		return fmt.Errorf("git.WorktreeRemove: %w", err)
	}
	return nil
}

// DeleteBranch force-deletes one Arena-owned branch after its worktree has
// been removed. Callers pass an exact validated branch name, never user shell
// text. A missing branch is already clean and succeeds, making partial-start
// cleanup and terminal discard safely convergent.
func DeleteBranch(ctx context.Context, repoRoot, branch string) error {
	if branch == "" {
		return fmt.Errorf("git.DeleteBranch: branch required")
	}
	exists, err := localBranchExists(ctx, repoRoot, branch)
	if err != nil {
		return fmt.Errorf("git.DeleteBranch: %w", err)
	}
	if !exists {
		return nil
	}
	if _, err := runGit(ctx, repoRoot, "branch", "-D", branch); err != nil {
		return fmt.Errorf("git.DeleteBranch: %w", err)
	}
	return nil
}

// CommitAll stages every change (new, modified, deleted — including
// untracked) in the worktree and commits it on the worktree's branch,
// returning the resulting commit SHA. An identity is forced so commits work
// in repos without configured user.name/user.email; --allow-empty keeps an
// inert candidate (agent made no edits) a clean committable branch.
func CommitAll(ctx context.Context, wtPath, message string) (string, error) {
	if wtPath == "" {
		return "", fmt.Errorf("git.CommitAll: worktree path required")
	}
	if _, err := runGit(ctx, wtPath, "add", "-A"); err != nil {
		return "", fmt.Errorf("git.CommitAll: add: %w", err)
	}
	if _, err := runGit(ctx, wtPath,
		"-c", "user.name=observer-arena",
		"-c", "user.email=arena@observer.local",
		"commit", "-m", message, "--allow-empty"); err != nil {
		return "", fmt.Errorf("git.CommitAll: commit: %w", err)
	}
	sha, err := HeadSHA(ctx, wtPath)
	if err != nil {
		return "", fmt.Errorf("git.CommitAll: %w", err)
	}
	return sha, nil
}

// DiffStat counts files/insertions/deletions of the diff between baseSHA and
// the worktree's working tree (staged + unstaged + untracked after add -A).
// It shells to `git diff --numstat` against baseSHA; binary files count as
// one changed file with no line counts.
func DiffStat(ctx context.Context, wtPath, baseSHA string) (files, added, removed int, err error) {
	if baseSHA == "" {
		return 0, 0, 0, fmt.Errorf("git.DiffStat: baseSHA required")
	}
	out, err := runGit(ctx, wtPath, "diff", "--numstat", baseSHA)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("git.DiffStat: %w", err)
	}
	for _, line := range strings.Split(out, "\n") {
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}
		files++
		added += parseNumstat(parts[0])
		removed += parseNumstat(parts[1])
	}
	return files, added, removed, nil
}

// Patch writes nothing itself; callers capture the full diff via
// PatchText so file contents stay out of the DB.

// PatchText returns the full patch text between baseSHA and the worktree's
// current state. Callers persist it to disk under the run directory.
func PatchText(ctx context.Context, wtPath, baseSHA string) (string, error) {
	if baseSHA == "" {
		return "", fmt.Errorf("git.PatchText: baseSHA required")
	}
	out, err := runGit(ctx, wtPath, "diff", baseSHA)
	if err != nil {
		return "", fmt.Errorf("git.PatchText: %w", err)
	}
	return out, nil
}

func parseNumstat(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0 // "-" for binary files
		}
		n = n*10 + int(c-'0')
	}
	return n
}

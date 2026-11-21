//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/gitview"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// terminal_sandbox_returns.go runs "open a saved diff as a branch" (lane
// RETURNS, audit item H6): the pure plan is internal/workspace
// (applydiff.go), and this is the one place it is executed, in the person's
// own repository, through the return's hardened git runner (hooks and
// fsmonitor off, no system or global config, no inherited GIT_* variable;
// runReturnGitEnv with workspace.Step.Hardened). The working tree, the
// repository's own index, HEAD and every existing ref are left alone: the
// diff goes into a temporary index, and the only write is the new branch,
// created only if it does not exist.

// sandboxDiffGit runs one diff-branch step (a test seam).
var sandboxDiffGit = func(ctx context.Context, s workspace.GitStep) ([]byte, error) {
	return runReturnGitEnv(ctx, workspace.Step{Argv: s.Argv, Hardened: true}, s.Env)
}

// sandboxDiffBranchResult is what one "open as a branch" made.
type sandboxDiffBranchResult struct {
	Branch string `json:"branch"`
	Ref    string `json:"ref"`
	Commit string `json:"commit"`
	Repo   string `json:"repo"`
	Files  int    `json:"files"`
}

// sandboxDiffBranchTimeout bounds one "open as a branch".
const sandboxDiffBranchTimeout = 5 * time.Minute

// sandboxOpenDiffBranch opens the saved diff at diffFile as the branch
// refs/heads/observer-sandbox/<run>/changes of repo, on base. Every refusal
// names the check that refused and leaves the repository as it was.
func sandboxOpenDiffBranch(ctx context.Context, repo, diffFile, runID, base string) (sandboxDiffBranchResult, error) {
	ctx, cancel := context.WithTimeout(ctx, sandboxDiffBranchTimeout)
	defer cancel()
	res := sandboxDiffBranchResult{Repo: repo}
	if dir, refused := gitview.HostGitRefused(repo); refused {
		return res, fmt.Errorf("host git was refused in %s before, so it is not run there now", dir)
	}
	tmp, err := os.MkdirTemp("", "observer-diff-branch-*")
	if err != nil {
		return res, fmt.Errorf("make a temporary folder: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	if resolved, rerr := filepath.EvalSymlinks(tmp); rerr == nil {
		tmp = resolved
	}
	// One copy of the diff, so every step reads the same bytes.
	diff := filepath.Join(tmp, "run.diff")
	if err := copyCappedNoFollow(diffFile, diff, int64(sandbox.MaxStagedDiff)); err != nil {
		return res, err
	}
	plan, err := workspace.PlanDiffBranch(workspace.DiffBranchRequest{Repo: repo, DiffPath: diff, TempDir: tmp, RunID: runID, Base: base})
	if err != nil {
		return res, err
	}
	res.Ref, res.Branch = plan.Ref, workspace.DiffBranchName(plan.Ref)
	d := diffBranchRun{
		plan: plan, repo: repo, base: base, short: base[:min(len(base), 12)],
		run: func(s workspace.GitStep) ([]byte, error) { return sandboxDiffGit(ctx, s) },
	}
	if res.Files, err = d.check(res.Branch); err != nil {
		return res, err
	}
	tree, err := d.applyChecked()
	if err != nil {
		return res, err
	}
	if res.Commit, err = d.record(tree, res.Branch); err != nil {
		return res, err
	}
	return res, nil
}

// diffBranchRun is one "open as a branch" between its plan and its end.
type diffBranchRun struct {
	plan              workspace.DiffBranchPlan
	repo, base, short string
	run               func(workspace.GitStep) ([]byte, error)
}

// check runs every check before anything is applied: the base is in the
// repository, the branch does not exist, every path of the diff passes the
// return's rules, and every file the diff changes is, in the base, exactly
// the file the box started from. It returns how many paths the diff names.
func (d diffBranchRun) check(branch string) (int, error) {
	if _, err := d.run(d.plan.VerifyBase()); err != nil {
		return 0, fmt.Errorf("commit %s, which the box started from, is not in %s", d.short, d.repo)
	}
	if _, err := d.run(d.plan.RefExists()); err == nil {
		return 0, fmt.Errorf("the branch %s already exists in %s; it is never moved", branch, d.repo)
	}
	if _, err := d.run(d.plan.SeedIndex()); err != nil {
		return 0, fmt.Errorf("read commit %s into a temporary index: %w", d.short, err)
	}
	out, err := d.run(d.plan.DiffPaths())
	if err != nil {
		return 0, fmt.Errorf("the diff could not be read: %w", err)
	}
	paths, err := workspace.CheckDiffPaths(out)
	if err != nil {
		return 0, err
	}
	if _, err := d.run(d.plan.FakeAncestor()); err != nil {
		return 0, fmt.Errorf("the diff does not name, in a form Observer can check, files that are in %s (it was not made against commit %s): %w", d.repo, d.short, err)
	}
	anc, err := d.run(d.plan.ListAncestor())
	if err != nil {
		return 0, fmt.Errorf("list the files the diff starts from: %w", err)
	}
	ancestor, err := workspace.ParseIndexEntries(anc)
	if err != nil {
		return 0, err
	}
	bt, err := d.run(d.plan.ListBase())
	if err != nil {
		return 0, fmt.Errorf("list commit %s: %w", d.short, err)
	}
	baseTree, err := workspace.ParseTreeEntries(bt)
	if err != nil {
		return 0, err
	}
	return len(paths), workspace.CheckAncestorMatchesBase(ancestor, baseTree, d.base)
}

// applyChecked applies the diff to the temporary index, writes the tree and
// checks every entry it changes (no gitlink, symlinks inside the tree).
func (d diffBranchRun) applyChecked() (string, error) {
	if _, err := d.run(d.plan.Apply()); err != nil {
		return "", fmt.Errorf("the diff does not apply to commit %s (nothing was changed): %w", d.short, err)
	}
	wt, err := d.run(d.plan.WriteTree())
	if err != nil {
		return "", fmt.Errorf("write the new tree: %w", err)
	}
	tree := strings.TrimSpace(string(wt))
	if !workspace.ValidSHA(tree) {
		return "", fmt.Errorf("write the new tree: the answer was %q", tree)
	}
	ch, err := d.run(d.plan.ChangedEntries(tree))
	if err != nil {
		return "", fmt.Errorf("list what the diff changes: %w", err)
	}
	changed, err := workspace.ParseRawDiff(ch)
	if err != nil {
		return "", err
	}
	if len(changed) == 0 {
		return "", fmt.Errorf("the diff changes nothing in commit %s", d.short)
	}
	links, err := workspace.CheckChangedEntries(changed)
	if err != nil {
		return "", err
	}
	if len(links) > 0 {
		if err := sandboxDiffCheckLinks(d.run, d.plan, tree, links); err != nil {
			return "", err
		}
	}
	return tree, nil
}

// record commits the tree on the base and creates the branch, create-only,
// then reads it back.
func (d diffBranchRun) record(tree, branch string) (string, error) {
	co, err := d.run(d.plan.CommitTree(tree))
	if err != nil {
		return "", fmt.Errorf("record the commit: %w", err)
	}
	commit := strings.TrimSpace(string(co))
	if !workspace.ValidSHA(commit) {
		return "", fmt.Errorf("record the commit: the answer was %q", commit)
	}
	if _, err := d.run(d.plan.CreateRef(commit)); err != nil {
		return "", fmt.Errorf("create %s (only if it does not exist): %w", branch, err)
	}
	got, err := d.run(d.plan.VerifyRef())
	if err != nil {
		return "", fmt.Errorf("read %s back: %w", branch, err)
	}
	if strings.TrimSpace(string(got)) != commit {
		return "", fmt.Errorf("read %s back: it names %q, not the new commit", branch, strings.TrimSpace(string(got)))
	}
	return commit, nil
}

// sandboxDiffCheckLinks checks the symlinks a diff adds or changes: each
// target on its own (CheckSymlinkTarget), then every chain that starts at
// one, through every symlink of the new tree.
func sandboxDiffCheckLinks(run func(workspace.GitStep) ([]byte, error), plan workspace.DiffBranchPlan, tree string, links []workspace.TreeEntry) error {
	all, err := run(plan.ListTree(tree))
	if err != nil {
		return fmt.Errorf("list the new tree: %w", err)
	}
	entries, err := workspace.ParseTreeEntries(all)
	if err != nil {
		return err
	}
	changed := map[string]bool{}
	starts := make([]string, 0, len(links))
	for _, l := range links {
		changed[l.Path] = true
		starts = append(starts, l.Path)
	}
	targets := map[string]string{}
	n := 0
	for _, e := range entries {
		if e.Mode != "120000" {
			continue
		}
		if n++; n > workspace.MaxReturnSymlinks {
			return fmt.Errorf("the new tree has more than %d symlinks", workspace.MaxReturnSymlinks)
		}
		if !workspace.ValidSHA(e.Object) {
			return fmt.Errorf("the symlink %q names object %q", e.Path, e.Object)
		}
		target, err := run(plan.ReadBlob(e.Object))
		if err != nil {
			return fmt.Errorf("read the symlink %q: %w", e.Path, err)
		}
		if changed[e.Path] {
			if err := workspace.CheckSymlinkTarget(e.Path, target); err != nil {
				return err
			}
		}
		targets[e.Path] = string(target)
	}
	return workspace.CheckSymlinkChainsFrom(starts, targets)
}

// copyCappedNoFollow copies src (a regular file, never followed through a
// link) to a new file dst, refusing one over limit bytes.
func copyCappedNoFollow(src, dst string, limit int64) error {
	fi, err := os.Lstat(src)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("the saved diff %s is not there any more", src)
	case err != nil:
		return err
	case !fi.Mode().IsRegular():
		return fmt.Errorf("the saved diff %s is not a regular file", src)
	case fi.Size() > limit:
		return fmt.Errorf("the saved diff is over %d bytes", limit)
	}
	in, err := os.Open(src) //nolint:gosec // G304: a saved diff under Observer's own returns directory, lstat-checked regular and capped
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: a fresh file in a fresh temporary folder
	if err != nil {
		return err
	}
	n, cerr := io.Copy(out, io.LimitReader(in, limit+1))
	if err := out.Close(); cerr == nil {
		cerr = err
	}
	if cerr != nil {
		return cerr
	}
	if n > limit {
		return fmt.Errorf("the saved diff is over %d bytes", limit)
	}
	return nil
}

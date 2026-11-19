//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/gitview"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
)

// terminal_sandbox_hosted_nongit.go lists a folder that is not a git
// repository for a hosted upload (decision SBXD-8, audit item H8), without
// touching the folder: git's own ignore machinery runs over a TEMPORARY git
// directory made outside the folder (`git --git-dir=<temp> --work-tree=<folder>
// ls-files -z --others --exclude-standard --exclude-from=<default ignore
// file>`) through the hardened read-only envelope (gitview.RunReadOnlyEnv
// plus extrun.GitHardeningEnv: no hooks, fsmonitor, system or global config),
// so the folder's own .gitignore files apply as in a repository, and the
// default ignore table (sandboxremote.DefaultUploadIgnore) plus
// [terminal.sandbox.hosted].upload_ignore add what a repository would
// normally ignore. The folder is never `git init`ed and nothing is written
// in it; the temporary directory is removed before the listing returns.
// sandboxremote.PlanManifest then applies the usual credential-shaped,
// link and size exclusions and the caps.

// hostedUploadListing is how a hosted run lists a folder that is not a
// repository: [terminal.sandbox.hosted].upload_non_git and upload_ignore,
// carried on the run's plan so the helper's re-list matches the consent.
type hostedUploadListing struct {
	NonGit bool     `json:"non_git,omitempty"`
	Ignore []string `json:"ignore,omitempty"`
}

// hostedUploadListingFor is the listing the hosted block configures.
func hostedUploadListingFor(c config.TerminalSandboxHostedConfig) hostedUploadListing {
	return hostedUploadListing{NonGit: c.UploadNonGit, Ignore: append([]string(nil), c.UploadIgnore...)}
}

// hostedPlanUpload lists root and plans its upload: a repository's own
// listing (hostedListWorkspace), else, with the listing's NonGit on, the
// non-repository listing; PlanManifest decides. The root and home rules are
// checked before a folder that is not a repository is listed, so the home
// folder or / is never walked.
func hostedPlanUpload(ctx context.Context, root, home string, l hostedUploadListing) (sandboxremote.Manifest, error) {
	cands, repo, err := hostedListWorkspace(ctx, root)
	if err != nil {
		return sandboxremote.Manifest{}, err
	}
	in := sandboxremote.ManifestInput{Root: filepath.ToSlash(root), Home: home, Repository: repo, Candidates: cands}
	if !repo && l.NonGit {
		in.NonRepository, in.Ignore = true, l.Ignore
		if _, err := sandboxremote.PlanManifest(sandboxremote.ManifestInput{Root: in.Root, Home: home, NonRepository: true}); err != nil {
			return sandboxremote.Manifest{}, fmt.Errorf("terminal_sandbox: %w", err)
		}
		if in.Candidates, err = hostedListNonGit(ctx, root, l.Ignore); err != nil {
			return sandboxremote.Manifest{}, err
		}
	}
	m, err := sandboxremote.PlanManifest(in)
	if err != nil {
		return m, fmt.Errorf("terminal_sandbox: %w", err)
	}
	return m, nil
}

// errHostedNonGitHoldsGit refuses a folder git cannot read as a repository
// although it holds a .git entry (another user's repository, a broken
// checkout): it is never listed as a plain folder.
var errHostedNonGitHoldsGit = errors.New("terminal_sandbox: the folder holds a .git that git cannot read as a repository; fix the repository or pick another folder")

// hostedListNonGit lists the upload candidates of root, a folder that is not
// a repository (a variable so tests stand it in).
var hostedListNonGit = func(ctx context.Context, root string, extra []string) ([]sandboxremote.Candidate, error) {
	if _, err := os.Lstat(filepath.Join(root, ".git")); err == nil {
		return nil, errHostedNonGitHoldsGit
	}
	tmp, err := os.MkdirTemp("", "observer-upload-list-")
	if err != nil {
		return nil, fmt.Errorf("terminal_sandbox: make the temporary git directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	if hostedTempInside(tmp, root) {
		return nil, fmt.Errorf("terminal_sandbox: the temporary folder %s is inside %s, so listing it would write into it; pick another folder or set TMPDIR elsewhere", tmp, root)
	}
	gitDir, exclude, err := hostedTempGitDir(tmp, extra)
	if err != nil {
		return nil, err
	}
	env := append(extrun.GitHardeningEnv(""), "GIT_DIR="+gitDir, "GIT_WORK_TREE="+root, "GIT_INDEX_FILE="+filepath.Join(gitDir, "index"))
	out, over, err := gitview.RunReadOnlyEnv(ctx, root, 64<<20, 60*time.Second, env,
		"--git-dir="+gitDir, "--work-tree="+root,
		"ls-files", "-z", "--others", "--exclude-standard", "--exclude-from="+exclude)
	if err != nil {
		return nil, fmt.Errorf("terminal_sandbox: list the folder's files: %w", err)
	}
	if over {
		return nil, fmt.Errorf("terminal_sandbox: %w: the folder's file list is over 64 MiB", sandboxremote.ErrScopeTooLarge)
	}
	return hostedCandidates(root, out), nil
}

// hostedBaselineScript makes the box's baseline repository of the uploaded
// tree (history never leaves the machine), so the box's staged diff is
// exactly its changes.
const hostedBaselineScript = `command -v git >/dev/null 2>&1 || exit 0; git init -q && git add -A && git -c user.email=observer@localhost -c user.name=observer commit -q --allow-empty -m observer-baseline`

// hostedBaselineNonGitScript is the same for a folder that is not a
// repository: the listing's ignore lines (passed as arguments, never parsed
// by the shell) go into the box repository's own .git/info/exclude first,
// so what the agent installs or builds in the box (node_modules, .venv)
// stays out of the returned diff as it stayed out of the upload.
const hostedBaselineNonGitScript = `command -v git >/dev/null 2>&1 || exit 0; git init -q && mkdir -p .git/info && printf '%s\n' "$@" >> .git/info/exclude && git add -A && git -c user.email=observer@localhost -c user.name=observer commit -q --allow-empty -m observer-baseline`

// hostedBaselineArgv is the baseline step's argv in the box.
func hostedBaselineArgv(nonRepository bool, extra []string) []string {
	if !nonRepository {
		return []string{"sh", "-c", hostedBaselineScript}
	}
	argv := []string{"sh", "-c", hostedBaselineNonGitScript, "sh"}
	for _, line := range strings.Split(strings.TrimSuffix(string(sandboxremote.UploadIgnoreFile(extra)), "\n"), "\n") {
		if line != "" {
			argv = append(argv, line)
		}
	}
	return argv
}

// hostedTempGitDir makes the smallest git directory git accepts (HEAD,
// objects, refs; no config, no hooks, no index) and the exclude file inside
// tmp.
func hostedTempGitDir(tmp string, extra []string) (gitDir, exclude string, err error) {
	gitDir = filepath.Join(tmp, "git")
	for _, d := range []string{"objects", "refs"} {
		if err := os.MkdirAll(filepath.Join(gitDir, d), 0o700); err != nil {
			return "", "", fmt.Errorf("terminal_sandbox: make the temporary git directory: %w", err)
		}
	}
	if err := os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: refs/heads/observer\n"), 0o600); err != nil {
		return "", "", fmt.Errorf("terminal_sandbox: make the temporary git directory: %w", err)
	}
	exclude = filepath.Join(tmp, "exclude")
	if err := os.WriteFile(exclude, sandboxremote.UploadIgnoreFile(extra), 0o600); err != nil {
		return "", "", fmt.Errorf("terminal_sandbox: write the ignore list: %w", err)
	}
	return gitDir, exclude, nil
}

// hostedTempInside reports whether tmp is root or lies inside it, with
// symlinks resolved on both sides.
func hostedTempInside(tmp, root string) bool {
	if t, err := filepath.EvalSymlinks(tmp); err == nil {
		tmp = t
	}
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
	return pathWithin(tmp, root)
}

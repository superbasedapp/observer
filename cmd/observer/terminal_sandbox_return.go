//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/gitview"
	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// terminal_sandbox_return.go runs the return step of a copy workspace
// (sandbox plan v2 section 6, SBX-BE-10, the M7 scan hook; lane SBX-P3A):
// the commits a box made in its copy come back into the source repository
// as one new ref, refs/observer/sandbox/<run>, never into the working tree.
// The pure planning is internal/workspace (return.go); this file is the
// one place it is executed. It is called by the oci-runc host helper when
// a clone-local run ends; the bwrap driver's copy runs are unchanged (their
// managed workspaces stay as they were).

// sandboxReturnScanInput is what the scan sees: the source repository, the
// returned commit (already in the source's object store, checked), and the
// ref about to be written. ConfigPath is the daemon's resolved config
// file, handed to the host helper in its plan (lane sec-box audit finding
// 4); "" when the caller does not know it.
type sandboxReturnScanInput struct {
	Repo       string
	Commit     string
	Ref        string
	RunID      string
	ConfigPath string
}

// sandboxReturnScan is the ONE injected scan of the return step, called
// after the returned objects are fetched and checked and BEFORE the ref is
// written; an error refuses the return (no ref is written, the copy
// stays). It is nil while the security module is absent; the security
// track's SEC-BOX lane binds the real commit-scope scan here.
var sandboxReturnScan func(ctx context.Context, in sandboxReturnScanInput) error

// sandboxReturnResult is what one return did.
type sandboxReturnResult struct {
	Ref    string
	Commit string
	// NothingNew: the copy's HEAD is a commit the source already has.
	NothingNew bool
}

// sandboxReturnTimeout bounds one return.
const sandboxReturnTimeout = 5 * time.Minute

// sandboxReturn runs the return for req: size cap, the copy's HEAD, the
// checked fetch, the path checks, the scan, the create-only ref and its
// read-back. run executes one git step and returns its stdout.
func sandboxReturn(ctx context.Context, req workspace.ReturnRequest, run func(context.Context, workspace.Step) ([]byte, error), scan func(context.Context, sandboxReturnScanInput) error) (sandboxReturnResult, error) {
	plan, err := workspace.PlanReturn(req)
	if err != nil {
		return sandboxReturnResult{}, err
	}
	if err := sandboxReturnPrecheck(ctx, req.CopyDir, run); err != nil {
		return sandboxReturnResult{Ref: plan.Ref}, err
	}
	return sandboxReturnChecked(ctx, req, plan, run, scan)
}

// sandboxReturnChecked is the return after sandboxReturnPrecheck passed:
// the copy's HEAD, the checked fetch, the path checks, the scan, the
// create-only ref and its read-back.
func sandboxReturnChecked(ctx context.Context, req workspace.ReturnRequest, plan workspace.ReturnPlan, run func(context.Context, workspace.Step) ([]byte, error), scan func(context.Context, sandboxReturnScanInput) error) (sandboxReturnResult, error) {
	res := sandboxReturnResult{Ref: plan.Ref}
	out, err := run(ctx, plan.HeadOfCopy())
	if err != nil {
		return res, fmt.Errorf("read the copy's HEAD: %w", err)
	}
	sha, err := workspace.ParseHead(out)
	if err != nil {
		return res, err
	}
	res.Commit = sha
	if _, err := run(ctx, plan.Exists(sha)); err == nil {
		res.NothingNew = true
		return res, nil
	}
	// The host git's version, read once for this return through the same
	// runner: git before 2.29 rejects --no-write-fetch-head and
	// --no-auto-maintenance, so the plan leaves them out there and the
	// source's FETCH_HEAD is put back as it was instead. A version that
	// cannot be read takes that older-git path, which works on every git.
	var ver workspace.GitVersion
	if out, verr := run(ctx, plan.VersionStep()); verr == nil {
		ver = workspace.ParseGitVersion(out)
	}
	plan = plan.WithGitVersion(ver)
	var restoreFetchHead func() error
	if plan.FetchWritesFetchHead() {
		restoreFetchHead, err = keepFetchHead(ctx, run, plan, req.SourceRepo)
		if err != nil {
			return res, err
		}
	}
	_, ferr := run(ctx, plan.Fetch(sha))
	if restoreFetchHead != nil {
		if rerr := restoreFetchHead(); rerr != nil && ferr == nil {
			// The objects are in, but the source's FETCH_HEAD could not be
			// put back: refuse the return (no ref is written) rather than
			// leave the user's repository changed.
			return res, fmt.Errorf("put the source's FETCH_HEAD back after the fetch: %w", rerr)
		}
	}
	if ferr != nil {
		return res, fmt.Errorf("fetch the returned commit (objects are checked): %w", ferr)
	}
	tree, err := run(ctx, plan.ListTree(sha))
	if err != nil {
		return res, fmt.Errorf("list the returned tree: %w", err)
	}
	links, err := workspace.CheckReturnedTree(tree)
	if err != nil {
		return res, err
	}
	targets := make(map[string]string, len(links))
	for _, l := range links {
		target, err := run(ctx, plan.ReadBlob(l.Object))
		if err != nil {
			return res, fmt.Errorf("read the returned symlink %q: %w", l.Path, err)
		}
		if err := workspace.CheckSymlinkTarget(l.Path, target); err != nil {
			return res, err
		}
		targets[l.Path] = string(target)
	}
	if err := workspace.CheckSymlinkChains(targets); err != nil {
		return res, err
	}
	if scan != nil {
		if err := scan(ctx, sandboxReturnScanInput{Repo: req.SourceRepo, Commit: sha, Ref: plan.Ref, RunID: req.RunID}); err != nil {
			return res, fmt.Errorf("the return scan refused the commit: %w", err)
		}
	}
	if _, err := run(ctx, plan.CreateRef(sha)); err != nil {
		return res, fmt.Errorf("write %s (it is written only if it does not exist): %w", plan.Ref, err)
	}
	got, err := run(ctx, plan.VerifyRef())
	if err != nil {
		return res, fmt.Errorf("read %s back: %w", plan.Ref, err)
	}
	if strings.TrimSpace(string(got)) != sha {
		return res, fmt.Errorf("read %s back: it names %q, not the returned commit", plan.Ref, strings.TrimSpace(string(got)))
	}
	return res, nil
}

// sandboxReturnBare is the return of a clone-remote copy (lane SBX-P3C):
// there is no local source repository, so the host creates the run's bare
// return repository (workspace.ReturnRepoPath, beside the copy under the
// managed root; one that already exists is left alone and refuses) and runs
// the same return into it: sandboxReturnPrecheck first, before any host git
// reads the copy, then the checked fetch, the path checks and the scan
// before the create-only ref (sandboxReturnChecked). A
// copy still at the commit it was cloned at returns nothing and creates no
// repository; a return that fails removes the repository it created.
// Nothing is ever pushed.
func sandboxReturnBare(ctx context.Context, req workspace.ReturnRequest, run func(context.Context, workspace.Step) ([]byte, error), scan func(context.Context, sandboxReturnScanInput) error) (sandboxReturnResult, error) {
	plan, err := workspace.PlanReturn(req)
	if err != nil || !req.Bare {
		if err == nil {
			err = fmt.Errorf("not a clone-remote return")
		}
		return sandboxReturnResult{}, err
	}
	res := sandboxReturnResult{Ref: plan.Ref}
	// The same scan as a clone-local return, before any host git touches
	// the box-written copy (lane SBX-P3C audit finding 1: the ls-remote
	// below spawns upload-pack, which reads the copy's config).
	if err := sandboxReturnPrecheck(ctx, req.CopyDir, run); err != nil {
		return res, err
	}
	out, err := run(ctx, plan.CopyHead())
	if err != nil {
		return res, fmt.Errorf("read the copy's HEAD: %w", err)
	}
	sha, err := workspace.ParseHead(out)
	if err != nil {
		return res, err
	}
	if sha == req.BaseCommit {
		res.Commit, res.NothingNew = sha, true
		return res, nil
	}
	if _, err := os.Lstat(req.SourceRepo); err == nil {
		return res, fmt.Errorf("the return repository %s already exists; it is left alone and nothing is returned", req.SourceRepo)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return res, err
	}
	if _, err := run(ctx, plan.InitBare()); err != nil {
		_ = os.RemoveAll(req.SourceRepo)
		return res, fmt.Errorf("create the return repository: %w", err)
	}
	res, err = sandboxReturnChecked(ctx, req, plan, run, scan)
	if err != nil || res.NothingNew {
		_ = os.RemoveAll(req.SourceRepo)
	}
	return res, err
}

// sandboxReturnPrecheck is the ONE check both return paths (sandboxReturn
// and sandboxReturnBare) run on a box-written copy before any other host
// git step touches it, so the two cannot drift (lane SBX-P3C audit finding
// 1, Linux live re-check 4 DEFECT D4):
//
//  1. a copy already stamped refused is refused again, with no git run;
//  2. the size cap over the copy's .git (and its alternates);
//  3. the text scan of the git dir (workspace.CopyReturnGitDirViolations):
//     the execution-risk paths a clean clone never has, and the
//     execution-capable keys, include and includeIf directives of its
//     config and config.worktree;
//  4. the effective config git itself would read for the copy, includes
//     followed, in a neutral environment (workspace.CopyConfigListStep;
//     reading config runs nothing): any execution-capable key whose origin
//     is not the runner's own command line refuses.
//
// A copy refused at 1, 3 or 4 (or whose .git is not a directory) is kept
// and stamped (gitview.HostGitRefusedStamp) so Observer never runs host git
// in it again, and the refusal tells the user not to run git there either.
func sandboxReturnPrecheck(ctx context.Context, copyDir string, run func(context.Context, workspace.Step) ([]byte, error)) error {
	if dir, refused := gitview.HostGitRefused(copyDir); refused {
		return fmt.Errorf("the copy at %s was refused before and is stamped, so the host's git is not run on it again%s", dir, sandboxDoNotRunGit(copyDir))
	}
	size, err := copyGitSize(copyDir)
	if err != nil {
		stampHostGitRefused(copyDir, err.Error())
		return fmt.Errorf("%w%s", err, sandboxDoNotRunGit(copyDir))
	}
	if err := workspace.CheckReturnSize(size); err != nil {
		return err
	}
	// Defence in depth (live Mac D1, ledger SBX-BE-21): the copy is entirely
	// box-written after its clone, and the host's very first git step reads
	// FROM it (ls-remote/fetch spawn git-upload-pack in the copy, which reads
	// the copy's own config). Refuse before any host git touches the copy if
	// it carries an execution-risk path a clean clone never has (commondir,
	// config.worktree, info/attributes, an object alternates file, a planted
	// hook, a linked worktree or submodule git dir) or a config that redirects
	// git at a program or at more config. The file is named so the operator
	// can see what the box planted; the copy is kept, not deleted.
	viol, err := workspace.CopyReturnGitDirViolations(filepath.Join(copyDir, ".git"))
	if err != nil {
		return fmt.Errorf("scan the copy's git dir before running the host's git on it: %w", err)
	}
	if len(viol) > 0 {
		reason := "the copy's git dir carries box-written execution-risk paths, so the host's git is not run on it: " + strings.Join(viol, ", ")
		stampHostGitRefused(copyDir, reason)
		return fmt.Errorf("%s%s", reason, sandboxDoNotRunGit(copyDir))
	}
	out, err := run(ctx, workspace.CopyConfigListStep(copyDir))
	if err == nil {
		viol, err = workspace.EffectiveConfigViolations(out)
	}
	if err != nil {
		reason := "git could not list the copy's effective config (" + err.Error() + "), so the host's git is not run on it"
		stampHostGitRefused(copyDir, reason)
		return fmt.Errorf("%s%s", reason, sandboxDoNotRunGit(copyDir))
	}
	if len(viol) > 0 {
		reason := "the config git would read for the copy sets execution-capable keys, so the host's git is not run on it: " + strings.Join(viol, ", ")
		stampHostGitRefused(copyDir, reason)
		return fmt.Errorf("%s%s", reason, sandboxDoNotRunGit(copyDir))
	}
	return nil
}

// sandboxDoNotRunGit is the refusal's advice to the user.
func sandboxDoNotRunGit(copyDir string) string {
	return "; do not run git in the kept copy at " + copyDir + " yourself either: its git config could make git run a program the box chose (inspect the files with a plain editor)"
}

// stampHostGitRefused writes gitview.HostGitRefusedStamp at the top of a
// refused copy: created exclusively, never through an existing entry (a
// stamp the box planted already refuses, which is the safe direction). A
// stamp that cannot be written is only lost protection for later reads; the
// return is refused either way.
func stampHostGitRefused(copyDir, reason string) {
	p := filepath.Join(copyDir, gitview.HostGitRefusedStamp)
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: the stamp at the top of a managed copy, created exclusively
	if err != nil {
		return
	}
	_, _ = fmt.Fprintf(f, "Observer refused to run host git in this copy: %s\nDo not run git here: its git config could make git run a program the sandboxed agent chose.\n", reason)
	_ = f.Close()
}

// maxFetchHeadKeep caps the FETCH_HEAD the return keeps and puts back.
const maxFetchHeadKeep = 16 << 20

// keepFetchHead reads the source repository's FETCH_HEAD before a fetch on
// a git that writes it (before 2.29, workspace.ReturnPlan.FetchWritesFetchHead)
// and returns the function that puts it back afterwards: the same bytes and
// mode when there was one, no file when there was none. A FETCH_HEAD that
// is not a regular file, or is over the cap, refuses the return before
// anything is fetched.
func keepFetchHead(ctx context.Context, run func(context.Context, workspace.Step) ([]byte, error), plan workspace.ReturnPlan, repo string) (func() error, error) {
	out, err := run(ctx, plan.FetchHeadPath())
	if err != nil {
		return nil, fmt.Errorf("find the source's FETCH_HEAD: %w", err)
	}
	p := strings.TrimSpace(string(out))
	if p == "" || strings.ContainsAny(p, "\n\r\x00") || filepath.Base(p) != "FETCH_HEAD" {
		return nil, fmt.Errorf("find the source's FETCH_HEAD: git answered %q", p)
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(repo, p)
	}
	fi, err := os.Lstat(p)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return func() error {
			if rerr := os.Remove(p); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
				return rerr
			}
			return nil
		}, nil
	case err != nil:
		return nil, fmt.Errorf("read the source's FETCH_HEAD: %w", err)
	case !fi.Mode().IsRegular():
		return nil, fmt.Errorf("the source's FETCH_HEAD is not a regular file; on git older than 2.29 the return cannot keep it unchanged, so it is not run")
	case fi.Size() > maxFetchHeadKeep:
		return nil, fmt.Errorf("the source's FETCH_HEAD is over %d bytes; on git older than 2.29 the return cannot keep it unchanged, so it is not run", maxFetchHeadKeep)
	}
	prev, err := os.ReadFile(p) //nolint:gosec // G304: the source repository's own FETCH_HEAD, named by its git, lstat-checked regular and capped
	if err != nil {
		return nil, fmt.Errorf("read the source's FETCH_HEAD: %w", err)
	}
	mode := fi.Mode().Perm()
	return func() error { return replaceFileAtomic(p, prev, mode) }, nil
}

// replaceFileAtomic writes data to path through a temporary file in the
// same directory and a rename, so a reader never sees a half-written file.
func replaceFileAtomic(path string, data []byte, mode fs.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".observer-return-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// copyGitSize sums the regular files of the copy's .git directory without
// following any symlink, plus every object directory its alternates name
// (SBX-P3A merge finding F10: git upload-pack serves objects from them, so
// they are part of what a fetch can bring); a .git that is not a directory
// (a gitfile pointing elsewhere) is refused.
func copyGitSize(copyDir string) (int64, error) {
	dir := filepath.Join(copyDir, ".git")
	fi, err := os.Lstat(dir)
	if err != nil {
		return 0, fmt.Errorf("the copy has no .git directory: %w", err)
	}
	if !fi.IsDir() {
		return 0, fmt.Errorf("the copy's .git is not a directory (a link or a gitfile is never followed)")
	}
	var total int64
	stop := errors.New("over the cap")
	sum := func(root string) error {
		return filepath.WalkDir(root, func(_ string, d fs.DirEntry, werr error) error {
			if werr != nil {
				return werr
			}
			if d.Type().IsRegular() {
				info, ierr := d.Info()
				if ierr != nil {
					return ierr
				}
				total += info.Size()
				if total > workspace.MaxReturnBytes {
					return stop
				}
			}
			return nil
		})
	}
	err = sum(dir)
	if err == nil {
		for _, alt := range copyGitAlternates(filepath.Join(dir, "objects")) {
			if isWithinPath(alt, dir) {
				continue // already counted with the .git walk
			}
			if err = sum(alt); err != nil {
				break
			}
		}
	}
	if errors.Is(err, stop) {
		return total, nil
	}
	return total, err
}

// copyGitAlternatesDepth is how deep alternates of alternates are followed
// (git's own limit is five).
const copyGitAlternatesDepth = 5

// copyGitAlternatesMax caps the alternates read in all.
const copyGitAlternatesMax = 64

// copyGitAlternates returns the existing object directories named by the
// objects/info/alternates file of objectsDir and, recursively, by theirs
// (an absolute line as it is, a relative one from the objects directory
// naming it), each once. Each file is read only when it is a regular file.
func copyGitAlternates(objectsDir string) []string {
	var out []string
	seen := map[string]bool{filepath.Clean(objectsDir): true}
	var walk func(objs string, depth int)
	walk = func(objs string, depth int) {
		if depth > copyGitAlternatesDepth || len(out) >= copyGitAlternatesMax {
			return
		}
		p := filepath.Join(objs, "info", "alternates")
		fi, err := os.Lstat(p) //nolint:gosec // G703: the copy's own alternates file under its .git, never followed
		if err != nil || !fi.Mode().IsRegular() || fi.Size() > 64<<10 {
			return
		}
		b, err := os.ReadFile(p) //nolint:gosec // G304: the copy's own alternates file, lstat-checked regular and capped
		if err != nil {
			return
		}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			alt := line
			if !filepath.IsAbs(alt) {
				alt = filepath.Join(objs, alt)
			}
			alt = filepath.Clean(alt)
			if seen[alt] {
				continue
			}
			seen[alt] = true
			if afi, err := os.Stat(alt); err != nil || !afi.IsDir() { //nolint:gosec // G703: an alternates line of the copy, stat only, counted toward the size cap
				continue
			}
			out = append(out, alt)
			if len(out) >= copyGitAlternatesMax {
				return
			}
			walk(alt, depth+1)
		}
	}
	walk(objectsDir, 1)
	return out
}

// isWithinPath reports whether p is root or inside it.
func isWithinPath(p, root string) bool {
	p, root = filepath.Clean(p), filepath.Clean(root)
	return p == root || strings.HasPrefix(p, root+string(filepath.Separator))
}

// runReturnGit runs one return step: git from PATH, no prompt, stdout
// captured and capped, stderr tail kept for the error. A Hardened step (the
// worktree source's) runs with hardenedGitEnv.
func runReturnGit(ctx context.Context, step workspace.Step) ([]byte, error) {
	if len(step.Argv) == 0 || step.Argv[0] != "git" {
		return nil, fmt.Errorf("not a git step")
	}
	cctx, cancel := context.WithTimeout(ctx, sandboxReturnTimeout)
	defer cancel()
	//nolint:gosec // G204: argv is built by workspace.ReturnPlan from validated paths and a checked object name
	cmd := exec.CommandContext(cctx, step.Argv[0], step.Argv[1:]...)
	cmd.Env = append(gitPrepEnv(), "GIT_CONFIG_NOSYSTEM=1")
	if step.Hardened {
		cmd.Env = hardenedGitEnv(cmd.Env)
	}
	if step.NeutralHome {
		home, herr := os.MkdirTemp("", "observer-return-home-*")
		if herr != nil {
			return nil, fmt.Errorf("make the scan's empty home: %w", herr)
		}
		defer func() { _ = os.RemoveAll(home) }()
		env := make([]string, 0, len(cmd.Env)+2)
		for _, kv := range cmd.Env {
			if !strings.HasPrefix(kv, "HOME=") && !strings.HasPrefix(kv, "XDG_CONFIG_HOME=") {
				env = append(env, kv)
			}
		}
		env = append(env, "HOME="+home, "XDG_CONFIG_HOME="+home)
		cmd.Env = env
	}
	cmd.Stdin = nil
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &cappedWriter{w: &stdout, left: 256 << 20}
	cmd.Stderr = &cappedWriter{w: &stderr, left: 64 << 10}
	if err := cmd.Run(); err != nil {
		return stdout.Bytes(), fmt.Errorf("%w: %s", err, tailStderr(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// cappedWriter keeps at most left bytes and then reports an error.
type cappedWriter struct {
	w    io.Writer
	left int64
}

func (c *cappedWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > c.left {
		return 0, fmt.Errorf("output over the cap")
	}
	c.left -= int64(len(p))
	return c.w.Write(p)
}

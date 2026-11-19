//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"crypto/sha1" //nolint:gosec // G505: git's object names are SHA-1 in a SHA-1 repository; this names blobs, it protects nothing
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/gitview"
	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// terminal_sandbox_returns_copy.go gathers the facts the copy removal table
// (workspace.DecideCopyRemoval) decides on, at the moment the person asks to
// remove a copy (lane RETURNS, audit item L1): whether the run is live,
// whether the copy's commits came back (the bwrap return record, or, for a
// copy another driver returned, the returned ref itself, read from a
// repository Observer trusts), and whether the copy's files are exactly its
// last commit's. That comparison never runs git in the box-written copy: the
// commit's tree is listed from the source repository (or the host-made
// return repository), the copy's files are hashed here, and the files that
// are not in the commit are judged against the SOURCE repository's ignore
// rules (`git check-ignore --no-index`, which reads only the source's
// .gitignore files; a clone-remote copy has no source working tree, so
// every such file counts).

// The comparison's caps: past them the copy is kept, said plainly.
const (
	copyCompareMaxFiles  = 200000
	copyCompareMaxBytes  = 4 << 30
	copyCompareMaxExtra  = 50000
	copyCheckIgnoreBatch = 200
)

// copyFacts are a managed copy's facts as the route reads them.
type copyFacts struct {
	workspace.CopyRemovalFacts
	// Commit is the copy's last commit, Repo the trusted repository that
	// holds it, Ref the returned ref ("" when none).
	Commit, Repo, Ref string
}

// sandboxCopyFacts reads the removal facts of the copy <managedRoot>/<id>.
func sandboxCopyFacts(ctx context.Context, observerDir, managedRoot, id string, meta workspace.Meta, copyDir string) copyFacts {
	var f copyFacts
	f.RunLive = sandboxWorktreeRunLive(observerDir, id)
	if _, stamped := gitview.HostGitRefused(copyDir); stamped {
		f.Stamped = true
	}
	f.Return = workspace.CopyReturnUnknown
	if rec, err := readSandboxLocalReturn(sandboxLocalReturnPath(observerDir, id)); err == nil {
		f.Return, f.Commit, f.Ref = rec.State, rec.Commit, rec.Ref
		if rec.Request != nil {
			f.Repo = rec.Request.SourceRepo
		}
	} else {
		// A copy another driver returned (its host helper prints the outcome
		// and keeps no record): the returned ref, when it is there.
		f.Repo = copyTrustedRepo(managedRoot, id, meta)
		if f.Repo != "" {
			if c, ok := copyReturnedRef(ctx, f.Repo, id); ok {
				f.Return, f.Commit, f.Ref = workspace.CopyReturnReturned, c, workspace.ReturnRefPrefix+id
			} else if c, ok := copyHeadByFiles(copyDir); ok && copyHasCommit(ctx, f.Repo, c) {
				// No ref, but the copy is still at a commit the trusted
				// repository holds: the box made no commit to bring back.
				f.Return, f.Commit = workspace.CopyReturnNothingNew, c
			}
		}
	}
	if f.RunLive || f.Stamped || (f.Return != workspace.CopyReturnReturned && f.Return != workspace.CopyReturnNothingNew) {
		return f
	}
	if !workspace.ValidSHA(f.Commit) || f.Repo == "" {
		f.CompareError = "its last commit is not recorded"
		return f
	}
	if _, err := os.Stat(f.Repo); err != nil {
		f.CompareError = "its last commit is only in the copy itself"
		return f
	}
	ignoreRepo := ""
	if meta.Source == workspace.SourceCloneLocal {
		ignoreRepo = f.Repo
	}
	changed, extra, err := compareCopyWithCommit(ctx, f.Repo, f.Commit, copyDir, ignoreRepo)
	if err != nil {
		f.CompareError = err.Error()
		return f
	}
	f.Compared, f.Changed, f.Extra = true, changed, extra
	return f
}

// copyTrustedRepo is the repository a copy's commits return into: the
// source repository of a clone-local copy, the host-made return repository
// of a clone-remote one.
func copyTrustedRepo(managedRoot, id string, meta workspace.Meta) string {
	switch meta.Source {
	case workspace.SourceCloneLocal:
		if filepath.IsAbs(meta.Origin) {
			return meta.Origin
		}
	case workspace.SourceCloneRemote:
		if p, err := workspace.ReturnRepoPath(managedRoot, id); err == nil {
			return p
		}
	}
	return ""
}

// copyGit runs one read of a trusted repository (a test seam).
var copyGit = func(ctx context.Context, repo string, args ...string) ([]byte, error) {
	argv := append([]string{"git", "-C", repo, "-c", "core.hooksPath=" + os.DevNull, "-c", "core.fsmonitor=false"}, args...)
	return runReturnGit(ctx, workspace.Step{Argv: argv, Hardened: true})
}

// copyReturnedRef reads refs/observer/sandbox/<id> in repo.
func copyReturnedRef(ctx context.Context, repo, id string) (string, bool) {
	out, err := copyGit(ctx, repo, "rev-parse", "--verify", "--quiet", workspace.ReturnRefPrefix+id+"^{commit}")
	if err != nil {
		return "", false
	}
	c := strings.TrimSpace(string(out))
	return c, workspace.ValidSHA(c)
}

// copyHasCommit reports whether repo holds commit c.
func copyHasCommit(ctx context.Context, repo, c string) bool {
	_, err := copyGit(ctx, repo, "cat-file", "-e", c+"^{commit}")
	return err == nil
}

// copyHeadByFiles reads the commit the copy's HEAD names from its files
// only (HEAD, then the loose ref or a packed-refs line), never running git
// in it; ok is false for anything it cannot read plainly.
func copyHeadByFiles(copyDir string) (string, bool) {
	gitDir := filepath.Join(copyDir, ".git")
	if fi, err := os.Lstat(gitDir); err != nil || !fi.IsDir() { //nolint:gosec // G703: the .git of a managed copy, lstat only (never followed)
		return "", false
	}
	head, err := readRegularCapped(filepath.Join(gitDir, "HEAD"), 4096)
	if err != nil {
		return "", false
	}
	h := strings.TrimSpace(string(head))
	if workspace.ValidSHA(h) {
		return h, true
	}
	ref, ok := strings.CutPrefix(h, "ref: ")
	if !ok || !strings.HasPrefix(ref, "refs/heads/") || strings.Contains(ref, "..") || strings.ContainsAny(ref, "\\\x00") {
		return "", false
	}
	if b, err := readRegularCapped(filepath.Join(gitDir, filepath.FromSlash(ref)), 4096); err == nil {
		c := strings.TrimSpace(string(b))
		return c, workspace.ValidSHA(c)
	}
	packed, err := readRegularCapped(filepath.Join(gitDir, "packed-refs"), 16<<20)
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(packed), "\n") {
		if fields := strings.Fields(line); len(fields) == 2 && fields[1] == ref && workspace.ValidSHA(fields[0]) {
			return fields[0], true
		}
	}
	return "", false
}

// compareCopyWithCommit compares the copy's files with commit's tree (listed
// from repo): changed counts the commit's files missing or different in the
// copy, extra the copy's files not in the commit and not ignored by
// ignoreRepo's rules ("" judges none ignored).
func compareCopyWithCommit(ctx context.Context, repo, commit, copyDir, ignoreRepo string) (changed, extra int, err error) {
	out, err := copyGit(ctx, repo, "ls-tree", "-r", "-z", "--full-tree", commit)
	if err != nil {
		return 0, 0, fmt.Errorf("list its last commit: %w", err)
	}
	entries, err := workspace.ParseTreeEntries(out)
	if err != nil {
		return 0, 0, err
	}
	tracked := make(map[string]workspace.TreeEntry, len(entries))
	for _, e := range entries {
		if e.Mode == "160000" {
			return 0, 0, fmt.Errorf("its last commit holds another repository (%s)", e.Path)
		}
		tracked[e.Path] = e
	}
	newHash := sha1.New //nolint:gosec // G401: git object names
	if len(commit) == 64 {
		newHash = sha256.New
	}
	seen := map[string]bool{}
	var extras []string
	files := 0
	var hashed int64
	walkErr := filepath.WalkDir(copyDir, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		rel, rerr := filepath.Rel(copyDir, p)
		if rerr != nil {
			return rerr
		}
		if rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if files++; files > copyCompareMaxFiles {
			return fmt.Errorf("the copy has more than %d files", copyCompareMaxFiles)
		}
		te, isTracked := tracked[rel]
		if !isTracked {
			if len(extras) >= copyCompareMaxExtra {
				return fmt.Errorf("the copy has more than %d files that are not in its last commit", copyCompareMaxExtra)
			}
			extras = append(extras, rel)
			return nil
		}
		seen[rel] = true
		same, n, herr := copyEntryMatches(p, d, te, newHash)
		hashed += n
		if herr != nil {
			return herr
		}
		if hashed > copyCompareMaxBytes {
			return fmt.Errorf("the copy holds more than %d bytes to compare", int64(copyCompareMaxBytes))
		}
		if !same {
			changed++
		}
		return nil
	})
	if walkErr != nil {
		return 0, 0, walkErr
	}
	for path := range tracked {
		if !seen[path] {
			changed++
		}
	}
	if ignoreRepo == "" || len(extras) == 0 {
		return changed, len(extras), nil
	}
	ignored, err := copyIgnored(ctx, ignoreRepo, extras)
	if err != nil {
		return 0, 0, err
	}
	return changed, len(extras) - ignored, nil
}

// copyEntryMatches reports whether the copy's file at p is the tree entry
// te: the same kind (file, executable, symlink) and the same git object
// name. It returns the bytes it hashed.
func copyEntryMatches(p string, d fs.DirEntry, te workspace.TreeEntry, newHash func() hash.Hash) (bool, int64, error) {
	if d.Type()&fs.ModeSymlink != 0 {
		if te.Mode != "120000" {
			return false, 0, nil
		}
		target, err := os.Readlink(p)
		if err != nil {
			return false, 0, err
		}
		return gitBlobName(newHash, strings.NewReader(target), int64(len(target))) == te.Object, int64(len(target)), nil
	}
	if !d.Type().IsRegular() {
		return false, 0, nil
	}
	info, err := d.Info()
	if err != nil {
		return false, 0, err
	}
	exec := info.Mode().Perm()&0o111 != 0
	if (te.Mode == "100755") != exec || (te.Mode != "100755" && te.Mode != "100644") {
		return false, 0, nil
	}
	f, err := os.Open(p) //nolint:gosec // G304: a file of a managed copy, opened by WalkDir's own path (a symlink is handled above, never followed)
	if err != nil {
		return false, 0, err
	}
	defer func() { _ = f.Close() }()
	return gitBlobName(newHash, f, info.Size()) == te.Object, info.Size(), nil
}

// gitBlobName is git's object name of a blob of size bytes read from r.
func gitBlobName(newHash func() hash.Hash, r io.Reader, size int64) string {
	h := newHash()
	_, _ = io.WriteString(h, "blob "+strconv.FormatInt(size, 10)+"\x00")
	if _, err := io.Copy(h, io.LimitReader(r, size)); err != nil {
		return ""
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// copyIgnored counts the paths the source repository's ignore rules cover
// (`git check-ignore --no-index`, which reads only that repository's ignore
// files; nothing of the copy is read), in batches. check-ignore takes -z
// only with --stdin, which the runner does not feed, so a path git would
// quote (a quote, a backslash or a control character in it) is not asked
// about and counts as not ignored (the safe side: the copy is kept).
func copyIgnored(ctx context.Context, repo string, paths []string) (int, error) {
	var plain []string
	for _, p := range paths {
		if !strings.ContainsFunc(p, func(r rune) bool { return r == '"' || r == '\\' || r < 0x20 || r == 0x7f }) {
			plain = append(plain, p)
		}
	}
	n := 0
	for len(plain) > 0 {
		batch := plain[:min(len(plain), copyCheckIgnoreBatch)]
		plain = plain[len(batch):]
		asked := make(map[string]bool, len(batch))
		for _, p := range batch {
			asked[p] = true
		}
		args := append([]string{"-c", "core.quotePath=false", "check-ignore", "--no-index", "--"}, batch...)
		out, err := copyGit(ctx, repo, args...)
		var ee *exec.ExitError
		switch {
		case err == nil:
		case errors.As(err, &ee) && ee.ExitCode() == 1:
			continue // none of the batch is ignored
		default:
			return 0, fmt.Errorf("check the copy's other files against the source's ignore rules: %w", err)
		}
		for _, line := range strings.Split(string(out), "\n") {
			if asked[line] {
				n++
				delete(asked, line)
			}
		}
	}
	return n, nil
}

// removeSandboxCopy removes the copy <managedRoot>/<id> once the removal
// table allows it. The facts are read again here, never taken from the
// request. A worktree run's workspace is not removed here (its own end
// keeps its registration and branch in step).
func removeSandboxCopy(ctx context.Context, observerDir, managedRoot, id string) (workspace.CopyRemovalVerdict, error) {
	v, runDir, err := sandboxCopyVerdict(ctx, observerDir, managedRoot, id)
	if err != nil || !v.Remove {
		return v, err
	}
	if err := os.RemoveAll(runDir); err != nil { //nolint:gosec // G703: <managedRoot>/<id>, checked strictly under the managed root and lstat'd a real directory
		return v, fmt.Errorf("remove %s: %w", runDir, err)
	}
	forgetSandboxCopyVerdict(id)
	return v, nil
}

// sandboxCopyVerdict is the ONE eligibility rule of a copy's removal: the
// removal table (workspace.DecideCopyRemoval) over the facts read now. The
// click, the bulk click, the age sweep and the panel's "safe to remove"
// count all come through it (D4: the count used a looser rule of its own and
// counted a copy the click then kept). runDir is the copy's run dir.
func sandboxCopyVerdict(ctx context.Context, observerDir, managedRoot, id string) (workspace.CopyRemovalVerdict, string, error) {
	if !validSandboxWorktreeID(id) {
		return workspace.CopyRemovalVerdict{}, "", fmt.Errorf("%q is not a copy's id", id)
	}
	runDir := filepath.Join(managedRoot, id)
	if err := workspace.ValidateManagedWorkspace(runDir, managedRoot); err != nil {
		return workspace.CopyRemovalVerdict{}, "", err
	}
	fi, err := os.Lstat(runDir)
	if err != nil || !fi.IsDir() {
		return workspace.CopyRemovalVerdict{}, "", fmt.Errorf("there is no copy %s", id)
	}
	meta, ok := readWorkspaceMeta(runDir)
	if !ok {
		return workspace.CopyRemovalVerdict{}, "", fmt.Errorf("the copy %s has no record of how it was made", id)
	}
	if meta.Source != workspace.SourceCloneLocal && meta.Source != workspace.SourceCloneRemote {
		return workspace.CopyRemovalVerdict{Reason: "only a clone's copy is removed here; a worktree's workspace is removed with observer workspaces rm, which keeps its branch"}, "", nil
	}
	copyDir, ok := sandboxCopyDir(runDir)
	if !ok {
		return workspace.CopyRemovalVerdict{Reason: "Observer could not find the copy's folder"}, "", nil
	}
	cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	facts := sandboxCopyFacts(cctx, observerDir, managedRoot, id, meta, copyDir)
	return workspace.DecideCopyRemoval(facts.CopyRemovalFacts), runDir, nil
}

// sandboxCopyVerdictTTL bounds how long the panel reuses a copy's verdict
// when nothing it keys on changed (a variable for tests).
var sandboxCopyVerdictTTL = 10 * time.Minute

// sandboxCopyVerdicts caches the panel's verdicts: the facts run git and
// hash the copy, so they are read again only when the copy's files, its
// return record or the TTL changed. The click never reads the cache.
var sandboxCopyVerdicts struct {
	mu sync.Mutex
	m  map[string]cachedCopyVerdict
}

type cachedCopyVerdict struct {
	key string
	at  time.Time
	v   workspace.CopyRemovalVerdict
}

// sandboxCopyVerdictCached is sandboxCopyVerdict for the panel's list,
// reused while key (the copy's size, newest file time and return) holds.
// An error is a kept copy with its reason, as the click would say it.
func sandboxCopyVerdictCached(ctx context.Context, observerDir, managedRoot, id, key string) workspace.CopyRemovalVerdict {
	now := time.Now()
	sandboxCopyVerdicts.mu.Lock()
	if c, ok := sandboxCopyVerdicts.m[id]; ok && c.key == key && now.Sub(c.at) < sandboxCopyVerdictTTL {
		sandboxCopyVerdicts.mu.Unlock()
		return c.v
	}
	sandboxCopyVerdicts.mu.Unlock()
	v, _, err := sandboxCopyVerdict(ctx, observerDir, managedRoot, id)
	if err != nil {
		v = workspace.CopyRemovalVerdict{Reason: err.Error()}
	}
	if ctx.Err() != nil {
		return v
	}
	sandboxCopyVerdicts.mu.Lock()
	if sandboxCopyVerdicts.m == nil {
		sandboxCopyVerdicts.m = map[string]cachedCopyVerdict{}
	}
	sandboxCopyVerdicts.m[id] = cachedCopyVerdict{key: key, at: now, v: v}
	sandboxCopyVerdicts.mu.Unlock()
	return v
}

// forgetSandboxCopyVerdict drops a removed copy's cached verdict.
func forgetSandboxCopyVerdict(id string) {
	sandboxCopyVerdicts.mu.Lock()
	delete(sandboxCopyVerdicts.m, id)
	sandboxCopyVerdicts.mu.Unlock()
}

// sandboxCopyDir is the copy's folder inside its run dir: the one directory
// beside meta.json, never followed through a link.
func sandboxCopyDir(runDir string) (string, bool) {
	entries, err := os.ReadDir(runDir)
	if err != nil {
		return "", false
	}
	found := ""
	for _, e := range entries {
		if !e.IsDir() || e.Type()&fs.ModeSymlink != 0 {
			continue
		}
		if found != "" {
			return "", false
		}
		found = filepath.Join(runDir, e.Name())
	}
	return found, found != ""
}

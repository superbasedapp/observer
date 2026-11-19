package workspace

import (
	"bytes"
	"fmt"
	"path"
	"path/filepath"
	"strings"
)

// applydiff.go plans "open a saved diff as a branch" (lane RETURNS, audit
// item H6): a hosted run's changes come home only as a diff file
// (<observer>/sandbox-hosted/returns/<run>.diff), and the person turns it
// into a branch of their own repository with one click. The diff is the
// box's output, so it is untrusted, and the step never touches the working
// tree, the real index, HEAD or any ref that already exists:
//
//   - every path the diff names is checked with the return's path rules
//     (checkReturnedPath: no absolute path, no "..", no .git component, no
//     control character, the length and count caps) before anything is
//     applied, from git's own reading of the diff (`git apply --numstat`);
//   - the base is the commit the run recorded when the files were sent
//     (DecideDiffBase says whether that commit is exactly what the box
//     started from); every file the diff changes or removes must be, in that
//     commit, exactly the file the box started from (the diff's own full
//     blob names, read through `git apply --build-fake-ancestor`, compared
//     with the commit's tree), so a hunk never lands on a different file by
//     offset and nothing is ever merged three ways;
//   - the diff is applied into a TEMPORARY index (GIT_INDEX_FILE) seeded
//     from that commit, never the repository's own index; `write-tree`,
//     then the changed entries are checked again (no gitlink; a symlink's
//     target stays inside the tree and out of .git, chains included);
//   - `commit-tree` with the base as the only parent, and `update-ref`
//     CREATE-ONLY of refs/heads/observer-sandbox/<run>/changes (an empty old
//     value: a branch that exists is never moved), read back.
//
// Why that branch name: it is a real branch, so `git switch` checks it out
// (refs/observer/sandbox/* is not a branch: switch refuses it and checkout
// detaches); it shares the observer-sandbox/<run>/<name> shape the worktree
// source's branches use, so `git branch --list 'observer-sandbox/*'` shows
// every sandbox branch together; and it can never be a branch the person
// already uses, since <run> is a fresh random id.
//
// This file only builds argv and parses git's answers; the cmd layer runs
// the steps in order through its hardened git runner, in the person's own
// repository (never a box-written one), and stops at the first failure.

// DiffBranchPrefix is the namespace every branch opened from a saved diff
// lives in (the worktree source's branch family).
const DiffBranchPrefix = "refs/heads/observer-sandbox/"

// DiffBranchLabel is the last component of a diff branch.
const DiffBranchLabel = "changes"

// DiffBranchRef is runID's diff branch ref.
func DiffBranchRef(runID string) (string, error) {
	if !runIDRE.MatchString(runID) {
		return "", fmt.Errorf("workspace: run id %q is not a clean token", runID)
	}
	return DiffBranchPrefix + runID + "/" + DiffBranchLabel, nil
}

// DiffBranchName is the branch name a person types (the ref without
// refs/heads/).
func DiffBranchName(ref string) string { return strings.TrimPrefix(ref, "refs/heads/") }

// DiffBaseFacts are what a run recorded about where its saved diff starts:
// the facts measured when the files were sent and when the diff was saved.
type DiffBaseFacts struct {
	// RemoteClone: the box cloned the repository itself (nothing was sent
	// from this machine).
	RemoteClone bool
	// Commit is the commit the box started from: the folder's HEAD when its
	// files were sent, or the commit the box cloned ("" when not recorded).
	Commit string
	// StatusKnown and StatusClean: whether the folder's `git status` was
	// read when the files were sent, and whether it showed nothing (no
	// change to a tracked file, no file git does not ignore or track).
	StatusKnown bool
	StatusClean bool
	// AgentCommits is how many commits the agent made in the box on top of
	// the starting point (-1 when it could not be read).
	AgentCommits int
	// IncludesAgentCommits: the diff was taken in the box against the
	// commit the box started from (the upload's observer-baseline commit,
	// or the commit a box-side clone cloned), not against the box's HEAD,
	// so every commit the agent made is in it and AgentCommits does not
	// matter to the base.
	IncludesAgentCommits bool
	// Truncated: the box's diff was cut at its size cap.
	Truncated bool
	// NoRepository: the files were sent from a folder that is not a git
	// repository (decision SBXD-8), so there is no commit or branch.
	NoRepository bool
}

// DiffBaseVerdict is DecideDiffBase's answer.
type DiffBaseVerdict struct {
	// Exact: the diff applies to Commit and gives back exactly the box's
	// final files.
	Exact bool
	// Reason says why not, in plain words ("" when Exact).
	Reason string
}

// diffBaseRule is one row of the base table, walked top-down; the first
// row that matches decides.
type diffBaseRule struct {
	exact  bool
	reason func(f DiffBaseFacts) string
	match  func(f DiffBaseFacts) bool
}

func fixedReason(s string) func(DiffBaseFacts) string { return func(DiffBaseFacts) string { return s } }

// diffBaseRules decide whether a saved diff's base can be reproduced
// exactly. A row never guesses: when the box's starting point is not a
// commit Observer can name, the diff is offered as a file only.
var diffBaseRules = []diffBaseRule{
	{
		// SBXD-8: a folder that is not a repository has no commit to open a
		// branch on, whatever else is true; the diff is the whole return.
		reason: fixedReason("the files were sent from a folder that is not a git repository, so there is no branch to open; the changes are this diff file"),
		match:  func(f DiffBaseFacts) bool { return f.NoRepository && !f.RemoteClone },
	},
	{
		reason: fixedReason("the box's diff was cut at its size limit, so it is not the whole change"),
		match:  func(f DiffBaseFacts) bool { return f.Truncated },
	},
	{
		reason: func(f DiffBaseFacts) string {
			return fmt.Sprintf("the agent made %d commit(s) of its own in the box, and the saved diff holds only the changes after its last one", f.AgentCommits)
		},
		match: func(f DiffBaseFacts) bool { return f.AgentCommits > 0 && !f.IncludesAgentCommits },
	},
	{
		reason: fixedReason("Observer could not tell whether the agent made commits of its own in the box"),
		match:  func(f DiffBaseFacts) bool { return f.AgentCommits < 0 && !f.IncludesAgentCommits },
	},
	{
		reason: fixedReason("the box cloned the repository itself, and the commit it cloned was not recorded"),
		match:  func(f DiffBaseFacts) bool { return f.RemoteClone && !shaRE.MatchString(f.Commit) },
	},
	{
		exact: true,
		match: func(f DiffBaseFacts) bool { return f.RemoteClone },
	},
	{
		reason: fixedReason("the folder had no commit Observer could read when its files were sent"),
		match:  func(f DiffBaseFacts) bool { return !shaRE.MatchString(f.Commit) },
	},
	{
		reason: fixedReason("Observer could not tell whether the folder had uncommitted changes when its files were sent"),
		match:  func(f DiffBaseFacts) bool { return !f.StatusKnown },
	},
	{
		reason: fixedReason("the folder had uncommitted changes, or files git does not track, when its files were sent, so the box started from a state no commit holds"),
		match:  func(f DiffBaseFacts) bool { return !f.StatusClean },
	},
	{exact: true, match: func(DiffBaseFacts) bool { return true }},
}

// DecideDiffBase says whether a saved diff applies to the recorded commit
// and gives back exactly the box's files, and why not.
func DecideDiffBase(f DiffBaseFacts) DiffBaseVerdict {
	for _, r := range diffBaseRules {
		if r.match(f) {
			v := DiffBaseVerdict{Exact: r.exact}
			if r.reason != nil {
				v.Reason = r.reason(f)
			}
			return v
		}
	}
	return DiffBaseVerdict{}
}

// DiffApplyCommand is the command a person runs in their own checkout to
// apply a saved diff by hand (the offer when no branch can be opened).
func DiffApplyCommand(diffPath string) string {
	return "git apply --index " + shellQuote(diffPath)
}

// shellQuote quotes s for a POSIX shell when it needs it.
func shellQuote(s string) string {
	if s != "" && strings.IndexFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("/._-+:@", r))
	}) < 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// DiffBranchRequest names one "open as a branch".
type DiffBranchRequest struct {
	// Repo is the person's repository the branch is created in (absolute):
	// the folder the run's files were sent from.
	Repo string
	// DiffPath is the saved diff, already copied into TempDir by the
	// caller so every step reads the same bytes (absolute).
	DiffPath string
	// TempDir is a fresh owner-only directory outside Repo that holds the
	// temporary indexes (absolute).
	TempDir string
	// RunID names the run, and so the branch.
	RunID string
	// Base is the commit the box started from.
	Base string
}

// DiffBranchPlan builds the steps of one "open as a branch".
type DiffBranchPlan struct {
	req DiffBranchRequest
	// Ref is the branch ref the plan creates.
	Ref string
}

// GitStep is one git command of a diff-branch plan: its argv and the
// environment entries it adds on top of the runner's hardened environment
// (only GIT_INDEX_FILE and the commit identity, both set by the plan).
type GitStep struct {
	Argv []string
	Env  []string
}

// PlanDiffBranch validates a diff-branch request.
func PlanDiffBranch(req DiffBranchRequest) (DiffBranchPlan, error) {
	for _, f := range []struct{ name, v string }{{"Repo", req.Repo}, {"DiffPath", req.DiffPath}, {"TempDir", req.TempDir}} {
		if err := validateAbsPath(f.name, f.v); err != nil {
			return DiffBranchPlan{}, fmt.Errorf("workspace.PlanDiffBranch: %w", err)
		}
	}
	ref, err := DiffBranchRef(req.RunID)
	if err != nil {
		return DiffBranchPlan{}, fmt.Errorf("workspace.PlanDiffBranch: %w", err)
	}
	if !shaRE.MatchString(req.Base) {
		return DiffBranchPlan{}, fmt.Errorf("workspace.PlanDiffBranch: the base %q is not a commit name", req.Base)
	}
	repo, tmp := filepath.Clean(req.Repo), filepath.Clean(req.TempDir)
	if isWithinHostDir(tmp, repo) || isWithinHostDir(repo, tmp) {
		return DiffBranchPlan{}, fmt.Errorf("workspace.PlanDiffBranch: the temporary directory %s and the repository %s overlap", tmp, repo)
	}
	if !isWithinHostDir(filepath.Clean(req.DiffPath), tmp) {
		return DiffBranchPlan{}, fmt.Errorf("workspace.PlanDiffBranch: the diff %s is not the copy in the temporary directory %s", req.DiffPath, tmp)
	}
	return DiffBranchPlan{req: req, Ref: ref}, nil
}

// isWithinHostDir reports whether p is root or inside it, in the host's
// path syntax.
func isWithinHostDir(p, root string) bool {
	rel, err := filepath.Rel(root, p)
	return err == nil && (rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))))
}

// diffGit are the -c settings every diff-branch step runs with: no hooks
// (update-ref would otherwise run the reference-transaction hook), no
// fsmonitor, no automatic maintenance, no untracked cache.
var diffGit = []string{
	"-c", "core.hooksPath=" + nullDevice(),
	"-c", "core.fsmonitor=false",
	"-c", "core.untrackedCache=false",
	"-c", "gc.auto=0",
	"-c", "maintenance.auto=false",
	"-c", "apply.whitespace=nowarn",
}

// nullDevice is the host's null device for core.hooksPath.
func nullDevice() string {
	if filepath.Separator == '\\' {
		return "NUL"
	}
	return "/dev/null"
}

// The temporary index files of a plan.
const (
	diffAncestorIndex = "ancestor.index"
	diffWorkIndex     = "work.index"
)

func (p DiffBranchPlan) git(env []string, args ...string) GitStep {
	argv := append([]string{"git", "-C", p.req.Repo}, diffGit...)
	return GitStep{Argv: append(argv, args...), Env: env}
}

func (p DiffBranchPlan) indexEnv(name string) []string {
	return []string{"GIT_INDEX_FILE=" + filepath.Join(p.req.TempDir, name)}
}

// VerifyBase asks the repository whether it holds the base commit.
func (p DiffBranchPlan) VerifyBase() GitStep {
	return p.git(nil, "rev-parse", "--verify", "--quiet", p.req.Base+"^{commit}")
}

// RefExists asks whether the branch already exists (it must not: a
// success here refuses the plan).
func (p DiffBranchPlan) RefExists() GitStep {
	return p.git(nil, "rev-parse", "--verify", "--quiet", p.Ref)
}

// DiffPaths is git's own reading of the diff's paths, NUL separated
// (CheckDiffPaths). --numstat turns the apply off; --cached and the
// temporary index are defence in depth, so that even an apply would reach
// only that index, never the working tree.
func (p DiffBranchPlan) DiffPaths() GitStep {
	return p.git(p.indexEnv(diffWorkIndex), "apply", "--cached", "--numstat", "-z", "--", p.req.DiffPath)
}

// FakeAncestor writes, into a temporary index, the blobs the diff says it
// starts from (its full blob names), failing when the repository does not
// hold one. Like DiffPaths it applies nothing (and would reach only the
// temporary work index if it did).
func (p DiffBranchPlan) FakeAncestor() GitStep {
	return p.git(p.indexEnv(diffWorkIndex), "apply", "--cached", "--build-fake-ancestor="+filepath.Join(p.req.TempDir, diffAncestorIndex), "--", p.req.DiffPath)
}

// ListAncestor lists that index's entries.
func (p DiffBranchPlan) ListAncestor() GitStep {
	return p.git(p.indexEnv(diffAncestorIndex), "ls-files", "--stage", "-z")
}

// ListBase lists the base commit's whole tree.
func (p DiffBranchPlan) ListBase() GitStep {
	return p.git(nil, "ls-tree", "-r", "-z", "--full-tree", p.req.Base)
}

// SeedIndex fills the temporary work index from the base commit (the
// working tree is never read or written: no -u).
func (p DiffBranchPlan) SeedIndex() GitStep {
	return p.git(p.indexEnv(diffWorkIndex), "read-tree", p.req.Base+"^{tree}")
}

// Apply applies the diff to the temporary index only: all or nothing, no
// three-way merge, no fuzz, no working tree.
func (p DiffBranchPlan) Apply() GitStep {
	return p.git(p.indexEnv(diffWorkIndex), "apply", "--cached", "--", p.req.DiffPath)
}

// WriteTree writes the temporary index as a tree.
func (p DiffBranchPlan) WriteTree() GitStep {
	return p.git(p.indexEnv(diffWorkIndex), "write-tree")
}

// ChangedEntries lists every entry the new tree changes against the base
// (raw, renames off, NUL separated; ParseRawDiff).
func (p DiffBranchPlan) ChangedEntries(tree string) GitStep {
	return p.git(nil, "diff-tree", "-r", "-z", "--no-renames", "--raw", p.req.Base, tree)
}

// ListTree lists a tree whole (its symlinks, for the chain check).
func (p DiffBranchPlan) ListTree(tree string) GitStep {
	return p.git(nil, "ls-tree", "-r", "-z", "--full-tree", tree)
}

// ReadBlob reads one blob (a changed symlink's target).
func (p DiffBranchPlan) ReadBlob(oid string) GitStep { return p.git(nil, "cat-file", "blob", oid) }

// diffIdentity is who the branch's commit is from: the sandboxed run, not
// the person (the same identity the box's own baseline commit uses).
var diffIdentity = []string{
	"GIT_AUTHOR_NAME=Observer sandbox", "GIT_AUTHOR_EMAIL=observer@localhost",
	"GIT_COMMITTER_NAME=Observer sandbox", "GIT_COMMITTER_EMAIL=observer@localhost",
}

// CommitTree records the tree as one commit on the base.
func (p DiffBranchPlan) CommitTree(tree string) GitStep {
	msg := "Changes from sandboxed run " + p.req.RunID + "\n\nOpened by Observer from the run's saved diff, on commit " + p.req.Base + ".\nReview before you merge: the diff was written inside the sandbox.\n"
	return p.git(append([]string(nil), diffIdentity...), "commit-tree", tree, "-p", p.req.Base, "-m", msg)
}

// CreateRef writes the branch only if it does not exist (empty old value).
func (p DiffBranchPlan) CreateRef(commit string) GitStep {
	return p.git(nil, "update-ref", "-m", "observer sandbox diff "+p.req.RunID, p.Ref, commit, "")
}

// VerifyRef reads the branch back.
func (p DiffBranchPlan) VerifyRef() GitStep {
	return p.git(nil, "rev-parse", "--verify", "--quiet", p.Ref+"^{commit}")
}

// CheckDiffPaths checks every path of `git apply --numstat -z`'s answer
// with the return's path rules and returns them (a rename's old and new
// path both). Each record is "<added>\t<deleted>\t<path>" or, for a rename
// or copy, "<added>\t<deleted>\t" followed by two more records, the old and
// the new path.
func CheckDiffPaths(out []byte) ([]string, error) {
	recs := bytes.Split(bytes.TrimSuffix(out, []byte{0}), []byte{0})
	var paths []string
	for i := 0; i < len(recs); i++ {
		rec := string(recs[i])
		if rec == "" {
			continue
		}
		parts := strings.SplitN(rec, "\t", 3)
		if len(parts) != 3 {
			return nil, fmt.Errorf("workspace: git's reading of the diff has a line %q that is not <added>\\t<deleted>\\t<path>", rec)
		}
		names := []string{parts[2]}
		if parts[2] == "" {
			if i+2 >= len(recs) {
				return nil, fmt.Errorf("workspace: git's reading of the diff ends inside a rename")
			}
			names = []string{string(recs[i+1]), string(recs[i+2])}
			i += 2
		}
		for _, n := range names {
			if err := checkReturnedPath(n); err != nil {
				return nil, err
			}
			paths = append(paths, n)
			if len(paths) > MaxReturnPaths {
				return nil, fmt.Errorf("workspace: the diff names more than %d paths", MaxReturnPaths)
			}
		}
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("workspace: the diff changes no file")
	}
	return paths, nil
}

// IndexEntry is one entry of `git ls-files --stage -z`.
type IndexEntry struct {
	Mode   string
	Object string
	Path   string
}

// ParseIndexEntries reads `git ls-files --stage -z`: "<mode> <object>
// <stage>\t<path>" per NUL-separated record.
func ParseIndexEntries(out []byte) ([]IndexEntry, error) {
	var es []IndexEntry
	for _, raw := range bytes.Split(out, []byte{0}) {
		if len(raw) == 0 {
			continue
		}
		meta, name, ok := strings.Cut(string(raw), "\t")
		f := strings.Fields(meta)
		if !ok || len(f) != 3 || !shaRE.MatchString(f[1]) {
			return nil, fmt.Errorf("workspace: an index entry %q is not <mode> <object> <stage>\\t<path>", string(raw))
		}
		es = append(es, IndexEntry{Mode: f[0], Object: f[1], Path: name})
		if len(es) > MaxReturnPaths {
			return nil, fmt.Errorf("workspace: more than %d index entries", MaxReturnPaths)
		}
	}
	return es, nil
}

// ParseTreeEntries reads `git ls-tree -r -z`: "<mode> <type>
// <object>\t<path>" per NUL-separated record (paths are not judged: a base
// commit is the person's own).
func ParseTreeEntries(out []byte) ([]TreeEntry, error) {
	var es []TreeEntry
	for _, raw := range bytes.Split(out, []byte{0}) {
		if len(raw) == 0 {
			continue
		}
		meta, name, ok := strings.Cut(string(raw), "\t")
		f := strings.Fields(meta)
		if !ok || len(f) != 3 {
			return nil, fmt.Errorf("workspace: a tree entry %q is not <mode> <type> <object>\\t<path>", string(raw))
		}
		es = append(es, TreeEntry{Mode: f[0], Type: f[1], Object: f[2], Path: name})
	}
	return es, nil
}

// CheckAncestorMatchesBase requires every file the diff starts from (the
// fake ancestor's entries) to be, in the base, exactly that file: the same
// blob and mode at the same path. A file the diff changes that the base
// lacks, or holds another version of, means the box did not start from the
// base, and nothing is applied.
func CheckAncestorMatchesBase(ancestor []IndexEntry, base []TreeEntry, baseName string) error {
	byPath := make(map[string]TreeEntry, len(base))
	for _, e := range base {
		byPath[e.Path] = e
	}
	short := baseName
	if len(short) > 12 {
		short = short[:12]
	}
	for _, a := range ancestor {
		b, ok := byPath[a.Path]
		switch {
		case !ok:
			return fmt.Errorf("the diff changes %q, which commit %s does not have, so the box did not start from that commit", a.Path, short)
		case b.Object != a.Object:
			return fmt.Errorf("the diff changes %q from a version that is not the one in commit %s, so the box did not start from that commit", a.Path, short)
		case b.Mode != a.Mode:
			return fmt.Errorf("the diff changes %q from a file mode (%s) that is not the one in commit %s (%s)", a.Path, a.Mode, short, b.Mode)
		}
	}
	return nil
}

// ChangedEntry is one entry of `git diff-tree -r -z --raw`.
type ChangedEntry struct {
	OldMode, NewMode     string
	OldObject, NewObject string
	Status               string
	Path                 string
}

// ParseRawDiff reads `git diff-tree -r -z --raw --no-renames`: a
// ":<old mode> <new mode> <old object> <new object> <status>" record and
// then the path record, each NUL terminated.
func ParseRawDiff(out []byte) ([]ChangedEntry, error) {
	recs := bytes.Split(out, []byte{0})
	var es []ChangedEntry
	for i := 0; i < len(recs); i++ {
		rec := string(recs[i])
		if rec == "" {
			continue
		}
		f := strings.Fields(strings.TrimPrefix(rec, ":"))
		if !strings.HasPrefix(rec, ":") || len(f) != 5 || i+1 >= len(recs) {
			return nil, fmt.Errorf("workspace: a changed entry %q is not :<mode> <mode> <object> <object> <status> and a path", rec)
		}
		es = append(es, ChangedEntry{OldMode: f[0], NewMode: f[1], OldObject: f[2], NewObject: f[3], Status: f[4], Path: string(recs[i+1])})
		i++
		if len(es) > MaxReturnPaths {
			return nil, fmt.Errorf("workspace: the diff changes more than %d paths", MaxReturnPaths)
		}
	}
	return es, nil
}

// CheckChangedEntries checks every entry the new tree changes: each path by
// the return's rules, a gitlink refused, and the symlinks it adds or
// changes returned for their targets to be read and checked
// (CheckSymlinkTarget, then CheckSymlinkChainsFrom), at most
// MaxReturnSymlinks of them.
func CheckChangedEntries(es []ChangedEntry) ([]TreeEntry, error) {
	var links []TreeEntry
	for _, e := range es {
		if err := checkReturnedPath(e.Path); err != nil {
			return nil, err
		}
		switch e.NewMode {
		case modeGitlink:
			return nil, fmt.Errorf("workspace: the diff makes %q a gitlink (a submodule commit of another repository); a branch opened from a diff may not carry one", e.Path)
		case modeSymlink:
			if !shaRE.MatchString(e.NewObject) {
				return nil, fmt.Errorf("workspace: the diff's symlink %q names object %q", e.Path, e.NewObject)
			}
			if len(links) >= MaxReturnSymlinks {
				return nil, fmt.Errorf("workspace: the diff adds more than %d symlinks", MaxReturnSymlinks)
			}
			links = append(links, TreeEntry{Mode: e.NewMode, Type: "blob", Object: e.NewObject, Path: e.Path})
		}
	}
	return links, nil
}

// CheckSymlinkChainsFrom resolves each of the starts (the symlinks a diff
// added or changed) through every symlink of the new tree (targets maps
// each link's path to its target) and refuses one that leaves the tree,
// enters a .git directory or loops. The person's own links are followed but
// not judged on their own: only a resolution that starts at a changed link
// is.
func CheckSymlinkChainsFrom(starts []string, targets map[string]string) error {
	for _, link := range starts {
		target, ok := targets[link]
		if !ok {
			continue
		}
		dir := path.Dir(link)
		var stack []string
		if dir != "." {
			stack = strings.Split(dir, "/")
		}
		if _, err := resolveReturned(stack, target, targets); err != nil {
			return fmt.Errorf("workspace: the diff's symlink %q: %w", link, err)
		}
	}
	return nil
}

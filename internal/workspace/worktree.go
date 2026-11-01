package workspace

import (
	"fmt"
	"path/filepath"
	"strings"
)

// worktree.go is the pure planning of the `worktree` workspace source
// (sandbox plan v2 section 6, lane SBX-WORKTREE-SOURCE): the branch a run
// works on, the binds that let git inside the box reach the main
// repository's objects while everything else in the main repository's git
// directory stays read-only, and the end-of-run decision. The cmd seam
// (cmd/observer/terminal_sandbox_worktree.go) reads the filesystem, runs
// the git steps and applies the binds; nothing here touches either.

// WorktreeBranchPrefix is the first component of every branch a worktree
// run creates. Each run gets its own directory below it
// (`<prefix>/<run id>/<label>`), so the run's ref and reflog live in a
// directory no other ref shares, and that directory is the only part of
// the main repository's refs the box can write.
const WorktreeBranchPrefix = "observer-sandbox"

// WorktreeDefaultLabel is the last branch component when the launch named
// no branch.
const WorktreeDefaultLabel = "work"

// WorktreeBranch composes the branch of a worktree run:
// `observer-sandbox/<id>/<label>`, label defaulting to "work". The id and
// the label are each one clean path segment (no separator, no leading
// '-', no "." or "..", no whitespace or control character), and the label
// may not end in ".lock" (git refuses such a ref).
func WorktreeBranch(id, label string) (string, error) {
	if err := validateCleanToken("ID", id); err != nil {
		return "", err
	}
	if label == "" {
		label = WorktreeDefaultLabel
	}
	if err := ValidateRefComponent(label); err != nil {
		return "", err
	}
	return WorktreeBranchPrefix + "/" + id + "/" + label, nil
}

// MaxRefComponentLen bounds a worktree branch label (a launch request
// field; git itself has no such bound).
const MaxRefComponentLen = 100

// refComponentRules is git check-ref-format's rule set for ONE component of
// a ref name (a label carries no '/'), plus the flag-injection guard every
// git argv token here gets. Walked top-down; the first rule that matches
// refuses, with its reason.
var refComponentRules = []struct {
	why string
	bad func(string) bool
}{
	{"must not be empty", func(s string) bool { return s == "" }},
	{"is longer than 100 characters", func(s string) bool { return len(s) > MaxRefComponentLen }},
	{"must not contain a path separator", func(s string) bool { return strings.ContainsAny(s, "/\\") }},
	{"contains whitespace or a control character", func(s string) bool {
		return strings.IndexFunc(s, func(r rune) bool { return r <= ' ' || r == 0x7f }) >= 0
	}},
	{"must not begin with '-'", func(s string) bool { return strings.HasPrefix(s, "-") }},
	{"must not begin with '.'", func(s string) bool { return strings.HasPrefix(s, ".") }},
	{"must not end with '.'", func(s string) bool { return strings.HasSuffix(s, ".") }},
	{"must not end with \".lock\"", func(s string) bool { return strings.HasSuffix(s, ".lock") }},
	{"must not contain \"..\"", func(s string) bool { return strings.Contains(s, "..") }},
	{"must not contain \"@{\"", func(s string) bool { return strings.Contains(s, "@{") }},
	{"must not be \"@\"", func(s string) bool { return s == "@" }},
	{"must not contain any of ~ ^ : ? * [", func(s string) bool { return strings.ContainsAny(s, "~^:?*[") }},
}

// ValidateRefComponent reports whether label can be the last component of
// a git branch name, by git's own check-ref-format rules for one component
// (no '/', so a label is exactly one component). The dashboard shows the
// same rules as a hint; this is the check the daemon enforces.
func ValidateRefComponent(label string) error {
	for _, r := range refComponentRules {
		if r.bad(label) {
			return fmt.Errorf("workspace: Branch %q %s (it must be one git branch name component)", label, r.why)
		}
	}
	return nil
}

// WorktreeRunRefDir is the directory, relative to the git common dir, that
// holds the ref of branch (refs/heads/<all but the last component>). The
// same relative path under "logs" holds its reflog.
func WorktreeRunRefDir(branch string) string {
	return filepath.Join("refs", "heads", filepath.FromSlash(pathDir(branch)))
}

// pathDir is path.Dir for a slash-separated branch name.
func pathDir(branch string) string {
	if i := strings.LastIndex(branch, "/"); i > 0 {
		return branch[:i]
	}
	return ""
}

// validStartPoint reports whether s is a full hexadecimal object id (SHA-1
// or SHA-256), the only start point a worktree plan accepts.
func validStartPoint(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// WorktreeLayout is what the cmd seam read, host side and before the box
// starts, about a prepared worktree: every path absolute, symlinks
// resolved, and checked to be git's own layout.
type WorktreeLayout struct {
	// WorkspaceDir is the worktree's top level (the run's workspace).
	WorkspaceDir string
	// CommonDir is the main repository's git common dir.
	CommonDir string
	// AdminDir is this worktree's own git dir, <CommonDir>/worktrees/<name>.
	AdminDir string
	// Branch is the run's branch (WorktreeBranch).
	Branch string
	// OtherAdmins are the other worktrees' git dirs under
	// <CommonDir>/worktrees.
	OtherAdmins []string
	// RefDirExists and LogDirExists report whether the run's ref
	// directory and reflog directory exist (git created them when it made
	// the branch; a repository that keeps no reflogs has no log dir).
	RefDirExists, LogDirExists bool
}

// ProtectRow is one path the box must see read-only (Dir marks a
// directory), applied through the launch's protective overlays.
type ProtectRow struct {
	Path string
	Dir  bool
}

// WorktreeBox is the bind plan of a worktree run.
type WorktreeBox struct {
	// ReadOnly are bound read-only before ReadWrite: the whole common dir,
	// so the main checkout's HEAD and index, every ref outside the run's
	// own directory, packed-refs, the config, the hooks and the other
	// worktrees' git dirs are all read-only in the box.
	ReadOnly []string
	// ReadWrite are bound read-write after ReadOnly: what a commit on the
	// run's branch writes (the object store, this worktree's own git dir,
	// the run's ref directory and its reflog directory).
	ReadWrite []string
	// Protect are re-bound read-only after every read-write bind, whatever
	// [terminal.sandbox].allow_tool_config_writes says: the files git
	// executes or follows that sit inside a read-write bind (alternates,
	// this worktree's commondir, gitdir and config.worktree, the
	// workspace's .git pointer) and, as a second line, the common dir's
	// executed state named by the plan (hooks, config, info,
	// config.worktree, the other worktrees' git dirs).
	Protect []ProtectRow
}

// WorktreeProtectCap bounds the other worktrees' git dirs listed as rows;
// beyond it they stay read-only through the common dir's read-only bind.
const WorktreeProtectCap = 64

// worktreeCommonProtect is the common dir's executed or trusted state
// (relative to the common dir): read-only in the box through the overlays
// as well as through the read-only bind of the whole common dir.
var worktreeCommonProtect = []ProtectRow{
	{Path: "hooks", Dir: true},
	{Path: "config"},
	{Path: "info", Dir: true},
	{Path: "config.worktree"},
	{Path: filepath.Join("objects", "info", "alternates")},
	{Path: filepath.Join("objects", "info", "http-alternates")},
}

// worktreeAdminProtect is this worktree's own git dir state git follows or
// executes (relative to the admin dir): its pointer to the common dir, its
// pointer back to the workspace, and its per-worktree config.
var worktreeAdminProtect = []ProtectRow{
	{Path: "commondir"},
	{Path: "gitdir"},
	{Path: "config.worktree"},
}

// PlanWorktreeBox composes the bind plan of a worktree run from its
// layout. It refuses a layout that is not git's own (the admin dir outside
// <common>/worktrees, the workspace inside the common dir, a branch that is
// not a worktree run's) and a run whose ref directory does not exist (git
// inside the box could not move its own branch).
func PlanWorktreeBox(l WorktreeLayout) (WorktreeBox, error) {
	for _, f := range []struct{ name, p string }{{"WorkspaceDir", l.WorkspaceDir}, {"CommonDir", l.CommonDir}, {"AdminDir", l.AdminDir}} {
		if err := validateAbsPath(f.name, f.p); err != nil {
			return WorktreeBox{}, err
		}
	}
	common := filepath.Clean(l.CommonDir)
	admin := filepath.Clean(l.AdminDir)
	if filepath.Dir(admin) != filepath.Join(common, "worktrees") {
		return WorktreeBox{}, fmt.Errorf("workspace: worktree git dir %q is not under %q", admin, filepath.Join(common, "worktrees"))
	}
	if within(filepath.Clean(l.WorkspaceDir), common) || within(common, filepath.Clean(l.WorkspaceDir)) {
		return WorktreeBox{}, fmt.Errorf("workspace: the worktree %q and the git common dir %q overlap", l.WorkspaceDir, common)
	}
	if !strings.HasPrefix(l.Branch, WorktreeBranchPrefix+"/") || strings.Count(l.Branch, "/") != 2 {
		return WorktreeBox{}, fmt.Errorf("workspace: branch %q is not a worktree run's branch", l.Branch)
	}
	if !l.RefDirExists {
		return WorktreeBox{}, fmt.Errorf("workspace: the run's ref directory %q does not exist (the repository may keep its refs in reftable, which the worktree source does not support)", filepath.Join(common, WorktreeRunRefDir(l.Branch)))
	}
	box := WorktreeBox{
		ReadOnly:  []string{common},
		ReadWrite: []string{filepath.Join(common, "objects"), admin, filepath.Join(common, WorktreeRunRefDir(l.Branch))},
	}
	if l.LogDirExists {
		box.ReadWrite = append(box.ReadWrite, filepath.Join(common, "logs", WorktreeRunRefDir(l.Branch)))
	}
	for _, r := range worktreeCommonProtect {
		box.Protect = append(box.Protect, ProtectRow{Path: filepath.Join(common, r.Path), Dir: r.Dir})
	}
	for _, r := range worktreeAdminProtect {
		box.Protect = append(box.Protect, ProtectRow{Path: filepath.Join(admin, r.Path), Dir: r.Dir})
	}
	box.Protect = append(box.Protect, ProtectRow{Path: filepath.Join(filepath.Clean(l.WorkspaceDir), ".git")})
	n := 0
	for _, o := range l.OtherAdmins {
		o = filepath.Clean(o)
		if o == admin || filepath.Dir(o) != filepath.Join(common, "worktrees") {
			continue
		}
		if n >= WorktreeProtectCap {
			break
		}
		box.Protect = append(box.Protect, ProtectRow{Path: o, Dir: true})
		n++
	}
	return box, nil
}

// within reports whether p is root or lies under it (both cleaned).
func within(p, root string) bool {
	if p == root {
		return true
	}
	rel, err := filepath.Rel(root, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// WorktreeEndFacts is what the cmd seam read about a worktree run that has
// ended, from the main repository (never from a file the box wrote alone).
type WorktreeEndFacts struct {
	// Registered: the main repository still lists the worktree.
	Registered bool
	// DirExists: the worktree's directory is still on disk.
	DirExists bool
	// OnBranch: the worktree's HEAD is the run's branch.
	OnBranch bool
	// Locked: the worktree is locked (`git worktree lock`).
	Locked bool
	// NestedRepo, when set, says why the worktree holds another
	// repository: a gitlink in its index, a modules folder in its git dir or
	// a nested .git anywhere in its tree. A host git command would then run
	// inside a repository whose config the box wrote, so the worktree is
	// kept and never cleaned (SBX-WORKTREE-SOURCE audit finding 1).
	NestedRepo string
	// Dirty: the worktree has uncommitted changes or untracked files.
	Dirty bool
	// BranchTip is the run's branch tip ("" when the branch is gone);
	// Base is the commit the run started from.
	BranchTip, Base string
}

// WorktreeEndAction is what the end of a worktree run does.
type WorktreeEndAction string

// The end-of-run actions.
const (
	// WorktreeEndRemoveAll removes the worktree, prunes its registration
	// and deletes the branch, which holds no commit of the run.
	WorktreeEndRemoveAll WorktreeEndAction = "remove_all"
	// WorktreeEndRemoveKeepBranch removes the worktree and prunes its
	// registration, and keeps the branch, which holds the run's commits.
	WorktreeEndRemoveKeepBranch WorktreeEndAction = "remove_keep_branch"
	// WorktreeEndPruneOnly removes this run's own registration, whose
	// directory is gone (the cmd seam removes only the run's admin dir,
	// never `git worktree prune` over the whole repository); the branch is
	// deleted only when it holds no commit of the run.
	WorktreeEndPruneOnly WorktreeEndAction = "prune_only"
	// WorktreeEndKeep keeps the worktree and its branch for the user.
	WorktreeEndKeep WorktreeEndAction = "keep"
)

// WorktreeEndDecision is one end-of-run decision: the action, whether the
// branch is deleted (only ever when its tip is still the base), and the
// reason shown to the user.
type WorktreeEndDecision struct {
	Action       WorktreeEndAction
	DeleteBranch bool
	Reason       string
}

// worktreeEndRule is one row of the end-of-run table; the first row whose
// when holds decides.
type worktreeEndRule struct {
	name string
	when func(f WorktreeEndFacts) bool
	then func(f WorktreeEndFacts) WorktreeEndDecision
}

// branchUnmoved reports whether the run's branch holds no commit of the
// run: it still points at the base (or is already gone).
func branchUnmoved(f WorktreeEndFacts) bool {
	return f.BranchTip == "" || (f.Base != "" && f.BranchTip == f.Base)
}

// worktreeEndRules is the end-of-run table (lane SBX-WORKTREE-SOURCE
// milestone 2). Nothing in it deletes a branch that holds a commit, and the
// worktree is removed only when it is clean, on the run's branch and not
// locked; `git worktree remove` without --force checks cleanliness again.
var worktreeEndRules = []worktreeEndRule{
	{
		"gone", func(f WorktreeEndFacts) bool { return !f.DirExists },
		func(f WorktreeEndFacts) WorktreeEndDecision {
			if branchUnmoved(f) {
				return WorktreeEndDecision{Action: WorktreeEndPruneOnly, DeleteBranch: f.BranchTip != "", Reason: "the worktree directory is gone and its branch holds no commit of the run"}
			}
			return WorktreeEndDecision{Action: WorktreeEndPruneOnly, Reason: "the worktree directory is gone; its branch holds the run's commits and is kept"}
		},
	},
	{
		"unregistered", func(f WorktreeEndFacts) bool { return !f.Registered },
		func(WorktreeEndFacts) WorktreeEndDecision {
			return WorktreeEndDecision{Action: WorktreeEndKeep, Reason: "the main repository no longer lists this worktree; nothing is removed"}
		},
	},
	{
		"locked", func(f WorktreeEndFacts) bool { return f.Locked },
		func(WorktreeEndFacts) WorktreeEndDecision {
			return WorktreeEndDecision{Action: WorktreeEndKeep, Reason: "the worktree is locked; it and its branch are kept"}
		},
	},
	{
		"off-branch", func(f WorktreeEndFacts) bool { return !f.OnBranch },
		func(WorktreeEndFacts) WorktreeEndDecision {
			return WorktreeEndDecision{Action: WorktreeEndKeep, Reason: "the worktree is no longer on the run's branch; it is kept so no commit is lost"}
		},
	},
	{
		"nested-repo", func(f WorktreeEndFacts) bool { return f.NestedRepo != "" },
		func(f WorktreeEndFacts) WorktreeEndDecision {
			return WorktreeEndDecision{Action: WorktreeEndKeep, Reason: "the worktree holds another repository (" + f.NestedRepo + "); it and its branch are kept and never cleaned"}
		},
	},
	{
		"dirty", func(f WorktreeEndFacts) bool { return f.Dirty },
		func(WorktreeEndFacts) WorktreeEndDecision {
			return WorktreeEndDecision{Action: WorktreeEndKeep, Reason: "the worktree has uncommitted changes; it and its branch are kept"}
		},
	},
	{
		"clean-no-commits", branchUnmoved,
		func(f WorktreeEndFacts) WorktreeEndDecision {
			return WorktreeEndDecision{Action: WorktreeEndRemoveAll, DeleteBranch: f.BranchTip != "", Reason: "the worktree is clean and the run made no commit"}
		},
	},
	{
		"clean-with-commits", func(WorktreeEndFacts) bool { return true },
		func(WorktreeEndFacts) WorktreeEndDecision {
			return WorktreeEndDecision{Action: WorktreeEndRemoveKeepBranch, Reason: "the worktree is clean; its branch holds the run's commits and is kept"}
		},
	},
}

// DecideWorktreeEnd walks the end-of-run table.
func DecideWorktreeEnd(f WorktreeEndFacts) WorktreeEndDecision {
	for _, r := range worktreeEndRules {
		if r.when(f) {
			return r.then(f)
		}
	}
	return WorktreeEndDecision{Action: WorktreeEndKeep, Reason: "no rule matched"}
}

// WorktreeEndRequest is the input of PlanWorktreeEnd.
type WorktreeEndRequest struct {
	// MainRoot is the main repository's top level (where git runs).
	MainRoot string
	// WorkspaceDir is the worktree.
	WorkspaceDir string
	Branch       string
	Base         string
}

// worktreeHostGit is the hardening every host-side git step of the
// worktree source carries in its argv (SBX-WORKTREE-SOURCE audit findings 1
// and 6): no file system monitor, no hooks (so `worktree add` does not run
// the main repository's post-checkout hook) and no file transport, so a
// command a repository config names is never started by the host. The
// runner adds the extrun git hardening environment on top (Step.Hardened).
var worktreeHostGit = []string{"-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=never"}

// WorktreeHostGitArgs returns a copy of the hardening flags every host git
// command of the worktree source carries, for the cmd seam's own reads
// (rev-parse, worktree list, ls-files, status).
func WorktreeHostGitArgs() []string { return append([]string(nil), worktreeHostGit...) }

// PlanWorktreeEnd composes the git steps of decision d, in order, each
// hardened (WorktreeHostGitArgs, Step.Hardened). The worktree is removed
// without --force, so git refuses a worktree that changed since the facts
// were read; the branch is deleted with a compare-and-delete against the
// base, so a branch that moved since is never deleted. No step prunes the
// whole repository: a registration left behind (the directory already
// gone) is this run's alone, and the cmd seam removes exactly that one.
func PlanWorktreeEnd(req WorktreeEndRequest, d WorktreeEndDecision) ([]Step, error) {
	if err := validateAbsPath("MainRoot", req.MainRoot); err != nil {
		return nil, err
	}
	if err := validateAbsPath("WorkspaceDir", req.WorkspaceDir); err != nil {
		return nil, err
	}
	git := func(args ...string) Step {
		argv := append([]string{"git", "-C", req.MainRoot}, worktreeHostGit...)
		return Step{Argv: append(argv, args...), Hardened: true}
	}
	var steps []Step
	switch d.Action {
	case WorktreeEndKeep:
		return nil, nil
	case WorktreeEndRemoveAll, WorktreeEndRemoveKeepBranch:
		steps = append(steps, git("worktree", "remove", "--", req.WorkspaceDir))
	case WorktreeEndPruneOnly:
		// No git step: the run's own registration is removed by the cmd seam.
	default:
		return nil, fmt.Errorf("workspace.PlanWorktreeEnd: unknown action %q", d.Action)
	}
	if d.DeleteBranch {
		if !strings.HasPrefix(req.Branch, WorktreeBranchPrefix+"/") || strings.Count(req.Branch, "/") != 2 {
			return nil, fmt.Errorf("workspace.PlanWorktreeEnd: refusing to delete %q, not a worktree run's branch", req.Branch)
		}
		if !validStartPoint(req.Base) {
			return nil, fmt.Errorf("workspace.PlanWorktreeEnd: no base commit to compare the branch against")
		}
		steps = append(steps, git("update-ref", "-d", "refs/heads/"+req.Branch, req.Base))
	}
	return steps, nil
}

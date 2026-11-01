package workspace

import (
	"fmt"
	"path/filepath"
)

// Step is one git invocation the caller's injected runner must execute.
// Argv[0] is always "git". Dir is the working directory to invoke the
// process from; empty means the command is fully path-qualified (via a
// `-C <dir>` git flag or absolute positional arguments) so the runner's
// own default working directory is fine.
type Step struct {
	Argv []string
	Dir  string
	// Hardened marks a step that runs git on the host against a repository
	// a box could write (the worktree source): the runner drops the
	// inherited GIT_* environment and adds the extrun git hardening
	// environment (no system or global config, no fsmonitor, no hooks, no
	// prompt) on top of the argv's own -c flags (WorktreeHostGitArgs).
	Hardened bool
	// NeutralHome marks a step that must read no configuration of the
	// host user: the runner points HOME and XDG_CONFIG_HOME at an empty
	// directory for it (the return scan's config read, CopyConfigListStep).
	NeutralHome bool
}

// Steps is Plan's result: the resolved final workspace directory (Dir)
// plus the ordered git Steps that produce it (empty for SourceLive). The
// caller executes Steps in order via its own injected subprocess runner
// — this package never calls os/exec — and stops at the first failure.
// Branch is the branch the plan creates: for a worktree the composed
// WorktreeBranch, for a clone the requested Branch ("" when none).
type Steps struct {
	Dir    string
	Steps  []Step
	Branch string
}

// Plan is the pure decision at the heart of U3 workspace preparation
// (docs/plans/b9-sandboxed-terminals-implementation-plan-2026-08-08.md
// §4). It computes the destination path and the ordered git argv needed
// to produce it, validating every path/token that will reach a
// subprocess argv along the way. It never execs anything; the caller
// supplies its own git runner and invokes it once per returned Step, in
// order, stopping at the first failure.
func Plan(req Request) (Steps, error) {
	switch req.Source {
	case SourceLive:
		return planLive(req)
	case SourceCloneLocal:
		return planCloneLocal(req)
	case SourceCloneRemote:
		return planCloneRemote(req)
	case SourceWorktree:
		return planWorktree(req)
	default:
		return Steps{}, fmt.Errorf("workspace.Plan: unknown source %q", req.Source)
	}
}

// planLive is the ruled degenerate case: no copy, no git steps. The
// workspace IS the validated project root.
func planLive(req Request) (Steps, error) {
	if err := validateAbsPath("ProjectRoot", req.ProjectRoot); err != nil {
		return Steps{}, err
	}
	return Steps{Dir: req.ProjectRoot}, nil
}

// planCloneLocal composes
//
//	git clone --no-hardlinks -- <ProjectRoot> <dest>
//
// --no-hardlinks is load-bearing (mutation proof #5): git's default
// --local clone hardlinks object files, so the sandboxed agent's own
// `git gc`/repack inside the workspace could mutate objects shared with
// the REAL repo's object store. Dropping the flag must fail
// TestCloneLocalUsesNoHardlinks.
func planCloneLocal(req Request) (Steps, error) {
	if err := validateAbsPath("ProjectRoot", req.ProjectRoot); err != nil {
		return Steps{}, err
	}
	dest, err := mintDest(req.ManagedRoot, req.ID, filepath.Base(req.ProjectRoot))
	if err != nil {
		return Steps{}, err
	}
	steps := []Step{
		{Argv: []string{"git", "clone", "--no-hardlinks", "--", req.ProjectRoot, dest}},
	}
	if req.Branch != "" {
		if err := validateCleanToken("Branch", req.Branch); err != nil {
			return Steps{}, err
		}
		steps = append(steps, Step{Argv: []string{"git", "-C", dest, "checkout", "-b", req.Branch}})
	}
	return Steps{Dir: dest, Steps: steps, Branch: req.Branch}, nil
}

// planCloneRemote composes `git clone -- <url> <dest>`, run host-side
// with the operator's ambient auth. Gated by AllowRemoteClone; the URL
// is validated by ValidateRemoteURL before it ever reaches an argv.
func planCloneRemote(req Request) (Steps, error) {
	if !req.AllowRemoteClone {
		return Steps{}, fmt.Errorf("workspace.Plan: clone-remote source requires allow_remote_clone (the daemon runs `git clone <url>` with your ambient auth, so it is opt-in)")
	}
	if err := ValidateRemoteURL(req.RemoteURL, req.RemoteAllowedHosts); err != nil {
		return Steps{}, err
	}
	dest, err := mintDest(req.ManagedRoot, req.ID, repoLeafFromURL(req.RemoteURL))
	if err != nil {
		return Steps{}, err
	}
	steps := []Step{
		{Argv: []string{"git", "clone", "--", req.RemoteURL, dest}},
	}
	if req.Branch != "" {
		if err := validateCleanToken("Branch", req.Branch); err != nil {
			return Steps{}, err
		}
		steps = append(steps, Step{Argv: []string{"git", "-C", dest, "checkout", "-b", req.Branch}})
	}
	return Steps{Dir: dest, Steps: steps, Branch: req.Branch}, nil
}

// planWorktree composes
//
//	git -C <ProjectRoot> <WorktreeHostGitArgs> worktree add -b <branch> -- <dest> [<StartPoint>]
//
// Gated by AllowWorktreeSource: the box gets the main repository's git
// object store, its own worktree git dir and the run's ref directory
// read-write (PlanWorktreeBox), and the run attributes to the main
// repository (git.FindRoot resolves a linked worktree to it, F0-14). The
// branch is always a fresh `observer-sandbox/<id>/<label>` (WorktreeBranch;
// Branch is only the label, "work" when empty), so it never collides with a
// branch ProjectRoot has checked out and `-b` refuses rather than resets
// an existing one. StartPoint, when set, pins the commit the branch starts
// from (a full object id), so the run's base is known exactly. The add
// carries the host hardening (WorktreeHostGitArgs, Step.Hardened), so the
// main repository's post-checkout hook and fsmonitor do not run.
func planWorktree(req Request) (Steps, error) {
	if !req.AllowWorktreeSource {
		return Steps{}, fmt.Errorf("workspace.Plan: worktree source requires allow_worktree_source (it mounts the main repository's .git folder writable in the box - off by default)")
	}
	if err := validateAbsPath("ProjectRoot", req.ProjectRoot); err != nil {
		return Steps{}, err
	}
	branch, err := WorktreeBranch(req.ID, req.Branch)
	if err != nil {
		return Steps{}, err
	}
	if req.StartPoint != "" && !validStartPoint(req.StartPoint) {
		return Steps{}, fmt.Errorf("workspace.Plan: worktree StartPoint %q is not a full object id", req.StartPoint)
	}
	dest, err := mintDest(req.ManagedRoot, req.ID, filepath.Base(req.ProjectRoot))
	if err != nil {
		return Steps{}, err
	}
	argv := append(append([]string{"git", "-C", req.ProjectRoot}, worktreeHostGit...), "worktree", "add", "-b", branch, "--", dest)
	if req.StartPoint != "" {
		argv = append(argv, req.StartPoint)
	}
	return Steps{Dir: dest, Steps: []Step{{Argv: argv, Hardened: true}}, Branch: branch}, nil
}

// mintDest computes <managedRoot>/<id>/<leafCandidate> and validates
// every component: managedRoot must be an absolute path, id must be a
// clean single path segment, and leafCandidate (the caller-derived
// candidate repo directory name) is validated the same way — an
// empty/"."/".." or otherwise unsafe candidate is REJECTED, never
// silently substituted. The result additionally passes validateAbsPath
// as a final sanity check; ValidateManagedWorkspace re-verifies
// containment once the caller has resolved the real filesystem path.
func mintDest(managedRoot, id, leafCandidate string) (string, error) {
	if err := validateAbsPath("ManagedRoot", managedRoot); err != nil {
		return "", err
	}
	if err := validateCleanToken("ID", id); err != nil {
		return "", err
	}
	if err := validateCleanToken("repoLeaf", leafCandidate); err != nil {
		return "", fmt.Errorf("workspace: could not derive a workspace directory name: %w", err)
	}
	dest := filepath.Join(managedRoot, id, leafCandidate)
	if err := validateAbsPath("dest", dest); err != nil {
		return "", err
	}
	return dest, nil
}

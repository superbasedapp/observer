package workspace

import (
	"fmt"
	"path"
	"time"
)

// return_bare.go is the return step of a clone-remote copy (sandbox plan v2
// section 6 "Return", ledger SBX-BE-10, lane SBX-P3C). A clone-remote copy
// was cloned on the host from a URL, so there is no local source
// repository to bring the box's commits into. They land instead in a bare
// repository the HOST creates beside the copy under the managed root,
// <managed>/<run>.return.git: never the agent-written copy, never pushed
// anywhere, through exactly the same steps as a clone-local return (the size
// cap, the checked fetch, the path and symlink checks, the injected scan
// before the ref, the create-only ref and its read-back). The developer
// brings the ref into their own checkout with one fetch (ReturnFetchCommand).

// ReturnRepoSuffix ends a clone-remote run's return repository.
const ReturnRepoSuffix = ".return.git"

// ReturnRepoPath is a run's return repository: <managedRoot>/<run>.return.git.
func ReturnRepoPath(managedRoot, runID string) (string, error) {
	if err := validateAbsPath("ManagedRoot", managedRoot); err != nil {
		return "", err
	}
	if !runIDRE.MatchString(runID) {
		return "", fmt.Errorf("workspace: run id %q is not a clean token", runID)
	}
	return path.Join(path.Clean(managedRoot), runID+ReturnRepoSuffix), nil
}

// checkBareReturn requires a bare return's repository to be exactly the
// run's return repository, outside the copy.
func checkBareReturn(req ReturnRequest) error {
	want, err := ReturnRepoPath(req.ManagedRoot, req.RunID)
	if err != nil {
		return err
	}
	if path.Clean(req.SourceRepo) != want {
		return fmt.Errorf("a clone-remote return lands only in %s, not %s", want, req.SourceRepo)
	}
	if isWithinDir(req.SourceRepo, req.CopyDir) || isWithinDir(req.CopyDir, req.SourceRepo) {
		return fmt.Errorf("the return repository %s and the copy %s overlap", req.SourceRepo, req.CopyDir)
	}
	if req.BaseCommit != "" && !shaRE.MatchString(req.BaseCommit) {
		return fmt.Errorf("the base commit %q is not a commit name", req.BaseCommit)
	}
	return nil
}

// CopyHead asks the copy which commit its HEAD names without a repository
// to run in (a bare return's repository does not exist yet): git upload-pack
// reads the copy; nothing in it runs.
func (p ReturnPlan) CopyHead() Step {
	argv := append([]string{"git"}, safeGit...)
	return Step{Argv: append(argv, "ls-remote", p.req.CopyDir, "HEAD")}
}

// InitBare creates the return repository: bare, with no template (so no
// sample hook or config of the host's template directory lands in it) and
// the return's own safe settings.
func (p ReturnPlan) InitBare() Step {
	argv := append([]string{"git"}, safeGit...)
	return Step{Argv: append(argv, "init", "--bare", "--quiet", "--template=", p.req.SourceRepo)}
}

// ReturnFetchCommand is the one command that brings a returned ref into the
// developer's own checkout (run in it): the ref, under its own name, from the
// return repository.
func ReturnFetchCommand(repo, ref string) string {
	return "git fetch " + repo + " " + ref + ":" + ref
}

// ReturnRepoFacts are what the host knows about one run's return repository
// when it decides whether to remove it (lane LEFT-SBX).
type ReturnRepoFacts struct {
	// RunLive: the run still has its relay record (a return may be in
	// flight, or still to come).
	RunLive bool
	// HasRef: the repository holds the run's returned ref
	// (refs/observer/sandbox/<run>, loose or packed).
	HasRef bool
	// LastWrite is the newest write the host sees in it.
	LastWrite time.Time
}

// returnRepoRule is one row of the return repository's removal table,
// walked top-down; the first that matches decides.
type returnRepoRule struct {
	reason string
	remove bool
	match  func(f ReturnRepoFacts, age, retention time.Duration) bool
}

var returnRepoRules = []returnRepoRule{
	{reason: "a return may be in flight", remove: false, match: func(f ReturnRepoFacts, _, _ time.Duration) bool { return f.RunLive }},
	{reason: "nothing was returned into it", remove: true, match: func(f ReturnRepoFacts, _, _ time.Duration) bool { return !f.HasRef }},
	{reason: "older than the retention bound", remove: true, match: func(_ ReturnRepoFacts, age, retention time.Duration) bool { return retention > 0 && age >= retention }},
	{reason: "the returned commits are still to be fetched", remove: false, match: func(ReturnRepoFacts, time.Duration, time.Duration) bool { return true }},
}

// DecideReturnRepo says whether a run's return repository is removed now,
// and why: never while its run is live; at once when nothing was returned
// into it; otherwise once its last write is older than retention (the
// developer has had that long to fetch the ref).
func DecideReturnRepo(f ReturnRepoFacts, now time.Time, retention time.Duration) (bool, string) {
	age := now.Sub(f.LastWrite)
	for _, r := range returnRepoRules {
		if r.match(f, age, retention) {
			return r.remove, r.reason
		}
	}
	return false, ""
}

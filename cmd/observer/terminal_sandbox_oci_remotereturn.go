//go:build !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/termsvc"
	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// ociCloneRemoteReturn is a clone-remote run's return request (lane
// SBX-P3C, plan 6): into the run's host-created bare return repository,
// with the commit the host cloned (read now, before the box runs) as the
// base, so a copy with no new commit returns nothing. An error says why no
// return can be planned (the copy's HEAD cannot be read, the request does
// not plan); the caller shows it on the run's terminal and keeps it in the
// run's plan record (lane SBX-P3C audit finding 8), never a silent nil.
func ociCloneRemoteReturn(managedRoot string, run termsvc.SandboxRun) (*workspace.ReturnRequest, error) {
	repo, err := workspace.ReturnRepoPath(managedRoot, run.ID)
	if err != nil {
		return nil, err
	}
	rr := workspace.ReturnRequest{SourceRepo: repo, CopyDir: run.Dir, ManagedRoot: managedRoot, RunID: run.ID, Bare: true}
	plan, err := workspace.PlanReturn(rr)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := runReturnGit(ctx, plan.CopyHead())
	if err != nil {
		return nil, fmt.Errorf("read the clone's HEAD: %w", err)
	}
	sha, err := workspace.ParseHead(out)
	if err != nil {
		return nil, err
	}
	rr.BaseCommit = sha
	if _, err := workspace.PlanReturn(rr); err != nil {
		return nil, err
	}
	return &rr, nil
}

// ociReturnRepoRetentionDefault bounds how long a clone-remote run's return
// repository is kept once the run ended, when
// [terminal.sandbox].workspace_retention_days does not set a bound (lane
// LEFT-SBX): the developer has that long to fetch the returned ref
// (`observer workspaces ls` names the repository and the fetch).
const ociReturnRepoRetentionDefault = 30 * 24 * time.Hour

// ociReturnRepoRetention is the bound for a node's config: its workspace
// retention when set, else the default.
func ociReturnRepoRetention(days int) time.Duration {
	if days > 0 {
		return time.Duration(days) * 24 * time.Hour
	}
	return ociReturnRepoRetentionDefault
}

// ociReturnRepoFacts reads what workspace.DecideReturnRepo needs about one
// return repository, with file reads only (no git runs in it): whether the
// run's ref is there (loose, or a line of packed-refs), and its newest write
// (the repository, its refs and packed-refs).
func ociReturnRepoFacts(repo, runID string, live bool) workspace.ReturnRepoFacts {
	f := workspace.ReturnRepoFacts{RunLive: live}
	ref := workspace.ReturnRefPrefix + runID
	newest := func(p string) {
		if fi, err := os.Lstat(p); err == nil && fi.ModTime().After(f.LastWrite) { //nolint:gosec // G703: a path inside the run's own return repository
			f.LastWrite = fi.ModTime()
		}
	}
	newest(repo)
	loose := filepath.Join(repo, filepath.FromSlash(ref))
	if fi, err := os.Lstat(loose); err == nil && fi.Mode().IsRegular() {
		f.HasRef = true
		newest(loose)
	}
	packed := filepath.Join(repo, "packed-refs")
	if b, err := readOwnedNoFollow(packed, 4<<20); err == nil {
		newest(packed)
		for _, line := range strings.Split(string(b), "\n") {
			if fields := strings.Fields(line); len(fields) == 2 && fields[1] == ref {
				f.HasRef = true
			}
		}
	}
	return f
}

// ociSweepReturnRepos removes the clone-remote return repositories
// (<managed>/<run>.return.git) workspace.DecideReturnRepo says to remove:
// never while the run is live (a return may be in flight), at once when
// nothing was returned into one, and once its last write is older than
// retention. A symlink or a non-directory at the name is left alone. It
// reports how many it removed.
func ociSweepReturnRepos(managedRoot string, live func(runID string) bool, now time.Time, retention time.Duration) (int, error) {
	if managedRoot == "" {
		return 0, nil
	}
	entries, err := os.ReadDir(managedRoot)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	n := 0
	var errs []error
	for _, e := range entries {
		id, ok := strings.CutSuffix(e.Name(), workspace.ReturnRepoSuffix)
		if !ok || !e.IsDir() || e.Type()&fs.ModeSymlink != 0 {
			continue
		}
		repo, perr := workspace.ReturnRepoPath(managedRoot, id)
		if perr != nil || repo != filepath.Join(managedRoot, e.Name()) {
			continue
		}
		remove, _ := workspace.DecideReturnRepo(ociReturnRepoFacts(repo, id, live(id)), now, retention)
		if !remove {
			continue
		}
		if err := os.RemoveAll(repo); err != nil {
			errs = append(errs, err)
			continue
		}
		n++
	}
	return n, errors.Join(errs...)
}

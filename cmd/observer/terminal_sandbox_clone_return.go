//go:build !(sbo_omit_terminals_sandbox_vm && sbo_omit_terminals_sandbox_oci) && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/termsvc"
	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// cloneRemoteReturn is a clone-remote run's return request (lane
// SBX-P3C, plan 6): into the run's host-created bare return repository,
// with the commit the host cloned (read now, before the box runs) as the
// base, so a copy with no new commit returns nothing. An error says why no
// return can be planned (the copy's HEAD cannot be read, the request does
// not plan); the caller shows it on the run's terminal and keeps it in the
// run's plan record (lane SBX-P3C audit finding 8), never a silent nil.
// The oci-runc and cloud-hypervisor drivers both call it; this file's build
// line keeps it linked while either driver is, and drops it when both are
// omitted, so it is never unused.
func cloneRemoteReturn(managedRoot string, run termsvc.SandboxRun) (*workspace.ReturnRequest, error) {
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

//go:build !sbo_omit_security

package main

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestSecurityQuickScanLinkedWorktree: a commit in a linked worktree shares
// the main checkout's project root (F0-14) but not its index, so the quick
// scan never answers it from the main checkout: the plan is opaque
// (unknown, the gate asks), as it was before F0-14. A `cd` from the main
// checkout into a worktree leaves the root's checkout too.
func TestSecurityQuickScanLinkedWorktree(t *testing.T) {
	mainRoot, wtRoot := linkedWorktreeFixture(t)
	if got := hookRootOf(wtRoot); got != mainRoot {
		t.Errorf("hookRootOf (the posture key) = %q, want %q", got, mainRoot)
	}
	if got := hookCheckoutOf(wtRoot); got != wtRoot {
		t.Errorf("hookCheckoutOf = %q, want %q", got, wtRoot)
	}
	root := hookProjectRoot(&policy.Event{Cwd: wtRoot})
	if root != mainRoot {
		t.Fatalf("hookProjectRoot(worktree) = %q, want the main project %q", root, mainRoot)
	}
	commit := func(cwd, cmd string) securityQuickScanPlan {
		return securityQuickScanPlanFor(&policy.Event{Kind: policy.KindShellExec, Target: cmd, Cwd: cwd}, root, nil)
	}
	if p := commit(wtRoot, "git commit -m x"); !p.opaque || len(p.reqs) != 0 {
		t.Errorf("worktree commit plan = %+v, want opaque", p)
	}
	if p := commit(mainRoot, "git commit -m x"); p.opaque || len(p.reqs) != 1 {
		t.Errorf("main commit plan = %+v, want one request", p)
	}
	if p := commit(mainRoot, "cd "+wtRoot+" && git commit -m x"); !p.opaque {
		t.Errorf("cd into the worktree plan = %+v, want opaque", p)
	}
	// A working directory outside the project is not this case either: it
	// is another repository, whose own posture is read (lane SEC-GATE5
	// milestone 1). A relayed event's box path never reaches here, since
	// a relayed write is placed from the run's checkout
	// (TestRelayChildCleanScanCoversTheHostMarker).
	if p := commit("/box/work", "git commit -m x"); !p.opaque || p.otherCheckout || len(p.otherRepos) != 1 {
		t.Errorf("outside cwd plan = %+v, want opaque with one other repository", p)
	}
}

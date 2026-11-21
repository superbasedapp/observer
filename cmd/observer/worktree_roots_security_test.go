//go:build !sbo_omit_security

package main

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestSecurityQuickScanLinkedWorktree: a commit in a linked worktree shares
// the main checkout's project root (F0-14) but not its index, so the quick
// scan never answers it from the main checkout: it reads the worktree's own
// checkout instead (one request naming the worktree, covering no dirty
// counter), whether the event's working directory is the worktree or a
// `cd` from the main checkout reaches it. Before, this plan was always
// opaque, and S-793 asked on every worktree commit with "the quick scan did
// not finish" although no scan had run.
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
	wantWorktree := func(name string, p securityQuickScanPlan) {
		t.Helper()
		if p.opaque || !p.otherCheckout || len(p.reqs) != 1 || !hookSamePath(p.reqs[0].ProjectRoot, wtRoot) {
			t.Errorf("%s plan = %+v, want one request for the worktree %s", name, p, wtRoot)
		}
	}
	wantWorktree("worktree commit", commit(wtRoot, "git commit -m x"))
	if p := commit(mainRoot, "git commit -m x"); p.opaque || p.otherCheckout || len(p.reqs) != 1 || p.reqs[0].ProjectRoot != root {
		t.Errorf("main commit plan = %+v, want one request for the main checkout", p)
	}
	wantWorktree("cd into the worktree", commit(mainRoot, "cd "+shPath(wtRoot)+" && git commit -m x"))
	// Writes in both checkouts on one line cannot be scanned as one index.
	if p := commit(mainRoot, "git commit -m x && cd "+shPath(wtRoot)+" && git commit -m y"); !p.opaque {
		t.Errorf("commits in two checkouts plan = %+v, want opaque", p)
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

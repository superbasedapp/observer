//go:build !sbo_omit_security

package main

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/localipc"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secipc"
	"github.com/marmutapp/superbased-observer/internal/secposture"
)

// serveQuickScan serves the production quick scan (the daemon's role) on
// the node's endpoint until the test ends.
func (n *worktreeGateNode) serveQuickScan(t *testing.T) {
	t.Helper()
	if !localipc.Supported() {
		t.Skip("no owner-only IPC transport on this platform")
	}
	ln, _, err := secipc.Listen(n.layout.Dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		_ = secipc.Serve(ctx, ln, securityQuickScanner(n.layout, newSecurityQuickScanEngine(func(string, string) string { return "" })))
	}()
}

// TestSecurityWorktreeCommitScansItsOwnIndex is the S-793 root cause: an
// agent working in a linked worktree of the project (an isolated
// subagent's worktree, or a `cd` into one) commits there. Before, the plan
// was always opaque for such a commit, so the hook never asked the daemon
// and the verdict read "the quick scan did not finish" on every commit,
// whatever was staged. Now the scan reads the worktree's own index: a clean
// worktree commit proceeds, a staged secret there is still caught, and the
// clean answer covers no dirty counter (the main checkout's index was not
// read), so the main checkout's commits are unaffected.
func TestSecurityWorktreeCommitScansItsOwnIndex(t *testing.T) {
	n := newWorktreeGateNode(t)
	n.serveQuickScan(t)
	if err := os.WriteFile(filepath.Join(n.wt, "ok.py"), []byte("x = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitIn(t, n.wt, "add", "ok.py")

	for _, tc := range []struct {
		name string
		cmd  string
		cwd  string
	}{
		{"worktree working directory", "git commit -m wip", n.wt},
		{"cd from the main checkout", "cd " + shPath(n.wt) + " && git commit -m wip", n.root},
	} {
		// A dirty project (an agent wrote since the last clean), and a
		// clean one: the worktree's commit is scanned either way.
		for _, dirty := range []bool{true, false} {
			n.clean(t)
			if dirty {
				if err := secposture.RaiseDirty(n.layout, secposture.ProjectRootHash(n.root)); err != nil {
					t.Fatal(err)
				}
			}
			before := n.dirtyCounter(t)
			pe := shellCommit(tc.cmd, tc.cwd, "")
			v := n.evaluate(t, pe)
			if v.RuleID == "S-793" || v.RuleID == "S-794" {
				t.Fatalf("%s (dirty %v): clean worktree commit verdict %+v (security %+v), want it to proceed", tc.name, dirty, v, pe.Security)
			}
			if pe.Security == nil || pe.Security.QuickScan != policy.QuickScanClean {
				t.Fatalf("%s (dirty %v): security %+v, want a clean quick scan", tc.name, dirty, pe.Security)
			}
			// The worktree's clean speaks for nothing in the main checkout:
			// the plan claimed no dirty counter.
			plan := securityQuickScanPlanFor(shellCommit(tc.cmd, tc.cwd, ""), n.root, nil)
			plan.captureDirty(n.layout, n.root)
			if len(plan.reqs) != 1 || plan.reqs[0].DirtySeen != 0 || !hookSamePath(plan.reqs[0].ProjectRoot, n.wt) {
				t.Fatalf("%s: plan %+v, want one request for the worktree covering nothing", tc.name, plan)
			}
			if after := n.dirtyCounter(t); after < before {
				t.Fatalf("%s: dirty counter went back from %d to %d", tc.name, before, after)
			}
		}
	}

	// A secret staged in the worktree is still caught there.
	if err := os.WriteFile(filepath.Join(n.wt, "cfg.py"), []byte(secretLine), 0o600); err != nil {
		t.Fatal(err)
	}
	gitIn(t, n.wt, "add", "cfg.py")
	n.clean(t)
	pe := shellCommit("git commit -m wip", n.wt, "")
	v := n.evaluate(t, pe)
	if v.RuleID != "S-793" || pe.Security.QuickScan != policy.QuickScanBlocking {
		t.Fatalf("staged secret in the worktree: verdict %+v (security %+v), want S-793 on a blocking quick scan", v, pe.Security)
	}
	if !strings.Contains(v.Reason, "found a blocking finding") {
		t.Fatalf("reason %q", v.Reason)
	}
}

// TestSecurityQuickScanGitNamesTheWorktreeGitDir: the quick scan's git
// runs in a linked worktree's checkout with GIT_DIR and GIT_WORK_TREE set
// (a worktree a Windows git made carries a `.git` pointer a WSL git cannot
// follow), always through the never-lazily-fetching envelope, and in a
// plain checkout with neither.
func TestSecurityQuickScanGitNamesTheWorktreeGitDir(t *testing.T) {
	mainRoot, wtRoot := linkedWorktreeFixture(t)
	var gotEnv []string
	prev := securityQuickScanGitRun
	securityQuickScanGitRun = func(_ context.Context, _ string, _ int, _ time.Duration, env []string, _ ...string) ([]byte, bool, error) {
		gotEnv = env
		return nil, false, nil
	}
	t.Cleanup(func() { securityQuickScanGitRun = prev })
	gitDir, ok := git.LinkedGitDir(wtRoot)
	if !ok {
		t.Fatal("LinkedGitDir(worktree) = false")
	}
	if _, _, err := securityQuickScanGit(context.Background(), wtRoot, 10, time.Second, "diff", "--cached"); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(gotEnv, "GIT_DIR="+gitDir) || !slices.Contains(gotEnv, "GIT_WORK_TREE="+wtRoot) {
		t.Fatalf("worktree env = %q, want GIT_DIR=%s and GIT_WORK_TREE=%s", gotEnv, gitDir, wtRoot)
	}
	if _, _, err := securityQuickScanGit(context.Background(), mainRoot, 10, time.Second, "diff", "--cached"); err != nil {
		t.Fatal(err)
	}
	if len(gotEnv) != 0 {
		t.Fatalf("main checkout env = %q, want none", gotEnv)
	}
	if _, ok := git.LinkedGitDir(filepath.Join(wtRoot, "sub")); ok {
		t.Fatal("LinkedGitDir answers only for the worktree's own top level")
	}
	if _, ok := git.LinkedGitDir(mainRoot); ok {
		t.Fatal("LinkedGitDir(main checkout) = true")
	}
}

// TestSecurityAllowRootAcceptsAWorktreeCheckout: the endpoint answers for a
// linked worktree's own checkout of a known project (where a worktree
// commit is now scanned), and still refuses an unknown directory.
func TestSecurityAllowRootAcceptsAWorktreeCheckout(t *testing.T) {
	mainRoot, wtRoot := linkedWorktreeFixture(t)
	var r securityRuntime
	list := func(context.Context) ([]string, error) { return []string{mainRoot}, nil }
	r.projects.Store(&list)
	now := time.Now()
	if !r.allowRoot(mainRoot, now) {
		t.Fatal("the known project is refused")
	}
	if !r.allowRoot(wtRoot, now) {
		t.Fatal("the project's linked worktree checkout is refused")
	}
	if r.allowRoot(filepath.Join(wtRoot, "sub"), now) {
		t.Fatal("a directory below the worktree is allowed")
	}
	if r.allowRoot(t.TempDir(), now) {
		t.Fatal("an unknown directory is allowed")
	}
}

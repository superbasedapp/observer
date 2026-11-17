//go:build !sbo_omit_security

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/hookctx"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestSecurityGitDashCResolvesLikeCwd pins R3-67: `git -C <checkout> commit`
// (or a `cd` into it) is read the way the same commit run from inside that
// checkout is. Before, a -C commit in a linked worktree was refused by the
// daemon's scan (the form named a directory: "does not model what this
// command records"), and a -C commit run from a directory in no working tree
// keyed the posture on that directory and read unknown (S-794).
func TestSecurityGitDashCResolvesLikeCwd(t *testing.T) {
	n := newWorktreeGateNode(t)
	n.serveQuickScan(t)
	if err := os.MkdirAll(filepath.Join(n.wt, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(n.wt, "ok.py"), []byte("x = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitIn(t, n.wt, "add", "ok.py")
	outside := t.TempDir()

	for _, tc := range []struct {
		name, cmd, cwd string
		wantRule       string // "" = the commit proceeds
		wantScan       policy.QuickScanVerdict
	}{
		{"-C worktree from the main checkout", "git -C " + shPath(n.wt) + " commit -m wip", n.root, "", policy.QuickScanClean},
		{"-C worktree from outside any repository", "git -C " + shPath(n.wt) + " commit -m wip", outside, "", policy.QuickScanClean},
		{"cd into the worktree from outside", "cd " + shPath(n.wt) + " && git commit -m wip", outside, "", policy.QuickScanClean},
		{"-C main checkout from outside", "git -C " + shPath(n.root) + " commit -m wip", outside, "", policy.QuickScanNone},
		// A subdirectory's pathspecs resolve against it, not the
		// checkout: the scan still refuses the form (asks, never a vacuous
		// clean).
		{"-C a worktree subdirectory", "git -C " + shPath(filepath.Join(n.wt, "sub")) + " commit -m wip", n.root, "S-793", policy.QuickScanUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n.clean(t)
			pe := shellCommit(tc.cmd, tc.cwd, "")
			v := n.evaluate(t, pe)
			if v.RuleID != tc.wantRule {
				t.Fatalf("verdict %+v (security %+v), want rule %q", v, pe.Security, tc.wantRule)
			}
			if pe.Security == nil || pe.Security.Posture == policy.SecurityPostureUnknown {
				t.Fatalf("security %+v, want the repository's posture, not unknown", pe.Security)
			}
			if pe.Security.QuickScan != tc.wantScan {
				t.Fatalf("quick scan %q (%+v), want %q", pe.Security.QuickScan, pe.Security.QuickScanDetail, tc.wantScan)
			}
		})
	}

	// A secret staged in the worktree is caught through -C from outside.
	if err := os.WriteFile(filepath.Join(n.wt, "cfg.py"), []byte(secretLine), 0o600); err != nil {
		t.Fatal(err)
	}
	gitIn(t, n.wt, "add", "cfg.py")
	n.clean(t)
	pe := shellCommit("git -C "+shPath(n.wt)+" commit -m wip", outside, "")
	if v := n.evaluate(t, pe); v.RuleID != "S-793" || pe.Security.QuickScan != policy.QuickScanBlocking {
		t.Fatalf("staged secret via -C: verdict %+v (security %+v), want S-793 on a blocking scan", v, pe.Security)
	}

	// A plain commit run outside any repository is still unknown: nothing
	// names a repository.
	n.clean(t)
	pe = shellCommit("git commit -m wip", outside, "")
	if v := n.evaluate(t, pe); v.RuleID != "S-794" {
		t.Fatalf("commit outside any repository: verdict %+v, want S-794", v)
	}
}

// TestSecurityGitTargetRootTable is securityGitTargetRoot's rule table.
func TestSecurityGitTargetRootTable(t *testing.T) {
	mainRoot, wtRoot := linkedWorktreeFixture(t)
	other, _ := linkedWorktreeFixture(t)
	outside := t.TempDir()
	for _, tc := range []struct {
		name, cmd, cwd, root, want string
	}{
		{"root in a checkout is kept", "git -C " + shPath(other) + " commit -m x", mainRoot, mainRoot, mainRoot},
		{"-C from outside", "git -C " + shPath(mainRoot) + " commit -m x", outside, outside, mainRoot},
		{"-C worktree from outside keys the main repository", "git -C " + shPath(wtRoot) + " commit -m x", outside, outside, mainRoot},
		{"two repositories keep root", "git -C " + shPath(mainRoot) + " commit -m x && git -C " + shPath(other) + " commit -m y", outside, outside, outside},
		{"no repository named keeps root", "git commit -m x", outside, outside, outside},
		{"no root", "git -C " + shPath(mainRoot) + " commit -m x", "", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := securityGitTargetRoot(shellCommit(tc.cmd, tc.cwd, ""), tc.root, nil)
			if !hookSamePath(hookAbs(got), hookAbs(tc.want)) && got != tc.want {
				t.Fatalf("root = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestSecurityRelayedLiveWorktreeCommitIsScanned: a relayed LIVE run edits
// its host checkout, so its commit in a linked worktree is scanned there
// (R3-67); a copy run's tree is the box's, so its plan stays opaque.
func TestSecurityRelayedLiveWorktreeCommitIsScanned(t *testing.T) {
	mainRoot, wtRoot := linkedWorktreeFixture(t)
	for _, tc := range []struct {
		delivery string
		opaque   bool
	}{
		{hookctx.DeliveryLive, false},
		{"", false},
		{hookctx.DeliveryCopy, true},
	} {
		ch := hookctx.Channel{RunID: "run", ProjectRoot: mainRoot, CheckoutRoot: wtRoot, Delivery: tc.delivery}
		hookctx.SetProcess(hookctx.Daemon(context.Background(), hookctx.Request{}, ch, hookctx.DaemonProviders{}))
		p := securityQuickScanPlanFor(&policy.Event{Kind: policy.KindShellExec, Target: "git commit -m x"}, mainRoot, nil)
		hookctx.SetProcess(nil)
		if p.opaque != tc.opaque || !p.otherCheckout {
			t.Fatalf("delivery %q: plan %+v, want opaque=%v in another checkout", tc.delivery, p, tc.opaque)
		}
		if !tc.opaque && (len(p.reqs) != 1 || !hookSamePath(p.reqs[0].ProjectRoot, wtRoot)) {
			t.Fatalf("delivery %q: plan %+v, want one request for the worktree", tc.delivery, p)
		}
	}
}

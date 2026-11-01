//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals && !sbo_omit_security

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/hookctx"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// TestWorktreeBoxCommitIsGatedThroughTheRelay (milestone 3): a commit an
// agent makes inside a worktree box reaches the commit gate through the
// relay as a live run's does (S-791 to S-794). The run record is a copy
// delivery whose workspace is the worktree; its relayed security state keys
// on the main repository (F0-14) while its checkout is the worktree, so the
// main checkout's signed clean posture never speaks for the worktree's
// index: with a secret staged in the worktree, the commit asks (S-793),
// whether the box reports the worktree as its working directory or reports
// none. The control, a live run in the main checkout, proceeds under the
// same clean posture.
func TestWorktreeBoxCommitIsGatedThroughTheRelay(t *testing.T) {
	repo := worktreeRepo(t)
	r := newWorktreeRuntime(t)
	_, wtDir := prepareWorktreeRun(t, r, repo)
	if err := os.WriteFile(filepath.Join(wtDir, "cfg.py"), []byte(secretLine), 0o600); err != nil {
		t.Fatal(err)
	}
	wtGit(t, wtDir, "add", "cfg.py")

	n := &worktreeGateNode{gatefixNode: newGatefixNode(t), wt: wtDir}
	n.root = repo
	relay := func(run sandboxrelayd.RunRecord) {
		ch := hookctx.Channel{
			RunID: run.RunID, ProjectRoot: relayRunProjectRoot(run), CheckoutRoot: relayRunCheckoutRoot(run),
			Delivery: string(run.Delivery), CopyHostPath: run.CopyHostPath,
		}
		hookctx.SetProcess(hookctx.Daemon(context.Background(), hookctx.Request{}, ch, hookctx.DaemonProviders{}))
	}
	t.Cleanup(func() { hookctx.SetProcess(nil) })

	box := sandboxrelayd.RunRecord{RunID: "run", Tool: "claude-code", ProjectRoot: repo, WorkspaceDir: wtDir, Roots: []string{wtDir}, Delivery: sandboxrelayd.DeliveryCopy, CopyHostPath: wtDir}
	if got := relayRunCheckoutRoot(box); got != wtDir {
		t.Fatalf("box checkout = %q, want the worktree %q", got, wtDir)
	}
	relay(box)
	if root := hookProjectRoot(&policy.Event{Kind: policy.KindShellExec, Target: "git commit -m x"}); root != repo {
		t.Fatalf("relayed project root = %q, want the main repository %q", root, repo)
	}
	for _, tc := range []struct {
		name string
		pe   *policy.Event
	}{
		{"box reports the worktree", shellCommit("git commit -m wip", wtDir, "")},
		{"box reports no directory", shellCommit("git commit -m wip", "", "")},
		{"box names the main project", shellCommit("git commit -m wip", wtDir, repo)},
	} {
		n.clean(t)
		wantWorktreeAsk(t, tc.name, n.evaluate(t, tc.pe), tc.pe)
	}

	// A clone run is unchanged: it keys on its own workspace.
	clone, err := r.prepareWorkspace(context.Background(), termsvc.PrepareRequest{Tool: "claude-code", ProjectRoot: repo, WorkspaceSource: "clone-local"})
	if err != nil {
		t.Fatal(err)
	}
	if got := relayRunProjectRoot(sandboxrelayd.RunRecord{ProjectRoot: repo, WorkspaceDir: clone.dir, Delivery: sandboxrelayd.DeliveryCopy}); got != clone.dir {
		t.Fatalf("clone copy run root = %q, want the clone %q", got, clone.dir)
	}

	// The control: a live run in the main checkout under the same posture.
	relay(sandboxrelayd.RunRecord{RunID: "run", Tool: "claude-code", ProjectRoot: repo, WorkspaceDir: repo, Roots: []string{repo}, Delivery: sandboxrelayd.DeliveryLive})
	n.clean(t)
	control := shellCommit("git commit -m wip", repo, "")
	if v := n.evaluate(t, control); v.RuleID == "S-793" || v.RuleID == "S-794" {
		t.Fatalf("main checkout commit under a clean posture: verdict %+v (security %+v), want it to proceed", v, control.Security)
	}
}

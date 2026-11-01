//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals && !sbo_omit_security

package main

import (
	"context"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/hookctx"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
)

// TestRelayRunProjectRootLinkedWorktree (SHR-WORKTREE merge): a live run in
// a linked worktree keys its relayed security state on the main repository,
// as the host path does (F0-14); the commit gate still sees the worktree as
// another checkout from the event's working directory, so its plan is
// opaque. A live run in the main checkout and a copy run are unchanged.
func TestRelayRunProjectRootLinkedWorktree(t *testing.T) {
	mainRoot, wtRoot := linkedWorktreeFixture(t)
	live := func(root string) sandboxrelayd.RunRecord {
		return sandboxrelayd.RunRecord{RunID: "run", Tool: "codex", ProjectRoot: root, WorkspaceDir: root, Roots: []string{root}, Delivery: sandboxrelayd.DeliveryLive}
	}
	if got := relayRunProjectRoot(live(wtRoot)); got != mainRoot {
		t.Fatalf("live worktree run root = %q, want the main repository %q", got, mainRoot)
	}
	if got := relayRunCheckoutRoot(live(wtRoot)); got != wtRoot {
		t.Fatalf("live worktree run checkout = %q, want the worktree %q", got, wtRoot)
	}
	if got := relayRunProjectRoot(live(mainRoot)); got != mainRoot {
		t.Fatalf("live main run root = %q, want %q", got, mainRoot)
	}
	// A copy run whose workspace is a linked worktree (the worktree
	// workspace source, lane SBX-WORKTREE-SOURCE) keys on the main
	// repository too; its checkout stays the worktree.
	copyRun := sandboxrelayd.RunRecord{RunID: "run", Tool: "codex", ProjectRoot: mainRoot, WorkspaceDir: wtRoot, Roots: []string{wtRoot}, Delivery: sandboxrelayd.DeliveryCopy, CopyHostPath: wtRoot}
	if got := relayRunProjectRoot(copyRun); got != mainRoot {
		t.Fatalf("worktree copy run root = %q, want the main repository %q", got, mainRoot)
	}
	if got := relayRunCheckoutRoot(copyRun); got != wtRoot {
		t.Fatalf("worktree copy run checkout = %q, want the worktree %q", got, wtRoot)
	}
	pe := &policy.Event{Kind: policy.KindShellExec, Target: "git commit -m x", Cwd: wtRoot}
	if p := securityQuickScanPlanFor(pe, relayRunProjectRoot(live(wtRoot)), nil); !p.opaque || !p.otherCheckout {
		t.Fatalf("relayed worktree commit plan = %+v, want opaque and another checkout", p)
	}
	// On the daemon path the run's launched checkout places the event even
	// when the box reports no working directory.
	ch := hookctx.Channel{RunID: "run", ProjectRoot: relayRunProjectRoot(live(wtRoot)), CheckoutRoot: relayRunCheckoutRoot(live(wtRoot))}
	hookctx.SetProcess(hookctx.Daemon(context.Background(), hookctx.Request{}, ch, hookctx.DaemonProviders{}))
	t.Cleanup(func() { hookctx.SetProcess(nil) })
	bare := &policy.Event{Kind: policy.KindShellExec, Target: "git commit -m x"}
	root := hookProjectRoot(bare)
	if root != mainRoot {
		t.Fatalf("relayed project root = %q, want %q", root, mainRoot)
	}
	if p := securityQuickScanPlanFor(bare, root, nil); !p.opaque || !p.otherCheckout {
		t.Fatalf("relayed worktree commit with no cwd: plan = %+v, want opaque and another checkout", p)
	}
}

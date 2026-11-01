//go:build !sbo_omit_security && !sbo_omit_security_trust && !sbo_omit_benchmark

package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/arena"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/sectrust"
)

// TestArenaWorktreeHonoursSourceAccepts (items a and b): the Arena seam
// checks the candidate's worktree, honours the accepts of the repository it
// was made from, and hands the marker to the candidate's environment.
func TestArenaWorktreeHonoursSourceAccepts(t *testing.T) {
	ctx := context.Background()
	cfgPath, _ := daemonTrustSetup(t, "enforce")
	allowArenaLaunches(t, cfgPath)
	source, worktree := writeTrustRepo(t, untrustedHookRepo), writeTrustRepo(t, untrustedHookRepo)
	seam := arenaBudgetAdmissionSeam(cfgPath)

	// Not accepted anywhere yet: the candidate is refused, and the refusal
	// names the source as where to accept.
	if err := seam(arenaTarget(ctx, worktree, source), "claude-code", ""); err == nil || !strings.Contains(err.Error(), "S-701") ||
		!strings.Contains(err.Error(), "observer security trust accept --all --dir "+source) {
		t.Fatalf("unaccepted: %v", err)
	}
	// What the check raised in the worktree is recorded under the
	// worktree's own hash, never in the source's list.
	st := openTrustTestDBFromConfig(t, cfgPath)
	if recs, _ := st.ListSecTrustItems(ctx, guard.HashProjectRoot(source)); len(recs) != 0 {
		t.Fatalf("worktree items in the source's list: %+v", recs)
	}
	if recs, _ := st.ListSecTrustItems(ctx, guard.HashProjectRoot(worktree)); len(recs) == 0 {
		t.Fatal("worktree items not recorded under the worktree's hash")
	}

	// The developer accepts the hook in the source repository.
	res, err := sectrust.Check(ctx, sectrust.OSFS(source), sectrust.Request{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.AcceptSecTrustItems(ctx, guard.HashProjectRoot(source), secTrustItems(res), "cli:test", time.Now()); err != nil {
		t.Fatal(err)
	}
	tctx := arenaTarget(ctx, worktree, source)
	if err := seam(tctx, "claude-code", ""); err != nil {
		t.Fatalf("worktree of an accepted source refused: %v", err)
	}
	target, _ := arena.LaunchTargetFrom(tctx)
	if len(target.ChildEnv) != 1 || target.ChildEnv[0] != repoTrustCheckedEnv+"="+guard.HashProjectRoot(worktree) {
		t.Fatalf("candidate env %v", target.ChildEnv)
	}
	if os.Getenv(repoTrustCheckedEnv) != "" {
		t.Fatal("the daemon's environment carries the marker")
	}
	// The same worktree with no source named honours only its own accepts.
	if err := seam(arenaTarget(ctx, worktree, ""), "claude-code", ""); err == nil {
		t.Fatal("a worktree with no source honoured another repository's accepts")
	}
	// The judge runs in its own empty scratch directory with no source.
	if err := seam(arenaTarget(ctx, t.TempDir(), ""), "claude-code", ""); err != nil {
		t.Fatalf("judge: %v", err)
	}
}

// arenaTarget is a context carrying an Arena launch target, the way
// internal/arena hands it to the admission seam.
func arenaTarget(ctx context.Context, dir, source string) context.Context {
	return arena.ContextWithLaunchTarget(ctx, &arena.LaunchTarget{Dir: dir, SourceRoot: source})
}

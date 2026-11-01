//go:build !sbo_omit_security && !sbo_omit_security_trust

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/sectrust"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestTrustCheckCmdAtHomeLeavesObserverOwnOut (SEC-TRUST4 merge residual,
// plans decision log P-044): `observer security trust check` in the home
// directory leaves Observer's own registrations out the way the launch row
// does, so after `observer init` it reports a clean repository and records
// nothing; a foreign hook in the same settings file still raises. A
// repository elsewhere gets no such exception (TestRepoTrustOwnAtOnlyAtHome).
func TestTrustCheckCmdAtHomeLeavesObserverOwnOut(t *testing.T) {
	ctx := context.Background()
	st := baselineTestStore(t)
	home := trustHome(t)
	registerObserverInto(t, home, filepath.Join(home, "bin", "observer"))
	setRunningBinary(t, filepath.Join(t.TempDir(), "elsewhere", "observer"))

	target, err := resolveRepoTrustTarget(home)
	if err != nil {
		t.Fatal(err)
	}
	s := trustCmdState{st: st, target: target, rootHash: guard.HashProjectRoot(target.root), close: func() {}}
	plain, err := sectrust.Check(ctx, sectrust.OSFS(home), sectrust.Request{})
	if err != nil {
		t.Fatal(err)
	}
	if plain.Verdict == sectrust.VerdictClean {
		t.Fatal("the check at home read none of Observer's registrations; the test proves nothing")
	}
	res, err := s.runTrustCheck(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != sectrust.VerdictClean || len(res.Reasons) != 0 {
		t.Fatalf("check at home after observer init: %s %+v", res.Verdict, res.Reasons)
	}
	if recs, err := st.ListSecTrustItems(ctx, s.rootHash); err != nil || len(recs) != 0 {
		t.Fatalf("recorded %+v %v", recs, err)
	}

	addClaudeHook(t, home, "node ~/.cache/x/run.js")
	res, err = s.runTrustCheck(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var raised []sectrust.Reason
	for _, r := range res.Reasons {
		if r.Level >= sectrust.LevelFlagged {
			raised = append(raised, r)
		}
	}
	if len(raised) != 1 || !strings.Contains(raised[0].Excerpt, "run.js") {
		t.Fatalf("a foreign hook at home: %s %+v", res.Verdict, res.Reasons)
	}
	if recs, err := st.ListSecTrustItems(ctx, s.rootHash); err != nil || len(recs) != 1 {
		t.Fatalf("recorded %+v %v, want the foreign hook only", recs, err)
	}
}

// TestRepoTrustProjectBaselineAtHome (SEC-TRUST4 merge residual, plans
// decision log P-044): the project baseline of the home directory (a home
// directory that is a repository an agent ran in) records no finding for
// `observer init` or for a release that rewrites every registration for
// another binary, and still reports a foreign hook added beside Observer's.
func TestRepoTrustProjectBaselineAtHome(t *testing.T) {
	ctx := context.Background()
	st := baselineTestStore(t)
	home := trustHome(t)
	setRunningBinary(t, filepath.Join(t.TempDir(), "elsewhere", "observer"))
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	pass := func(at time.Time) int {
		t.Helper()
		return repoTrustBaselinePass(ctx, st, []string{home}, at, nil)
	}
	if n := pass(now); n != 0 {
		t.Fatalf("first pass recorded %d", n)
	}

	registerObserverInto(t, home, filepath.Join(home, "bin", "observer"))
	// Without Own the registration's files would be reported: the case the
	// fix is for.
	res, err := sectrust.Check(ctx, sectrust.OSFS(home), sectrust.Request{Own: repoTrustOwnAt(home)})
	if err != nil {
		t.Fatal(err)
	}
	if len(repoTrustOnlyObserverFiles(res, true)) == 0 {
		t.Fatal("the project table read none of Observer's registrations at home; the test proves nothing")
	}
	if n := pass(now.Add(time.Minute)); n != 0 {
		t.Fatalf("observer init recorded %d findings, want 0", n)
	}
	registerObserverInto(t, home, filepath.Join(home, "opt", "observer-v2", "observer"))
	if n := pass(now.Add(2 * time.Minute)); n != 0 {
		t.Fatalf("a re-registration for a new binary recorded %d findings, want 0", n)
	}
	key := guard.HashProjectRoot(home)
	if fs, err := st.ListSecFindings(ctx, store.SecFindingFilter{ProjectRootHash: key}); err != nil || len(fs) != 0 {
		t.Fatalf("findings %+v %v", fs, err)
	}

	addClaudeHook(t, home, "node ~/.cache/x/run.js")
	if n := pass(now.Add(3 * time.Minute)); n != 1 {
		t.Fatalf("a foreign hook recorded %d, want 1", n)
	}
	fs, err := st.ListSecFindings(ctx, store.SecFindingFilter{ProjectRootHash: key})
	if err != nil || len(fs) != 1 || fs[0].Location.RelPath != ".claude/settings.json" || fs[0].Severity != policy.FindingSeverityHigh {
		t.Fatalf("findings %+v %v, want one High finding on .claude/settings.json", fs, err)
	}

	// A removal is still reported, even of a file that held only
	// Observer's entries.
	if err := os.Remove(filepath.Join(home, ".cursor", "hooks.json")); err != nil {
		t.Fatal(err)
	}
	if n := pass(now.Add(4 * time.Minute)); n != 1 {
		t.Fatalf("a removed hooks file recorded %d, want 1", n)
	}
}

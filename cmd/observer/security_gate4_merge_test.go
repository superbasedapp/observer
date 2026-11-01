//go:build !sbo_omit_security

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secquickscan"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestSecurityForkPlainPush (lane sec-gate4 audit finding 5, at the
// merge): in a fork setup (origin pushable, upstream fetch-only through a
// push URL that differs) the daemon resolves and signs the default push
// remote of the checked-out branch, so a plain `git push` to origin, which
// already has the held commit, passes; a push to upstream, which is never
// credited, is gated, and so is a plain push whose command line overrides
// where it goes.
func TestSecurityForkPlainPush(t *testing.T) {
	r := newGate4Repo(t, "origin", "upstream")
	gitRun(t, r.n.root, "remote", "set-url", "--push", "upstream", "no_push")
	gitRun(t, r.n.root, "branch", "--set-upstream-to=origin/main")
	gitRun(t, r.n.root, "push", "-q", "origin", "main")
	r.tick(t, time.Now())
	if got := securityPushDefaults.get(secposture.ProjectRootHash(r.n.root)); got != "origin" {
		t.Fatalf("resolved default push remote = %q, want origin", got)
	}
	if v := r.push(t, "git push"); strings.HasPrefix(v.RuleID, "S-79") {
		t.Fatalf("a plain push to origin, which has the commit, is gated: %+v", v)
	}
	v := r.push(t, "git push upstream main")
	if v.RuleID != "S-792" || !strings.Contains(v.Reason, "not on remote upstream yet") {
		t.Fatalf("a push to upstream with the held commit: %+v, want S-792 naming upstream", v)
	}
	if v := r.push(t, "git -c branch.main.pushRemote=upstream push"); v.RuleID != "S-792" {
		t.Fatalf("a plain push with a -c override: %+v, want S-792", v)
	}
	if f := r.n.only(t, "secret.aws_access_key"); f.Status != policy.FindingStatusOpen {
		t.Fatalf("finding = %s, want open (upstream never receives pushes)", f.Status)
	}
}

// TestSecurityTrackingRefOnlyStaysHeld (audit finding 4): a commit only a
// remote-tracking ref still holds (the local branch was reset away after a
// push to origin) stays held for the remote that lacks it, because a
// tracking ref is a valid push source.
func TestSecurityTrackingRefOnlyStaysHeld(t *testing.T) {
	r := newGate4Repo(t, "origin", "backup")
	gitRun(t, r.n.root, "push", "-q", "origin", "main")
	if err := os.Remove(r.n.root + "/cfg.py"); err != nil {
		t.Fatal(err)
	}
	gitRun(t, r.n.root, "reset", "-q", "HEAD~1")
	r.tick(t, time.Now())
	f := r.n.only(t, "secret.aws_access_key")
	if f.Status != policy.FindingStatusOpen {
		t.Fatalf("finding = %s, want open (backup lacks the commit)", f.Status)
	}
	if v := r.push(t, "git push backup origin/main:refs/heads/x"); v.RuleID != "S-792" {
		t.Fatalf("pushing the tracking ref to backup: %+v, want S-792", v)
	}
	if v := r.push(t, "git push origin main"); strings.HasPrefix(v.RuleID, "S-79") {
		t.Fatalf("a push to origin, which has the commit: %+v", v)
	}
}

// TestSecurityHistoryCursorStaysOnACutCheck (audit finding 9): when the
// pass budget runs out during a commit's check, the cursor does not move
// past that commit, so the next pass checks it again.
func TestSecurityHistoryCursorStaysOnACutCheck(t *testing.T) {
	ctx := context.Background()
	n := newGate2Node(t)
	if err := os.MkdirAll(n.root, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := n.st.UpsertProject(ctx, n.root, ""); err != nil {
		t.Fatal(err)
	}
	hash := secposture.ProjectRootHash(n.root)
	for i := range securityHistoryBatch + 1 {
		f := secfinding.Normalize(secfinding.Finding{
			LocalKey: "k" + string(rune('a'+i)), Rule: secfinding.Rule{ID: "secret.aws_access_key", Pack: securitySecretsPack}, Engine: secfinding.Engine{Driver: "native"},
			Category: policy.FindingSecret, Severity: policy.FindingSeverityHigh, Confidence: policy.FindingConfidenceHigh,
			Project: secfinding.Project{RootHash: hash}, Scope: policy.FindingScopeCommit,
			Commit: secfinding.Commit{SHA: strings.Repeat(string(rune('a'+i%6)), 39) + string(rune('0'+i))},
		})
		if _, _, err := n.st.UpsertSecFinding(ctx, f, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	byHash := map[string]string{hash: n.root}
	run := func(cut bool) store.SecFindingCommit {
		pctx, cancel := context.WithCancel(ctx)
		defer cancel()
		calls := 0
		rs := &securityRescan{
			st: n.st, q: n.q, logger: n.log,
			pushDefault: func(context.Context, string) (string, bool) { return "", true },
			history: func(context.Context, string, string) secquickscan.HistoryVerdict {
				calls++
				if cut && calls == 2 {
					cancel()
				}
				return secquickscan.HistoryVerdict{State: secquickscan.HistoryUnknown}
			},
		}
		rs.checkHistory(pctx, byHash, []string{hash}, time.Now())
		return rs.held
	}
	first := func() store.SecFindingCommit {
		held, err := n.st.SecHeldCommits(ctx, []string{hash}, store.SecFindingCommit{}, 1)
		if err != nil || len(held) != 1 {
			t.Fatalf("held = %v %v", held, err)
		}
		return held[0]
	}()
	if got := run(true); got != first {
		t.Fatalf("cursor after a check the budget cut = %+v, want the first commit %+v (the second is checked again)", got, first)
	}
	if got := run(false); got == first || got == (store.SecFindingCommit{}) {
		t.Fatalf("cursor after a full batch = %+v, want past the first commit", got)
	}
}

// TestSecurityCheckoutRootInWorktree (audit finding 7, P-041): the
// pre-commit check scans the linked worktree's own checkout, while the
// posture stays keyed on the main repository.
func TestSecurityCheckoutRootInWorktree(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	main := filepath.Join(t.TempDir(), "main")
	if err := os.MkdirAll(main, 0o700); err != nil {
		t.Fatal(err)
	}
	gitInitMain(t, main)
	if err := os.WriteFile(filepath.Join(main, "README"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitRun(t, main, "add", "README")
	gitRun(t, main, "commit", "-q", "-m", "first")
	wt := filepath.Join(t.TempDir(), "wt")
	gitRun(t, main, "worktree", "add", "-q", wt)
	got, err := securityCheckoutRoot(wt)
	if err != nil {
		t.Fatal(err)
	}
	proj, err := securityProjectRoot(wt)
	if err != nil {
		t.Fatal(err)
	}
	wantWT, _ := filepath.EvalSymlinks(wt)
	wantMain, _ := filepath.EvalSymlinks(main)
	if got != wantWT || proj != wantMain {
		t.Fatalf("checkout root %q (want %q), project root %q (want %q)", got, wantWT, proj, wantMain)
	}
}

// TestSecurityBranchSwitchPushDefault (lane SEC-GATE5 milestone 2,
// SECP-18): the signed default push remote is the branch's at the time it
// was resolved. After a branch switch made in its own call, a plain push
// is an unknown target until the daemon has resolved the new branch's
// remote: the hook drops a default signed before the switch, the daemon
// signs none while its entry predates the switch, and the HEAD watch
// resolves it again within seconds (re-signing either way).
func TestSecurityBranchSwitchPushDefault(t *testing.T) {
	r := newGate4Repo(t, "origin", "upstream")
	ctx := context.Background()
	hash := secposture.ProjectRootHash(r.n.root)
	gitRun(t, r.n.root, "remote", "set-url", "--push", "upstream", "no_push")
	gitRun(t, r.n.root, "branch", "--set-upstream-to=origin/main")
	gitRun(t, r.n.root, "push", "-q", "origin", "main")
	r.tick(t, time.Now())
	if v := r.push(t, "git push"); strings.HasPrefix(v.RuleID, "S-79") {
		t.Fatalf("plain push on main, origin has the commit: %+v", v)
	}

	gitRun(t, r.n.root, "checkout", "-q", "-b", "side")
	gitRun(t, r.n.root, "config", "branch.side.pushRemote", "upstream")
	// The hook still holds the posture signed before the switch.
	pe := &policy.Event{Kind: policy.KindShellExec, Target: "git push", ProjectRoot: r.n.root, Cwd: r.n.root}
	// (Gated as S-792 on the unknown target, or S-793 when the posture also
	// reads dirty from the earlier evaluated push.)
	if v := r.gn.evaluate(t, pe); !strings.HasPrefix(v.RuleID, "S-79") || pe.Security.DefaultPushRemote != "" {
		t.Fatalf("plain push right after a switch, old posture: %+v (default %q), want it gated with no default", v, pe.Security.DefaultPushRemote)
	}
	// A re-sign before the watch ran signs no default.
	if got := securityPushDefaults.get(hash); got != "" {
		t.Fatalf("stale default read as %q, want none", got)
	}
	if v := r.push(t, "git push"); v.RuleID != "S-792" {
		t.Fatalf("plain push after a re-sign, before the watch: %+v, want S-792", v)
	}

	r.rs.watchPushDefaultHeads(ctx)
	r.rs.waitHistory()
	if got := securityPushDefaults.get(hash); got != "upstream" {
		t.Fatalf("after the HEAD watch: default %q, want upstream", got)
	}
	if v := r.push(t, "git push"); v.RuleID != "S-792" {
		t.Fatalf("plain push to upstream, which never has the commit: %+v, want S-792", v)
	}

	gitRun(t, r.n.root, "checkout", "-q", "main")
	r.rs.watchPushDefaultHeads(ctx)
	r.rs.waitHistory()
	if got := securityPushDefaults.get(hash); got != "origin" {
		t.Fatalf("back on main: default %q, want origin", got)
	}
	if v := r.push(t, "git push"); strings.HasPrefix(v.RuleID, "S-79") {
		t.Fatalf("plain push back on main: %+v", v)
	}
}

// TestPushDefaultTableStaleness: an entry reads "" once a checkout's HEAD
// was written at or after it was resolved, or the HEADs cannot be read;
// stale lists exactly those, at most the limit.
func TestPushDefaultTableStaleness(t *testing.T) {
	t0 := time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)
	heads := map[string]time.Time{"/a": t0.Add(-time.Second), "/b": t0.Add(time.Second), "/c": t0}
	old := pushDefaultHeadWrite
	pushDefaultHeadWrite = func(root string) (time.Time, bool) { at, ok := heads[root]; return at, ok }
	t.Cleanup(func() { pushDefaultHeadWrite = old })
	var tab pushDefaultTable
	for _, e := range []struct{ hash, root string }{{"ha", "/a"}, {"hb", "/b"}, {"hc", "/c"}, {"hd", "/d"}} {
		tab.set(e.hash, e.root, "origin", true, t0)
	}
	want := map[string]string{"ha": "origin", "hb": "", "hc": "", "hd": ""}
	for h, w := range want {
		if got := tab.get(h); got != w {
			t.Errorf("get(%s) = %q, want %q", h, got, w)
		}
	}
	if got := tab.stale(10); len(got) != 3 || got["hb"] != "/b" || got["hc"] != "/c" || got["hd"] != "/d" {
		t.Fatalf("stale = %v", got)
	}
	if got := tab.stale(2); len(got) != 2 {
		t.Fatalf("stale(2) = %v", got)
	}
	if tab.set("ha", "/a", "", false, t0) != true || tab.get("ha") != "" {
		t.Fatal("forgetting an entry")
	}
}

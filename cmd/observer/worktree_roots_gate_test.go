//go:build !sbo_omit_security

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secposture"
)

// worktreeGateNode is a gatefix node whose project is the main repository
// of a real linked worktree (F0-14 keys both checkouts on it).
type worktreeGateNode struct {
	gatefixNode
	wt  string
	seq uint64
}

func newWorktreeGateNode(t *testing.T) *worktreeGateNode {
	t.Helper()
	mainRoot, wtRoot := linkedWorktreeFixture(t)
	n := newGatefixNode(t)
	n.root = mainRoot
	return &worktreeGateNode{gatefixNode: n, wt: wtRoot}
}

// clean signs a fresh, current, clean posture for the project whose clean
// record covers the dirty counter as it is now: what the daemon writes
// after a clean quick scan of the MAIN checkout (RecordCleanScan, then a
// re-sign).
func (n *worktreeGateNode) clean(t *testing.T) {
	t.Helper()
	counter := n.dirtyCounter(t)
	n.seq++
	seq := n.seq
	n.writeCleanPosture(t, func(f *secposture.File) {
		f.Sequence = seq
		f.DirtyCleanEpoch = counter
	})
}

func (n *worktreeGateNode) dirtyCounter(t *testing.T) uint64 {
	t.Helper()
	c, err := secposture.ReadDirty(n.layout, secposture.ProjectRootHash(n.root))
	if err != nil {
		return 0
	}
	return c
}

func gitIn(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v %s", args, err, out)
	}
}

// shPath spells a path the way a POSIX shell line holds it on Windows too
// (Git Bash, the shell Claude Code runs there): forward slashes. In an
// unquoted POSIX word a backslash is an escape, so `cd C:\Users\x` names
// `C:Usersx` in bash itself, and the hook reads it the same way (R-160:
// these tests asked S-794 on Windows only because they spelled the
// directory with backslashes).
func shPath(p string) string { return filepath.ToSlash(p) }

func shellCommit(cmd, cwd, projectRoot string) *policy.Event {
	return &policy.Event{Kind: policy.KindShellExec, ActionType: models.ActionRunCommand, Target: cmd, Cwd: cwd, ProjectRoot: projectRoot}
}

// wantWorktreeAsk: a commit recording a worktree's index never reads the
// main checkout's clean: the posture reads at least dirty and the quick
// scan is opaque (unknown), so S-793 asks.
func wantWorktreeAsk(t *testing.T, name string, v policy.Verdict, pe *policy.Event) {
	t.Helper()
	if v.RuleID != "S-793" || v.Decision != policy.DecisionAsk {
		t.Fatalf("%s: verdict %+v (security %+v), want S-793 ask", name, v, pe.Security)
	}
	if pe.Security == nil || pe.Security.Posture != policy.SecurityPostureDirty || pe.Security.QuickScan != policy.QuickScanUnknown {
		t.Fatalf("%s: security %+v, want dirty with an unknown quick scan", name, pe.Security)
	}
}

// TestSecurityWorktreeCommitNeverInheritsMainClean (SHR-WORKTREE merge,
// audit finding 1): the main checkout is clean and signed, a secret is
// staged in a linked worktree, and an agent commits in the worktree. The
// commit shares the main project's posture key (F0-14), but the gate does
// not let it through on the main checkout's clean: it asks, whether the
// event names the worktree as its working directory, names the main
// project as its root, or reaches the worktree with a `cd`. The control (a
// commit in the main checkout under the same clean posture) proceeds.
func TestSecurityWorktreeCommitNeverInheritsMainClean(t *testing.T) {
	n := newWorktreeGateNode(t)
	if err := os.WriteFile(filepath.Join(n.wt, "cfg.py"), []byte(secretLine), 0o600); err != nil {
		t.Fatal(err)
	}
	gitIn(t, n.wt, "add", "cfg.py")
	sub := filepath.Join(n.wt, "pkg")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}

	n.clean(t)
	control := shellCommit("git commit -m wip", n.root, "")
	if v := n.evaluate(t, control); v.RuleID == "S-793" || v.RuleID == "S-794" {
		t.Fatalf("main checkout commit under a clean posture: verdict %+v (security %+v), want it to proceed", v, control.Security)
	}
	if control.Security == nil || control.Security.Posture != policy.SecurityPostureClean {
		t.Fatalf("control security %+v, want clean", control.Security)
	}

	for _, tc := range []struct {
		name string
		pe   *policy.Event
	}{
		{"worktree working directory", shellCommit("git commit -m wip", n.wt, "")},
		{"worktree subdirectory", shellCommit("git commit -m wip", sub, "")},
		{"host names the main project", shellCommit("git commit -m wip", n.wt, n.root)},
		{"cd from the main checkout", shellCommit("cd "+shPath(n.wt)+" && git commit -m wip", n.root, "")},
		{"push from the worktree", shellCommit("git push", n.wt, "")},
	} {
		n.clean(t)
		v := n.evaluate(t, tc.pe)
		wantWorktreeAsk(t, tc.name, v, tc.pe)
	}
}

// TestSecurityMainCleanDoesNotClearWorktreeRaise (audit finding 1, the
// shared counter): a worktree write raises the project's dirty counter; a
// clean quick scan of the MAIN checkout then covers that counter (it read
// the main index, which the worktree's write never touched). The main
// checkout reads clean, which is right for its own index, but the
// worktree's commit still asks: no clean record of one checkout speaks for
// another checkout's raise.
func TestSecurityMainCleanDoesNotClearWorktreeRaise(t *testing.T) {
	n := newWorktreeGateNode(t)
	n.clean(t)
	before := n.dirtyCounter(t)
	write := &policy.Event{
		Kind: policy.KindFileAccess, ActionType: models.ActionWriteFile, Target: filepath.Join(n.wt, "cfg.py"), Cwd: n.wt,
		Edits: []policy.ProposedEdit{{Kind: policy.EditWhole, New: secretLine}},
	}
	n.evaluate(t, write)
	if after := n.dirtyCounter(t); after <= before {
		t.Fatalf("worktree write did not raise the project's counter: %d -> %d", before, after)
	}

	// The main checkout's clean quick scan covers the raise.
	n.clean(t)
	wt := shellCommit("git commit -m wip", n.wt, "")
	wantWorktreeAsk(t, "worktree commit after the main checkout's clean scan", n.evaluate(t, wt), wt)

	n.clean(t)
	main := shellCommit("git commit -m wip", n.root, "")
	if v := n.evaluate(t, main); v.RuleID == "S-793" || v.RuleID == "S-794" {
		t.Fatalf("main checkout commit after its own clean scan: verdict %+v, want it to proceed", v)
	}
}

// TestSecurityPlainRepoCommitUnchanged: a repository with no linked
// worktree has one checkout, so the worktree rule never holds: a commit
// under a clean posture proceeds and its plan is the ordinary one request.
func TestSecurityPlainRepoCommitUnchanged(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	repo := t.TempDir()
	if r, err := filepath.EvalSymlinks(repo); err == nil {
		repo = r
	}
	gitIn(t, repo, "init", "-q")
	sub := filepath.Join(repo, "pkg")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	n := newGatefixNode(t)
	n.root = repo
	n.writeCleanPosture(t, nil)
	for _, cwd := range []string{repo, sub, ""} {
		pe := shellCommit("git commit -m wip", cwd, "")
		if securityInOtherCheckout(pe, repo) {
			t.Fatalf("plain repository at %q reads as another checkout", cwd)
		}
		if p := securityQuickScanPlanFor(pe, repo, nil); p.opaque || p.otherCheckout || len(p.reqs) != 1 {
			t.Fatalf("plain repository plan at %q = %+v, want one request", cwd, p)
		}
	}
	pe := shellCommit("git commit -m wip", repo, "")
	if v := n.evaluate(t, pe); v.RuleID == "S-793" || v.RuleID == "S-794" {
		t.Fatalf("plain repository commit under a clean posture: verdict %+v (security %+v)", v, pe.Security)
	}
	if pe.Security == nil || pe.Security.Posture != policy.SecurityPostureClean {
		t.Fatalf("plain repository security %+v, want clean", pe.Security)
	}
}

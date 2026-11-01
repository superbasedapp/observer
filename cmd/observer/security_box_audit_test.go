//go:build !sbo_omit_security

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secdetect"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secquickscan"
	"github.com/marmutapp/superbased-observer/internal/secsvc"
)

// security_box_audit_test.go pins the SEC-BOX merge-audit fixes on the
// security module's side (findings 1, 2, 3 and 5).

// TestSecurityBoxFindingDoesNotGateHostCommits (audit finding 1, end to
// end): a secret committed on a box ref, recorded with its run, is history
// only. The developer's own commit of an unrelated change in the same
// project is not asked or denied because of it, while the agent's push,
// which would send the box commit, still is (S-792).
func TestSecurityBoxFindingDoesNotGateHostCommits(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	ctx := context.Background()
	gn := newGatefixNode(t)
	n := newGate2Node(t)
	n.root = gn.root
	if err := os.MkdirAll(n.root, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := n.st.UpsertProject(ctx, n.root, ""); err != nil {
		t.Fatal(err)
	}
	gitInitMain(t, n.root)
	n.write(t, "README", "hello\n")
	gitRun(t, n.root, "add", "README")
	gitRun(t, n.root, "commit", "-q", "-m", "first")

	// The box commits a secret; it comes back on its box ref only.
	gitRun(t, n.root, "checkout", "-q", "-b", "boxwork")
	n.write(t, "cfg.py", secretLine)
	gitRun(t, n.root, "add", "cfg.py")
	gitRun(t, n.root, "commit", "-q", "-m", "box")
	sha := gitRun(t, n.root, "rev-parse", "HEAD")
	ref := "refs/observer/sandbox/RUNBOX"
	gitRun(t, n.root, "update-ref", ref, sha)
	gitRun(t, n.root, "checkout", "-q", "main")
	gitRun(t, n.root, "branch", "-q", "-D", "boxwork")
	if _, err := os.Stat(filepath.Join(n.root, "cfg.py")); !os.IsNotExist(err) {
		t.Fatalf("the box's file is in the developer's tree: %v", err)
	}
	hash := secposture.ProjectRootHash(n.root)
	step := &securityCommitStep{st: n.st, logger: n.log}
	step.recordCommit(secsvc.WithBoxCommit(ctx, secsvc.BoxCommit{RunID: "RUNBOX", Ref: ref, Commit: sha}), n.root, hash, secquickscan.CommitResult{SHA: sha, Result: secquickscan.Result{
		Verdict: secquickscan.VerdictBlocking, Files: 1,
		Findings: []secquickscan.Finding{{Path: "cfg.py", Line: 1, Type: "aws_access_key", Confidence: secdetect.ConfidenceHigh, Identity: "id-aws_access_key-" + fakeSecretAWSKeyID}},
	}})
	if f := n.only(t, "secret.aws_access_key"); f.Status != policy.FindingStatusOpen {
		t.Fatalf("box finding %s, want open", f.Status)
	}

	// The developer's own unrelated change.
	n.write(t, "notes.txt", "todo\n")
	gitRun(t, n.root, "add", "notes.txt")
	n.signPostureScanned(t, gn)
	if v := gn.evaluate(t, gn.commit()); strings.HasPrefix(v.RuleID, "S-79") {
		t.Fatalf("the developer's commit is gated by a box-only secret: %+v", v)
	}
	push := &policy.Event{Kind: policy.KindShellExec, Target: "git push", ProjectRoot: n.root, Cwd: n.root}
	n.signPostureScanned(t, gn)
	if v := gn.evaluate(t, push); v.RuleID != "S-792" || v.Decision != policy.DecisionAsk {
		t.Fatalf("the agent's push: %+v, want S-792 ask (the box commit holds it)", v)
	}
}

// boxPlantRefs points count box refs at tip with one git call and returns
// their names in order.
func boxPlantRefs(repo *boxRefRepo, count int, tip string) []string {
	var b strings.Builder
	refs := make([]string, 0, count)
	for i := 0; i < count; i++ {
		ref := fmt.Sprintf("refs/observer/sandbox/RUN%05d", i)
		refs = append(refs, ref)
		fmt.Fprintf(&b, "create %s %s\n", ref, tip)
	}
	repo.gitIn(b.String(), "update-ref", "--stdin")
	return refs
}

// TestSecurityBoxRefWalkOverCap (audit finding 2): a box ref listing over
// its cap records one unknown run naming the cap and walks the first refs,
// never returning silently.
func TestSecurityBoxRefWalkOverCap(t *testing.T) {
	repo := newBoxRefRepo(t)
	step, database, _ := boxRefStep(t)
	step.scan.MaxBoxRefs = 5
	c1 := repo.commitFile("a.txt", "a\n", "")
	refs := boxPlantRefs(repo, 8, c1)
	tips := &boxRefTips{}
	step.walkBoxRefs(context.Background(), repo.root, tips)
	hash := secposture.ProjectRootHash(repo.root)
	if n := boxCountRows(t, database, `SELECT COUNT(*) FROM sec_scan_runs WHERE project_root_hash = ? AND outcome = 'unknown'
		AND coverage_json LIKE '%box_refs_over_cap%' AND target_json LIKE '%"list_cap":5%'`, hash); n != 1 {
		t.Fatalf("over-cap runs %d, want 1", n)
	}
	if n := boxCountRows(t, database, `SELECT COUNT(*) FROM sec_scan_runs WHERE project_root_hash = ? AND outcome = 'clean'`, hash); n != 1 {
		t.Fatalf("scanned runs %d, want 1 (the first refs share one commit)", n)
	}
	got := tips.get(repo.root)
	if len(got) != 5 {
		t.Fatalf("walked %d refs, want the first 5", len(got))
	}
	for _, r := range refs[:5] {
		if got[r] != c1 {
			t.Fatalf("%s not walked: %v", r, got)
		}
	}
}

// TestSecurityBoxRefWalkBounded (audit finding 3): with 2000 box refs a
// tick walks at most the per-tick cap and writes ONE aggregate unknown run
// for the rest, so the rows a tick adds stay bounded; the refs left are not
// remembered as walked.
func TestSecurityBoxRefWalkBounded(t *testing.T) {
	repo := newBoxRefRepo(t)
	step, database, _ := boxRefStep(t)
	c1 := repo.commitFile("a.txt", "a\n", "")
	boxPlantRefs(repo, 2000, c1)
	tips := &boxRefTips{}
	hash := secposture.ProjectRootHash(repo.root)
	rows := func() int {
		return boxCountRows(t, database, `SELECT COUNT(*) FROM sec_scan_runs WHERE project_root_hash = ?`, hash)
	}
	per := step.scan.BoxWalksPerTick()
	for tick := 1; tick <= 3; tick++ {
		before := rows()
		step.walkBoxRefs(context.Background(), repo.root, tips)
		if added := rows() - before; added > per+2 {
			t.Fatalf("tick %d added %d rows, want at most %d", tick, added, per+2)
		}
		left := 2000 - tick*per
		if n := boxCountRows(t, database, `SELECT COUNT(*) FROM sec_scan_runs WHERE project_root_hash = ? AND outcome = 'unknown'
			AND coverage_json LIKE '%box_refs_left%' AND target_json LIKE ?`, hash, fmt.Sprintf(`%%"refs_left":%d}%%`, left)); n != 1 {
			t.Fatalf("tick %d: no one aggregate run with refs_left %d", tick, left)
		}
		if got := len(tips.get(repo.root)); got != tick*per {
			t.Fatalf("tick %d remembers %d refs, want %d (only the walked ones)", tick, got, tick*per)
		}
	}
	if n := boxCountRows(t, database, `SELECT COUNT(*) FROM sec_scan_runs WHERE project_root_hash = ? AND outcome = 'unknown'`, hash); n != 3 {
		t.Fatalf("unknown runs %d, want one a tick", n)
	}
}

// TestSecurityBoxRefWalkRetriesTheRest (audit finding 3): refs past the
// per-tick cap are walked on later ticks, until every ref is covered and
// no unknown run is written any more.
func TestSecurityBoxRefWalkRetriesTheRest(t *testing.T) {
	repo := newBoxRefRepo(t)
	step, database, _ := boxRefStep(t)
	step.scan.MaxBoxWalks = 2
	for i := 0; i < 5; i++ {
		c := repo.commitFile(fmt.Sprintf("f%d.txt", i), fmt.Sprintf("%d\n", i), "")
		repo.git("update-ref", fmt.Sprintf("refs/observer/sandbox/RUN%d", i), c)
	}
	tips := &boxRefTips{}
	hash := secposture.ProjectRootHash(repo.root)
	for range 4 {
		step.walkBoxRefs(context.Background(), repo.root, tips)
	}
	if n := boxCountRows(t, database, `SELECT COUNT(*) FROM sec_scan_runs WHERE project_root_hash = ? AND outcome = 'clean'`, hash); n != 5 {
		t.Fatalf("scanned runs %d, want every ref's commit", n)
	}
	if n := boxCountRows(t, database, `SELECT COUNT(*) FROM sec_scan_runs WHERE project_root_hash = ? AND outcome = 'unknown' AND coverage_json LIKE '%box_refs_left%'`, hash); n != 2 {
		t.Fatalf("aggregate runs %d, want 2 (3 then 1 refs left)", n)
	}
	if len(tips.get(repo.root)) != 5 {
		t.Fatalf("remembered %v", tips.get(repo.root))
	}
}

// TestSecurityBoxRefWalkClaimedRunID (audit finding 5): a worktree
// branch's run id, which the box can write, is recorded only when a host
// run record owns it for this repository; otherwise the finding carries
// UnknownRunID.
func TestSecurityBoxRefWalkClaimedRunID(t *testing.T) {
	for _, tc := range []struct {
		name string
		owns bool
		want string
	}{
		{"a run record owns it", true, "RUNWT"},
		{"no run record owns it", false, secfinding.UnknownRunID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := newBoxRefRepo(t)
			step, database, _ := boxRefStep(t)
			prev := securityBoxRunOwns
			var asked []string
			securityBoxRunOwns = func(_ context.Context, root, runID string) bool {
				asked = append(asked, runID)
				return tc.owns && root == repo.root && runID == "RUNWT"
			}
			t.Cleanup(func() { securityBoxRunOwns = prev })
			c := repo.commitFile("cfg.py", boxSecret, "")
			repo.git("update-ref", "refs/heads/observer-sandbox/RUNWT/work", c)
			step.walkBoxRefs(context.Background(), repo.root, &boxRefTips{})
			var run string
			if err := database.QueryRow(`SELECT run_id FROM sec_findings WHERE project_root_hash = ?`, secposture.ProjectRootHash(repo.root)).Scan(&run); err != nil || run != tc.want {
				t.Fatalf("run_id %q %v, want %q", run, err, tc.want)
			}
			if len(asked) != 1 || asked[0] != "RUNWT" {
				t.Fatalf("asked %v", asked)
			}
		})
	}
	// A return ref's run id is the host's own: it is not asked.
	repo := newBoxRefRepo(t)
	step, database, _ := boxRefStep(t)
	prev := securityBoxRunOwns
	securityBoxRunOwns = func(context.Context, string, string) bool { t.Error("a return ref's run id was checked"); return false }
	t.Cleanup(func() { securityBoxRunOwns = prev })
	repo.git("update-ref", "refs/observer/sandbox/RUNRET", repo.commitFile("cfg.py", boxSecret, ""))
	step.walkBoxRefs(context.Background(), repo.root, &boxRefTips{})
	var run string
	if err := database.QueryRow(`SELECT run_id FROM sec_findings`).Scan(&run); err != nil || run != "RUNRET" {
		t.Fatalf("return ref run_id %q %v", run, err)
	}
}

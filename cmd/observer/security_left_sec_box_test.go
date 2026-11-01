//go:build !sbo_omit_security && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Lane LEFT-SEC milestone 2: box work.

// TestLeftSecCopyRunMeetsSourceSections: a sandbox copy's tree reads its
// source project's security.scanning sections, so a floored project's box
// commit is held like its host commit (the posture writer signs the
// project's commit gate floor into the copy's posture), while a tree no copy
// run holds keeps its own (none).
func TestLeftSecCopyRunMeetsSourceSections(t *testing.T) {
	obs := boxRunsFixture(t)
	src, copyTree := filepath.Join(t.TempDir(), "src"), filepath.Join(t.TempDir(), "copy", "work")
	rec, err := sandboxrelayd.NewRunRecord(sandboxrelayd.RunRecord{
		RunID: "RUNCOPY", Tool: "codex", ProjectRoot: src, WorkspaceDir: copyTree, Roots: []string{copyTree},
		Delivery: sandboxrelayd.DeliveryCopy, CopyHostPath: copyTree,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sandboxrelayd.WriteRun(obs, rec); err != nil {
		t.Fatal(err)
	}
	gate := `{"require":{"commit_gate":"quick_scan"}}`
	withProjectSections(t, true, true, config.DefaultSecurityConfig(), map[string]guard.ProjectFamilyLoad{
		filepath.Clean(src): matched(guard.ProjectFamilySet{OrgProjectID: "P", Members: []orgcontract.ProjectFamilyMember{sectionMember(t, 3, gate, "P")}}),
	})
	floors := securityPostureFloors(config.DefaultSecurityConfig())
	if cg, _ := floors(src); cg != policy.CommitGateFloorQuickScan {
		t.Fatalf("the source project's own floor %q", cg)
	}
	if cg, _ := floors(copyTree); cg != policy.CommitGateFloorQuickScan {
		t.Fatalf("the copy's floor %q, want the source project's quick_scan", cg)
	}
	if cg, _ := floors(filepath.Join(t.TempDir(), "elsewhere")); cg != "" {
		t.Fatalf("a tree no copy run holds took a floor: %q", cg)
	}
}

// TestLeftSecWorktreeRunIDOutlivesTheIndex: a worktree run's branch walked
// after its relay record left the index (an hour after the run ended) still
// names the run, through the host's own worktree run record; with no such
// record, or one for another repository, the run id stays unknown.
func TestLeftSecWorktreeRunIDOutlivesTheIndex(t *testing.T) {
	for _, tc := range []struct {
		name   string
		record func(obs, root string)
		want   string
	}{
		{"kept worktree record", func(obs, root string) {
			if err := writeSandboxWorktreeRecord(obs, sandboxWorktreeRecord{V: sandboxWorktreeRecordVersion, RunID: "wtlate", MainRoot: root, CommonDir: filepath.Join(root, ".git"), WorkspaceDir: filepath.Join(obs, "wt"), Branch: "observer-sandbox/wtlate/work", State: sandboxWorktreeKept, CreatedAt: time.Now().Add(-2 * time.Hour)}); err != nil {
				t.Fatal(err)
			}
		}, "wtlate"},
		{"no record", func(string, string) {}, secfinding.UnknownRunID},
		{"another repository's record", func(obs, _ string) {
			if err := writeSandboxWorktreeRecord(obs, sandboxWorktreeRecord{V: sandboxWorktreeRecordVersion, RunID: "wtlate", MainRoot: t.TempDir(), CommonDir: filepath.Join(obs, "c"), WorkspaceDir: filepath.Join(obs, "wt"), Branch: "observer-sandbox/wtlate/work", State: sandboxWorktreeKept}); err != nil {
				t.Fatal(err)
			}
		}, secfinding.UnknownRunID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			obs := boxRunsFixture(t)
			repo := newBoxRefRepo(t)
			step, database, _ := boxRefStep(t)
			tc.record(obs, repo.root)
			c := repo.commitFile("cfg.py", boxSecret, "")
			repo.git("update-ref", "refs/heads/observer-sandbox/wtlate/work", c)
			step.walkBoxRefs(context.Background(), repo.root, &boxRefTips{})
			var run string
			if err := database.QueryRow(`SELECT run_id FROM sec_findings WHERE project_root_hash = ?`, secposture.ProjectRootHash(repo.root)).Scan(&run); err != nil || run != tc.want {
				t.Fatalf("run id %q (%v), want %q", run, err, tc.want)
			}
		})
	}
}

// TestLeftSecRoundRobinReachesRef65: with 65 box refs and the per-tick cap
// of 64, a box that moves its first 64 refs every tick no longer holds ref
// 65 back: the second tick resumes after the last ref the first walked, so
// ref 65 is walked within two ticks.
func TestLeftSecRoundRobinReachesRef65(t *testing.T) {
	repo := newBoxRefRepo(t)
	step, database, _ := boxRefStep(t)
	if step.scan.BoxWalksPerTick() != 64 {
		t.Fatalf("the per-tick cap is %d, want 64", step.scan.BoxWalksPerTick())
	}
	tree := repo.git("rev-parse", "HEAD^{tree}")
	head := repo.git("rev-parse", "HEAD")
	commit := func(msg string) string { return repo.git("commit-tree", tree, "-p", head, "-m", msg) }
	var refs strings.Builder
	for i := 1; i <= 65; i++ {
		fmt.Fprintf(&refs, "update refs/observer/sandbox/R%03d %s\n", i, commit(fmt.Sprintf("t1 %d", i)))
	}
	repo.gitIn(refs.String(), "update-ref", "--stdin")
	tips := &boxRefTips{}
	ctx := context.Background()
	walked := func(ref string) int {
		return boxCountRows(t, database, `SELECT COUNT(*) FROM sec_scan_runs WHERE target_json LIKE ?`, `%"ref":"`+ref+`"%`)
	}
	step.walkBoxRefs(ctx, repo.root, tips)
	if walked("refs/observer/sandbox/R001") != 1 || walked("refs/observer/sandbox/R065") != 0 {
		t.Fatalf("tick 1: R001 %d, R065 %d", walked("refs/observer/sandbox/R001"), walked("refs/observer/sandbox/R065"))
	}
	// The box moves its first 64 refs again.
	refs.Reset()
	for i := 1; i <= 64; i++ {
		fmt.Fprintf(&refs, "update refs/observer/sandbox/R%03d %s\n", i, commit(fmt.Sprintf("t2 %d", i)))
	}
	repo.gitIn(refs.String(), "update-ref", "--stdin")
	step.walkBoxRefs(ctx, repo.root, tips)
	if walked("refs/observer/sandbox/R065") != 1 {
		t.Fatal("ref 65 was not walked within two ticks while the first 64 kept moving")
	}
}

// TestLeftSecOutOfTreeWorktreeWrite: a write in an out-of-tree linked
// worktree is read under that checkout (not the main checkout's copy), its
// finding is sighted at the checkout's own key, and the minute rescan of
// that checkout closes it once the secret is gone there.
func TestLeftSecOutOfTreeWorktreeWrite(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	n := newGate2Node(t)
	gitInitMain(t, n.root)
	n.write(t, "README", "x\n")
	gitRun(t, n.root, "add", "README")
	gitRun(t, n.root, "commit", "-qm", "first")
	wt := filepath.Join(t.TempDir(), "wt")
	if r, err := filepath.EvalSymlinks(filepath.Dir(wt)); err == nil {
		wt = filepath.Join(r, "wt")
	}
	gitRun(t, n.root, "worktree", "add", "-q", "-b", "feature", wt)
	if err := os.MkdirAll(filepath.Join(wt, "pkg"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wt, "pkg", "a.go"), []byte(secretLine), 0o600); err != nil {
		t.Fatal(err)
	}
	pw, ok := store.PostWriteFor(n.root, "pkg/a.go", filePathInput(filepath.Join(wt, "pkg", "a.go")))
	if !ok || pw.Checkout != wt || pw.CheckoutPath != "pkg/a.go" || !strings.HasPrefix(pw.Path, "[worktree:") {
		t.Fatalf("the out-of-tree write was not placed under its checkout: %+v %v", pw, ok)
	}
	pw.SessionID, pw.ActionID = "s", 1
	ctx := context.Background()
	n.q.Submit(securityPostWriteFor(ctx, n.st, pw))
	n.q.Drain(ctx)
	f := n.only(t, "secret.aws_access_key")
	if f.Status != policy.FindingStatusOpen || f.Location.RelPath != pw.Path {
		t.Fatalf("finding %s at %q, want open at %q", f.Status, f.Location.RelPath, pw.Path)
	}
	// The secret leaves the worktree's file: the rescan of that checkout
	// closes the sighting.
	if err := os.WriteFile(filepath.Join(wt, "pkg", "a.go"), []byte("k = os.environ['K']\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w := securityRescanWrite(n.root, pw.Path)
	if w.Checkout != wt || w.CheckoutPath != "pkg/a.go" {
		t.Fatalf("the rescan did not find the checkout: %+v", w)
	}
	n.q.Submit(w)
	n.q.Drain(ctx)
	if f := n.only(t, "secret.aws_access_key"); f.Status != policy.FindingStatusNotReproduced {
		t.Fatalf("after the checkout's rescan: %s, want not_reproduced", f.Status)
	}
}

// TestLeftSecHostedSavedDiff: a hosted run's saved staged diff is scanned
// once and its finding carries the run id (shown, gating nothing until the
// tree holds it); a diff the guest cut at its cap and a kept diff error are
// unknown runs, never clean; a diff no record attributes yet waits.
func TestLeftSecHostedSavedDiff(t *testing.T) {
	step, database := boxTestStep(t, nil)
	obs, secDir, root := t.TempDir(), t.TempDir(), t.TempDir()
	returns := filepath.Join(hostedStateDir(obs), "returns")
	if err := os.MkdirAll(returns, 0o700); err != nil {
		t.Fatal(err)
	}
	diff := "diff --git a/cfg.py b/cfg.py\nnew file mode 100644\n--- /dev/null\n+++ b/cfg.py\n@@ -0,0 +1 @@\n+" + strings.TrimSuffix(secretLine, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(returns, "HOSTED1.diff"), []byte(diff), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(returns, "HOSTEDCUT.diff"), []byte(strings.Repeat("x", sandbox.MaxStagedDiff)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(returns, "UNNAMED.diff"), []byte(diff), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := hostedWithState(obs, true, func() error {
		return hostedKeepDiffErrorLocked(obs, sandboxremote.Record{RunID: "HOSTEDLOST", Provider: "e2b", DiffError: "the box has no git"}, time.Now())
	}); err != nil {
		t.Fatal(err)
	}
	projectOf := func(_ context.Context, id string) string {
		if id == "UNNAMED" {
			return ""
		}
		return root
	}
	ctx := context.Background()
	securityScanHostedReturns(ctx, step, secDir, obs, projectOf)
	hash := secposture.ProjectRootHash(root)
	var run string
	if err := database.QueryRow(`SELECT run_id FROM sec_findings WHERE project_root_hash = ? AND rule_id = 'secret.aws_access_key'`, hash).Scan(&run); err != nil || run != "HOSTED1" {
		t.Fatalf("hosted diff finding run=%q %v", run, err)
	}
	if keys, err := step.st.SecBlockingKeys(ctx, store.SecBlockingQuery{ProjectRootHash: hash, Severities: []secfinding.Severity{policy.FindingSeverityHigh, policy.FindingSeverityCritical}}, 10); err != nil || len(keys) != 0 {
		t.Fatalf("a never-applied hosted diff gates the project: %v %v", keys, err)
	}
	for _, reason := range []string{hostedDiffTruncated, hostedDiffNotSaved} {
		if n := boxCountRows(t, database, `SELECT COUNT(*) FROM sec_scan_runs WHERE project_root_hash = ? AND outcome = 'unknown' AND coverage_json LIKE ?`, hash, "%"+reason+"%"); n != 1 {
			t.Fatalf("%s: %d unknown runs, want 1", reason, n)
		}
	}
	before := boxCountRows(t, database, `SELECT COUNT(*) FROM sec_scan_runs`)
	securityScanHostedReturns(ctx, step, secDir, obs, projectOf)
	if after := boxCountRows(t, database, `SELECT COUNT(*) FROM sec_scan_runs`); after != before {
		t.Fatalf("a second tick scanned again: %d runs, want %d", after, before)
	}
	if _, err := os.Stat(filepath.Join(secDir, hostedReturnsMarkerDir, "UNNAMED")); !os.IsNotExist(err) {
		t.Fatal("an unattributed diff was marked handled")
	}
}

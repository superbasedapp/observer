//go:build !sbo_omit_security

package main

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/gitview"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secquickscan"
)

// boxRefRepo is a repository with one commit on its branch, and helpers to
// commit on a box ref without moving the branch.
type boxRefRepo struct {
	t    *testing.T
	root string
}

func newBoxRefRepo(t *testing.T) *boxRefRepo {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	root := t.TempDir()
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
	r := &boxRefRepo{t: t, root: root}
	r.git("init", "-q")
	r.git("symbolic-ref", "HEAD", "refs/heads/main")
	r.commitFile("README", "x\n", "")
	return r
}

func (r *boxRefRepo) git(args ...string) string {
	r.t.Helper()
	cmd := exec.Command("git", args...) //nolint:gosec // G204: fixed git argv in a temp repo
	cmd.Dir = r.root
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@x", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@x", "GIT_CONFIG_NOSYSTEM=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		r.t.Fatalf("git %v: %v %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// commitFile commits path with body on top of parent ("" for HEAD)
// without touching the working tree or any ref, and returns the commit.
func (r *boxRefRepo) commitFile(path, body, parent string) string {
	r.t.Helper()
	blob := r.gitIn(body, "hash-object", "-w", "--stdin")
	base := parent
	if base == "" {
		if out, err := exec.Command("git", "-C", r.root, "rev-parse", "--verify", "-q", "HEAD").Output(); err == nil {
			base = strings.TrimSpace(string(out))
		}
	}
	idx := filepath.Join(r.t.TempDir(), "index")
	env := []string{"GIT_INDEX_FILE=" + idx}
	if base != "" {
		r.gitEnv(env, "", "read-tree", base)
	}
	r.gitEnv(env, "", "update-index", "--add", "--cacheinfo", "100644,"+blob+","+path)
	tree := r.gitEnv(env, "", "write-tree")
	args := []string{"commit-tree", tree, "-m", "c " + path}
	if base != "" {
		args = append(args, "-p", base)
	}
	sha := r.gitEnv(env, "", args...)
	if parent == "" && base == "" {
		r.git("update-ref", "refs/heads/main", sha)
	}
	return sha
}

func (r *boxRefRepo) gitIn(stdin string, args ...string) string {
	return r.gitEnv(nil, stdin, args...)
}

func (r *boxRefRepo) gitEnv(env []string, stdin string, args ...string) string {
	r.t.Helper()
	cmd := exec.Command("git", args...) //nolint:gosec // G204: fixed git argv in a temp repo
	cmd.Dir = r.root
	cmd.Env = append(append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@x", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@x"), env...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		r.t.Fatalf("git %v: %v %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// boxRefStep is a commit-scan step over a fresh store whose git calls are
// counted.
func boxRefStep(t *testing.T) (*securityCommitStep, *sql.DB, *atomic.Int64) {
	t.Helper()
	st, database := openTestStore(t)
	var calls atomic.Int64
	eng := newSecurityQuickScanEngine(func(typ, _ string) string { return "id-" + typ })
	eng.Git = func(ctx context.Context, root string, max int, timeout time.Duration, args ...string) ([]byte, bool, error) {
		calls.Add(1)
		return gitview.RunReadOnlyTimeout(ctx, root, max, timeout, args...)
	}
	return &securityCommitStep{scan: &secquickscan.CommitScan{Engine: eng}, st: st, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}, database, &calls
}

func boxCountRows(t *testing.T, database *sql.DB, q string, args ...any) int {
	t.Helper()
	var n int
	if err := database.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

const boxSecret = "k = \"" + fakeSecretAWSKeyID + "\"\n"

// TestSecurityBoxRefWalk: a new box ref is scanned once and its finding
// carries the run; a moved ref scans only its new commits; a deleted ref
// is forgotten; a repository with no box ref costs one git call a tick.
func TestSecurityBoxRefWalk(t *testing.T) {
	repo := newBoxRefRepo(t)
	step, database, calls := boxRefStep(t)
	tips := &boxRefTips{}
	ctx := context.Background()
	hash := secposture.ProjectRootHash(repo.root)
	runsOf := func() int {
		return boxCountRows(t, database, `SELECT COUNT(*) FROM sec_scan_runs WHERE project_root_hash = ? AND scope = 'commit'`, hash)
	}

	calls.Store(0)
	step.walkBoxRefs(ctx, repo.root, tips)
	if calls.Load() != 1 || runsOf() != 0 {
		t.Fatalf("no box ref: %d git calls, %d runs", calls.Load(), runsOf())
	}

	c1 := repo.commitFile("cfg.py", boxSecret, "")
	repo.git("update-ref", "refs/observer/sandbox/RUNA", c1)
	step.walkBoxRefs(ctx, repo.root, tips)
	if runsOf() != 1 {
		t.Fatalf("a new box ref: %d runs", runsOf())
	}
	var run, commit string
	if err := database.QueryRow(`SELECT run_id, commit_sha FROM sec_findings WHERE project_root_hash = ?`, hash).Scan(&run, &commit); err != nil || run != "RUNA" || commit != c1 {
		t.Fatalf("finding run=%q commit=%q %v", run, commit, err)
	}
	step.walkBoxRefs(ctx, repo.root, tips)
	if runsOf() != 1 {
		t.Fatalf("an unchanged ref was walked again: %d runs", runsOf())
	}

	c2 := repo.commitFile("b.txt", "two\n", c1)
	c3 := repo.commitFile("c.txt", "three\n", c2)
	repo.git("update-ref", "refs/observer/sandbox/RUNA", c3)
	step.walkBoxRefs(ctx, repo.root, tips)
	if runsOf() != 3 {
		t.Fatalf("a moved ref: %d runs, want 3 (its two new commits only)", runsOf())
	}

	repo.git("update-ref", "-d", "refs/observer/sandbox/RUNA")
	step.walkBoxRefs(ctx, repo.root, tips)
	if tips.get(repo.root) != nil {
		t.Fatalf("a deleted ref is remembered: %v", tips.get(repo.root))
	}

	// A daemon restart (empty memory) that sees the ref again skips the
	// commits the store already holds a box run for.
	repo.git("update-ref", "refs/observer/sandbox/RUNA", c3)
	step.walkBoxRefs(ctx, repo.root, &boxRefTips{})
	if runsOf() != 3 {
		t.Fatalf("after a restart: %d runs, want 3", runsOf())
	}
}

// TestSecurityBoxRefWalkCap: commits past the commit cap are not scanned
// that tick and are recorded in the tick's one aggregate unknown run,
// never silent; the ref is walked again on the next ticks until every
// commit is scanned (lane sec-box audit finding 3); a walk out of budget
// is an unknown run too.
func TestSecurityBoxRefWalkCap(t *testing.T) {
	repo := newBoxRefRepo(t)
	step, database, _ := boxRefStep(t)
	step.scan.MaxCommits = 1
	parent := ""
	for i, name := range []string{"x.txt", "y.txt", "z.txt"} {
		parent = repo.commitFile(name, strings.Repeat("v", i+1)+"\n", parent)
	}
	repo.git("update-ref", "refs/observer/sandbox/RUNCAP", parent)
	tips := &boxRefTips{}
	step.walkBoxRefs(context.Background(), repo.root, tips)
	hash := secposture.ProjectRootHash(repo.root)
	if n := boxCountRows(t, database, `SELECT COUNT(*) FROM sec_scan_runs WHERE project_root_hash = ? AND outcome = 'unknown' AND coverage_json LIKE '%box_refs_left%'`, hash); n != 1 {
		t.Fatalf("cap remainder runs %d", n)
	}
	if n := boxCountRows(t, database, `SELECT COUNT(*) FROM sec_scan_runs WHERE project_root_hash = ? AND outcome = 'clean'`, hash); n != 1 {
		t.Fatalf("scanned runs %d, want 1 (the cap)", n)
	}
	if tips.get(repo.root) != nil {
		t.Fatalf("a ref cut short by the cap is remembered as walked: %v", tips.get(repo.root))
	}
	for range 3 {
		step.walkBoxRefs(context.Background(), repo.root, tips)
	}
	if n := boxCountRows(t, database, `SELECT COUNT(*) FROM sec_scan_runs WHERE project_root_hash = ? AND outcome = 'clean'`, hash); n != 3 {
		t.Fatalf("after the retries: %d scanned runs, want all 3 commits", n)
	}
	if n := boxCountRows(t, database, `SELECT COUNT(*) FROM sec_scan_runs WHERE project_root_hash = ? AND outcome = 'unknown'`, hash); n != 2 {
		t.Fatalf("after the retries: %d unknown runs, want 2 (two ticks cut short)", n)
	}

	repo2 := newBoxRefRepo(t)
	step2, database2, _ := boxRefStep(t)
	step2.scan.Budget = time.Nanosecond
	repo2.git("update-ref", "refs/observer/sandbox/RUNBUD", repo2.commitFile("q.txt", "q\n", ""))
	step2.walkBoxRefs(context.Background(), repo2.root, &boxRefTips{})
	if n := boxCountRows(t, database2, `SELECT COUNT(*) FROM sec_scan_runs WHERE outcome = 'unknown'`); n == 0 {
		t.Fatal("a walk out of budget left no unknown run")
	}
}

// TestSecurityBoxRefWalkWorktreeBranch: the worktree source's branch
// refs/heads/observer-sandbox/<id>/<label>, checked out in a linked
// worktree (its HEAD), is covered.
func TestSecurityBoxRefWalkWorktreeBranch(t *testing.T) {
	repo := newBoxRefRepo(t)
	step, database, _ := boxRefStep(t)
	// The branch's run id is the box's claim: a host run record owns it
	// here (TestSecurityBoxRefWalkClaimedRunID covers the other case).
	prev := securityBoxRunOwns
	securityBoxRunOwns = func(_ context.Context, _, runID string) bool { return runID == "RUNWT" }
	t.Cleanup(func() { securityBoxRunOwns = prev })
	wt := filepath.Join(t.TempDir(), "work")
	repo.git("worktree", "add", "-q", "-b", "observer-sandbox/RUNWT/work", wt)
	// Commit inside the worktree, as the box does.
	if err := os.WriteFile(filepath.Join(wt, "cfg.py"), []byte(boxSecret), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"add", "cfg.py"}, {"commit", "-qm", "box"}} {
		cmd := exec.Command("git", args...) //nolint:gosec // G204: fixed git argv in a temp repo
		cmd.Dir = wt
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@x", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@x")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	step.walkBoxRefs(context.Background(), repo.root, &boxRefTips{})
	var run string
	if err := database.QueryRow(`SELECT run_id FROM sec_findings WHERE project_root_hash = ?`, secposture.ProjectRootHash(repo.root)).Scan(&run); err != nil || run != "RUNWT" {
		t.Fatalf("worktree branch finding run=%q %v", run, err)
	}
}

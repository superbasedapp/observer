package arena

import (
	"context"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// judgedCandidate runs one claude-code candidate of a fresh run to the
// judged state the keep step accepts.
func judgedCandidate(t *testing.T, r *Runner, repo, runID string) models.ArenaCandidate {
	t.Helper()
	ctx := context.Background()
	prep, err := r.StartRun(ctx, validRunSpec(runID, repo))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.DriveCandidates(ctx, prep); err != nil {
		t.Fatal(err)
	}
	rows, _ := r.opts.Store.ArenaCandidates(ctx, runID)
	rows[0].Status = models.ArenaCandidateStatusJudged
	if err := r.opts.Store.UpdateArenaCandidate(ctx, &rows[0]); err != nil {
		t.Fatal(err)
	}
	if err := r.opts.Store.UpdateArenaRunStatus(ctx, runID, models.ArenaRunStatusComplete); err != nil {
		t.Fatal(err)
	}
	return rows[0]
}

// useJudge swaps the claude-code binary for the keep phase only.
func useJudge(t *testing.T, bin string) {
	t.Helper()
	prev := driveBinOverrides["claude-code"]
	driveBinOverrides["claude-code"] = bin
	t.Cleanup(func() { driveBinOverrides["claude-code"] = prev })
}

// mergeBody is a judge that history-merges the run's claude-code candidate
// branch in its working directory and commits.
func mergeBody(runID string) string {
	return `
git merge --no-edit --no-ff arena/` + runID + `/claude-code >/dev/null 2>&1 || true
echo '{"type":"result","result":"done"}'
`
}

func gitOut(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := osexec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
	return string(out)
}

func realPath(t *testing.T, p string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestJudgeMergeNeverRunsInTheRealCheckout (OSH-R-006): the merge agent works
// in a temporary keep worktree, never the operator's checkout; the checkout
// moves only by the final fast-forward; the keep worktree and its branch are
// gone afterwards.
func TestJudgeMergeNeverRunsInTheRealCheckout(t *testing.T) {
	repo := initArenaRepo(t)
	r := allowSkip(startTestRunner(t, repo)) // judge_merge runs only in the skip lane (audit F3)
	row := judgedCandidate(t, r, repo, "iso1")
	ctx := context.Background()
	baseHead, _ := git.HeadSHA(ctx, repo)
	where := filepath.Join(t.TempDir(), "pwd.txt")
	useJudge(t, fakeBin(t, t.TempDir(), "iso-judge", `pwd -P > "`+where+`"`+mergeBody("iso1")))

	sha, err := r.Keep(ctx, &row, repo, KeepJudgeMerge, JudgeSpec{Tool: "claude-code"})
	if err != nil {
		t.Fatalf("Keep(judge_merge): %v", err)
	}
	ran, _ := os.ReadFile(where)
	if got := strings.TrimSpace(string(ran)); got == "" || got == realPath(t, repo) {
		t.Fatalf("the merge agent ran in %q, want an isolated worktree, not the checkout %q", got, repo)
	}
	head, _ := git.HeadSHA(ctx, repo)
	if head != sha || sha == baseHead {
		t.Fatalf("checkout HEAD %s, landed %s, base %s: want the checkout fast-forwarded to the landed commit", head, sha, baseHead)
	}
	if ok, _ := git.IsAncestor(ctx, repo, baseHead, sha); !ok {
		t.Fatal("landed commit does not descend from the base")
	}
	keepDir, keepBranch := r.keepWorktreeFor(&row)
	if _, err := os.Stat(keepDir); !os.IsNotExist(err) {
		t.Fatalf("keep worktree left behind: %v", err)
	}
	if out := gitOut(t, repo, "branch", "--list", keepBranch); strings.TrimSpace(out) != "" {
		t.Fatalf("keep branch %q left behind", keepBranch)
	}
}

// TestJudgeMergeCancelLeavesCheckoutUntouched (OSH-R-006): a request
// cancelled while the merge agent works (after it has already committed its
// merge) stops the agent and leaves the operator's checkout exactly where it
// was, clean, with no half-landed commit.
func TestJudgeMergeCancelLeavesCheckoutUntouched(t *testing.T) {
	repo := initArenaRepo(t)
	r := allowSkip(startTestRunner(t, repo)) // judge_merge runs only in the skip lane (audit F3)
	row := judgedCandidate(t, r, repo, "iso2")
	baseHead, _ := git.HeadSHA(context.Background(), repo)
	marker := filepath.Join(t.TempDir(), "committed")
	useJudge(t, fakeBin(t, t.TempDir(), "slow-judge", `
git merge --no-edit --no-ff arena/iso2/claude-code >/dev/null 2>&1 || true
echo half > half-done.txt
touch "`+marker+`"
sleep 30
`))
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for i := 0; i < 400; i++ {
			if _, err := os.Stat(marker); err == nil {
				cancel()
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
		cancel()
	}()
	if _, err := r.Keep(ctx, &row, repo, KeepJudgeMerge, JudgeSpec{Tool: "claude-code"}); err == nil {
		t.Fatal("a cancelled judge_merge keep reported success")
	}
	bg := context.Background()
	if head, _ := git.HeadSHA(bg, repo); head != baseHead {
		t.Fatalf("checkout HEAD moved from %s to %s after a cancelled keep", baseHead, head)
	}
	if dirty, _ := git.IsDirty(bg, repo); dirty {
		t.Fatal("a cancelled keep left the checkout dirty")
	}
	keepDir, _ := r.keepWorktreeFor(&row)
	if _, err := os.Stat(keepDir); !os.IsNotExist(err) {
		t.Fatalf("keep worktree left behind after a cancel: %v", err)
	}
	rows, _ := r.opts.Store.ArenaCandidates(bg, "iso2")
	if rows[0].Status == models.ArenaCandidateStatusKept {
		t.Fatal("a cancelled keep was recorded as kept")
	}
}

// TestJudgeMergeRefusesWhenCheckoutMoved (OSH-R-006): the operator committed
// while the judge worked; the verified merge is not landed over that commit.
func TestJudgeMergeRefusesWhenCheckoutMoved(t *testing.T) {
	repo := initArenaRepo(t)
	r := allowSkip(startTestRunner(t, repo)) // judge_merge runs only in the skip lane (audit F3)
	row := judgedCandidate(t, r, repo, "iso3")
	useJudge(t, fakeBin(t, t.TempDir(), "racing-judge", `
git -C "`+repo+`" -c user.name=op -c user.email=op@example.com commit -q --allow-empty -m "operator commit"
`+mergeBody("iso3")))
	ctx := context.Background()
	_, err := r.Keep(ctx, &row, repo, KeepJudgeMerge, JudgeSpec{Tool: "claude-code"})
	if err == nil || !strings.Contains(err.Error(), "moved") {
		t.Fatalf("Keep = %v, want a refusal because the branch moved", err)
	}
	msg, _ := git.CommitMessage(ctx, repo, "HEAD")
	if !strings.HasPrefix(msg, "operator commit") {
		t.Fatalf("checkout HEAD is %q, want the operator's own commit left in place", msg)
	}
}

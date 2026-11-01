package arena

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
)

func validRunSpec(id, repo string) RunSpec {
	return RunSpec{
		ID:          id,
		ProjectRoot: repo,
		Prompt:      "make a useful change",
		Candidates:  []CandidateSpec{{Tool: "claude-code"}},
		JudgeTool:   "claude-code",
	}
}

func TestStartRunRejectsUnsafeInputsBeforeMutation(t *testing.T) {
	repo := initArenaRepo(t)
	r := startTestRunner(t, repo)
	tests := []struct {
		name string
		edit func(*RunSpec)
		want string
	}{
		{name: "path traversal id", edit: func(s *RunSpec) { s.ID = "../escape" }, want: "ASCII letters"},
		{name: "separator id", edit: func(s *RunSpec) { s.ID = "run/slash" }, want: "ASCII letters"},
		{name: "duplicate tool", edit: func(s *RunSpec) { s.Candidates = append(s.Candidates, CandidateSpec{Tool: "claude-code"}) }, want: "duplicate"},
		{name: "missing judge", edit: func(s *RunSpec) { s.JudgeTool = "" }, want: "judge tool"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spec := validRunSpec("safe-"+strings.ReplaceAll(tc.name, " ", "-"), repo)
			tc.edit(&spec)
			if _, err := r.StartRun(context.Background(), spec); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("StartRun error = %v, want %q", err, tc.want)
			}
			if _, err := os.Stat(filepath.Join(r.opts.WorkspaceDir, spec.ID)); err == nil {
				t.Fatalf("invalid request created workspace for %q", spec.ID)
			}
		})
	}
}

func TestStartRunRejectsDetachedHead(t *testing.T) {
	repo := initArenaRepo(t)
	r := startTestRunner(t, repo)
	cmd := exec.Command("git", "-C", repo, "checkout", "--detach", "HEAD")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("detach: %v: %s", err, out)
	}
	if _, err := r.StartRun(context.Background(), validRunSpec("detached", repo)); err == nil || !strings.Contains(err.Error(), "detached HEAD") {
		t.Fatalf("detached StartRun = %v", err)
	}
}

func TestStartRunPreservesStaleBranchAndCleansPartialState(t *testing.T) {
	repo := initArenaRepo(t)
	r := startTestRunner(t, repo)
	ctx := context.Background()
	staleBranch := "arena/partial/codex"
	cmd := exec.Command("git", "-C", repo, "branch", staleBranch)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("seed stale branch: %v: %s", err, out)
	}
	spec := validRunSpec("partial", repo)
	spec.Candidates = []CandidateSpec{{Tool: "claude-code"}, {Tool: "codex"}}
	if _, err := r.StartRun(ctx, spec); err == nil || !strings.Contains(err.Error(), "branch already exists") {
		t.Fatalf("StartRun = %v, want stale-branch refusal", err)
	}
	if branchGone(t, repo, staleBranch) {
		t.Fatal("failed setup deleted a branch it did not create")
	}
	if !branchGone(t, repo, "arena/partial/claude-code") {
		t.Fatal("partial setup left its first candidate branch behind")
	}
	if _, err := os.Stat(filepath.Join(r.opts.WorkspaceDir, "partial", "claude-code")); !os.IsNotExist(err) {
		t.Fatalf("partial setup left its first worktree: %v", err)
	}
	run, err := r.opts.Store.ArenaRun(ctx, "partial")
	if err != nil || run == nil || run.Status != models.ArenaRunStatusFailed {
		t.Fatalf("partial run status = %+v err=%v", run, err)
	}
	rows, err := r.opts.Store.ArenaCandidates(ctx, "partial")
	if err != nil || len(rows) != 1 || rows[0].Status != models.ArenaCandidateStatusFailed {
		t.Fatalf("partial candidate rows = %+v err=%v", rows, err)
	}
	if err := r.DiscardCandidate(ctx, rows[0], repo); err != nil {
		t.Fatalf("discard cleaned partial candidate: %v", err)
	}
	rows, _ = r.opts.Store.ArenaCandidates(ctx, "partial")
	if len(rows) != 1 || rows[0].Status != models.ArenaCandidateStatusDiscarded {
		t.Fatalf("partial candidate did not converge to discarded: %+v", rows)
	}
}

func TestStartRunRequiresNewRunWorkspace(t *testing.T) {
	repo := initArenaRepo(t)
	r := startTestRunner(t, repo)
	runDir := filepath.Join(r.opts.WorkspaceDir, "preplanted")
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(runDir, "operator.txt")
	if err := os.WriteFile(marker, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.StartRun(context.Background(), validRunSpec("preplanted", repo)); err == nil || !strings.Contains(err.Error(), "must be new") {
		t.Fatalf("StartRun = %v", err)
	}
	if body, err := os.ReadFile(marker); err != nil || string(body) != "preserve" {
		t.Fatalf("pre-existing run directory was mutated: %q err=%v", body, err)
	}
}

func TestWritePatchFileReplacesSymlinkWithoutFollowingIt(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim.txt")
	patch := filepath.Join(dir, "candidate.patch")
	if err := os.WriteFile(victim, []byte("operator data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, patch); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := writePatchFile(patch, []byte("safe patch")); err != nil {
		t.Fatal(err)
	}
	if body, _ := os.ReadFile(victim); string(body) != "operator data" {
		t.Fatalf("patch write followed symlink and changed victim: %q", body)
	}
	info, err := os.Lstat(patch)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("patch artifact is not regular: %v %+v", err, info)
	}
}

func TestMarkRunFailedPreservesCompletedCandidate(t *testing.T) {
	repo := initArenaRepo(t)
	r := startTestRunner(t, repo)
	ctx := context.Background()
	spec := validRunSpec("markfailed", repo)
	spec.Candidates = []CandidateSpec{{Tool: "claude-code"}, {Tool: "codex"}}
	if _, err := r.StartRun(ctx, spec); err != nil {
		t.Fatal(err)
	}
	rows, _ := r.opts.Store.ArenaCandidates(ctx, spec.ID)
	rows[0].Status = models.ArenaCandidateStatusDone
	rows[1].Status = models.ArenaCandidateStatusRunning
	for i := range rows {
		if err := r.opts.Store.UpdateArenaCandidate(ctx, &rows[i]); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.MarkRunFailed(ctx, spec.ID, errors.New("database unavailable")); err != nil {
		t.Fatal(err)
	}
	got, _ := r.opts.Store.ArenaCandidates(ctx, spec.ID)
	if got[0].Status != models.ArenaCandidateStatusDone {
		t.Fatalf("completed candidate destroyed: %+v", got[0])
	}
	if got[1].Status != models.ArenaCandidateStatusFailed || !strings.Contains(got[1].Error, "database unavailable") {
		t.Fatalf("running candidate not finalized: %+v", got[1])
	}
	run, _ := r.opts.Store.ArenaRun(ctx, spec.ID)
	if run == nil || run.Status != models.ArenaRunStatusFailed {
		t.Fatalf("run not failed: %+v", run)
	}
}

func TestDriveCandidatesRejectsMissingRunBeforeDrive(t *testing.T) {
	repo := initArenaRepo(t)
	r := startTestRunner(t, repo)
	err := r.DriveCandidates(context.Background(), &PreparedRun{Spec: RunSpec{ID: "missing"}})
	if err == nil || !strings.Contains(err.Error(), "run not found") {
		t.Fatalf("DriveCandidates missing run = %v", err)
	}
}

func TestHasArenaProvenanceRequiresCanonicalFields(t *testing.T) {
	row := &models.ArenaCandidate{
		RunID: "run-1", Tool: "claude-code", Model: "sonnet",
		SessionIDs: []string{"session-1"}, InputTokens: 12, OutputTokens: 3, CostUSD: 0.004,
	}
	good := provenanceFooter(row, "usd")
	if !hasArenaProvenance(good, row, "usd") {
		t.Fatalf("canonical footer was rejected: %q", good)
	}
	for name, corrupted := range map[string]string{
		"wrong run":     strings.Replace(good, "Arena-Run:  run-1", "Arena-Run:  other", 1),
		"wrong harness": strings.Replace(good, "Harness:    claude-code (sonnet)", "Harness:    codex", 1),
		"wrong usage":   strings.Replace(good, "Usage:      12 input", "Usage:      99 input", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if hasArenaProvenance(corrupted, row, "usd") {
				t.Fatalf("accepted non-canonical footer: %q", corrupted)
			}
		})
	}
}

// TestProvenanceFollowsCostDisplay pins T-204: under the token-usage
// developer cost display the footer a kept commit carries into shared git
// history names the token counts and no dollar figure, and the verifier
// accepts exactly that footer.
func TestProvenanceFollowsCostDisplay(t *testing.T) {
	row := &models.ArenaCandidate{
		RunID: "run-1", Tool: "claude-code", Model: "sonnet",
		SessionIDs: []string{"session-1"}, InputTokens: 12, OutputTokens: 3, CostUSD: 0.004,
	}
	rows := []struct {
		mode      string
		wantUsage string
		dollar    bool
	}{
		{"usd", "Usage:      12 input / 3 output / $0.004000\n", true},
		{"tokens", "Usage:      12 input / 3 output\n", false},
	}
	for _, r := range rows {
		footer := provenanceFooter(row, r.mode)
		if !strings.Contains(footer, r.wantUsage) {
			t.Errorf("%s footer = %q, want usage line %q", r.mode, footer, r.wantUsage)
		}
		if strings.Contains(footer, "$") != r.dollar {
			t.Errorf("%s footer dollar presence = %v, want %v: %q", r.mode, !r.dollar, r.dollar, footer)
		}
		if !hasArenaProvenance(footer, row, r.mode) {
			t.Errorf("%s footer rejected by its own verifier", r.mode)
		}
		for _, prompt := range []string{provenanceMessage(row, r.mode), renderJudgeMergePrompt(row, r.mode)} {
			if strings.Contains(prompt, "$") != r.dollar {
				t.Errorf("%s message/prompt dollar presence wrong: %q", r.mode, prompt)
			}
		}
	}
}

func TestKeepRejectsWrongLifecycleStrategyAndBranch(t *testing.T) {
	repo := initArenaRepo(t)
	r := startTestRunner(t, repo)
	ctx := context.Background()
	prep, err := r.StartRun(ctx, validRunSpec("keepguards", repo))
	if err != nil {
		t.Fatal(err)
	}
	rows, _ := r.opts.Store.ArenaCandidates(ctx, prep.Spec.ID)
	if err := r.opts.Store.UpdateArenaRunStatus(ctx, prep.Spec.ID, models.ArenaRunStatusComplete); err != nil {
		t.Fatal(err)
	}
	forged := rows[0]
	forged.Status = models.ArenaCandidateStatusJudged
	forged.RunID = "some-other-run"
	forged.BranchName = "main"
	forged.WorktreePath = repo
	if _, err := r.Keep(ctx, &forged, repo, KeepSquash); err == nil || !strings.Contains(err.Error(), "not judged") {
		t.Fatalf("pending keep = %v", err)
	}
	if err := r.DriveCandidates(ctx, prep); err != nil {
		t.Fatal(err)
	}
	rows, _ = r.opts.Store.ArenaCandidates(ctx, prep.Spec.ID)
	rows[0].Status = models.ArenaCandidateStatusJudged
	if err := r.opts.Store.UpdateArenaCandidate(ctx, &rows[0]); err != nil {
		t.Fatal(err)
	}
	if err := r.opts.Store.UpdateArenaRunStatus(ctx, prep.Spec.ID, models.ArenaRunStatusComplete); err != nil {
		t.Fatal(err)
	}
	baseHead, _ := git.HeadSHA(ctx, repo)
	if _, err := r.Keep(ctx, &rows[0], repo, KeepStrategy("typo")); err == nil || !strings.Contains(err.Error(), "unknown strategy") {
		t.Fatalf("unknown strategy keep = %v", err)
	}
	afterUnknown, _ := git.HeadSHA(ctx, repo)
	if afterUnknown != baseHead {
		t.Fatal("unknown strategy changed HEAD")
	}
	cmd := exec.Command("git", "-C", repo, "checkout", "-b", "other")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("checkout other: %v: %s", err, out)
	}
	if _, err := r.Keep(ctx, &rows[0], repo, KeepSquash); err == nil || !strings.Contains(err.Error(), "does not match run base branch") {
		t.Fatalf("cross-branch keep = %v", err)
	}
}

func TestCandidateMutationsRejectActiveRun(t *testing.T) {
	repo := initArenaRepo(t)
	r := startTestRunner(t, repo)
	ctx := context.Background()
	prep, err := r.StartRun(ctx, validRunSpec("active-mutation", repo))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := r.opts.Store.ArenaCandidates(ctx, prep.Spec.ID)
	if err != nil || len(rows) != 1 {
		t.Fatalf("candidates = %+v err=%v", rows, err)
	}
	rows[0].Status = models.ArenaCandidateStatusJudged
	if err := r.opts.Store.UpdateArenaCandidate(ctx, &rows[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Keep(ctx, &rows[0], repo, KeepSquash); err == nil || !strings.Contains(err.Error(), "still active") {
		t.Fatalf("Keep during pending run = %v", err)
	}
	if err := r.DiscardCandidate(ctx, rows[0], repo); err == nil || !strings.Contains(err.Error(), "still active") {
		t.Fatalf("Discard during pending run = %v", err)
	}
	if _, err := os.Stat(rows[0].WorktreePath); err != nil {
		t.Fatalf("active-run rejection removed worktree: %v", err)
	}
}

func TestDiscardUsesCanonicalCandidateTargets(t *testing.T) {
	repo := initArenaRepo(t)
	r := startTestRunner(t, repo)
	ctx := context.Background()
	prep, err := r.StartRun(ctx, validRunSpec("discardcanonical", repo))
	if err != nil {
		t.Fatal(err)
	}
	rows, _ := r.opts.Store.ArenaCandidates(ctx, prep.Spec.ID)
	rows[0].Status = models.ArenaCandidateStatusFailed
	if err := r.opts.Store.UpdateArenaCandidate(ctx, &rows[0]); err != nil {
		t.Fatal(err)
	}
	if err := r.opts.Store.UpdateArenaRunStatus(ctx, prep.Spec.ID, models.ArenaRunStatusFailed); err != nil {
		t.Fatal(err)
	}
	actualWorktree, actualBranch := rows[0].WorktreePath, rows[0].BranchName
	forged := rows[0]
	forged.RunID = "other"
	forged.BranchName = "main"
	forged.WorktreePath = repo
	if err := r.DiscardCandidate(ctx, forged, repo); err != nil {
		t.Fatal(err)
	}
	branch, err := git.CurrentBranch(ctx, repo)
	if err != nil || branch != prep.BaseBranch {
		t.Fatalf("forged row selected the main branch: branch=%q err=%v", branch, err)
	}
	if _, err := os.Stat(actualWorktree); !os.IsNotExist(err) {
		t.Fatalf("canonical worktree was not removed: %v", err)
	}
	if !branchGone(t, repo, actualBranch) {
		t.Fatalf("canonical branch %q remains", actualBranch)
	}
}

func TestJudgeMergeRejectsUnrelatedCommitAndRollsBack(t *testing.T) {
	repo := initArenaRepo(t)
	r := allowSkip(startTestRunner(t, repo)) // judge_merge runs only in the skip lane (audit F3)
	ctx := context.Background()
	prep, err := r.StartRun(ctx, validRunSpec("ancestry", repo))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.DriveCandidates(ctx, prep); err != nil {
		t.Fatal(err)
	}
	rows, _ := r.opts.Store.ArenaCandidates(ctx, prep.Spec.ID)
	rows[0].Status = models.ArenaCandidateStatusJudged
	if err := r.opts.Store.UpdateArenaCandidate(ctx, &rows[0]); err != nil {
		t.Fatal(err)
	}
	if err := r.opts.Store.UpdateArenaRunStatus(ctx, prep.Spec.ID, models.ArenaRunStatusComplete); err != nil {
		t.Fatal(err)
	}
	baseHead, _ := git.HeadSHA(ctx, repo)
	judge := fakeBin(t, t.TempDir(), "unrelated-judge", `
echo unrelated > unrelated.txt
git add -A
git -c user.name=judge -c user.email=judge@example.com commit -q -m "unrelated judge commit"
cat <<'JSON'
{"type":"result","result":"done"}
JSON
`)
	prev := driveBinOverrides["claude-code"]
	driveBinOverrides["claude-code"] = judge
	defer func() { driveBinOverrides["claude-code"] = prev }()
	if _, err := r.Keep(ctx, &rows[0], repo, KeepJudgeMerge, JudgeSpec{Tool: "claude-code"}); err == nil || !strings.Contains(err.Error(), "without history-merging") {
		t.Fatalf("unrelated judge keep = %v", err)
	}
	after, _ := git.HeadSHA(ctx, repo)
	if after != baseHead {
		t.Fatalf("unrelated judge commit was not rolled back: %s -> %s", baseHead, after)
	}
	if _, err := os.Stat(filepath.Join(repo, "unrelated.txt")); !os.IsNotExist(err) {
		t.Fatalf("unrelated judge residue remains: %v", err)
	}
}

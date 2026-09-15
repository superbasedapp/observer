package arena

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// startTestRunner wires a Runner against a temp repo + temp workspace with
// a fake claude/codex binary pair. The claude fake doubles as the judge:
// its result payload is the rubric JSON, which is exactly how JudgeRun
// consumes it (FinalAnswer → parseJudgeScores).
func startTestRunner(t *testing.T, projectRoot string) *Runner {
	t.Helper()
	binDir := t.TempDir()
	// The result payload is the rubric JSON itself (escaped for embedding
	// inside the outer JSON string), so one fake serves candidate + judge.
	rubricDoc := `{"type":"result","result":"{\"correctness\":8,\"completeness\":7,\"code_quality\":9,\"performance\":6,\"risk\":3,\"overall\":8,\"verdict_rationale\":\"good enough\"}"}`
	claude := fakeBin(t, binDir, "claude-fake", "cat <<'JSON'\n"+rubricDoc+"\nJSON\necho edited > candidate.txt\n")
	codex := fakeBin(t, binDir, "codex-fake", `
prev=""
for a in "$@"; do
  if [ "$prev" = "-o" ]; then echo "codex done" > "$a"; fi
  prev="$a"
done
echo '{"type":"thread.started","thread_id":"thr-e2e"}'
echo edited > codework.txt
`)
	driveBinOverrides["claude-code"] = claude
	driveBinOverrides["codex"] = codex
	r, err := NewRunner(Options{
		Store:        arenaTestStore(t),
		WorkspaceDir: t.TempDir(),
		MaxParallel:  2,
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestStartRun_DirtyTreeRefused(t *testing.T) {
	repo := initArenaRepo(t)
	r := startTestRunner(t, repo)
	if err := os.WriteFile(filepath.Join(repo, "dirty.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec := RunSpec{
		ID: "run-dirty", ProjectRoot: repo, Prompt: "p",
		Candidates: []CandidateSpec{{Tool: "claude-code"}},
		JudgeTool:  "claude-code",
	}
	if _, err := r.StartRun(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "uncommitted") {
		t.Fatalf("want dirty-tree refusal, got %v", err)
	}
	if _, err := r.StartRunWithForce(context.Background(), spec); err != nil {
		t.Fatalf("force start should pass: %v", err)
	}
}

func TestEndToEnd_RunJudgeKeepSquash(t *testing.T) {
	repo := initArenaRepo(t)
	r := startTestRunner(t, repo)
	ctx := context.Background()
	var admissionMu sync.Mutex
	admissionCalls := map[string]int{}
	r.opts.Admission = func(_ context.Context, tool, _ string) error {
		admissionMu.Lock()
		defer admissionMu.Unlock()
		admissionCalls[tool]++
		return nil
	}

	prep, err := r.StartRun(ctx, RunSpec{
		ID:          "e2e1",
		ProjectRoot: repo,
		Prompt:      "make it better",
		Candidates:  []CandidateSpec{{Tool: "claude-code"}, {Tool: "codex"}},
		JudgeTool:   "claude-code",
		Timeout:     30 * time.Second,
	})
	if err != nil {
		t.Fatalf("StartRun: %v", err)
	}

	// Worktrees exist on disk and rows are pending.
	rows, _ := r.opts.Store.ArenaCandidates(ctx, "e2e1")
	if len(rows) != 2 || rows[0].Status != models.ArenaCandidateStatusPending {
		t.Fatalf("candidates not seeded: %+v", rows)
	}
	for _, row := range rows {
		if _, err := os.Stat(row.WorktreePath); err != nil {
			t.Fatalf("worktree missing for %s: %v", row.Tool, err)
		}
	}

	if err := r.DriveCandidates(ctx, prep); err != nil {
		t.Fatalf("DriveCandidates: %v", err)
	}
	if err := r.JudgeRun(ctx, prep); err != nil {
		t.Fatalf("JudgeRun: %v", err)
	}
	admissionMu.Lock()
	claudeAdmissions := admissionCalls["claude-code"]
	codexAdmissions := admissionCalls["codex"]
	admissionMu.Unlock()
	if claudeAdmissions != 3 || codexAdmissions != 1 {
		t.Fatalf("admission calls = %v, want one per two candidates and two judges", admissionCalls)
	}

	rows, _ = r.opts.Store.ArenaCandidates(ctx, "e2e1")
	for _, row := range rows {
		if row.Status != models.ArenaCandidateStatusJudged {
			t.Fatalf("%s status=%s (%s), want judged", row.Tool, row.Status, row.Error)
		}
		if row.Scores == nil || row.Scores.Overall != 8 {
			t.Fatalf("%s scores=%+v, want overall 8", row.Tool, row.Scores)
		}
		if row.DiffFiles < 1 {
			t.Fatalf("%s captured no diff", row.Tool)
		}
		if row.PatchPath == "" {
			t.Fatalf("%s patch not persisted", row.Tool)
		}
	}

	// Keep the first candidate via squash merge: its file lands in MAIN repo.
	winner := rows[0]
	sha, err := r.Keep(ctx, &winner, repo, KeepSquash)
	if err != nil {
		t.Fatalf("Keep: %v", err)
	}
	landed, err := os.ReadFile(filepath.Join(repo, "candidate.txt"))
	if err != nil || strings.TrimSpace(string(landed)) != "edited" {
		t.Fatalf("squash merge did not land candidate work: %v %q", err, landed)
	}
	if sha == "" {
		t.Fatal("no kept commit sha")
	}
	updated, _ := r.opts.Store.ArenaCandidates(ctx, "e2e1")
	if updated[0].Status != models.ArenaCandidateStatusKept || updated[0].KeptCommitSHA != sha {
		t.Fatalf("keep not stamped: %+v", updated[0])
	}
	// Keep prunes the winner's worktree + branch: the squash land already
	// contains everything (plan §2f).
	if _, err := os.Stat(winner.WorktreePath); !os.IsNotExist(err) {
		t.Fatalf("winner worktree still present after keep")
	}
	if !branchGone(t, repo, winner.BranchName) {
		t.Fatalf("winner branch still present after keep")
	}

	// Discard the loser: worktree + branch pruned.
	loser := updated[1]
	if err := r.DiscardCandidate(ctx, loser, repo); err != nil {
		t.Fatalf("DiscardCandidate: %v", err)
	}
	if _, err := os.Stat(loser.WorktreePath); !os.IsNotExist(err) {
		t.Fatalf("loser worktree still present")
	}
	if !branchGone(t, repo, loser.BranchName) {
		t.Fatalf("loser branch still present after discard")
	}
	final, _ := r.opts.Store.ArenaCandidates(ctx, "e2e1")
	if final[1].Status != models.ArenaCandidateStatusDiscarded {
		t.Fatalf("discard not stamped: %+v", final[1])
	}
}

func TestKeepSquashConflictAbortsCleanly(t *testing.T) {
	repo := initArenaRepo(t)
	r := startTestRunner(t, repo)
	ctx := context.Background()

	prep, err := r.StartRun(ctx, RunSpec{
		ID:          "conflict1",
		ProjectRoot: repo,
		Prompt:      "edit base",
		Candidates:  []CandidateSpec{{Tool: "claude-code"}},
		JudgeTool:   "claude-code",
	})
	if err != nil {
		t.Fatal(err)
	}
	if prep == nil || prep.BaseSHA == "" {
		t.Fatal("prep incomplete")
	}
	// Candidate edits base.txt; main repo edits base.txt too → conflict.
	rows, _ := r.opts.Store.ArenaCandidates(ctx, "conflict1")
	if err := os.WriteFile(filepath.Join(rows[0].WorktreePath, "base.txt"), []byte("candidate version\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "base.txt"), []byte("main version\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	run("add", "-A")
	run("commit", "-m", "main edit")

	if _, cerr := git.CommitAll(ctx, rows[0].WorktreePath, "candidate edit"); cerr != nil {
		t.Fatalf("commit candidate: %v", cerr)
	}
	rows[0].Status = models.ArenaCandidateStatusJudged
	if err := r.opts.Store.UpdateArenaCandidate(ctx, &rows[0]); err != nil {
		t.Fatal(err)
	}
	if err := r.opts.Store.UpdateArenaRunStatus(ctx, prep.Spec.ID, models.ArenaRunStatusComplete); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Keep(ctx, &rows[0], repo, KeepSquash); err == nil {
		t.Fatal("conflicting keep succeeded — must refuse")
	} else if !errors.Is(err, ErrMergeConflict) && !strings.Contains(err.Error(), "conflict") {
		t.Fatalf("unexpected keep error: %v", err)
	}
	// Main repo's own edit must survive untouched.
	got, _ := os.ReadFile(filepath.Join(repo, "base.txt"))
	if strings.TrimSpace(string(got)) != "main version" {
		t.Fatalf("main edit clobbered after abort: %q", got)
	}
}

// branchGone reports whether a branch no longer exists in the repo.
func branchGone(t *testing.T, repo, branch string) bool {
	t.Helper()
	cmd := exec.Command("git", "-C", repo, "rev-parse", "--verify", branch)
	return cmd.Run() != nil
}

// KeepJudgeMerge success: the judge harness (fake) performs the merge
// itself inside the main repo; the engine verifies a landed commit, stamps
// kept provenance, and prunes worktree + branch.
func TestKeepJudgeMerge_LandsAndStamps(t *testing.T) {
	repo := initArenaRepo(t)
	r := startTestRunner(t, repo)
	ctx := context.Background()

	prep, err := r.StartRun(ctx, RunSpec{
		ID:          "jm1",
		ProjectRoot: repo,
		Prompt:      "edit base",
		Candidates:  []CandidateSpec{{Tool: "claude-code"}},
		JudgeTool:   "claude-code",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.DriveCandidates(ctx, prep); err != nil {
		t.Fatal(err)
	}
	rows, _ := r.opts.Store.ArenaCandidates(ctx, "jm1")
	rows[0].Status = models.ArenaCandidateStatusJudged
	if err := r.opts.Store.UpdateArenaCandidate(ctx, &rows[0]); err != nil {
		t.Fatal(err)
	}
	if err := r.opts.Store.UpdateArenaRunStatus(ctx, prep.Spec.ID, models.ArenaRunStatusComplete); err != nil {
		t.Fatal(err)
	}
	baseHead, _ := git.HeadSHA(ctx, repo)
	// Drive phase used the rubric fake (which writes candidate.txt). Swap
	// in the merge judge ONLY for the keep phase so the landed commit has
	// real content.
	mergeJudge := fakeBin(t, t.TempDir(), "judge-merge-fake", `
cat <<'JSON'
{"type":"result","result":"{\"correctness\":9,\"completeness\":9,\"code_quality\":8,\"performance\":8,\"risk\":2,\"overall\":9,\"verdict_rationale\":\"merged\"}"}
JSON
git merge --no-edit --no-squash arena/jm1/claude-code >/dev/null 2>&1 || true
git add -A
git commit -q -m "judge merge

Generated-by: observer agent arena" || true
echo "merged sha $(git rev-parse HEAD)"
`)
	prev := driveBinOverrides["claude-code"]
	driveBinOverrides["claude-code"] = mergeJudge
	defer func() { driveBinOverrides["claude-code"] = prev }()
	sha, err := r.Keep(ctx, &rows[0], repo, KeepJudgeMerge, JudgeSpec{Tool: "claude-code"})
	if err != nil {
		t.Fatalf("Keep(judge_merge): %v", err)
	}
	if sha == "" || sha == baseHead {
		t.Fatalf("expected a new commit, got %q (base %q)", sha, baseHead)
	}
	msg, err := git.CommitMessage(ctx, repo, sha)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg, "Generated-by: observer agent arena") {
		t.Fatalf("provenance footer missing from judge commit: %q", msg)
	}
	for _, want := range []string{"Arena-Run:  jm1", "Usage:      0 input / 0 output / $0.000000"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("provenance footer missing %q: %q", want, msg)
		}
	}
	if dirty, _ := git.IsDirty(ctx, repo); dirty {
		t.Fatal("repo left dirty after judge merge")
	}
	updated, _ := r.opts.Store.ArenaCandidates(ctx, "jm1")
	if updated[0].Status != models.ArenaCandidateStatusKept || updated[0].KeptCommitSHA != sha {
		t.Fatalf("keep not stamped: %+v", updated[0])
	}
}

// KeepJudgeMerge failure: a judge that lands nothing returns an honest
// error and leaves the repository exactly as it was.
func TestKeepJudgeMerge_NoLandIsHonestError(t *testing.T) {
	repo := initArenaRepo(t)
	r := startTestRunner(t, repo)
	ctx := context.Background()
	flatJudge := fakeBin(t, t.TempDir(), "flat-judge", `cat <<'JSON'
{"type":"result","result":"{\"correctness\":1,\"completeness\":1,\"code_quality\":1,\"performance\":1,\"risk\":9,\"overall\":1,\"verdict_rationale\":\"refused\"}"}
JSON
exit 0
`)
	prev := driveBinOverrides["claude-code"]
	driveBinOverrides["claude-code"] = flatJudge
	defer func() { driveBinOverrides["claude-code"] = prev }()

	prep, err := r.StartRun(ctx, RunSpec{
		ID:          "jm2",
		ProjectRoot: repo,
		Prompt:      "edit base",
		Candidates:  []CandidateSpec{{Tool: "claude-code"}},
		JudgeTool:   "claude-code",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.DriveCandidates(ctx, prep); err != nil {
		t.Fatal(err)
	}
	rows, _ := r.opts.Store.ArenaCandidates(ctx, "jm2")
	rows[0].Status = models.ArenaCandidateStatusJudged
	if err := r.opts.Store.UpdateArenaCandidate(ctx, &rows[0]); err != nil {
		t.Fatal(err)
	}
	if err := r.opts.Store.UpdateArenaRunStatus(ctx, prep.Spec.ID, models.ArenaRunStatusComplete); err != nil {
		t.Fatal(err)
	}
	baseHead, _ := git.HeadSHA(ctx, repo)
	if _, err := r.Keep(ctx, &rows[0], repo, KeepJudgeMerge, JudgeSpec{Tool: "claude-code"}); err == nil {
		t.Fatal("expected an error when the judge lands no commit")
	}
	newHead, _ := git.HeadSHA(ctx, repo)
	if newHead != baseHead {
		t.Fatalf("HEAD moved without a successful land: %s -> %s", baseHead, newHead)
	}
	if dirty, _ := git.IsDirty(ctx, repo); dirty {
		t.Fatal("failed judge merge left the tree dirty")
	}
}

func TestKeepJudgeMerge_AdmissionFailureNeverStartsJudge(t *testing.T) {
	repo := initArenaRepo(t)
	r := startTestRunner(t, repo)
	r.opts.ProxyURL = "http://127.0.0.1:8820"
	marker := filepath.Join(t.TempDir(), "judge-started")
	judge := fakeBin(t, t.TempDir(), "blocked-judge", `
echo started > "`+marker+`"
`)
	prev := driveBinOverrides["claude-code"]
	driveBinOverrides["claude-code"] = judge
	defer func() { driveBinOverrides["claude-code"] = prev }()

	wantErr := errors.New("managed budget refused keep judge")
	admissionCalls := 0
	r.opts.Admission = func(ctx context.Context, tool, proxyURL string) error {
		admissionCalls++
		if ctx == nil || tool != "claude-code" || proxyURL != r.opts.ProxyURL {
			t.Fatalf("keep admission inputs: ctx=%v tool=%q proxy=%q", ctx, tool, proxyURL)
		}
		return wantErr
	}
	row := &models.ArenaCandidate{
		RunID:      "keep-admission",
		Tool:       "codex",
		BranchName: "arena/keep-admission/codex",
	}
	_, err := r.judgeMergeKeep(context.Background(), row, repo, JudgeSpec{Tool: "claude-code"})
	if !errors.Is(err, wantErr) || !strings.Contains(err.Error(), "judge drive failed before landing") {
		t.Fatalf("judgeMergeKeep error = %v, want wrapped admission refusal", err)
	}
	if admissionCalls != 1 {
		t.Fatalf("admission calls = %d, want 1", admissionCalls)
	}
	if _, statErr := os.Stat(marker); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("keep judge started before admission: %v", statErr)
	}
}

func TestNormalizeContextFiles(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "pkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"one.go", filepath.Join("pkg", "two.go")} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("package p\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(root, "dir"), 0o755); err != nil {
		t.Fatal(err)
	}
	linkMade := true
	if err := os.Symlink("one.go", filepath.Join(root, "linked.go")); err != nil {
		linkMade = false
		t.Logf("symlink case unavailable: %v", err)
	} else {
		t.Cleanup(func() { _ = os.Remove(filepath.Join(root, "linked.go")) })
	}

	tests := []struct {
		name    string
		paths   []string
		want    []string
		wantErr string
	}{
		{name: "empty", paths: nil},
		{name: "trim and dedupe", paths: []string{" one.go ", filepath.Join("pkg", "two.go"), "one.go", ""}, want: []string{"one.go", filepath.Join("pkg", "two.go")}},
		{name: "absolute rejected", paths: []string{filepath.Join(root, "one.go")}, wantErr: "project-relative"},
		{name: "escape rejected", paths: []string{filepath.Join("..", "outside.go")}, wantErr: "escapes the project"},
		{name: "missing rejected", paths: []string{"missing.go"}, wantErr: "no such file"},
		{name: "directory rejected", paths: []string{"dir"}, wantErr: "not a regular file"},
	}
	if linkMade {
		tests = append(tests, struct {
			name    string
			paths   []string
			want    []string
			wantErr string
		}{name: "symlink rejected", paths: []string{"linked.go"}, wantErr: "must not traverse symlinks"})
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeContextFiles(root, tc.paths)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v; want substring %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeContextFiles: %v", err)
			}
			if strings.Join(got, "\x00") != strings.Join(tc.want, "\x00") {
				t.Fatalf("got = %v; want %v", got, tc.want)
			}
		})
	}
}

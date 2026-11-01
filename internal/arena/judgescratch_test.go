package arena

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestJudgeRunsInAFreshScratchDirectory: a judge drive starts in the one
// stable scratch directory under the arena workspace (never the daemon's
// working directory, never a new /tmp directory), emptied before the drive
// even when an earlier one left something, the admission callback sees it
// as the launch target with no source repository, and it is empty again,
// but still there, once the judge returns.
func TestJudgeRunsInAFreshScratchDirectory(t *testing.T) {
	workspace := t.TempDir()
	stale := filepath.Join(workspace, judgeScratchName, "left-over.txt")
	if err := os.MkdirAll(filepath.Dir(stale), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stale, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	where := filepath.Join(t.TempDir(), "pwd.txt")
	rubric := `{"type":"result","result":"{\"correctness\":8,\"completeness\":7,\"code_quality\":9,\"performance\":6,\"risk\":3,\"overall\":8,\"verdict_rationale\":\"ok\"}"}`
	bin := fakeBin(t, t.TempDir(), "judge-scratch", `pwd -P > "`+where+`"; ls -A | wc -l >> "`+where+`"`+"\ncat <<'JSON'\n"+rubric+"\nJSON\n")
	old := driveBinOverrides["claude-code"]
	driveBinOverrides["claude-code"] = bin
	t.Cleanup(func() { driveBinOverrides["claude-code"] = old })
	ic, _ := integration.For("claude-code")

	var seen LaunchTarget
	var emptyAtAdmission bool
	scores, _, err := judgeInScratch(context.Background(), driveRequest{
		Tool: "claude-code", Prompt: "judge", SourceRoot: "/the/source", Timeout: 30 * time.Second,
		Admission: func(ctx context.Context, _, _ string) error {
			target, ok := LaunchTargetFrom(ctx)
			if !ok {
				t.Fatal("no launch target on the admission context")
			}
			seen = *target
			ents, err := os.ReadDir(target.Dir)
			emptyAtAdmission = err == nil && len(ents) == 0
			return nil
		},
	}, ic.Headless, workspace)
	if err != nil || scores == nil || scores.Overall != 8 {
		t.Fatalf("judge: %+v %v", scores, err)
	}
	wd, _ := os.Getwd()
	if seen.Dir == "" || seen.Dir == wd || seen.SourceRoot != "" || !emptyAtAdmission {
		t.Fatalf("launch target %+v (empty %v), want a fresh empty directory with no source", seen, emptyAtAdmission)
	}
	ran, err := os.ReadFile(where)
	if err != nil {
		t.Fatal(err)
	}
	parent, _ := filepath.EvalSymlinks(filepath.Dir(seen.Dir))
	real := filepath.Join(parent, filepath.Base(seen.Dir))
	if want := real + "\n0\n"; string(ran) != want {
		t.Fatalf("judge ran in %q, want %q", ran, want)
	}
	if seen.Dir != filepath.Join(workspace, judgeScratchName) {
		t.Fatalf("judge dir %q, want the stable %q", seen.Dir, filepath.Join(workspace, judgeScratchName))
	}
	if ents, err := os.ReadDir(seen.Dir); err != nil || len(ents) != 0 {
		t.Fatalf("scratch directory after the judge: %v %v, want it present and empty", ents, err)
	}
	if _, err := judgeScratchDir(""); err == nil {
		t.Fatal("a judge with no workspace root got a scratch directory")
	}
}

// TestJudgeRunUsesScratchDirectories: JudgeRun gives every judge drive its
// own scratch directory, never a candidate's worktree or the source.
func TestJudgeRunUsesScratchDirectories(t *testing.T) {
	repo := initArenaRepo(t)
	r := startTestRunner(t, repo)
	ctx := context.Background()
	var targets []LaunchTarget
	r.opts.Admission = func(ctx context.Context, _, _ string) error {
		if target, ok := LaunchTargetFrom(ctx); ok {
			targets = append(targets, *target)
		}
		return nil
	}
	prep, err := r.StartRun(ctx, RunSpec{
		ID: "judge-scratch", ProjectRoot: repo, Prompt: "p",
		Candidates: []CandidateSpec{{Tool: "claude-code"}},
		JudgeTool:  "claude-code",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.DriveCandidates(ctx, prep); err != nil {
		t.Fatal(err)
	}
	targets = nil
	if err := r.JudgeRun(ctx, prep); err != nil {
		t.Fatal(err)
	}
	rows, _ := r.opts.Store.ArenaCandidates(ctx, "judge-scratch")
	if len(rows) != 1 || rows[0].Status != models.ArenaCandidateStatusJudged {
		t.Fatalf("rows %+v", rows)
	}
	if len(targets) != 1 {
		t.Fatalf("judge admissions %+v, want one", targets)
	}
	j := targets[0]
	if j.Dir == "" || j.Dir == repo || j.Dir == rows[0].WorktreePath || j.SourceRoot != "" {
		t.Fatalf("judge target %+v", j)
	}
	if j.Dir != filepath.Join(r.opts.WorkspaceDir, judgeScratchName) {
		t.Fatalf("judge dir %q, want the stable scratch directory under %q", j.Dir, r.opts.WorkspaceDir)
	}
	if ents, err := os.ReadDir(j.Dir); err != nil || len(ents) != 0 {
		t.Fatalf("judge scratch directory after the run: %v %v, want it empty", ents, err)
	}
}

// TestJudgeScratchWaitHonoursContext: a judge drive waiting for the scratch
// directory another drive holds gives up when its context ends, and the
// directory is free again once the holder lets go.
func TestJudgeScratchWaitHonoursContext(t *testing.T) {
	if err := lockJudgeScratch(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _, err := judgeInScratch(ctx, driveRequest{Tool: "claude-code", Prompt: "judge", Timeout: time.Second}, nil, t.TempDir())
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiting judge: %v, want the context's deadline", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("the waiting judge did not give up with its context")
	}
	unlockJudgeScratch()
	if err := lockJudgeScratch(context.Background()); err != nil {
		t.Fatal(err)
	}
	unlockJudgeScratch()
}

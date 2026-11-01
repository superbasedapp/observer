package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/skillhistory"
)

// linkedWorktreeFixture builds a real repository with one commit and a
// linked worktree outside it (`git init` then `git checkout -b`, never `git
// init -b`, so it runs on git 2.25), returning both top levels with
// symlinks resolved.
func linkedWorktreeFixture(t *testing.T) (mainRoot, wtRoot string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	repo := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	run("init", "-q")
	run("checkout", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(repo, "README.md"), []byte("r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run("add", "-A")
	run("commit", "-q", "-m", "init")
	wt := filepath.Join(t.TempDir(), "wt")
	if err := git.WorktreeAdd(context.Background(), repo, wt, "roots/wt", "HEAD"); err != nil {
		t.Fatalf("WorktreeAdd: %v", err)
	}
	var err error
	if mainRoot, err = filepath.EvalSymlinks(repo); err != nil {
		t.Fatal(err)
	}
	if wtRoot, err = filepath.EvalSymlinks(wt); err != nil {
		t.Fatal(err)
	}
	return mainRoot, wtRoot
}

// TestCheckoutCallersUseWorktreeRoot: the callers that read a checkout's
// files resolve a linked worktree to the worktree, not its main checkout
// (F0-14), while the project root stays the main checkout.
func TestCheckoutCallersUseWorktreeRoot(t *testing.T) {
	mainRoot, wtRoot := linkedWorktreeFixture(t)
	sub := filepath.Join(wtRoot, "pkg")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if r, ok := git.FindRoot(sub); !ok || r != mainRoot {
		t.Fatalf("FindRoot = %q %v, want the main checkout %q", r, ok, mainRoot)
	}
	if got := resolveProjectRoot(sub); got != wtRoot {
		t.Errorf("codeintel resolveProjectRoot = %q, want %q", got, wtRoot)
	}
	if got := launchHookSwitchDirs(sub); !slices.Equal(got, []string{sub, wtRoot}) {
		t.Errorf("launchHookSwitchDirs = %v, want [%s %s]", got, sub, wtRoot)
	}
}

// TestSkillSnapshotReadsWorktreeRecordsProject: a session in a linked
// worktree snapshots the worktree's own project skills and records them
// under the main project (F0-14).
func TestSkillSnapshotReadsWorktreeRecordsProject(t *testing.T) {
	mainRoot, wtRoot := linkedWorktreeFixture(t)
	writeSkillFile(t, filepath.Join(wtRoot, ".claude", "skills", "wtonly", "SKILL.md"), "---\nname: wtonly\n---\nx\n")
	env := productionSkillSnapEnv()
	home := t.TempDir()
	env.UserHome = func() (string, error) { return home, nil }
	snap, ok := buildSkillSnapshot(context.Background(), env, skillSnapRequest{
		SessionID: "s1", Event: skillhistory.EventSessionStart, Source: "startup", Cwd: wtRoot,
		TranscriptPath: filepath.Join(home, ".claude", "projects", "x", "s1.jsonl"),
	})
	if !ok {
		t.Fatal("no snapshot")
	}
	if snap.ProjectRoot != mainRoot {
		t.Errorf("snapshot ProjectRoot = %q, want the main project %q", snap.ProjectRoot, mainRoot)
	}
	if memberBy(snap.Members, ".claude/skills/wtonly/SKILL.md") == nil {
		t.Errorf("worktree skill not read: members %+v", snap.Members)
	}
}

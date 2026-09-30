package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/commitscan"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guidance"
	"github.com/marmutapp/superbased-observer/internal/intelligence/dashboard"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestSkillScanRealRepository drives the whole skills-history capture
// against a REAL repository through the production wiring: the commit
// scanner (newCommitScanner, the one gitview envelope) scans, its
// AfterScan runs the skills step (reflog, ls-tree, status porcelain), and
// the shared composition resolves it. It proves the argv shapes against a
// real binary: the reflog selector/format, ls-tree paths relative to the
// project root, and status paths for an untracked skill.
func TestSkillScanRealRepository(t *testing.T) {
	gitAvailableForBackfill(t)
	ctx := context.Background()
	repo := t.TempDir()
	// Each commit gets its own second: the reflog records the committer
	// date, and moves sharing one second are (correctly) reported as
	// uncertain rather than picked.
	date := "2026-09-01T10:00:00Z"
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_DATE="+date, "GIT_COMMITTER_DATE="+date)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v: %v: %s", args, err, out)
		}
	}
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(repo, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run("init")
	run("symbolic-ref", "HEAD", "refs/heads/main")
	run("config", "user.email", "t@example.com")
	run("config", "user.name", "t")
	write(".claude/skills/deploy/SKILL.md", "---\nname: deploy\n---\nv1\n")
	run("add", "-A")
	run("commit", "-m", "add deploy skill")
	date = "2026-09-01T10:05:00Z"
	write(".claude/skills/deploy/SKILL.md", "---\nname: deploy\n---\nv2\n")
	write(".claude/skills/deploy/run.sh", "echo hi\n")
	run("add", "-A")
	run("commit", "-m", "tighten deploy")
	write(".claude/skills/draft/SKILL.md", "---\nname: draft\n---\nwip\n") // untracked

	st, _ := openTestStore(t)
	start := time.Now().UTC().Add(-time.Minute)
	if _, err := st.Ingest(ctx, []models.ToolEvent{{
		SessionID: "s1", ProjectRoot: repo, Tool: models.ToolClaudeCode, ActionType: models.ActionReadFile,
		Target: "a", SourceFile: "/t.jsonl", SourceEventID: "e1", Timestamp: start, Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	projectID, err := st.ProjectIDForRoot(ctx, repo)
	if err != nil || projectID == 0 {
		t.Fatalf("project: %d %v", projectID, err)
	}
	if _, err := st.UpsertGuidanceScan(ctx, repo, []guidance.File{
		{Tool: "claude-code", Kind: guidance.KindSkill, Scope: guidance.ScopeProject, RelPath: ".claude/skills/deploy/SKILL.md", AbsPath: repo + "/.claude/skills/deploy/SKILL.md", Name: "deploy", ContentHash: "x"},
		{Tool: "claude-code", Kind: guidance.KindSkill, Scope: guidance.ScopeProject, RelPath: ".claude/skills/draft/SKILL.md", AbsPath: repo + "/.claude/skills/draft/SKILL.md", Name: "draft", ContentHash: "y"},
	}, start); err != nil {
		t.Fatal(err)
	}

	cfg := config.ProjectsConfig{CommitScan: true, CommitScanIntervalSeconds: 120, CommitLinkWindowDays: 14, ActiveProjectDays: 30, SkillHistory: true}
	sc := newCommitScanner(st, cfg, nil)
	root := commitscan.Root{ProjectID: projectID, RootPath: repo}
	res, err := sc.ScanOnce(ctx, root)
	if err != nil {
		t.Fatalf("ScanOnce: %v", err)
	}
	newSkillScanAfterScan(st, cfg, nil)(ctx, root, res)

	got, err := dashboard.ComposeProjectSkills(ctx, st, dashboard.ProjectSkillsInput{
		ProjectID: projectID, Days: 30, Since: time.Now().UTC().Add(-30 * 24 * time.Hour), Until: time.Now().UTC().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Capture.Git.State != "ok" {
		t.Fatalf("git state = %+v", got.Capture.Git)
	}
	var deployOK, draftOK bool
	for _, s := range got.Skills {
		switch s.Name {
		case "deploy":
			if s.Current.InGit != "committed" || len(s.Versions) != 2 || len(s.Commits) != 2 ||
				s.Commits[0].Status != "A" || s.Commits[1].Status != "M" || s.Current.HeadVersion == "" {
				t.Errorf("deploy = %+v", s)
			} else {
				deployOK = true
			}
		case "draft":
			if s.Current.InGit != "not_committed" || s.Current.Worktree != "untracked" {
				t.Errorf("draft = %+v", s.Current)
			} else {
				draftOK = true
			}
		}
	}
	if !deployOK || !draftOK {
		t.Fatalf("skills = %+v", got.Skills)
	}
	if len(got.Spans) == 0 || got.Spans[0].Head.State != "committed" {
		t.Errorf("spans = %+v, want the session's HEAD resolved from the reflog", got.Spans)
	}
}

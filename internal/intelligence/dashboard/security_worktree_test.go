//go:build !sbo_omit_security

package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// dashWorktree builds a real repository with one commit and a linked
// worktree outside it, returning both top levels with symlinks resolved.
func dashWorktree(t *testing.T) (mainRoot, wtRoot string) {
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
	if err := git.WorktreeAdd(context.Background(), repo, wt, "dash/wt", "HEAD"); err != nil {
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

// TestSecurityEditorRoute_LinkedWorktree: in a linked worktree the feed
// lists the project's findings (kept under the main checkout's root, F0-14)
// and the ones a scan in the worktree itself recorded under its checkout.
func TestSecurityEditorRoute_LinkedWorktree(t *testing.T) {
	mainRoot, wtRoot := dashWorktree(t)
	s, _ := newTestServer(t)
	ctx := context.Background()
	st := store.New(s.db())
	for key, c := range map[string]struct{ root, rel string }{
		"main": {mainRoot, "a.go"}, "checkout": {wtRoot, "b.go"},
	} {
		if _, _, err := st.UpsertSecFinding(ctx, secfinding.Normalize(secfinding.Finding{
			LocalKey: key, Rule: secfinding.Rule{ID: "S-721"}, Category: policy.FindingSecret,
			Severity: policy.FindingSeverityHigh, Confidence: policy.FindingConfidenceHigh, Baseline: policy.FindingBaselineNew,
			Project: secfinding.Project{RootHash: secposture.ProjectRootHash(c.root)}, Location: secfinding.Location{RelPath: c.rel, StartLine: 1},
			Message: "S-721: a secret", Status: policy.FindingStatusOpen,
		}), time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	read := func(dir string) map[string]bool {
		t.Helper()
		w := httptest.NewRecorder()
		s.handleSecurityEditor(w, httptest.NewRequest(http.MethodGet, "/api/security/editor?root="+dir, nil))
		var resp struct {
			ProjectRoot string                    `json:"project_root"`
			Findings    []securityEditorFindingJS `json:"findings"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || w.Code != http.StatusOK {
			t.Fatalf("%d %s %v", w.Code, w.Body, err)
		}
		if resp.ProjectRoot != mainRoot {
			t.Errorf("project_root = %q, want the main checkout %q", resp.ProjectRoot, mainRoot)
		}
		got := map[string]bool{}
		for _, f := range resp.Findings {
			got[f.RelPath] = true
		}
		return got
	}
	if got := read(wtRoot); len(got) != 2 || !got["a.go"] || !got["b.go"] {
		t.Errorf("worktree feed = %v, want a.go and b.go", got)
	}
	if got := read(mainRoot); len(got) != 1 || !got["a.go"] {
		t.Errorf("main feed = %v, want only a.go", got)
	}
}

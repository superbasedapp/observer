package secmcp

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
)

// TestFindingsReaderLinkedWorktree (lane shr-worktree2, PT-39): in a
// linked worktree (here a relative-path one, hand-made) the tool answers
// with the main project's findings plus those a scan kept under the
// worktree's checkout; the main checkout answers with its own; a
// project_dir naming the other checkout is the same project; another
// project is refused.
func TestFindingsReaderLinkedWorktree(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	w := func(p, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mainRoot, wt, other := filepath.Join(base, "main"), filepath.Join(base, "wt"), filepath.Join(base, "other")
	admin := filepath.Join(mainRoot, ".git", "worktrees", "wt")
	w(filepath.Join(mainRoot, ".git", "HEAD"), "ref: refs/heads/main\n")
	w(filepath.Join(admin, "HEAD"), "ref: refs/heads/wt\n")
	w(filepath.Join(admin, "commondir"), "../..\n")
	w(filepath.Join(admin, "gitdir"), "../../../../wt/.git\n")
	w(filepath.Join(wt, ".git"), "gitdir: ../main/.git/worktrees/wt\n")
	w(filepath.Join(wt, "pkg", "a.go"), "package pkg\n")
	w(filepath.Join(other, ".git", "HEAD"), "ref: refs/heads/main\n")

	byRoot := map[string][]secfinding.Finding{
		mainRoot: {{ID: "f-main"}},
		wt:       {{ID: "f-wt"}, {ID: "f-main"}},
		other:    {{ID: "f-other"}},
	}
	var asked []string
	list := func(_ context.Context, root string) ([]secfinding.Finding, error) {
		asked = append(asked, root)
		return append([]secfinding.Finding(nil), byRoot[root]...), nil
	}
	read := NewFindingsReader(git.FindRoot, git.FindCheckoutRoot, list)
	ids := func(fs []secfinding.Finding) []string {
		var out []string
		for _, f := range fs {
			out = append(out, f.ID)
		}
		return out
	}

	root, fs, err := read(context.Background(), filepath.Join(wt, "pkg"))
	if err != nil || root != mainRoot {
		t.Fatalf("worktree root = %q, %v; want the main project %q", root, err, mainRoot)
	}
	if got := ids(fs); len(got) != 2 || got[0] != "f-main" || got[1] != "f-wt" {
		t.Errorf("worktree findings = %v, want [f-main f-wt]", got)
	}
	asked = nil
	root, fs, _ = read(context.Background(), mainRoot)
	if root != mainRoot || len(fs) != 1 || len(asked) != 1 {
		t.Errorf("main checkout = %q %v (asked %v)", root, ids(fs), asked)
	}
	plain := t.TempDir()
	if root, _, _ := read(context.Background(), plain+string(filepath.Separator)+"."); root != filepath.Clean(plain) {
		t.Errorf("non-git root = %q", root)
	}

	tool := &findingsTool{d: Deps{WorkDir: wt, Findings: read}}
	if _, err := tool.Invoke(context.Background(), json.RawMessage(`{"project_dir":`+quote(mainRoot)+`}`)); err != nil {
		t.Errorf("the main checkout from a worktree: %v", err)
	}
	if _, err := tool.Invoke(context.Background(), json.RawMessage(`{"project_dir":`+quote(other)+`}`)); !errors.Is(err, ErrOtherProject) {
		t.Errorf("another project = %v, want ErrOtherProject", err)
	}
	out, err := tool.Invoke(context.Background(), nil)
	if err != nil || out.(FindingsOut).Open != 2 {
		t.Errorf("answer = %+v, %v", out, err)
	}
}

func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

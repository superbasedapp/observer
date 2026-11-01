package cline

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestTargets_LinkedWorktree: a file touched in the main checkout, an
// in-tree and an out-of-tree linked worktree stores one path, through the
// tool_use block path and the XML tool path alike.
func TestTargets_LinkedWorktree(t *testing.T) {
	mainRoot, inTree, outOfTree := handWorktree(t)
	a := New()
	for _, dir := range []string{mainRoot, inTree, outOfTree} {
		p := filepath.Join(dir, "pkg", "a.go")
		if got := a.extractTarget("write_to_file", json.RawMessage(`{"path":`+jsonPath(p)+`}`), mainRoot); got != "pkg/a.go" {
			t.Errorf("extractTarget(%s) = %q, want pkg/a.go", dir, got)
		}
		calls, _ := scanXMLTools("<read_file>\n<path>" + p + "</path>\n</read_file>")
		if len(calls) != 1 {
			t.Fatalf("calls = %d", len(calls))
		}
		evt := a.xmlToolEvent("/x/tasks/t1/api_conversation_history.json", models.ToolCline, "t1", mainRoot, "", "", "m", time.Unix(0, 0), 0, 0, calls[0])
		if evt.Target != "pkg/a.go" {
			t.Errorf("xmlToolEvent(%s).Target = %q, want pkg/a.go", dir, evt.Target)
		}
	}
}

// handWorktree lays out a main checkout with an in-tree and an out-of-tree
// linked worktree in git's own layout (hand-made, no git binary), for the
// checkout path seam tests (lane shr-worktree2, PT-39).
func handWorktree(t *testing.T) (mainRoot, inTree, outOfTree string) {
	t.Helper()
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
	mainRoot = filepath.Join(base, "main")
	inTree = filepath.Join(mainRoot, ".worktrees", "x")
	outOfTree = filepath.Join(base, "wt")
	w(filepath.Join(mainRoot, ".git", "HEAD"), "ref: refs/heads/main\n")
	for name, dir := range map[string]string{"x": inTree, "wt": outOfTree} {
		admin := filepath.Join(mainRoot, ".git", "worktrees", name)
		w(filepath.Join(admin, "HEAD"), "ref: refs/heads/"+name+"\n")
		w(filepath.Join(admin, "commondir"), "../..\n")
		w(filepath.Join(admin, "gitdir"), filepath.Join(dir, ".git")+"\n")
		w(filepath.Join(dir, ".git"), "gitdir: "+filepath.ToSlash(admin)+"\n")
	}
	for _, d := range []string{mainRoot, inTree, outOfTree} {
		w(filepath.Join(d, "pkg", "a.go"), "package pkg\n")
	}
	return mainRoot, inTree, outOfTree
}

// jsonPath quotes p as a JSON string.
func jsonPath(p string) string {
	b, _ := json.Marshal(p)
	return string(b)
}

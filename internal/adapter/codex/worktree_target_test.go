package codex

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestTargets_LinkedWorktree: a file touched in the main checkout, an
// in-tree and an out-of-tree linked worktree stores one path through every
// codex target site: tool arguments, a patch_apply_end change set, an
// apply_patch call's patch text and a view_image event.
func TestTargets_LinkedWorktree(t *testing.T) {
	mainRoot, inTree, outOfTree := handWorktree(t)
	a := New()
	for _, dir := range []string{mainRoot, inTree, outOfTree} {
		p := filepath.Join(dir, "pkg", "a.go")
		if got := a.extractTarget("file_read", json.RawMessage(`{"path":`+jsonPath(p)+`}`), mainRoot); got != "pkg/a.go" {
			t.Errorf("extractTarget(%s) = %q", dir, got)
		}
		if got := patchApplyTargetFromChanges(map[string]patchApplyChange{p: {Type: "update"}}, mainRoot); got != "pkg/a.go" {
			t.Errorf("patchApplyTargetFromChanges(%s) = %q", dir, got)
		}
		rc := responseItemCustomToolCall{CallID: "c1", Name: "apply_patch", Input: "*** Begin Patch\n*** Update File: " + p + "\n@@\n+x\n*** End Patch\n"}
		evt, _ := a.buildCustomToolCallEvent("/r.jsonl", "c1", sessionContext{}, mainRoot, time.Unix(0, 0), rc, "")
		if evt.Target != "pkg/a.go" {
			t.Errorf("buildCustomToolCallEvent(%s).Target = %q", dir, evt.Target)
		}
	}

	// view_image: the rollout's cwd is the main checkout, the image sits in
	// the out-of-tree worktree.
	img := filepath.Join(outOfTree, "pkg", "a.go")
	lines := []string{
		`{"timestamp":"2026-10-22T00:00:00.000Z","type":"session_meta","payload":{"id":"wt-001","timestamp":"2026-10-22T00:00:00.000Z","cwd":` + jsonPath(mainRoot) + `,"originator":"codex_cli_rs","cli_version":"0.122.0"}}`,
		`{"timestamp":"2026-10-22T00:00:01.000Z","type":"turn_context","payload":{"turn_id":"turn-A","model":"gpt-5-codex","cwd":` + jsonPath(mainRoot) + `}}`,
		`{"timestamp":"2026-10-22T00:00:02.000Z","type":"event_msg","payload":{"type":"view_image_tool_call","call_id":"call_view","turn_id":"turn-A","path":` + jsonPath(img) + `}}`,
	}
	path := filepath.Join(t.TempDir(), "rollout-2026-10-22T00-00-00-wt-001.jsonl")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, ev := range res.ToolEvents {
		if ev.RawToolName == "view_image_tool_call" {
			found = true
			if ev.Target != "pkg/a.go" {
				t.Errorf("view_image Target = %q, want pkg/a.go", ev.Target)
			}
		}
	}
	if !found {
		t.Fatalf("no view_image row in %+v", res.ToolEvents)
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

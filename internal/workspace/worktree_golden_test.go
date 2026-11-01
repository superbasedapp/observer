package workspace

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var updateWorktreeBox = flag.Bool("update-worktree-box", false, "rewrite testdata/worktree_box.golden")

// TestPlanWorktreeBoxGolden (lane LEFT-SBX milestone 2): the bwrap route of
// the worktree source is pinned byte for byte, so a later change to the
// worktree source (the oci route, a run-private object directory) cannot
// change what the bwrap box binds without changing this golden on purpose.
func TestPlanWorktreeBoxGolden(t *testing.T) {
	box, err := PlanWorktreeBox(WorktreeLayout{
		WorkspaceDir: "/home/dev/.observer/workspaces/run1/repo",
		CommonDir:    "/home/dev/src/repo/.git",
		AdminDir:     "/home/dev/src/repo/.git/worktrees/repo",
		Branch:       WorktreeBranchPrefix + "/run1/main",
		OtherAdmins:  []string{"/home/dev/src/repo/.git/worktrees/repo", "/home/dev/src/repo/.git/worktrees/side"},
		RefDirExists: true, LogDirExists: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, p := range box.ReadOnly {
		b.WriteString("ro " + filepath.ToSlash(p) + "\n")
	}
	for _, p := range box.ReadWrite {
		b.WriteString("rw " + filepath.ToSlash(p) + "\n")
	}
	for _, p := range box.Protect {
		kind := "file"
		if p.Dir {
			kind = "dir"
		}
		b.WriteString("protect " + kind + " " + filepath.ToSlash(p.Path) + "\n")
	}
	golden := filepath.Join("testdata", "worktree_box.golden")
	if *updateWorktreeBox {
		if err := os.WriteFile(golden, []byte(b.String()), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden) //nolint:gosec // G304: the test's own golden
	if err != nil {
		t.Fatal(err)
	}
	if b.String() != string(want) {
		t.Fatalf("the worktree box plan changed:\n%s\nwant:\n%s", b.String(), want)
	}
}

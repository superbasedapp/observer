//go:build !sbo_omit_codeintel

package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/platform/xcodehost"
)

// Audit row 8 (FU-193): the stored "Xcode (project unknown)" project root
// is not a directory. A working directory that holds a git repository of
// that name is planted, so a consumer that resolved the root against the
// working directory would find it.

func nonPathRootCwd(t *testing.T) string {
	t.Helper()
	cwd := t.TempDir()
	if err := os.MkdirAll(filepath.Join(cwd, xcodehost.ProjectUnknown, ".git", "worktrees"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(cwd)
	return cwd
}

// TestCodeIntelStartSkipsANonPathRoot: index-on-start never lists a root
// that is not rooted on this host.
func TestCodeIntelStartSkipsANonPathRoot(t *testing.T) {
	nonPathRootCwd(t)
	got := codeIntelStartProjects([]string{"/repo/a"}, []string{xcodehost.ProjectUnknown, "/repo/a", "/repo/b", "[cursor]"})
	if !slices.Equal(got, []string{"/repo/a", "/repo/b"}) {
		t.Errorf("codeIntelStartProjects = %q", got)
	}
}

// TestWorktreeRootsBackfillSkipsANonPathRoot: the worktree-roots backfill
// never resolves a non-path root through git.
func TestWorktreeRootsBackfillSkipsANonPathRoot(t *testing.T) {
	nonPathRootCwd(t)
	if target, ok, reason, gone := worktreeRootTarget(xcodehost.ProjectUnknown); ok || target != "" || reason != "" || gone {
		t.Errorf("worktreeRootTarget = %q, %v, %q; want a silent skip", target, ok, reason)
	}
}

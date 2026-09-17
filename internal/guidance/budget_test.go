package guidance

import (
	"context"
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
)

// -----------------------------------------------------------------------------
// Walker cost: the per-root time budget, and the directories that are
// never descended into at all.
// -----------------------------------------------------------------------------

// dirCountFS wraps an FS and cancels the scan once ReadDir has been
// called cancelAfter times. It stands in for a deadline firing mid-walk
// WITHOUT a real clock: a timing-based test of "the budget fired inside
// a deep walk" is a flake, while "the ctx was done by the 3rd ReadDir"
// is the same code path, deterministically.
type dirCountFS struct {
	FS
	reads       int
	cancelAfter int
	cancel      context.CancelFunc
}

func (c *dirCountFS) ReadDir(p string) ([]fs.DirEntry, error) {
	c.reads++
	if c.cancelAfter > 0 && c.reads >= c.cancelAfter {
		c.cancel()
	}
	return c.FS.ReadDir(p)
}

// deepTree builds a chain of nested directories, each carrying a
// CLAUDE.md, mounted at root. It is the shape "**/CLAUDE.md" walks: the
// recursion the budget has to be able to interrupt.
func deepTree(root string, depth, fanout int) *memFS {
	m := newMemFS()
	mapfs := fstest.MapFS{"CLAUDE.md": &fstest.MapFile{Data: []byte("root\n"), Mode: 0o644}}
	var add func(prefix string, level int)
	add = func(prefix string, level int) {
		if level > depth {
			return
		}
		for i := 0; i < fanout; i++ {
			dir := fmt.Sprintf("%sd%d_%d/", prefix, level, i)
			mapfs[dir+"CLAUDE.md"] = &fstest.MapFile{Data: []byte("nested\n"), Mode: 0o644}
			add(dir, level+1)
		}
	}
	add("", 0)
	m.mounts[normalizeRoot(root)] = mapfs
	return m
}

// TestScanBudgetCutsDeepWalkAndReportsIncomplete is the pin behind the
// per-root time budget: a deadline that fires INSIDE a "**" walk has to
// stop the walk, not merely be noticed after the rule finishes. It also
// pins the honesty half — a cut walk comes back Incomplete, which is
// what stops the caller persisting a partial inventory over rows whose
// files are all still there.
func TestScanBudgetCutsDeepWalkAndReportsIncomplete(t *testing.T) {
	t.Parallel()
	const root = "/deep/repo"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tree := deepTree(root, 5, 3)
	fsys := &dirCountFS{FS: tree, cancelAfter: 3, cancel: cancel}

	opts := Options{MaxFileBytes: 1 << 20, MaxDepth: 8}
	res, err := Scan(ctx, root, fsys, opts)
	if err == nil {
		t.Fatal("a cut walk must report the ctx error, not a clean success")
	}
	if !res.Incomplete {
		t.Error("Result.Incomplete = false — a partial walk that does not say so would be persisted and tombstone real rows")
	}
	// The whole point of checking inside the walk: it stopped early.
	full, ferr := Scan(context.Background(), root, deepTree(root, 5, 3), opts)
	if ferr != nil {
		t.Fatalf("uncancelled scan: %v", ferr)
	}
	if full.Incomplete {
		t.Error("an uncancelled scan must not be Incomplete")
	}
	if len(res.Files) >= len(full.Files) {
		t.Errorf("cut walk found %d files, uncancelled found %d — the deadline did not bound the walk",
			len(res.Files), len(full.Files))
	}
	if fsys.reads > 16 {
		t.Errorf("%d ReadDir calls after cancellation — the walk kept descending", fsys.reads)
	}
}

// TestScanDepthCapDoesNotReadTooDeepDirectories pins that the depth cap
// bounds the ReadDir COUNT, not just the result set: a directory past
// MaxDepth is skipped without being listed at all. Reading it and then
// discarding the result is the expensive half on a slow mount.
func TestScanDepthCapDoesNotReadTooDeepDirectories(t *testing.T) {
	t.Parallel()
	const root = "/deep/repo"
	shallow := &dirCountFS{FS: deepTree(root, 6, 2)}
	deep := &dirCountFS{FS: deepTree(root, 6, 2)}
	if _, err := Scan(context.Background(), root, shallow, Options{MaxFileBytes: 1 << 20, MaxDepth: 1}); err != nil {
		t.Fatalf("shallow scan: %v", err)
	}
	if _, err := Scan(context.Background(), root, deep, Options{MaxFileBytes: 1 << 20, MaxDepth: 4}); err != nil {
		t.Fatalf("deep scan: %v", err)
	}
	if shallow.reads >= deep.reads {
		t.Errorf("MaxDepth=1 issued %d ReadDir calls, MaxDepth=4 issued %d — the cap is not bounding directory reads",
			shallow.reads, deep.reads)
	}
}

// TestScanSkipsClaudeWorktrees pins the ".claude/worktrees" row of the
// nested skip table. A Claude Code worktree is another checkout of the
// SAME repo living inside it, so descending costs a second whole-repo
// walk and yields a stale duplicate of the CLAUDE.md already recorded at
// the root — which is exactly what the live scan reported.
func TestScanSkipsClaudeWorktrees(t *testing.T) {
	t.Parallel()
	const root = "/repo/demo"
	m := newMemFS()
	m.mounts[root] = fstest.MapFS{
		"CLAUDE.md": &fstest.MapFile{Data: []byte("the real one\n"), Mode: 0o644},
		".claude/worktrees/feature-x/CLAUDE.md": &fstest.MapFile{
			Data: []byte("a stale copy\n"), Mode: 0o644,
		},
		".claude/skills/demo/SKILL.md": &fstest.MapFile{
			Data: []byte("---\nname: demo\n---\nbody\n"), Mode: 0o644,
		},
	}
	res, err := Scan(context.Background(), root, m, Options{MaxFileBytes: 1 << 20, MaxDepth: 6})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	var sawRoot, sawSkill bool
	for _, f := range res.Files {
		if strings.Contains(f.RelPath, "worktrees") {
			t.Errorf("worktree copy was inventoried: %s (%s)", f.RelPath, f.Tool)
		}
		if f.RelPath == "CLAUDE.md" {
			sawRoot = true
		}
		if f.RelPath == ".claude/skills/demo/SKILL.md" {
			sawSkill = true
		}
	}
	if !sawRoot {
		t.Errorf("the root CLAUDE.md is missing: %v", relPaths(res, ""))
	}
	if !sawSkill {
		t.Errorf("skipping .claude/worktrees must not skip the rest of .claude: %v", relPaths(res, ""))
	}
}

// TestSkipDirTable is the table pin over the directory-skip predicate:
// unconditional names, the one contextual pair, and the names that must
// stay descendable.
func TestSkipDirTable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		parent, name string
		want         bool
	}{
		{parent: "/repo", name: ".git", want: true},
		{parent: "/repo", name: "node_modules", want: true},
		{parent: "/repo/pkg", name: "vendor", want: true},
		{parent: "/repo/.claude", name: "worktrees", want: true},
		{parent: "/repo", name: "worktrees", want: false},
		{parent: "/repo/src", name: "worktrees", want: false},
		{parent: "/repo", name: ".claude", want: false},
		{parent: "/repo/.claude", name: "skills", want: false},
		{parent: "/repo", name: "src", want: false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.parent+"/"+tc.name, func(t *testing.T) {
			t.Parallel()
			if got := skipDir(tc.parent, tc.name); got != tc.want {
				t.Errorf("skipDir(%q, %q) = %v, want %v", tc.parent, tc.name, got, tc.want)
			}
		})
	}
}

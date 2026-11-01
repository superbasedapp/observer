package store

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/freshness"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// handWorktrees lays out a main checkout with an in-tree and an
// out-of-tree linked worktree in git's own layout (hand-made, no git
// binary), each holding its own pkg/a.go.
type handWorktrees struct {
	main, inTree, outOfTree string
}

func newHandWorktrees(t *testing.T) handWorktrees {
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
	f := handWorktrees{
		main:      filepath.Join(base, "main"),
		outOfTree: filepath.Join(base, "wt"),
	}
	f.inTree = filepath.Join(f.main, ".worktrees", "x")
	w(filepath.Join(f.main, ".git", "HEAD"), "ref: refs/heads/main\n")
	w(filepath.Join(f.main, ".git", "config"), "[core]\n\tbare = false\n")
	for name, dir := range map[string]string{"x": f.inTree, "wt": f.outOfTree} {
		admin := filepath.Join(f.main, ".git", "worktrees", name)
		w(filepath.Join(admin, "HEAD"), "ref: refs/heads/"+name+"\n")
		w(filepath.Join(admin, "commondir"), "../..\n")
		w(filepath.Join(admin, "gitdir"), filepath.Join(dir, ".git")+"\n")
		w(filepath.Join(dir, ".git"), "gitdir: "+filepath.ToSlash(admin)+"\n")
	}
	w(filepath.Join(f.main, "pkg", "a.go"), "package main_copy\n")
	w(filepath.Join(f.inTree, "pkg", "a.go"), "package in_tree_copy\n")
	w(filepath.Join(f.outOfTree, "pkg", "a.go"), "package out_of_tree_copy\n")
	return f
}

func rawPathInput(t *testing.T, p string) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"file_path": p, "content": "package x\n"})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestCheckoutDiskPath: a target stored checkout-independently resolves to
// the checkout the tool's own absolute path named; anything else keeps the
// old join.
func TestCheckoutDiskPath(t *testing.T) {
	f := newHandWorktrees(t)
	if git.CheckoutRelativePath(f.main, filepath.Join(f.inTree, "pkg", "a.go")) != "pkg/a.go" {
		t.Fatal("fixture: the in-tree worktree is not recognized")
	}
	plain := t.TempDir()
	cases := []struct {
		name, root, target, raw, want string
		ok                            bool
	}{
		{"in-tree worktree", f.main, "pkg/a.go", rawPathInput(t, filepath.Join(f.inTree, "pkg", "a.go")), filepath.Join(f.inTree, "pkg", "a.go"), true},
		{"out-of-tree worktree", f.main, "pkg/a.go", rawPathInput(t, filepath.Join(f.outOfTree, "pkg", "a.go")), filepath.Join(f.outOfTree, "pkg", "a.go"), true},
		{"main checkout", f.main, "pkg/a.go", rawPathInput(t, filepath.Join(f.main, "pkg", "a.go")), filepath.Join(f.main, "pkg", "a.go"), true},
		{"no absolute spelling", f.main, "pkg/a.go", `{"path":"pkg/a.go"}`, "", false},
		{"not json", f.main, "pkg/a.go", "pkg/a.go", "", false},
		{"other file", f.main, "pkg/a.go", rawPathInput(t, filepath.Join(f.inTree, "pkg", "b.go")), "", false},
		{"project without worktrees", plain, "pkg/a.go", rawPathInput(t, filepath.Join(plain, "pkg", "a.go")), "", false},
		{"absolute target", f.main, filepath.Join(f.main, "pkg", "a.go"), rawPathInput(t, filepath.Join(f.inTree, "pkg", "a.go")), "", false},
		{"external target", f.main, "[external]/x", rawPathInput(t, "/x"), "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := checkoutDiskPath(c.root, c.target, c.raw)
			if ok != c.ok || got != c.want {
				t.Errorf("checkoutDiskPath = %q %v, want %q %v", got, ok, c.want, c.ok)
			}
		})
	}
}

// TestWorktreeTargetFreshnessHashesTheWorktreeFile: a file action in a
// linked worktree, stored as the main checkout's relative path, hashes and
// records the worktree's own file, never the main checkout's copy.
func TestWorktreeTargetFreshnessHashesTheWorktreeFile(t *testing.T) {
	s, d := newTestStore(t)
	ctx := context.Background()
	f := newHandWorktrees(t)
	classifier := freshness.New(d, freshness.Options{MaxHashSizeMB: 10})
	now := time.Date(2026, 10, 22, 10, 0, 0, 0, time.UTC)
	var events []models.ToolEvent
	for i, dir := range []string{f.main, f.inTree, f.outOfTree} {
		abs := filepath.Join(dir, "pkg", "a.go")
		events = append(events, models.ToolEvent{
			SourceFile: "wt.jsonl", SourceEventID: "wt" + string(rune('0'+i)), SessionID: "s_wt", ProjectRoot: f.main,
			Timestamp: now.Add(time.Duration(i) * time.Second), Tool: models.ToolClaudeCode,
			ActionType: models.ActionReadFile, Target: git.CheckoutRelativePath(f.main, abs),
			RawToolInput: rawPathInput(t, abs), Success: true, RawToolName: "Read",
		})
	}
	if _, err := s.Ingest(ctx, events, nil, IngestOptions{Classifier: classifier}); err != nil {
		t.Fatal(err)
	}
	rows, err := d.QueryContext(ctx, `SELECT file_path FROM file_state ORDER BY file_path`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var paths []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	want := []string{filepath.Join(f.inTree, "pkg", "a.go"), filepath.Join(f.main, "pkg", "a.go"), filepath.Join(f.outOfTree, "pkg", "a.go")}
	sortedWant := append([]string(nil), want...)
	sort.Strings(sortedWant)
	if !reflect.DeepEqual(paths, sortedWant) {
		t.Fatalf("file_state paths = %v, want one per checkout %v", paths, sortedWant)
	}
	var targets []string
	trows, err := d.QueryContext(ctx, `SELECT target FROM actions WHERE session_id = 's_wt' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer trows.Close()
	for trows.Next() {
		var tg string
		if err := trows.Scan(&tg); err != nil {
			t.Fatal(err)
		}
		targets = append(targets, tg)
	}
	if !reflect.DeepEqual(targets, []string{"pkg/a.go", "pkg/a.go", "pkg/a.go"}) {
		t.Fatalf("targets = %v, want one checkout-independent path", targets)
	}
}

// TestWorktreePostWrites: a write in an in-tree worktree is reported at its
// real place under the project root (as before the checkout path seam); a
// write in an out-of-tree worktree is reported under that checkout, at its
// per-checkout sighting key (lane LEFT-SEC, SECP-25 residual f; it was not
// reported before); the main checkout's write is unchanged. Both feeds
// agree.
func TestWorktreePostWrites(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	f := newHandWorktrees(t)
	start, err := s.MaxActionID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var sunk []string
	s.SetPostWriteSink(func(p PostWrite) { sunk = append(sunk, p.Path) })
	now := time.Now().UTC()
	var events []models.ToolEvent
	for i, dir := range []string{f.main, f.inTree, f.outOfTree} {
		abs := filepath.Join(dir, "pkg", "a.go")
		events = append(events, models.ToolEvent{
			SourceFile: "pw.jsonl", SourceEventID: "pw" + string(rune('0'+i)), SessionID: "s_pwt", ProjectRoot: f.main,
			Timestamp: now, Tool: models.ToolClaudeCode, ActionType: models.ActionWriteFile,
			Target: git.CheckoutRelativePath(f.main, abs), RawToolInput: rawPathInput(t, abs), Success: true,
		})
	}
	if _, err := s.Ingest(ctx, events, nil, IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	want := []string{"pkg/a.go", ".worktrees/x/pkg/a.go", WorktreeSightingPath(f.outOfTree, "pkg/a.go")}
	if !reflect.DeepEqual(sunk, want) {
		t.Errorf("sink paths = %v, want %v", sunk, want)
	}
	got, _, err := s.PostWritesAfter(ctx, start, 10)
	if err != nil {
		t.Fatal(err)
	}
	var polled []string
	for _, p := range got {
		if p.ProjectRoot != f.main {
			t.Errorf("post-write root = %q, want the project %q", p.ProjectRoot, f.main)
		}
		if _, _, keyed := SplitWorktreeSighting(p.Path); keyed && (p.Checkout != f.outOfTree || p.CheckoutPath != "pkg/a.go") {
			t.Errorf("out-of-tree write placed at %q %q, want %q pkg/a.go", p.Checkout, p.CheckoutPath, f.outOfTree)
		}
		polled = append(polled, p.Path)
	}
	if !reflect.DeepEqual(polled, want) {
		t.Errorf("PostWritesAfter paths = %v, want %v", polled, want)
	}
}

// TestCheckoutDiskPathReadsLayoutOncePerTTL (audit finding 5): many file
// actions in one project read its worktree layout from disk once per TTL,
// not once per action, and a raw input's write content is never a path
// candidate.
func TestCheckoutDiskPathReadsLayoutOncePerTTL(t *testing.T) {
	f := newHandWorktrees(t)
	now := time.Date(2026, 10, 23, 9, 0, 0, 0, time.UTC)
	c := &worktreeLayoutCache{ttl: worktreeLayoutTTL, now: func() time.Time { return now }, byRoot: map[string]worktreeLayout{}}
	for i := 0; i < 50; i++ {
		for _, dir := range []string{f.main, f.inTree, f.outOfTree} {
			abs := filepath.Join(dir, "pkg", "a.go")
			got, ok := c.diskPath(f.main, "pkg/a.go", rawPathInput(t, abs))
			if !ok || got != abs {
				t.Fatalf("diskPath(%s) = %q %v", abs, got, ok)
			}
		}
	}
	if n := c.loadCount(); n != 1 {
		t.Fatalf("layout reads = %d after 150 actions, want 1 (the cache is not used)", n)
	}
	now = now.Add(worktreeLayoutTTL)
	if _, ok := c.diskPath(f.main, "pkg/a.go", rawPathInput(t, filepath.Join(f.inTree, "pkg", "a.go"))); !ok {
		t.Fatal("after the TTL: no match")
	}
	if n := c.loadCount(); n != 2 {
		t.Fatalf("layout reads = %d after the TTL, want 2", n)
	}
	// An absolute path that is only write content, not a path key, is not
	// a candidate.
	raw := `{"content":"` + filepath.ToSlash(filepath.Join(f.inTree, "pkg", "a.go")) + `","path":"pkg/a.go"}`
	if got, ok := c.diskPath(f.main, "pkg/a.go", raw); ok {
		t.Fatalf("content was decoded as a path: %q", got)
	}
}

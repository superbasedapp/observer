package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/gitalias"
)

// TestFileGitAliasLookup pins the reader the hook and the daemon's guard
// share: no file is no table, a written table answers for its projects, a
// rewrite is picked up, and a corrupt file reads as no table.
func TestFileGitAliasLookup(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, gitalias.Filename)
	lookup := fileGitAliasLookup(path, nil)
	if _, ok := lookup("/home/u/proj"); ok {
		t.Fatal("missing file covered a directory")
	}
	write := func(exp string, mod time.Time) {
		t.Helper()
		tbl := gitalias.Table{Projects: []gitalias.Project{{Root: "/home/u/proj", Aliases: map[string]string{"ci": exp}}}}
		if err := gitalias.Write(path, tbl); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, mod, mod); err != nil {
			t.Fatal(err)
		}
	}
	base := time.Now().Add(-time.Hour)
	write("commit -n", base)
	if a, ok := lookup("/home/u/proj/src"); !ok || a["ci"] != "commit -n" {
		t.Fatalf("first read: %v %v", a, ok)
	}
	write("commit --no-verify", base.Add(time.Minute))
	if a, ok := lookup("/home/u/proj"); !ok || a["ci"] != "commit --no-verify" {
		t.Fatalf("after rewrite: %v %v", a, ok)
	}
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, base.Add(2*time.Minute), base.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, ok := lookup("/home/u/proj"); ok {
		t.Fatal("corrupt file covered a directory")
	}
	if fileGitAliasLookup("", nil) != nil {
		t.Fatal("empty path built a lookup")
	}
}

// TestGitAliasRefresher builds the table from a real repository with git's
// own config reader, writes it once, and skips the rewrite when nothing
// changed.
func TestGitAliasRefresher(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	t.Parallel()
	repo := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	run("config", "alias.ci", "commit --no-verify")
	empty := t.TempDir()
	run("-C", empty, "init", "-q")
	nested := filepath.Join(repo, "vendor", "lib")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	run("-C", nested, "init", "-q")

	out := filepath.Join(t.TempDir(), gitalias.Filename)
	r := &gitAliasRefresher{home: t.TempDir()}
	ctx := context.Background()
	now := time.Now()
	changed, err := r.refresh(ctx, out, []string{repo, empty, nested, filepath.Join(repo, "absent")}, now)
	if err != nil || !changed {
		t.Fatalf("first refresh: changed=%v err=%v", changed, err)
	}
	tbl, err := gitalias.Load(out)
	if err != nil || tbl == nil {
		t.Fatalf("Load: %v %v", tbl, err)
	}
	if a, ok := tbl.Lookup(repo); !ok || a["ci"] != "commit --no-verify" {
		t.Fatalf("repo aliases: %v %v", a, ok)
	}
	// A repository nested in another has its own (empty) alias set, not
	// the outer one's.
	if a, ok := tbl.Lookup(filepath.Join(nested, "src")); !ok || a["ci"] != "" {
		t.Fatalf("nested repo aliases: %v %v", a, ok)
	}
	if changed, err := r.refresh(ctx, out, []string{repo, empty, nested}, now); err != nil || changed {
		t.Fatalf("unchanged refresh rewrote the table: changed=%v err=%v", changed, err)
	}
	// Past gitAliasMaxAge a project is read again even with unchanged
	// config file times (a linked worktree's aliases live elsewhere).
	c := r.cache[repo]
	c.aliases = map[string]string{"ci": "stale"}
	r.cache[repo] = c
	if changed, err := r.refresh(ctx, out, []string{repo, empty, nested}, now.Add(gitAliasMaxAge/2)); err != nil || !changed {
		t.Fatalf("refresh inside max age: changed=%v err=%v", changed, err)
	}
	if tbl, _ = gitalias.Load(out); tbl == nil {
		t.Fatal("table missing")
	}
	if a, _ := tbl.Lookup(repo); a["ci"] != "stale" {
		t.Fatalf("inside max age the cached aliases are kept: %v", a)
	}
	if changed, err := r.refresh(ctx, out, []string{repo, empty, nested}, now.Add(gitAliasMaxAge)); err != nil || !changed {
		t.Fatalf("refresh past max age: changed=%v err=%v", changed, err)
	}
	if tbl, _ = gitalias.Load(out); tbl == nil {
		t.Fatal("table missing")
	}
	if a, _ := tbl.Lookup(repo); a["ci"] != "commit --no-verify" {
		t.Fatalf("past max age the aliases are read again: %v", a)
	}
}

package store

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/commitlog"
	"github.com/marmutapp/superbased-observer/internal/loc"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// locWorktreeRepo builds a real repository with pkg/a.go committed, an
// in-tree linked worktree at <repo>/.worktrees/in and an out-of-tree one,
// each on its own branch. Paths have symlinks resolved.
func locWorktreeRepo(t *testing.T) (repo, inTree, outTree string, git func(dir string, args ...string) string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git binary not available")
	}
	git = func(dir string, args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com", "GIT_CONFIG_NOSYSTEM=1", "HOME="+dir)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
		return string(out)
	}
	resolve := func(p string) string {
		r, err := filepath.EvalSymlinks(p)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	repo = resolve(t.TempDir())
	git(repo, "init")
	git(repo, "checkout", "-b", "main")
	if err := os.MkdirAll(filepath.Join(repo, "pkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "pkg", "a.go"), []byte("package pkg\n\nvar a = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git(repo, "add", "-A")
	git(repo, "commit", "-m", "init")
	inTree = filepath.Join(repo, ".worktrees", "in")
	git(repo, "worktree", "add", "-b", "in", inTree)
	outTree = filepath.Join(resolve(t.TempDir()), "out")
	git(repo, "worktree", "add", "-b", "out", outTree)
	return repo, inTree, outTree, git
}

func locEditOf(session, root, path, ev string) models.ToolEvent {
	raw := fmt.Sprintf(`{"file_path":%q,"old_string":"var a = 1","new_string":"var a = 2"}`, path)
	return locEvent(session, root, path, models.ActionEditFile, raw, ev, false)
}

func locHashOf(t *testing.T, s *Store, session string) []string {
	t.Helper()
	rows, err := s.db.QueryContext(context.Background(), `SELECT file_path_hash FROM file_changes WHERE session_id = ? ORDER BY id`, session)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			t.Fatal(err)
		}
		out = append(out, h)
	}
	return out
}

// TestLOCWorktreeEditsJoinTheirCommit (SHR-8, lane SHR-FOLLOWUPS): an edit
// in an in-tree and in an out-of-tree linked worktree hashes like the same
// file in the main checkout, and so equals the path hash of the commit that
// carried it (internal/commitlog hashes repository-relative paths).
func TestLOCWorktreeEditsJoinTheirCommit(t *testing.T) {
	repo, inTree, outTree, git := locWorktreeRepo(t)
	s, _ := newTestStore(t)
	ctx := context.Background()
	main := loc.PathHash(repo, filepath.Join(repo, "pkg", "a.go"))
	if main != loc.PathHash("", "pkg/a.go") {
		t.Fatalf("main-checkout hash %s is not the repository-relative one", main)
	}
	for i, wt := range []string{inTree, outTree} {
		session := fmt.Sprintf("wt%d", i)
		if _, err := s.Ingest(ctx, []models.ToolEvent{locEditOf(session, repo, filepath.Join(wt, "pkg", "a.go"), "e"+session)}, nil, IngestOptions{}); err != nil {
			t.Fatal(err)
		}
		got := locHashOf(t, s, session)
		if len(got) != 1 || got[0] != main {
			t.Fatalf("%s edit hashed %v, want the main checkout's %s", wt, got, main)
		}
		// The commit that carries the edit.
		if err := os.WriteFile(filepath.Join(wt, "pkg", "a.go"), []byte("package pkg\n\nvar a = 2\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		git(wt, "commit", "-am", "edit")
		out := git(wt, commitlog.Args("", 1)...)
		commits, err := commitlog.ParseLog([]byte(out), false)
		if err != nil || len(commits) != 1 || len(commits[0].Files) != 1 {
			t.Fatalf("parse the worktree commit: %+v %v", commits, err)
		}
		if commits[0].Files[0].PathHash != got[0] {
			t.Fatalf("the %s edit (%s) does not join its commit's file (%s)", wt, got[0], commits[0].Files[0].PathHash)
		}
	}
}

// TestLOCRekeyBackfill: rows an earlier build stored under the root-prefix
// key are moved by the opt-in backfill: a dry run counts and changes
// nothing, --apply moves each row once, a second run moves nothing, and a
// row in the main checkout is never read as a candidate. A re-ingest of an
// old row converges it the same way (no edit counted under two keys).
func TestLOCRekeyBackfill(t *testing.T) {
	repo, inTree, outTree, _ := locWorktreeRepo(t)
	s, _ := newTestStore(t)
	ctx := context.Background()
	inPath := filepath.Join(inTree, "pkg", "a.go")
	outPath := filepath.Join(outTree, "pkg", "a.go")
	mainPath := filepath.Join(repo, "pkg", "a.go")
	for _, e := range []models.ToolEvent{locEditOf("in", repo, inPath, "e1"), locEditOf("out", repo, outPath, "e2"), locEditOf("main", repo, mainPath, "e3")} {
		if _, err := s.Ingest(ctx, []models.ToolEvent{e}, nil, IngestOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	// Put the worktree rows back under the key an earlier build stored.
	legacy := map[string]string{"in": loc.PathHash(repo, inPath), "out": loc.PathHash(repo, outPath)}
	for sess, h := range legacy {
		if _, err := s.db.ExecContext(ctx, `UPDATE file_changes SET file_path_hash = ? WHERE session_id = ?`, h, sess); err != nil {
			t.Fatal(err)
		}
	}
	mainHash := locHashOf(t, s, "main")[0]

	dry, err := s.RekeyWorktreeFileChanges(ctx, RekeyLOCOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if fc := dry.Tables["file_changes"]; fc.Rekeyed != 2 || fc.AlreadyKeyed != 0 || dry.Sessions != 2 || dry.ActionsScanned != 3 {
		t.Fatalf("dry run: %+v", dry)
	}
	if got := locHashOf(t, s, "in"); got[0] != legacy["in"] {
		t.Fatal("the dry run wrote")
	}
	applied, err := s.RekeyWorktreeFileChanges(ctx, RekeyLOCOptions{Apply: true})
	if err != nil {
		t.Fatal(err)
	}
	if fc := applied.Tables["file_changes"]; fc.Rekeyed != 2 || fc.Clashes != 0 {
		t.Fatalf("apply: %+v", applied)
	}
	for _, sess := range []string{"in", "out"} {
		if got := locHashOf(t, s, sess); len(got) != 1 || got[0] != mainHash {
			t.Fatalf("%s after apply: %v, want %s", sess, got, mainHash)
		}
	}
	again, err := s.RekeyWorktreeFileChanges(ctx, RekeyLOCOptions{Apply: true})
	if err != nil {
		t.Fatal(err)
	}
	if fc := again.Tables["file_changes"]; fc.Rekeyed != 0 || fc.AlreadyKeyed != 2 {
		t.Fatalf("second run: %+v", again)
	}
	if got := locHashOf(t, s, "main"); len(got) != 1 || got[0] != mainHash {
		t.Fatalf("the main-checkout row changed: %v", got)
	}

	// A re-ingest of a row still under the legacy key moves it rather than
	// counting the edit twice.
	if _, err := s.db.ExecContext(ctx, `UPDATE file_changes SET file_path_hash = ? WHERE session_id = 'in'`, legacy["in"]); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Ingest(ctx, []models.ToolEvent{locEditOf("in", repo, inPath, "e1")}, nil, IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.BackfillLOC(ctx, BackfillLOCOptions{Rescan: true}); err != nil {
		t.Fatal(err)
	}
	if got := locHashOf(t, s, "in"); len(got) != 1 || got[0] != mainHash {
		t.Fatalf("after a re-ingest and a rescan: %v, want one row under %s", got, mainHash)
	}
}

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestBackfillWorktreeRoots_AllTablesRelativeAndIdentity (lane
// shr-worktree2, PT-39): a row rooted at a relative-path worktree's own
// checkout moves onto the main project with every project-keyed table,
// compaction_events through its owner's mover; the dry run reports per
// table and changes nothing; the main row the apply creates carries the
// repository's identity; with no identity to give it the row is left.
func TestBackfillWorktreeRoots_AllTablesRelativeAndIdentity(t *testing.T) {
	mainRoot, wtRoot := linkedWorktreeFixture(t)
	// Rewrite the worktree's pointers the way git 2.48 writes them under
	// worktree.useRelativePaths.
	admin := filepath.Join(mainRoot, ".git", "worktrees", filepath.Base(wtRoot))
	relGit, err := filepath.Rel(wtRoot, admin)
	if err != nil {
		t.Fatal(err)
	}
	relBack, err := filepath.Rel(admin, filepath.Join(wtRoot, ".git"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wtRoot, ".git"), []byte("gitdir: "+filepath.ToSlash(relGit)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(admin, "gitdir"), []byte(filepath.ToSlash(relBack)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "obs.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := database.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	count := func(q string, args ...any) int {
		t.Helper()
		var n int
		if err := database.QueryRowContext(ctx, q, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	const at = "2026-10-01T00:00:00Z"
	// The old build gave the relative-path worktree a project of its own;
	// there is no main row yet.
	exec(`INSERT INTO projects (id, root_path, created_at) VALUES (7, ?, ?)`, wtRoot, at)
	exec(`INSERT INTO sessions (id, tool, started_at, project_id) VALUES ('s-rel', 'claude-code', ?, 7)`, at)
	exec(`INSERT INTO compaction_events (session_id, project_id, timestamp, tool) VALUES ('s-rel', 7, ?, 'claude-code')`, at)
	exec(`INSERT INTO file_state (project_id, file_path, content_hash, file_mtime, file_size_bytes, last_action_type, last_seen_at) VALUES (7, ?, 'h', ?, 1, 'read_file', ?)`, filepath.Join(wtRoot, "README.md"), at, at)

	// No identity to give the main row: the old row is left.
	realIdentity := worktreeRootsIdentity
	worktreeRootsIdentity = func(context.Context, string) (string, store.ProjectIdentity) { return "", store.ProjectIdentity{} }
	res, err := backfillWorktreeRoots(ctx, database, true, nil)
	worktreeRootsIdentity = realIdentity
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Moves) != 0 || len(res.Skipped) != 1 || !strings.Contains(res.Skipped[0].Reason, "no identity") {
		t.Fatalf("identity-less apply = %+v", res)
	}
	if n := count(`SELECT COUNT(*) FROM projects`); n != 1 {
		t.Fatalf("an identity-less apply created %d project rows", n-1)
	}

	var out bytes.Buffer
	res, err = backfillWorktreeRoots(ctx, database, false, &out)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Moves) != 1 || res.Moves[0].FromID != 7 || res.Moves[0].ToRoot != mainRoot || res.Moves[0].ToID != 0 {
		t.Fatalf("dry run = %+v", res)
	}
	for _, want := range []string{"compaction_events: would move 1 row(s)", "file_state: would move 1 row(s)", "sessions: would move 1 row(s)", "rule: file_state"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("dry-run report lacks %q:\n%s", want, out.String())
		}
	}
	if n := count(`SELECT COUNT(*) FROM projects`); n != 1 {
		t.Fatal("the dry run created a project row")
	}

	res, err = backfillWorktreeRoots(ctx, database, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Moves) != 1 || res.Moves[0].ToID == 0 {
		t.Fatalf("apply = %+v", res)
	}
	toID := res.Moves[0].ToID
	for _, table := range []string{"sessions", "compaction_events", "file_state"} {
		if n := count(`SELECT COUNT(*) FROM `+table+` WHERE project_id = ?`, toID); n != 1 {
			t.Errorf("%s on the main project = %d, want 1", table, n)
		}
	}
	var rootSHA, fingerprint string
	if err := database.QueryRowContext(ctx, `SELECT COALESCE(root_commit_sha, ''), COALESCE(content_fingerprint, '') FROM projects WHERE id = ? AND root_path = ?`, toID, mainRoot).Scan(&rootSHA, &fingerprint); err != nil {
		t.Fatal(err)
	}
	if rootSHA == "" && fingerprint == "" {
		t.Error("the created main row carries no identity")
	}
	res, err = backfillWorktreeRoots(ctx, database, true, nil)
	if err != nil || len(res.Moves) != 0 {
		t.Fatalf("second apply = %+v, %v", res, err)
	}
}

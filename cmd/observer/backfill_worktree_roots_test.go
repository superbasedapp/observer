package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
)

// TestBackfillWorktreeRoots pins --worktree-roots: a dry run changes
// nothing; --apply moves the sessions, actions and api_turns rows of a
// `<main>/.git/worktrees` row onto the main project in one step, keeps the
// old row marked as moved, leaves a row whose repository is gone, and a
// second --apply is a no-op.
func TestBackfillWorktreeRoots(t *testing.T) {
	mainRoot, _ := linkedWorktreeFixture(t)
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
	const at = "2026-10-01T00:00:00Z"
	exec(`INSERT INTO projects (id, root_path, created_at) VALUES (1, ?, ?)`, mainRoot, at)
	exec(`INSERT INTO projects (id, root_path, created_at) VALUES (2, ?, ?)`, mainRoot+"/.git/worktrees", at)
	exec(`INSERT INTO projects (id, root_path, created_at) VALUES (3, '/gone/repo/.git/worktrees', ?)`, at)
	for sid, pid := range map[string]int{"s-main": 1, "s-wt1": 2, "s-wt2": 2, "s-gone": 3} {
		exec(`INSERT INTO sessions (id, tool, started_at, project_id) VALUES (?, 'claude-code', ?, ?)`, sid, at, pid)
	}
	exec(`INSERT INTO actions (session_id, project_id, timestamp, action_type, tool) VALUES ('s-wt1', 2, ?, 'read_file', 'claude-code')`, at)
	exec(`INSERT INTO api_turns (session_id, project_id, timestamp, provider, model, input_tokens, output_tokens) VALUES ('s-wt2', 2, ?, 'anthropic', 'm', 1, 1)`, at)

	count := func(q string, args ...any) int {
		t.Helper()
		var n int
		if err := database.QueryRowContext(ctx, q, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	var out bytes.Buffer
	res, err := backfillWorktreeRoots(ctx, database, false, &out)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Moves) != 1 || res.Moves[0].FromID != 2 || res.Moves[0].ToRoot != mainRoot || res.Moves[0].Sessions != 2 {
		t.Fatalf("dry run plan = %+v", res)
	}
	if len(res.Skipped) != 1 || res.Skipped[0].ID != 3 {
		t.Errorf("skipped = %+v, want the row whose repository is gone", res.Skipped)
	}
	if n := count(`SELECT COUNT(*) FROM sessions WHERE project_id = 2`); n != 2 {
		t.Fatalf("dry run moved sessions (%d left on the old row)", n)
	}
	if !strings.Contains(out.String(), "--apply") || !strings.Contains(out.String(), "org:") ||
		!strings.Contains(out.String(), "security: ") || !strings.Contains(out.String(), "--separate-git-dir") {
		t.Errorf("dry-run report = %q", out.String())
	}

	res, err = backfillWorktreeRoots(ctx, database, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Moves) != 1 || res.Moves[0].ToID != 1 || res.Moves[0].Moved.Sessions != 2 || res.Moves[0].Moved.Actions != 1 || res.Moves[0].Moved.APITurns != 1 {
		t.Fatalf("apply = %+v", res)
	}
	if n := count(`SELECT COUNT(*) FROM sessions WHERE project_id = 1`); n != 3 {
		t.Errorf("main project holds %d sessions, want 3", n)
	}
	if n := count(`SELECT COUNT(*) FROM actions WHERE project_id = 1`); n != 1 {
		t.Errorf("main project holds %d actions, want 1", n)
	}
	if n := count(`SELECT COUNT(*) FROM projects WHERE id = 2 AND name LIKE 'worktree root moved to project 1%'`); n != 1 {
		t.Error("the old row was not kept and marked")
	}
	if n := count(`SELECT COUNT(*) FROM sessions WHERE project_id = 3`); n != 1 {
		t.Error("the row whose repository is gone was touched")
	}

	res, err = backfillWorktreeRoots(ctx, database, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Moves) != 0 {
		t.Errorf("second apply moved again: %+v", res.Moves)
	}
}

package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
)

// TestBackfillWorktreeRootsContainedRows: the rows earlier hook builds filed
// under a folder inside a git working tree (a subdirectory of the main
// repository, a linked worktree's subdirectory, a worktree since removed)
// move onto the repository's project; a removed folder whose repository is
// not a project here is left with the reason, and a folder in no working
// tree is not touched.
func TestBackfillWorktreeRootsContainedRows(t *testing.T) {
	mainRoot, wtRoot := linkedWorktreeFixture(t)
	for _, d := range []string{filepath.Join(mainRoot, "web"), filepath.Join(wtRoot, "web"), filepath.Join(mainRoot, "docs")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	other, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("git", "init", "-q", other).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, out)
	}
	plain, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(other, "lib"), 0o755); err != nil {
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
	const at = "2026-11-07T00:00:00Z"
	rows := map[int]string{
		1: mainRoot,
		2: filepath.Join(mainRoot, "web"),
		3: filepath.Join(wtRoot, "web"),
		4: filepath.Join(mainRoot, ".claude", "worktrees", "removed"),
		5: filepath.Join(other, "gone", "web"),
		6: plain,
		7: filepath.Join(mainRoot, "docs"),
		8: filepath.Join(other, "lib"),
	}
	for id, root := range rows {
		exec(`INSERT INTO projects (id, root_path, created_at) VALUES (?, ?, ?)`, id, root, at)
	}
	exec(`INSERT INTO sessions (id, tool, started_at, project_id) VALUES ('s-main', 'claude-code', ?, 1)`, at)
	exec(`INSERT INTO sessions (id, tool, started_at, project_id) VALUES ('s-removed', 'claude-code', ?, 4)`, at)
	exec(`INSERT INTO sessions (id, tool, started_at, project_id) VALUES ('s-other', 'claude-code', ?, 5)`, at)
	exec(`INSERT INTO sessions (id, tool, started_at, project_id) VALUES ('s-plain', 'claude-code', ?, 6)`, at)
	for _, pid := range []int{2, 3} {
		exec(`INSERT INTO actions (session_id, project_id, timestamp, action_type, tool) VALUES ('s-main', ?, ?, 'read_file', 'claude-code')`, pid, at)
	}
	exec(`INSERT INTO actions (session_id, project_id, timestamp, action_type, tool) VALUES ('s-removed', 4, ?, 'read_file', 'claude-code')`, at)

	var out bytes.Buffer
	res, err := backfillWorktreeRoots(ctx, database, true, &out)
	if err != nil {
		t.Fatal(err)
	}
	moved := map[int64]WorktreeRootMove{}
	for _, m := range res.Moves {
		moved[m.FromID] = m
	}
	cases := []struct {
		name string
		from int64
		gone bool
	}{
		{"main repository subdirectory", 2, false},
		{"linked worktree subdirectory", 3, false},
		{"removed worktree folder", 4, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, ok := moved[tc.from]
			if !ok {
				t.Fatalf("project %d not moved; report:\n%s", tc.from, out.String())
			}
			if m.ToID != 1 || m.FolderGone != tc.gone {
				t.Errorf("move = %+v, want to project 1 with folder_gone=%v", m, tc.gone)
			}
		})
	}
	if _, ok := moved[5]; ok {
		t.Error("a removed folder of a repository that is no project here was moved")
	}
	if _, ok := moved[6]; ok {
		t.Error("a folder in no working tree was moved")
	}
	var skippedOther bool
	for _, s := range res.Skipped {
		if s.ID == 5 && s.Reason == worktreeRootsGoneReason {
			skippedOther = true
		}
	}
	if !skippedOther {
		t.Errorf("skipped = %+v, want project 5 left with the removed-folder reason", res.Skipped)
	}
	count := func(q string) int {
		t.Helper()
		var n int
		if err := database.QueryRowContext(ctx, q).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := count(`SELECT COUNT(*) FROM actions WHERE project_id = 1`); n != 3 {
		t.Errorf("main project holds %d actions, want 3", n)
	}
	if n := count(`SELECT COUNT(*) FROM sessions WHERE project_id = 1`); n != 2 {
		t.Errorf("main project holds %d sessions, want 2 (its own and the removed worktree's)", n)
	}
	if n := count(`SELECT COUNT(*) FROM sessions WHERE project_id IN (5, 6)`); n != 2 {
		t.Errorf("%d of the left rows' sessions remain, want 2", n)
	}
	if !strings.Contains(out.String(), "the folder is gone") {
		t.Errorf("report does not name the removed folder:\n%s", out.String())
	}
}

// TestBackfillWorktreeRootsMarksEmptyRows: a row inside a git working tree
// that holds nothing to move (an empty subdirectory row) is only marked as
// folded into the repository's project, so the project list stops showing
// it; an empty row of a repository that is no project here is left, and a
// second apply marks nothing again.
func TestBackfillWorktreeRootsMarksEmptyRows(t *testing.T) {
	mainRoot, _ := linkedWorktreeFixture(t)
	if err := os.MkdirAll(filepath.Join(mainRoot, "docs"), 0o755); err != nil {
		t.Fatal(err)
	}
	other, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("git", "init", "-q", other).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, out)
	}
	if err := os.MkdirAll(filepath.Join(other, "lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "obs.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	const at = "2026-11-07T00:00:00Z"
	for id, root := range map[int]string{1: mainRoot, 2: filepath.Join(mainRoot, "docs"), 3: filepath.Join(other, "lib")} {
		if _, err := database.ExecContext(ctx, `INSERT INTO projects (id, root_path, created_at) VALUES (?, ?, ?)`, id, root, at); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	res, err := backfillWorktreeRoots(ctx, database, true, &out)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Moves) != 1 || res.Moves[0].FromID != 2 || res.Moves[0].ToID != 1 || !res.Moves[0].MarkOnly {
		t.Fatalf("moves = %+v, want project 2 marked as folded into project 1; report:\n%s", res.Moves, out.String())
	}
	if !strings.Contains(out.String(), "marked project 2") {
		t.Errorf("report does not say the row was marked:\n%s", out.String())
	}
	var name string
	if err := database.QueryRowContext(ctx, `SELECT COALESCE(name, '') FROM projects WHERE id = 2`).Scan(&name); err != nil || !strings.HasPrefix(name, "worktree root moved to project 1") {
		t.Errorf("project 2 name = %q (%v), want the folded mark", name, err)
	}
	if err := database.QueryRowContext(ctx, `SELECT COALESCE(name, '') FROM projects WHERE id = 3`).Scan(&name); err != nil || name != "" {
		t.Errorf("project 3 name = %q (%v), want it left unmarked (its repository is no project here)", name, err)
	}
	again, err := backfillWorktreeRoots(ctx, database, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Moves) != 0 {
		t.Errorf("second apply moves = %+v, want none", again.Moves)
	}
}

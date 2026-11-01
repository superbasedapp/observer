package store

import (
	"context"
	"database/sql"
	"reflect"
	"testing"
)

// seedProjectMove lays out an old worktree project (2) and the main project
// (1) holding rows in every table MoveProjectRows covers, with one
// file_state path and one commit both projects hold: for a.go the old row
// is newer, for b.go the main row is; commit c1 is newer on the old row,
// commit c2 on the main row.
func seedProjectMove(t *testing.T, d *sql.DB) {
	t.Helper()
	ctx := context.Background()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := d.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	const at = "2026-10-01T00:00:00Z"
	exec(`INSERT INTO projects (id, root_path, created_at) VALUES (1, '/r/main', ?), (2, '/r/main/.git/worktrees', ?)`, at, at)
	exec(`INSERT INTO sessions (id, tool, started_at, project_id) VALUES ('s-main', 'claude-code', ?, 1), ('s-old', 'claude-code', ?, 2)`, at, at)
	exec(`INSERT INTO actions (id, session_id, project_id, timestamp, action_type, tool) VALUES (10, 's-old', 2, ?, 'run_command', 'claude-code')`, at)
	exec(`INSERT INTO api_turns (session_id, project_id, timestamp, provider, model, input_tokens, output_tokens) VALUES ('s-old', 2, ?, 'anthropic', 'm', 1, 1)`, at)
	exec(`INSERT INTO failure_context (action_id, session_id, project_id, timestamp, command_hash, command_summary) VALUES (10, 's-old', 2, ?, 'h', 'go test')`, at)
	exec(`INSERT INTO compaction_events (session_id, project_id, timestamp, tool) VALUES ('s-old', 2, ?, 'claude-code')`, at)
	fs := func(pid int, path, seen string) {
		exec(`INSERT INTO file_state (project_id, file_path, content_hash, file_mtime, file_size_bytes, last_action_type, last_seen_at) VALUES (?, ?, ?, ?, 1, 'read_file', ?)`,
			pid, path, path+"@"+seen, seen, seen)
	}
	fs(1, "/r/main/a.go", "2026-10-01T00:00:00Z")
	fs(2, "/r/main/a.go", "2026-10-02T00:00:00.5Z")
	fs(1, "/r/main/b.go", "2026-10-03T00:00:00Z")
	fs(2, "/r/main/b.go", "2026-10-02T00:00:00Z")
	fs(2, "/r/main/c.go", "2026-10-02T00:00:00Z")
	exec(`INSERT INTO file_changes (session_id, project_id, file_path_hash, actor, source) VALUES ('s-old', 2, 'h1', 'ai', 'action')`)
	commit := func(id, pid int, sha, scanned string) {
		exec(`INSERT INTO project_commits (id, project_id, sha, authored_at, committed_at, scanned_at) VALUES (?, ?, ?, ?, ?, ?)`, id, pid, sha, at, at, scanned)
		exec(`INSERT INTO project_commit_files (commit_id, rel_path, path_hash) VALUES (?, 'a.go', 'h')`, id)
	}
	commit(100, 1, "c1", "2026-10-01T00:00:00Z")
	commit(101, 2, "c1", "2026-10-02T00:00:00Z")
	commit(102, 1, "c2", "2026-10-03T00:00:00Z")
	commit(103, 2, "c2", "2026-10-02T00:00:00Z")
	commit(104, 2, "c3", "2026-10-02T00:00:00Z")
}

// TestMoveProjectRows_AllTables: one transaction moves every project-keyed
// table; on a clash the newer row ends on the target and the older stays
// on the old project (nothing deleted); the plan's counts equal the
// apply's and the plan changes nothing.
func TestMoveProjectRows_AllTables(t *testing.T) {
	s, d := newTestStore(t)
	ctx := context.Background()
	seedProjectMove(t, d)
	count := func(q string, args ...any) int64 {
		t.Helper()
		var n int64
		if err := d.QueryRowContext(ctx, q, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := count(`SELECT COUNT(*) FROM file_state`) + count(`SELECT COUNT(*) FROM project_commits`) + count(`SELECT COUNT(*) FROM project_commit_files`)

	plan, err := s.PlanProjectMove(ctx, 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	if n := count(`SELECT COUNT(*) FROM sessions WHERE project_id = 2`); n != 1 {
		t.Fatalf("the plan moved rows (%d sessions left)", n)
	}
	got, err := s.MoveProjectRows(ctx, 2, 1, "moved")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plan, got) {
		t.Errorf("plan %+v != apply %+v", plan, got)
	}
	want := map[string]TableMove{
		"sessions":        {Table: "sessions", Moved: 1},
		"actions":         {Table: "actions", Moved: 1},
		"api_turns":       {Table: "api_turns", Moved: 1},
		"failure_context": {Table: "failure_context", Moved: 1},
		"file_state":      {Table: "file_state", Moved: 2, KeptOnOld: 2, Swapped: 1},
		"file_changes":    {Table: "file_changes", Moved: 1},
		"project_commits": {Table: "project_commits", Moved: 2, KeptOnOld: 2, Swapped: 1},
	}
	if len(got.Tables) != len(want) {
		t.Fatalf("tables = %+v", got.Tables)
	}
	for _, tm := range got.Tables {
		if tm != want[tm.Table] {
			t.Errorf("%s = %+v, want %+v", tm.Table, tm, want[tm.Table])
		}
	}
	if got.Sessions != 1 || got.Actions != 1 || got.APITurns != 1 {
		t.Errorf("summary = %+v", got)
	}
	// compaction_events has no mover here (its owner's mover is passed by
	// the caller), so it stays.
	if n := count(`SELECT COUNT(*) FROM compaction_events WHERE project_id = 2`); n != 1 {
		t.Errorf("compaction_events moved without its mover")
	}
	// The newer row of each clash is on the main project.
	for path, wantSeen := range map[string]string{"/r/main/a.go": "2026-10-02T00:00:00.5Z", "/r/main/b.go": "2026-10-03T00:00:00Z", "/r/main/c.go": "2026-10-02T00:00:00Z"} {
		var seen string
		if err := d.QueryRowContext(ctx, `SELECT last_seen_at FROM file_state WHERE project_id = 1 AND file_path = ?`, path).Scan(&seen); err != nil || seen != wantSeen {
			t.Errorf("main %s last_seen_at = %q (%v), want %q", path, seen, err, wantSeen)
		}
	}
	for sha, wantID := range map[string]int64{"c1": 101, "c2": 102, "c3": 104} {
		if id := count(`SELECT id FROM project_commits WHERE project_id = 1 AND sha = ?`, sha); id != wantID {
			t.Errorf("main commit %s = row %d, want %d", sha, id, wantID)
		}
	}
	if n := count(`SELECT COUNT(*) FROM project_commits WHERE project_id = 2 AND sha IN ('c1', 'c2')`); n != 2 {
		t.Errorf("old project keeps %d clashing commits, want 2", n)
	}
	after := count(`SELECT COUNT(*) FROM file_state`) + count(`SELECT COUNT(*) FROM project_commits`) + count(`SELECT COUNT(*) FROM project_commit_files`)
	if after != before {
		t.Errorf("rows deleted: %d before, %d after", before, after)
	}
	if n := count(`SELECT COUNT(*) FROM file_state WHERE file_path LIKE '%swap%'`) + count(`SELECT COUNT(*) FROM project_commits WHERE sha LIKE '%swap%'`); n != 0 {
		t.Errorf("%d rows left with the swap mark", n)
	}
	if n := count(`SELECT COUNT(*) FROM projects WHERE id = 2 AND name = 'moved'`); n != 1 {
		t.Error("old row not kept and marked")
	}
}

// TestPlanProjectMove_NewTarget: with no target row yet the plan counts the
// old project's rows and creates nothing.
func TestPlanProjectMove_NewTarget(t *testing.T) {
	s, d := newTestStore(t)
	ctx := context.Background()
	seedProjectMove(t, d)
	plan, err := s.PlanProjectMove(ctx, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	moved := map[string]int64{}
	for _, tm := range plan.Tables {
		moved[tm.Table] = tm.Moved
	}
	if moved["file_state"] != 3 || moved["project_commits"] != 3 || moved["sessions"] != 1 {
		t.Errorf("plan = %+v", plan.Tables)
	}
	if _, err := s.MoveProjectRows(ctx, 2, 0, "x"); err == nil {
		t.Error("MoveProjectRows to no project succeeded")
	}
}

// TestMoveProjectRowsResendsToOrg (restored, audit finding 3): moving a
// pushed session onto another project (observer backfill --worktree-roots)
// re-sends it through the org push's re-send lane with the new project's
// hashes, keeps the old projects row, and refuses a move (or a plan) onto
// itself.
func TestMoveProjectRowsResendsToOrg(t *testing.T) {
	t.Parallel()
	s, db := newTestStore(t)
	ctx := context.Background()
	armResend(t, s)
	const oldRoot, newRoot, at = "/w/.git/worktrees", "/w", "2026-10-01T00:00:00Z"
	if _, err := db.ExecContext(ctx, `INSERT INTO projects (id, root_path, root_path_hash, created_at) VALUES (7, ?, ?, ?)`, oldRoot, sha256Hex(oldRoot), at); err != nil {
		t.Fatal(err)
	}
	newID, err := s.UpsertProject(ctx, newRoot, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO sessions (id, tool, started_at, project_id) VALUES ('wt-s', 'claude-code', ?, 7)`, at); err != nil {
		t.Fatal(err)
	}
	first := resendPushCycle(t, s)
	if len(first.Sessions) != 1 || first.Sessions[0].ProjectRootHash != sha256Hex(oldRoot) {
		t.Fatalf("first push = %+v", first.Sessions)
	}

	if _, err := s.MoveProjectRows(ctx, 7, 7, "x"); err == nil {
		t.Error("a move onto the same project must be refused")
	}
	if _, err := s.PlanProjectMove(ctx, 7, 7); err == nil {
		t.Error("a plan onto the same project must be refused")
	}
	moved, err := s.MoveProjectRows(ctx, 7, newID, "moved")
	if err != nil || moved.Sessions != 1 {
		t.Fatalf("MoveProjectRows = %+v, %v", moved, err)
	}
	again := resendPushCycle(t, s)
	if len(again.Sessions) != 1 || again.Sessions[0].ID != "wt-s" || again.Sessions[0].ProjectRootHash != sha256Hex(newRoot) {
		t.Fatalf("re-sent sessions = %+v, want wt-s under the new project's hash", again.Sessions)
	}
	var name string
	if err := db.QueryRowContext(ctx, `SELECT name FROM projects WHERE id = 7`).Scan(&name); err != nil || name != "moved" {
		t.Errorf("old row name = %q, %v; want it kept and marked", name, err)
	}
}

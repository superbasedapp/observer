package retention

import (
	"context"
	"database/sql"
	"testing"
)

// actionIDOf returns the id of the one action in a seeded session.
func actionIDOf(t *testing.T, d *sql.DB, session string) int64 {
	t.Helper()
	var id int64
	if err := d.QueryRow(`SELECT id FROM actions WHERE session_id = ?`, session).Scan(&id); err != nil {
		t.Fatalf("action of %s: %v", session, err)
	}
	return id
}

// TestRun_AgePruningDeletesDerivedRows pins MISC2-02: the lines-of-code
// (file_changes) and todo-transition (task_transitions) rows keyed to an
// aged action are deleted with it, in the batch's transaction, as the
// component purge already does. Neither table has a foreign key to actions,
// so before this they outlived the action as orphans. A fresh action keeps
// its rows, and an editor-save file_changes row (no action_id) is untouched.
func TestRun_AgePruningDeletesDerivedRows(t *testing.T) {
	ctx := context.Background()
	dbPath, _ := seed(t) // sess-a at -200d, sess-b at -90d, sess-c at -10d
	d := openExisting(t, dbPath)

	aged, fresh := actionIDOf(t, d, "sess-a"), actionIDOf(t, d, "sess-c")
	var project int64
	if err := d.QueryRow(`SELECT project_id FROM actions WHERE id = ?`, aged).Scan(&project); err != nil {
		t.Fatal(err)
	}
	for _, r := range []struct {
		session  any
		actionID any
		hash     string
		source   string
		actor    string
	}{
		{"sess-a", aged, "h-aged", "edit", "ai"},
		{"sess-a", aged, "h-aged-2", "patch", "ai"},
		{"sess-c", fresh, "h-fresh", "edit", "ai"},
		{nil, nil, "h-editor", "editor", "human"},
	} {
		if _, err := d.ExecContext(ctx, `INSERT INTO file_changes
			(session_id, project_id, action_id, file_path_hash, actor, source, saved_at, created_at)
			VALUES (?, ?, ?, ?, ?, ?, '2025-09-01T00:00:00Z', '2025-09-01T00:00:00Z')`,
			r.session, project, r.actionID, r.hash, r.actor, r.source); err != nil {
			t.Fatalf("seed file_changes %s: %v", r.hash, err)
		}
	}
	for _, r := range []struct {
		session  string
		actionID int64
		key      string
	}{
		{"sess-a", aged, "task-aged"},
		{"sess-c", fresh, "task-fresh"},
	} {
		if _, err := d.ExecContext(ctx, `INSERT INTO task_transitions
			(session_id, key, from_status, to_status, ts, action_id, source_event_id)
			VALUES (?, ?, '', 'in_progress', '2025-09-01T00:00:00Z', ?, ?)`,
			r.session, r.key, r.actionID, "ev-"+r.key); err != nil {
			t.Fatalf("seed task_transitions %s: %v", r.key, err)
		}
	}

	res, err := New(d).Run(ctx, Options{MaxAgeDays: 100, DBPath: dbPath})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ActionsDeleted != 1 {
		t.Fatalf("actions deleted = %d, want 1 (the -200d one)", res.ActionsDeleted)
	}
	if res.FileChangesDeleted != 2 || res.TaskTransitionsDeleted != 1 {
		t.Errorf("FileChangesDeleted = %d, TaskTransitionsDeleted = %d; want 2 and 1", res.FileChangesDeleted, res.TaskTransitionsDeleted)
	}
	count := func(q string, args ...any) int {
		t.Helper()
		var n int
		if err := d.QueryRow(q, args...).Scan(&n); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return n
	}
	for _, c := range []struct {
		what string
		q    string
		args []any
		want int
	}{
		{"file_changes of the aged action", `SELECT COUNT(*) FROM file_changes WHERE action_id = ?`, []any{aged}, 0},
		{"task_transitions of the aged action", `SELECT COUNT(*) FROM task_transitions WHERE action_id = ?`, []any{aged}, 0},
		{"file_changes of the fresh action", `SELECT COUNT(*) FROM file_changes WHERE action_id = ?`, []any{fresh}, 1},
		{"task_transitions of the fresh action", `SELECT COUNT(*) FROM task_transitions WHERE action_id = ?`, []any{fresh}, 1},
		{"the editor-save row", `SELECT COUNT(*) FROM file_changes WHERE action_id IS NULL AND file_path_hash = 'h-editor'`, nil, 1},
		{"orphans of any action", `SELECT
			(SELECT COUNT(*) FROM file_changes WHERE action_id IS NOT NULL AND action_id NOT IN (SELECT id FROM actions)) +
			(SELECT COUNT(*) FROM task_transitions WHERE action_id IS NOT NULL AND action_id NOT IN (SELECT id FROM actions))`, nil, 0},
	} {
		if got := count(c.q, c.args...); got != c.want {
			t.Errorf("%s: %d rows, want %d", c.what, got, c.want)
		}
	}
}

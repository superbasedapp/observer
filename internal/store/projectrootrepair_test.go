package store

import (
	"context"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// skipOnWindowsHost skips tests whose canonical form is the WSL
// /mnt/<drive> shape: on a Windows host a drive path is already native.
func skipOnWindowsHost(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("canonical project roots are /mnt/<drive> on a POSIX host only")
	}
}

// TestCanonicalProjectRoot pins the one spelling a root is stored under.
// The rows mirror the live node's bad roots (anonymized).
func TestCanonicalProjectRoot(t *testing.T) {
	skipOnWindowsHost(t)
	t.Parallel()
	tests := []struct{ name, in, want string }{
		{"windows hook cwd", `D:\programsx\proj`, "/mnt/d/programsx/proj"},
		{"windows lowercase", `d:\programsx\proj`, "/mnt/d/programsx/proj"},
		{"windows forward", "D:/programsx/proj", "/mnt/d/programsx/proj"},
		{"uri fsPath", "/d:/programsx/proj", "/mnt/d/programsx/proj"},
		{"undecoded file uri", `file://C:\Users\u\proj`, "/mnt/c/Users/u/proj"},
		{"windows .git admin dir", `D:\programsx\proj\.git\worktrees`, "/mnt/d/programsx/proj"},
		{"native unchanged", "/home/u/proj", "/home/u/proj"},
		{"translated unchanged", "/mnt/d/programsx/proj", "/mnt/d/programsx/proj"},
		{"synthetic unchanged", "[antigravity]", "[antigravity]"},
		{"git bash shape unchanged", "/c/proj", "/c/proj"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := canonicalProjectRoot(tc.in); got != tc.want {
				t.Errorf("canonicalProjectRoot(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestIngestCanonicalizesForeignRoot pins the ingest seam: a Windows hook
// cwd and the adapter's translated root for the same directory land on ONE
// projects row, for tool events and token events alike.
func TestIngestCanonicalizesForeignRoot(t *testing.T) {
	skipOnWindowsHost(t)
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	events := []models.ToolEvent{
		{
			SourceFile: "claude-code:hook", SourceEventID: "h1", SessionID: "s-hook",
			ProjectRoot: `C:\Users\u\proj`, Timestamp: now, Tool: models.ToolClaudeCode,
			ActionType: models.ActionRunCommand, Target: "go test", Success: true,
		},
		{
			SourceFile: "/t/a.jsonl", SourceEventID: "w1", SessionID: "s-watch",
			ProjectRoot: "/mnt/c/Users/u/proj", Timestamp: now, Tool: models.ToolClaudeCode,
			ActionType: models.ActionRunCommand, Target: "go vet", Success: true,
		},
	}
	tokens := []models.TokenEvent{{
		SessionID: "s-tok", ProjectRoot: "file:///C:/Users/u/proj", Timestamp: now,
		Tool: models.ToolClaudeCode, Model: "m", InputTokens: 1, SourceFile: "/t/tok.jsonl", SourceEventID: "t1",
	}}
	if _, err := s.Ingest(ctx, events, tokens, IngestOptions{}); err != nil {
		t.Fatal(err)
	}

	var roots []string
	rows, err := s.db.QueryContext(ctx, `SELECT root_path FROM projects ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			t.Fatal(err)
		}
		roots = append(roots, r)
	}
	rows.Close()
	if want := []string{"/mnt/c/Users/u/proj"}; !reflect.DeepEqual(roots, want) {
		t.Fatalf("projects = %q, want %q", roots, want)
	}
	var distinct int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(DISTINCT project_id) FROM sessions WHERE id IN ('s-hook','s-watch','s-tok')`).Scan(&distinct); err != nil {
		t.Fatal(err)
	}
	if distinct != 1 {
		t.Errorf("sessions span %d projects, want 1", distinct)
	}
}

// TestPlanProjectRootRepairs is the planner's rule table, one row per
// shape found on the live node.
func TestPlanProjectRootRepairs(t *testing.T) {
	skipOnWindowsHost(t)
	t.Parallel()
	rows := []ForeignProjectRootRow{
		{1, "/mnt/d/programsx/proj"},
		{2, `D:\programsx\proj`}, // twin exists -> merge
		{3, "d:/programsx/proj"}, // same twin -> merge
		{4, `C:\Users\u`},        // no twin -> rename
		{5, `c:\users\u`},        // differs only in case -> its own rename (POSIX keys are case-sensitive)
		{6, `/home/u/file:/C:\Users\u\probe`},
		{7, "/mnt/c/Users/u/probe"}, // twin of row 6
		{8, `E:\new`},               // two bad rows, no twin:
		{9, "E:/new"},               //   lowest id renames, the rest merge into it
		{10, `C:Users\u\AppData`},   // drive-relative: no host spelling
		{11, "[antigravity]"},
		{12, "/home/u/proj"},
	}
	repairs, unrepaired := planProjectRootRepairs(rows)
	want := []ProjectRootRepair{
		{ProjectID: 2, Root: `D:\programsx\proj`, NewRoot: "/mnt/d/programsx/proj", Action: RepairMerge, TwinID: 1},
		{ProjectID: 3, Root: "d:/programsx/proj", NewRoot: "/mnt/d/programsx/proj", Action: RepairMerge, TwinID: 1},
		{ProjectID: 4, Root: `C:\Users\u`, NewRoot: "/mnt/c/Users/u", Action: RepairRename},
		{ProjectID: 5, Root: `c:\users\u`, NewRoot: "/mnt/c/users/u", Action: RepairRename},
		{ProjectID: 6, Root: `/home/u/file:/C:\Users\u\probe`, NewRoot: "/mnt/c/Users/u/probe", Action: RepairMerge, TwinID: 7},
		{ProjectID: 8, Root: `E:\new`, NewRoot: "/mnt/e/new", Action: RepairRename},
		{ProjectID: 9, Root: "E:/new", NewRoot: "/mnt/e/new", Action: RepairMerge, TwinID: 8},
	}
	if !reflect.DeepEqual(repairs, want) {
		t.Errorf("repairs =\n%+v\nwant\n%+v", repairs, want)
	}
	if wantU := []ForeignProjectRootRow{{10, `C:Users\u\AppData`}}; !reflect.DeepEqual(unrepaired, wantU) {
		t.Errorf("unrepaired = %+v, want %+v", unrepaired, wantU)
	}
}

// TestRepairProjectRoots runs the repair end to end: the dry run reports
// exact counts and writes nothing; apply renames, merges (moving sessions
// and actions, dropping a colliding cache row) and deletes the bad rows.
func TestRepairProjectRoots(t *testing.T) {
	skipOnWindowsHost(t)
	t.Parallel()
	s, db := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// Seed bad rows the way a pre-fix build wrote them: straight SQL,
	// past the canonicalizing seam.
	insertRoot := func(root string) int64 {
		t.Helper()
		res, err := db.ExecContext(ctx,
			`INSERT INTO projects (root_path, created_at, root_path_hash) VALUES (?, ?, ?)`,
			root, timestamp(now), sha256Hex(root))
		if err != nil {
			t.Fatal(err)
		}
		id, _ := res.LastInsertId()
		return id
	}
	twin := insertRoot("/mnt/d/programsx/proj")
	bad := insertRoot(`D:\programsx\proj`)
	lone := insertRoot(`C:\Users\u`)

	for i, sp := range []struct {
		sid string
		pid int64
	}{{"s-twin", twin}, {"s-bad", bad}, {"s-lone", lone}} {
		if err := s.UpsertSession(ctx, models.Session{ID: sp.sid, ProjectID: sp.pid, Tool: models.ToolClaudeCode, StartedAt: now}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.InsertActions(ctx, []models.Action{{
			SessionID: sp.sid, ProjectID: sp.pid, Timestamp: now, ActionType: models.ActionRunCommand,
			Target: "go test", Success: true, Tool: models.ToolClaudeCode,
			SourceFile: "f.jsonl", SourceEventID: "e" + string(rune('0'+i)),
		}}); err != nil {
			t.Fatal(err)
		}
	}
	// file_state is unique on (project_id, file_path): the same file under
	// both rows collides on merge, and the twin's copy must win.
	for _, pid := range []int64{twin, bad} {
		if _, err := db.ExecContext(ctx, `INSERT INTO file_state
			(project_id, file_path, content_hash, file_mtime, file_size_bytes, last_action_type, last_seen_at)
			VALUES (?, 'main.go', ?, ?, 1, 'read_file', ?)`, pid, "h"+string(rune('0'+pid)), timestamp(now), timestamp(now)); err != nil {
			t.Fatal(err)
		}
	}

	wantRepairs := func(r ProjectRootRepairReport) {
		t.Helper()
		if len(r.Repairs) != 2 {
			t.Fatalf("repairs = %+v, want 2", r.Repairs)
		}
		m := r.Repairs[0]
		if m.ProjectID != bad || m.Action != RepairMerge || m.TwinID != twin {
			t.Errorf("merge = %+v", m)
		}
		if m.Repointed["sessions.project_id"] != 1 || m.Repointed["actions.project_id"] != 1 {
			t.Errorf("repointed = %v", m.Repointed)
		}
		if m.Collisions["file_state.project_id"] != 1 {
			t.Errorf("collisions = %v", m.Collisions)
		}
		if rn := r.Repairs[1]; rn.ProjectID != lone || rn.Action != RepairRename || rn.NewRoot != "/mnt/c/Users/u" {
			t.Errorf("rename = %+v", rn)
		}
	}

	dry, err := s.RepairProjectRoots(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	wantRepairs(dry)
	var n int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM projects`).Scan(&n); err != nil || n != 3 {
		t.Fatalf("after dry run: projects = %d (%v), want 3 untouched", n, err)
	}

	applied, err := s.RepairProjectRoots(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if !applied.Applied {
		t.Error("Applied = false")
	}
	wantRepairs(applied)

	var roots []string
	rows, err := db.QueryContext(ctx, `SELECT root_path FROM projects ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var r string
		_ = rows.Scan(&r)
		roots = append(roots, r)
	}
	rows.Close()
	if want := []string{"/mnt/d/programsx/proj", "/mnt/c/Users/u"}; !reflect.DeepEqual(roots, want) {
		t.Errorf("projects = %q, want %q", roots, want)
	}
	var sessPID, actPID int64
	if err := db.QueryRowContext(ctx, `SELECT project_id FROM sessions WHERE id = 's-bad'`).Scan(&sessPID); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT project_id FROM actions WHERE session_id = 's-bad'`).Scan(&actPID); err != nil {
		t.Fatal(err)
	}
	if sessPID != twin || actPID != twin {
		t.Errorf("merged refs: session %d action %d, want %d", sessPID, actPID, twin)
	}
	var hash string
	if err := db.QueryRowContext(ctx, `SELECT content_hash FROM file_state WHERE project_id = ?`, twin).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if want := "h" + string(rune('0'+twin)); hash != want {
		t.Errorf("file_state kept %q, want the twin's %q", hash, want)
	}

	// Idempotent: a second run finds nothing.
	again, err := s.RepairProjectRoots(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Repairs) != 0 {
		t.Errorf("second run repairs = %+v", again.Repairs)
	}
}

package store

import (
	"context"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestUpsertProjectFoldsWindowsCase (WINNODE2 item 11): one Windows folder
// reported with a lower-case and an upper-case drive letter (or any other
// case difference) is one project; the first spelling stored is kept. A
// POSIX path stays case-sensitive. On a non-Windows host a Windows path is
// first translated to its /mnt/<drive> spelling (pathnorm.NormalizeForeign),
// which folds the drive letter only; the full case fold is a Windows-host
// behaviour (run this test on Windows too).
func TestUpsertProjectFoldsWindowsCase(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	cases := []struct {
		first, second string
		same          bool
	}{
		{`C:\Users\developer\projects\payments-api`, `c:\Users\developer\projects\payments-api`, true},
		{`c:\Users\developer\projects\acme-api`, `C:\USERS\developer\projects\acme-api`, runtime.GOOS == "windows"},
		{`/home/dev/Project`, `/home/dev/project`, false},
	}
	for _, tc := range cases {
		a, err := s.UpsertProject(ctx, tc.first, "")
		if err != nil {
			t.Fatal(err)
		}
		b, err := s.UpsertProject(ctx, tc.second, "")
		if err != nil {
			t.Fatal(err)
		}
		if (a == b) != tc.same {
			t.Fatalf("%q and %q: ids %d and %d, want same=%v", tc.first, tc.second, a, b, tc.same)
		}
	}
	if runtime.GOOS != "windows" {
		return
	}
	// A new lower-case drive letter is stored upper-cased.
	id, err := s.UpsertProject(ctx, `d:\work\fresh`, "")
	if err != nil {
		t.Fatal(err)
	}
	var root string
	if err := s.db.QueryRowContext(ctx, `SELECT root_path FROM projects WHERE id = ?`, id).Scan(&root); err != nil || root != `D:\work\fresh` {
		t.Fatalf("stored root = %q (%v), want D:\\work\\fresh", root, err)
	}
}

// TestMergeCaseDuplicateProjects seeds the demo node's two rows for one
// folder (id 1 `C:\...`, a later `c:\...`) plus children, and an unrelated
// project: every child of the duplicate moves to the oldest row, a row the
// survivor already holds under a unique key is dropped (the survivor's
// wins), the duplicate is deleted, nothing else changes, and a second run
// does nothing.
func TestMergeCaseDuplicateProjects(t *testing.T) {
	s, database := newTestStore(t)
	ctx := context.Background()
	insertProject := func(root string) int64 {
		res, err := database.ExecContext(ctx,
			`INSERT INTO projects (root_path, created_at, root_path_hash) VALUES (?, ?, ?)`,
			root, timestamp(time.Now()), sha256Hex(root))
		if err != nil {
			t.Fatal(err)
		}
		id, _ := res.LastInsertId()
		return id
	}
	keep := insertProject(`C:\Users\developer\projects\payments-api`)
	other := insertProject(`C:\Users\developer\projects\acme-api`)
	dup := insertProject(`c:\Users\developer\projects\payments-api`)
	at := time.Date(2026, 10, 28, 13, 0, 0, 0, time.UTC)
	seed := func(pid int64, sid string, n int) {
		if err := s.UpsertSession(ctx, models.Session{ID: sid, ProjectID: pid, Tool: "claude-code", StartedAt: at}); err != nil {
			t.Fatal(err)
		}
		var acts []models.Action
		for i := 0; i < n; i++ {
			acts = append(acts, models.Action{
				SessionID: sid, ProjectID: pid, Timestamp: at, ActionType: "read_file",
				Tool: "claude-code", SourceFile: "seed", SourceEventID: fmt.Sprintf("%s-%d", sid, i),
			})
		}
		if _, err := s.InsertActions(ctx, acts); err != nil {
			t.Fatal(err)
		}
	}
	seed(keep, "s-keep", 2)
	seed(other, "s-other", 1)
	seed(dup, "s-dup", 3)
	for _, pid := range []int64{keep, dup} {
		if _, err := database.ExecContext(ctx,
			`INSERT INTO delivery_project_settings (project_id, mirror_enabled, updated_at) VALUES (?, ?, ?)`,
			pid, pid == dup, timestamp(at)); err != nil {
			t.Fatal(err)
		}
	}

	merges, err := s.MergeCaseDuplicateProjects(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(merges) != 1 || merges[0].ProjectID != dup || merges[0].TwinID != keep {
		t.Fatalf("merges = %+v, want the duplicate folded into the oldest row", merges)
	}
	count := func(q string, args ...any) int {
		var n int
		if err := database.QueryRowContext(ctx, q, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := count(`SELECT COUNT(*) FROM projects WHERE id = ?`, dup); n != 0 {
		t.Fatal("the duplicate project row survived")
	}
	if n := count(`SELECT COUNT(*) FROM sessions WHERE project_id = ?`, keep); n != 2 {
		t.Fatalf("survivor sessions = %d, want 2", n)
	}
	if n := count(`SELECT COUNT(*) FROM actions WHERE project_id = ?`, keep); n != 5 {
		t.Fatalf("survivor actions = %d, want 5", n)
	}
	if n := count(`SELECT COUNT(*) FROM delivery_project_settings WHERE project_id = ? AND mirror_enabled = 0`, keep); n != 1 {
		t.Fatal("the survivor's own unique-keyed row did not win")
	}
	for _, q := range []string{
		`SELECT COUNT(*) FROM sessions WHERE project_id = ?`,
		`SELECT COUNT(*) FROM actions WHERE project_id = ?`,
		`SELECT COUNT(*) FROM delivery_project_settings WHERE project_id = ?`,
	} {
		if n := count(q, dup); n != 0 {
			t.Fatalf("%s left %d rows on the duplicate", q, n)
		}
	}
	// Nothing else changed.
	if n := count(`SELECT COUNT(*) FROM actions WHERE project_id = ? AND session_id = 's-other'`, other); n != 1 {
		t.Fatal("the unrelated project's rows changed")
	}
	var root, hash string
	if err := database.QueryRowContext(ctx, `SELECT root_path, root_path_hash FROM projects WHERE id = ?`, keep).Scan(&root, &hash); err != nil {
		t.Fatal(err)
	}
	if root != `C:\Users\developer\projects\payments-api` || hash != sha256Hex(root) {
		t.Fatalf("survivor identity changed: %q %q", root, hash)
	}
	again, err := s.MergeCaseDuplicateProjects(ctx)
	if err != nil || len(again) != 0 {
		t.Fatalf("second run = %+v, %v; want nothing to do", again, err)
	}
}

// TestPlanCaseDuplicateProjects pins the pure plan, one case per row: only
// Windows-shaped roots fold, the oldest id survives whatever its spelling,
// and distinct folders never merge.
func TestPlanCaseDuplicateProjects(t *testing.T) {
	rows := []ForeignProjectRootRow{
		{ID: 9, Root: `C:\x\Repo`},
		{ID: 4, Root: `c:\x\repo`},
		{ID: 5, Root: `C:\x\elsewhere`},
		{ID: 6, Root: `/home/a/Repo`},
		{ID: 7, Root: `/home/a/repo`},
		{ID: 8, Root: `\\fs\Share\p`},
		{ID: 10, Root: `\\FS\share\P`},
	}
	got := planCaseDuplicateProjects(rows)
	want := map[int64]int64{9: 4, 10: 8}
	if len(got) != len(want) {
		t.Fatalf("plan = %+v, want %d merges", got, len(want))
	}
	for _, m := range got {
		if want[m.ProjectID] != m.TwinID || m.Action != RepairMerge {
			t.Fatalf("merge %+v, want %d -> %d", m, m.ProjectID, want[m.ProjectID])
		}
	}
}

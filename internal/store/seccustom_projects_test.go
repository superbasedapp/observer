package store

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// TestRecentActiveProjectRoots: the cap keeps the most recently active projects,
// newest first, not the lowest ids; a project with only an old session is
// left out; a session that ended recently counts as recent activity.
func TestRecentActiveProjectRoots(t *testing.T) {
	t.Parallel()
	s, database := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	ids := map[string]int64{}
	for i := 0; i < 5; i++ {
		root := fmt.Sprintf("/repo/p%d", i)
		id, err := s.UpsertProject(ctx, root, "")
		if err != nil {
			t.Fatal(err)
		}
		ids[root] = id
	}
	insert := func(sid, root string, started time.Time, ended *time.Time) {
		t.Helper()
		var end any
		if ended != nil {
			end = ended.Format(time.RFC3339Nano)
		}
		if _, err := database.ExecContext(ctx,
			`INSERT INTO sessions (id, project_id, tool, started_at, ended_at) VALUES (?, ?, 'claude-code', ?, ?)`,
			sid, ids[root], started.Format(time.RFC3339Nano), end); err != nil {
			t.Fatal(err)
		}
	}
	// p0 (the oldest id) was last active 6 days ago; p4 an hour ago.
	insert("a", "/repo/p0", now.Add(-6*24*time.Hour), nil)
	insert("b", "/repo/p1", now.Add(-5*24*time.Hour), nil)
	insert("c", "/repo/p2", now.Add(-3*24*time.Hour), nil)
	insert("c2", "/repo/p2", now.Add(-4*24*time.Hour), nil)
	insert("d", "/repo/p3", now.Add(-90*24*time.Hour), nil) // outside the window
	insert("e", "/repo/p4", now.Add(-time.Hour), nil)
	// p1's session started 5 days ago but ended 10 minutes ago.
	ended := now.Add(-10 * time.Minute)
	insert("f", "/repo/p1", now.Add(-5*24*time.Hour+time.Second), &ended)

	got, err := s.RecentActiveProjectRoots(ctx, 7, 3)
	if err != nil {
		t.Fatal(err)
	}
	var roots []string
	for _, r := range got {
		roots = append(roots, r.RootPath)
	}
	want := []string{"/repo/p1", "/repo/p4", "/repo/p2"}
	if fmt.Sprint(roots) != fmt.Sprint(want) {
		t.Fatalf("RecentActiveProjectRoots(7, 3) = %v, want %v", roots, want)
	}
	all, err := s.RecentActiveProjectRoots(ctx, 7, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 4 {
		t.Fatalf("no cap: %d roots, want 4 (p3 is outside the window)", len(all))
	}
}

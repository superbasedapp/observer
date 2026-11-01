package store

import (
	"context"
	"testing"
	"time"
)

// TestMergeCaseDuplicateProjectsCountsRootKeyedRows (WINNODE2 merge, audit
// M1): a fold counts, per table, the rows that name the duplicate project
// by its old root spelling or that spelling's hash, including the security
// tables, the organization's AI tool settings state and the codeintel
// graph. They are counted and left as they are (no row rewrite).
func TestMergeCaseDuplicateProjectsCountsRootKeyedRows(t *testing.T) {
	s, database := newTestStore(t)
	ctx := context.Background()
	now := timestamp(time.Date(2026, 10, 28, 13, 0, 0, 0, time.UTC))
	insertProject := func(root string) {
		if _, err := database.ExecContext(ctx,
			`INSERT INTO projects (root_path, created_at, root_path_hash) VALUES (?, ?, ?)`,
			root, now, sha256Hex(root)); err != nil {
			t.Fatal(err)
		}
	}
	const keep, dup = `C:\Users\developer\projects\payments-api`, `c:\Users\developer\projects\payments-api`
	insertProject(keep)
	insertProject(dup)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := database.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	exec(`INSERT INTO sec_change_consent (project_root_hash, root_path) VALUES (?, ?)`, sha256Hex(dup), dup)
	exec(`INSERT INTO sec_config_baseline (project_root_hash, content_hash, rel_path, first_seen_at, last_seen_at)
	      VALUES (?, 'h1', '.claude/settings.json', ?, ?)`, sha256Hex(dup), now, now)
	exec(`INSERT INTO agent_config_org_state (setting_id, file_id, project_root, tool, state, observed_at) VALUES ('s', 'f', ?, 'claude-code', 'ok', ?)`, dup, now)
	exec(`INSERT INTO codeintel_files (project, path) VALUES (?, ?)`, dup, dup+`\main.go`)
	var fileID int64
	if err := database.QueryRowContext(ctx, `SELECT id FROM codeintel_files WHERE project = ?`, dup).Scan(&fileID); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO codeintel_nodes (project, file_id, name) VALUES (?, ?, 'main')`, dup, fileID)
	exec(`INSERT INTO codeintel_nodes (project, file_id, name) VALUES (?, ?, 'run')`, dup, fileID)

	merges, err := s.MergeCaseDuplicateProjects(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(merges) != 1 {
		t.Fatalf("merges = %+v, want one fold", merges)
	}
	want := map[string]int64{
		"sec_change_consent.project_root_hash":  1,
		"sec_config_baseline.project_root_hash": 1,
		"agent_config_org_state.project_root":   1,
		"codeintel_files.project":               1,
		"codeintel_nodes.project":               2,
	}
	got := merges[0].RootKeyed
	for k, n := range want {
		if got[k] != n {
			t.Fatalf("RootKeyed[%s] = %d, want %d (all: %v)", k, got[k], n, got)
		}
	}
	// Counted only: the rows still carry the old spelling.
	var n int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM codeintel_nodes WHERE project = ?`, dup).Scan(&n); err != nil || n != 2 {
		t.Fatalf("codeintel_nodes on the old spelling = %d (err %v), want 2 (no rewrite)", n, err)
	}
}

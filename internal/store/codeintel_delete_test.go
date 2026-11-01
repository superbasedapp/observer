//go:build !sbo_omit_codeintel

package store

import (
	"context"
	"path/filepath"
	"testing"
)

// TestCodeIntelDeleteProject_AllTablesAndIsolation verifies the explicit
// per-table delete removes EVERY codeintel_* row for the target project
// (including codeintel_fts, which has no FK and the old cascade-only delete
// leaked) while leaving other projects untouched, and that FK enforcement is
// restored on the pinned connection afterward.
func TestCodeIntelDeleteProject_AllTablesAndIsolation(t *testing.T) {
	s, database := newTestStore(t)
	// Pin to one connection so the delete's foreign_keys toggle and the
	// follow-up FK-restored assertion exercise the SAME connection.
	database.SetMaxOpenConns(1)
	ctx := context.Background()

	tables := []string{
		"codeintel_files", "codeintel_nodes", "codeintel_edges",
		"codeintel_sites", "codeintel_minhash", "codeintel_embeddings",
		"codeintel_fts",
	}

	seed := func(project string) {
		t.Helper()
		rf, err := database.ExecContext(ctx,
			`INSERT INTO codeintel_files(project, path, lang, status) VALUES(?, ?, 'go', 'indexed')`,
			project, project+"/a.go")
		if err != nil {
			t.Fatalf("seed file: %v", err)
		}
		fid, _ := rf.LastInsertId()
		rn, err := database.ExecContext(ctx,
			`INSERT INTO codeintel_nodes(project, file_id, kind, name) VALUES(?, ?, 'function', 'Foo')`,
			project, fid)
		if err != nil {
			t.Fatalf("seed node: %v", err)
		}
		nid, _ := rn.LastInsertId()
		re, err := database.ExecContext(ctx,
			`INSERT INTO codeintel_edges(project, file_id, src_id, dst_id, kind) VALUES(?, ?, ?, ?, 'CALLS')`,
			project, fid, nid, nid)
		if err != nil {
			t.Fatalf("seed edge: %v", err)
		}
		eid, _ := re.LastInsertId()
		if _, err := database.ExecContext(ctx,
			`INSERT INTO codeintel_sites(project, edge_id, file_id, target_name) VALUES(?, ?, ?, 'Foo')`,
			project, eid, fid); err != nil {
			t.Fatalf("seed site: %v", err)
		}
		if _, err := database.ExecContext(ctx,
			`INSERT INTO codeintel_minhash(node_id, project, band, hash) VALUES(?, ?, 0, 123)`,
			nid, project); err != nil {
			t.Fatalf("seed minhash: %v", err)
		}
		if _, err := database.ExecContext(ctx,
			`INSERT INTO codeintel_embeddings(node_id, project, dim, vec) VALUES(?, ?, 8, x'0000000000000000')`,
			nid, project); err != nil {
			t.Fatalf("seed embedding: %v", err)
		}
		if _, err := database.ExecContext(ctx,
			`INSERT INTO codeintel_fts(tokens, node_id, project, name) VALUES('foo', ?, ?, 'Foo')`,
			nid, project); err != nil {
			t.Fatalf("seed fts: %v", err)
		}
	}

	seed("/p/keep")
	seed("/p/drop")

	if err := s.CodeIntelDeleteProject(ctx, "/p/drop"); err != nil {
		t.Fatalf("CodeIntelDeleteProject: %v", err)
	}

	count := func(tbl, project string) int {
		var n int
		if err := database.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM "+tbl+" WHERE project = ?", project).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", tbl, err)
		}
		return n
	}
	for _, tbl := range tables {
		if n := count(tbl, "/p/drop"); n != 0 {
			t.Errorf("%s: dropped project still has %d row(s)", tbl, n)
		}
		if n := count(tbl, "/p/keep"); n != 1 {
			t.Errorf("%s: kept project has %d row(s), want 1 (delete bled across projects)", tbl, n)
		}
	}

	// FK enforcement must be back on the (reused) connection: inserting a
	// node referencing a non-existent file_id must be rejected.
	if _, err := database.ExecContext(ctx,
		`INSERT INTO codeintel_nodes(project, file_id, name) VALUES('/p/x', 999999, 'Orphan')`); err == nil {
		t.Error("foreign_keys not restored after delete — orphan node insert succeeded")
	}
}

// TestCodeIntelDeleteProjectsUnder verifies the recursive un-index sweeps
// the exact root plus every nested descendant project, but respects path
// boundaries: a sibling that merely shares a string prefix ("/pxtra" vs
// "/p") is left untouched.
func TestCodeIntelDeleteProjectsUnder(t *testing.T) {
	s, database := newTestStore(t)
	ctx := context.Background()

	seedFile := func(project string) {
		t.Helper()
		if _, err := database.ExecContext(ctx,
			`INSERT INTO codeintel_files(project, path, lang, status) VALUES(?, ?, 'go', 'indexed')`,
			project, project+"/a.go"); err != nil {
			t.Fatalf("seed %s: %v", project, err)
		}
	}
	// Project keys are native paths (index.IndexProject keys a project by
	// filepath.Abs), so the fixture spells them with the OS separator. On
	// Windows the boundary is a backslash, and "/p/a" is not a key the
	// indexer ever writes there.
	k := filepath.FromSlash
	root, a, bc, other, pxtra := k("/p"), k("/p/a"), k("/p/b/c"), k("/other"), k("/pxtra")
	for _, p := range []string{root, a, bc, other, pxtra} {
		seedFile(p)
	}

	deleted, err := s.CodeIntelDeleteProjectsUnder(ctx, root)
	if err != nil {
		t.Fatalf("CodeIntelDeleteProjectsUnder: %v", err)
	}

	wantDeleted := map[string]bool{root: true, a: true, bc: true}
	if len(deleted) != len(wantDeleted) {
		t.Fatalf("deleted %v, want the 3 keys %v", deleted, wantDeleted)
	}
	for _, p := range deleted {
		if !wantDeleted[p] {
			t.Errorf("unexpected deleted project %q", p)
		}
	}

	remaining, err := s.CodeIntelListProjects(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	got := map[string]bool{}
	for _, p := range remaining {
		got[p] = true
	}
	if !got[other] || !got[pxtra] {
		t.Errorf("recursive delete removed a sibling: remaining=%v", remaining)
	}
	if got[root] || got[a] || got[bc] {
		t.Errorf("recursive delete left a target behind: remaining=%v", remaining)
	}
}

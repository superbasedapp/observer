package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/processobs"
)

// bytesByTable folds a StorageStats (dbstat) report into a name→bytes map so
// a test can assert per-table on-disk footprint deltas.
func bytesByTable(ctx context.Context, t *testing.T, database *sql.DB) map[string]int64 {
	t.Helper()
	rep, err := db.StorageStats(ctx, database)
	if err != nil {
		t.Fatalf("StorageStats: %v", err)
	}
	m := map[string]int64{}
	for _, tbl := range rep.Tables {
		m[tbl.Name] = tbl.Bytes
	}
	return m
}

// TestPruneReclaimsCodeIntelAndProcessBulk is the end-to-end reclamation
// proof for `observer prune`: it seeds a large stale codeintel project and a
// batch of old process rows, snapshots per-table storage via dbstat, runs the
// two heavy sweeps + a WAL checkpoint + VACUUM, and asserts the bulk tables
// actually shrank on disk (not merely that rows were deleted). This is the
// guard that the codeintel GC cascades to the embeddings bulk (the auzy_ leak
// that deleted only files) and that process retention reclaims process_runs.
func TestPruneReclaimsCodeIntelAndProcessBulk(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "reclaim.db")
	database, err := dbtemplate.Open(ctx, db.Options{Path: path})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer database.Close()
	s := New(database)

	// Disable auto-checkpoint so the WAL grows unbounded from the seeding
	// below — this lets the test prove that an explicit wal_checkpoint(
	// TRUNCATE) (the step added to `observer prune`) actually reclaims it,
	// deterministically, rather than racing the background auto-checkpoint.
	if _, err := database.ExecContext(ctx, `PRAGMA wal_autocheckpoint=0`); err != nil {
		t.Fatalf("disable autocheckpoint: %v", err)
	}

	now := time.Now().Unix()
	const day = int64(24 * 60 * 60)

	// A stale project (indexed 200 days ago) with a large embeddings table,
	// and a fresh project that must survive.
	seedCodeIntelProject(ctx, t, s, "/p/stale", now-200*day)
	seedCodeIntelProject(ctx, t, s, "/p/fresh", now-2*day)
	seedBulkEmbeddings(ctx, t, database, "/p/stale", 1200) // ~4.8MB of blobs
	seedBulkEmbeddings(ctx, t, database, "/p/fresh", 50)

	// Old + fresh process_runs (the 30-day horizon takes the old ones).
	sess, pid0 := mustProjectAndSession(t, s)
	var runs []processobs.ProcessRun
	for i := 0; i < 400; i++ {
		runs = append(runs, execRun(
			fmt.Sprintf("reclaim-old-%d", i), sess, pid0, 5000+i, t0Proc().Add(-100*24*time.Hour),
		))
	}
	for i := 0; i < 20; i++ {
		runs = append(runs, execRun(
			fmt.Sprintf("reclaim-new-%d", i), sess, pid0, 9000+i, time.Now().UTC(),
		))
	}
	if _, err := s.PersistRuns(ctx, runs); err != nil {
		t.Fatalf("PersistRuns: %v", err)
	}

	// With auto-checkpoint disabled, the seeding above has grown the WAL.
	// Prove the explicit TRUNCATE checkpoint reclaims it.
	walGrown := fileSize(path + "-wal")
	if walGrown == 0 {
		t.Fatalf("expected a non-empty WAL after seeding with autocheckpoint off")
	}
	if _, err := database.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatalf("checkpoint (pre): %v", err)
	}
	walTruncated := fileSize(path + "-wal")
	if walTruncated >= walGrown {
		t.Errorf("wal_checkpoint(TRUNCATE) did not reclaim WAL: %d → %d bytes", walGrown, walTruncated)
	}
	before := bytesByTable(ctx, t, database)

	// The two heavy sweeps under test.
	deleted, err := s.CodeIntelPruneStaleProjects(ctx, 90)
	if err != nil {
		t.Fatalf("CodeIntelPruneStaleProjects: %v", err)
	}
	if len(deleted) != 1 || deleted[0] != "/p/stale" {
		t.Fatalf("codeintel pruned %v, want [/p/stale]", deleted)
	}
	if _, err := s.PruneProcessRows(ctx, 30); err != nil {
		t.Fatalf("PruneProcessRows: %v", err)
	}

	// WAL checkpoint (the step added to `observer prune`) + VACUUM to return
	// freed pages to the OS, mirroring `observer prune --vacuum`.
	if _, err := database.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	if _, err := database.ExecContext(ctx, `VACUUM`); err != nil {
		t.Fatalf("VACUUM: %v", err)
	}
	after := bytesByTable(ctx, t, database)

	// codeintel_embeddings must shrink to (near) the fresh project's small
	// footprint — proof the GC cascaded to the embeddings bulk.
	if after["codeintel_embeddings"] >= before["codeintel_embeddings"] {
		t.Errorf("codeintel_embeddings did not shrink: before=%d after=%d",
			before["codeintel_embeddings"], after["codeintel_embeddings"])
	}
	if got := after["codeintel_embeddings"]; got > before["codeintel_embeddings"]/2 {
		t.Errorf("codeintel_embeddings reclaimed <50%%: before=%d after=%d", before["codeintel_embeddings"], got)
	}
	// process_runs must shrink too.
	if after["process_runs"] >= before["process_runs"] {
		t.Errorf("process_runs did not shrink: before=%d after=%d",
			before["process_runs"], after["process_runs"])
	}
	// The fresh codeintel project's rows survive.
	var freshEmb int
	if err := database.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM codeintel_embeddings WHERE project = '/p/fresh'`).Scan(&freshEmb); err != nil {
		t.Fatalf("count fresh: %v", err)
	}
	if freshEmb != 51 { // 1 from seedCodeIntelProject + 50 bulk
		t.Errorf("fresh project embeddings = %d, want 51 (survivors)", freshEmb)
	}
	// The stale project is entirely gone from every codeintel table.
	for _, tbl := range []string{"codeintel_files", "codeintel_nodes", "codeintel_embeddings", "codeintel_edges", "codeintel_sites"} {
		var n int
		if err := database.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM "+tbl+" WHERE project = '/p/stale'").Scan(&n); err != nil {
			t.Fatalf("count %s: %v", tbl, err)
		}
		if n != 0 {
			t.Errorf("%s still has %d stale rows", tbl, n)
		}
	}
	t.Logf("reclaimed embeddings %d→%d bytes, process_runs %d→%d bytes, wal checkpoint %d→%d bytes",
		before["codeintel_embeddings"], after["codeintel_embeddings"],
		before["process_runs"], after["process_runs"], walGrown, walTruncated)
}

// seedBulkEmbeddings inserts n (node, embedding) pairs for project — each
// embedding a distinct 4KB blob on its own node, since
// codeintel_embeddings.node_id is UNIQUE (one vector per symbol). This is what
// makes the table large enough to prove on-disk reclamation.
func seedBulkEmbeddings(ctx context.Context, t *testing.T, database *sql.DB, project string, n int) {
	t.Helper()
	var fileID int64
	if err := database.QueryRowContext(ctx,
		`SELECT id FROM codeintel_files WHERE project = ? LIMIT 1`, project).Scan(&fileID); err != nil {
		t.Fatalf("seedBulkEmbeddings: find file: %v", err)
	}
	blob := make([]byte, 4096)
	for i := range blob {
		blob[i] = byte(i)
	}
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("seedBulkEmbeddings: begin: %v", err)
	}
	nodeStmt, err := tx.PrepareContext(ctx,
		`INSERT INTO codeintel_nodes(project, file_id, kind, name) VALUES(?, ?, 'function', ?)`)
	if err != nil {
		t.Fatalf("seedBulkEmbeddings: prepare node: %v", err)
	}
	embStmt, err := tx.PrepareContext(ctx,
		`INSERT INTO codeintel_embeddings(node_id, project, dim, vec) VALUES(?, ?, 1024, ?)`)
	if err != nil {
		t.Fatalf("seedBulkEmbeddings: prepare emb: %v", err)
	}
	for i := 0; i < n; i++ {
		r, err := nodeStmt.ExecContext(ctx, project, fileID, fmt.Sprintf("Fn%d", i))
		if err != nil {
			t.Fatalf("seedBulkEmbeddings: insert node: %v", err)
		}
		nid, _ := r.LastInsertId()
		if _, err := embStmt.ExecContext(ctx, nid, project, blob); err != nil {
			t.Fatalf("seedBulkEmbeddings: insert emb: %v", err)
		}
	}
	nodeStmt.Close()
	embStmt.Close()
	if err := tx.Commit(); err != nil {
		t.Fatalf("seedBulkEmbeddings: commit: %v", err)
	}
}

func fileSize(path string) int64 {
	fi, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return fi.Size()
}

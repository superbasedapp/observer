package archivesvc_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/archive"
	"github.com/marmutapp/superbased-observer/internal/archivestore"
	"github.com/marmutapp/superbased-observer/internal/archivesvc"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// rig is one hot DB + one archive DB, wired into a Mover, on temp files.
type rig struct {
	hot   *sql.DB
	store *store.Store
	cold  *archivestore.Store
	mover *archivesvc.Mover
}

func newRig(t *testing.T) *rig {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	hot, err := db.Open(ctx, db.Options{Path: filepath.Join(dir, "observer.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = hot.Close() })
	cold, err := archivestore.Open(ctx, archivestore.Options{Path: filepath.Join(dir, "archive.db")})
	if err != nil {
		t.Fatalf("archivestore.Open: %v", err)
	}
	t.Cleanup(func() { _ = cold.Close() })
	st := store.New(hot)
	return &rig{
		hot:   hot,
		store: st,
		cold:  cold,
		mover: &archivesvc.Mover{Hot: st, Cold: cold, BatchRows: 2},
	}
}

// seedProject writes a small but structurally complete codeintel project:
// files, nodes, edges, sites, embeddings, minhash AND the derived FTS rows, so
// the test exercises the same fan-out a real project has — including the
// virtual FTS table that has no foreign key and is easy to leak.
func seedProject(t *testing.T, hot *sql.DB, project string, indexedAt int64, files int) {
	t.Helper()
	ctx := context.Background()
	for f := 0; f < files; f++ {
		path := fmt.Sprintf("%s/file%d.go", project, f)
		res, err := hot.ExecContext(ctx,
			`INSERT INTO codeintel_files (project, path, lang, content_hash, mtime, indexed_at, parser, status)
			 VALUES (?,?,'go',?,?,?,'goast','indexed')`,
			project, path, fmt.Sprintf("hash-%d", f), 1000+f, indexedAt)
		if err != nil {
			t.Fatalf("seed file: %v", err)
		}
		fileID, err := res.LastInsertId()
		if err != nil {
			t.Fatalf("file id: %v", err)
		}
		for n := 0; n < 2; n++ {
			nres, err := hot.ExecContext(ctx,
				`INSERT INTO codeintel_nodes (project, file_id, kind, name, fqn, lang,
				   start_line, end_line, start_byte, end_byte, signature, sig_hash)
				 VALUES (?,?,'function',?,?,'go',?,?,?,?,?,?)`,
				project, fileID, fmt.Sprintf("Fn%d_%d", f, n), fmt.Sprintf("pkg.Fn%d_%d", f, n),
				n*10, n*10+5, n*100, n*100+40, fmt.Sprintf("func Fn%d_%d()", f, n), fmt.Sprintf("sig-%d-%d", f, n))
			if err != nil {
				t.Fatalf("seed node: %v", err)
			}
			nodeID, err := nres.LastInsertId()
			if err != nil {
				t.Fatalf("node id: %v", err)
			}
			eres, err := hot.ExecContext(ctx,
				`INSERT INTO codeintel_edges (project, file_id, src_id, dst_id, kind, confidence, resolver_backend)
				 VALUES (?,?,?,0,'CALLS',0.75,'name-matched')`, project, fileID, nodeID)
			if err != nil {
				t.Fatalf("seed edge: %v", err)
			}
			edgeID, err := eres.LastInsertId()
			if err != nil {
				t.Fatalf("edge id: %v", err)
			}
			if _, err := hot.ExecContext(ctx,
				`INSERT INTO codeintel_sites (project, edge_id, file_id, start_line, start_byte,
				   raw_text, target_name, resolver_backend, confidence, recv_type)
				 VALUES (?,?,?,?,?,?,?,'name-matched',0.5,'Recv')`,
				project, edgeID, fileID, n, n*7, fmt.Sprintf("callee%d()", n), fmt.Sprintf("callee%d", n)); err != nil {
				t.Fatalf("seed site: %v", err)
			}
			if _, err := hot.ExecContext(ctx,
				`INSERT INTO codeintel_embeddings (node_id, project, dim, vec) VALUES (?,?,4,?)`,
				nodeID, project, []byte{byte(f), byte(n), 3, 4}); err != nil {
				t.Fatalf("seed embedding: %v", err)
			}
			for band := 0; band < 2; band++ {
				if _, err := hot.ExecContext(ctx,
					`INSERT INTO codeintel_minhash (node_id, project, band, hash) VALUES (?,?,?,?)`,
					nodeID, project, band, int64(band*1000+n)); err != nil {
					t.Fatalf("seed minhash: %v", err)
				}
			}
			if _, err := hot.ExecContext(ctx,
				`INSERT INTO codeintel_fts (tokens, node_id, project, name, fqn, kind, lang, file, start_line, end_line)
				 VALUES (?,?,?,?,?,'function','go',?,?,?)`,
				fmt.Sprintf("fn %d %d", f, n), nodeID, project,
				fmt.Sprintf("Fn%d_%d", f, n), fmt.Sprintf("pkg.Fn%d_%d", f, n), path, n*10, n*10+5); err != nil {
				t.Fatalf("seed fts: %v", err)
			}
		}
	}
}

func countRows(t *testing.T, database *sql.DB, table, project string) int {
	t.Helper()
	var n int
	//nolint:gosec // table is a test-local literal.
	if err := database.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM `+table+` WHERE project = ?`, project).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

var hotCodeIntelTables = []string{
	"codeintel_files", "codeintel_nodes", "codeintel_edges",
	"codeintel_sites", "codeintel_embeddings", "codeintel_minhash", "codeintel_fts",
}

func hotCounts(t *testing.T, database *sql.DB, project string) map[string]int {
	t.Helper()
	out := make(map[string]int, len(hotCodeIntelTables))
	for _, tbl := range hotCodeIntelTables {
		out[tbl] = countRows(t, database, tbl, project)
	}
	return out
}

// TestArchiveMovesProjectAndLeavesNothingHot is the happy path end to end: the
// cold copy is byte-equivalent to what was hot, EVERY hot table (including the
// foreign-key-less FTS virtual table) is emptied for that project, and the
// marker records the truth.
func TestArchiveMovesProjectAndLeavesNothingHot(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	const project = "/repo/alpha"
	seedProject(t, r.hot, project, 1000, 3)

	before := hotCounts(t, r.hot, project)
	hotDigest, err := r.store.CodeIntelProjectDigest(ctx, project, 2)
	if err != nil {
		t.Fatalf("hot digest: %v", err)
	}

	out, err := r.mover.ArchiveCodeIntelProject(ctx, project)
	if err != nil {
		t.Fatalf("ArchiveCodeIntelProject: %v", err)
	}
	if out.Result != archivesvc.ResultArchived {
		t.Fatalf("result = %s, want archived", out.Result)
	}
	if out.RowsArchived != hotDigest.TotalRows() {
		t.Fatalf("RowsArchived = %d, want %d", out.RowsArchived, hotDigest.TotalRows())
	}

	for tbl, n := range hotCounts(t, r.hot, project) {
		if n != 0 {
			t.Errorf("%s still holds %d rows for the archived project (was %d)", tbl, n, before[tbl])
		}
	}

	coldDigest, err := r.cold.CodeIntelProjectDigest(ctx, project, 2)
	if err != nil {
		t.Fatalf("cold digest: %v", err)
	}
	if err := archive.Verify(hotDigest, coldDigest); err != nil {
		t.Fatalf("cold copy is not equivalent to what was hot: %v", err)
	}

	marker, found, err := r.store.CodeIntelArchivedProject(ctx, project)
	if err != nil {
		t.Fatalf("marker read: %v", err)
	}
	if !found {
		t.Fatal("no marker row — an archived project is now indistinguishable from a never-indexed one")
	}
	if marker.LastIndexedAt != 1000 {
		t.Errorf("marker.LastIndexedAt = %d, want the archived watermark 1000", marker.LastIndexedAt)
	}
	if marker.RowsArchived != hotDigest.TotalRows() {
		t.Errorf("marker.RowsArchived = %d, want %d", marker.RowsArchived, hotDigest.TotalRows())
	}
}

// TestArchiveDoesNotTouchOtherProjects pins the scoping: a move is per
// project, and a second indexed project must be entirely unaffected.
func TestArchiveDoesNotTouchOtherProjects(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	seedProject(t, r.hot, "/repo/alpha", 1000, 2)
	seedProject(t, r.hot, "/repo/beta", 1000, 2)
	before := hotCounts(t, r.hot, "/repo/beta")

	if _, err := r.mover.ArchiveCodeIntelProject(ctx, "/repo/alpha"); err != nil {
		t.Fatalf("archive: %v", err)
	}
	for tbl, n := range hotCounts(t, r.hot, "/repo/beta") {
		if n != before[tbl] {
			t.Errorf("%s for the untouched project changed: %d -> %d", tbl, before[tbl], n)
		}
	}
	if _, found, _ := r.store.CodeIntelArchivedProject(ctx, "/repo/beta"); found {
		t.Error("an untouched project got an archived marker")
	}
}

// corruptingCold wraps the real archive store and drops rows from one write
// call, simulating a partially-durable copy. This is THE mutation-proof
// fixture for the verify step: with verification working, the hot rows must
// survive; if verification is ever weakened, this test is what fails.
type corruptingCold struct {
	*archivestore.Store
	dropNodes bool
}

func (c *corruptingCold) WriteNodes(ctx context.Context, rows []archive.NodeRow) error {
	if c.dropNodes && len(rows) > 0 {
		rows = rows[:len(rows)-1] // silently lose one row, as a torn write would
	}
	return c.Store.WriteNodes(ctx, rows)
}

// TestVerifyFailureLeavesHotRowsIntact is the core safety assertion of the
// whole arc: when the cold copy does not reproduce the hot rows, NOTHING is
// deleted.
//
// It is deliberately a lost-row scenario rather than an unwritable-archive
// scenario, because a write that ERRORS is easy to handle correctly by
// accident — the interesting failure is a copy that succeeds and is wrong.
func TestVerifyFailureLeavesHotRowsIntact(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	const project = "/repo/alpha"
	seedProject(t, r.hot, project, 1000, 3)
	before := hotCounts(t, r.hot, project)

	mover := &archivesvc.Mover{
		Hot:       r.store,
		Cold:      &corruptingCold{Store: r.cold, dropNodes: true},
		BatchRows: 2,
	}
	_, err := mover.ArchiveCodeIntelProject(ctx, project)
	if err == nil {
		t.Fatal("a lossy cold copy was accepted — verification is not gating the delete")
	}
	if !errors.Is(err, archive.ErrDigestMismatch) {
		t.Fatalf("error %v does not wrap ErrDigestMismatch", err)
	}

	after := hotCounts(t, r.hot, project)
	for tbl, n := range before {
		if after[tbl] != n {
			t.Errorf("%s lost rows despite a failed verification: %d -> %d", tbl, n, after[tbl])
		}
	}
	if _, found, _ := r.store.CodeIntelArchivedProject(ctx, project); found {
		t.Error("a marker was written for a project whose copy failed verification")
	}
}

// TestReRunAfterFailedCopyIsIdempotent covers the crash-between-copy-and-delete
// window. The first attempt leaves a bad (short) cold copy behind; the second
// attempt must clear it, re-copy, verify, and complete — not inherit the
// wreckage and wedge the project as permanently unverifiable.
func TestReRunAfterFailedCopyIsIdempotent(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	const project = "/repo/alpha"
	seedProject(t, r.hot, project, 1000, 3)
	hotDigest, err := r.store.CodeIntelProjectDigest(ctx, project, 2)
	if err != nil {
		t.Fatalf("hot digest: %v", err)
	}

	bad := &corruptingCold{Store: r.cold, dropNodes: true}
	badMover := &archivesvc.Mover{Hot: r.store, Cold: bad, BatchRows: 2}
	if _, err := badMover.ArchiveCodeIntelProject(ctx, project); err == nil {
		t.Fatal("expected the lossy first attempt to fail verification")
	}

	// Second attempt, healthy this time — the same rig, the same archive file
	// that still holds the failed attempt's partial rows.
	out, err := r.mover.ArchiveCodeIntelProject(ctx, project)
	if err != nil {
		t.Fatalf("retry after a failed copy: %v", err)
	}
	if out.Result != archivesvc.ResultArchived {
		t.Fatalf("retry result = %s, want archived", out.Result)
	}
	coldDigest, err := r.cold.CodeIntelProjectDigest(ctx, project, 2)
	if err != nil {
		t.Fatalf("cold digest: %v", err)
	}
	if err := archive.Verify(hotDigest, coldDigest); err != nil {
		t.Fatalf("retry left a cold copy that does not match the hot rows: %v", err)
	}
}

// TestReCopyOverAStaleColdCopyLeavesNoOrphans is the shrinking-project variant
// of the same window: the cold copy is a SUPERSET (a crashed attempt copied a
// larger version of the project). Upserting alone would leave the extra rows
// behind forever and the read-back digest would disagree with the hot digest
// on every future attempt. The pre-clear is what prevents that.
func TestReCopyOverAStaleColdCopyLeavesNoOrphans(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	const project = "/repo/alpha"

	// A larger earlier version of the project, archived.
	seedProject(t, r.hot, project, 1000, 4)
	if _, err := r.mover.ArchiveCodeIntelProject(ctx, project); err != nil {
		t.Fatalf("first archive: %v", err)
	}
	if err := r.store.CodeIntelClearArchivedProject(ctx, project); err != nil {
		t.Fatalf("clear marker: %v", err)
	}

	// Re-indexed smaller, then archived again.
	seedProject(t, r.hot, project, 2000, 2)
	hotDigest, err := r.store.CodeIntelProjectDigest(ctx, project, 2)
	if err != nil {
		t.Fatalf("hot digest: %v", err)
	}
	if _, err := r.mover.ArchiveCodeIntelProject(ctx, project); err != nil {
		t.Fatalf("second archive: %v", err)
	}
	coldDigest, err := r.cold.CodeIntelProjectDigest(ctx, project, 2)
	if err != nil {
		t.Fatalf("cold digest: %v", err)
	}
	if err := archive.Verify(hotDigest, coldDigest); err != nil {
		t.Fatalf("orphan rows from the earlier, larger copy survived: %v", err)
	}
}

// reindexingHot re-indexes the project between the copy and the delete,
// standing in for a concurrent index pass.
type reindexingHot struct {
	*store.Store
	hot     *sql.DB
	t       *testing.T
	project string
	fired   bool
}

func (h *reindexingHot) CodeIntelExportProject(ctx context.Context, project string, batchRows int, sink archive.ProjectSink) error {
	if err := h.Store.CodeIntelExportProject(ctx, project, batchRows, sink); err != nil {
		return err
	}
	if !h.fired && project == h.project {
		h.fired = true
		if _, err := h.hot.ExecContext(ctx,
			`UPDATE codeintel_files SET indexed_at = 9999 WHERE project = ?`, project); err != nil {
			h.t.Fatalf("simulate re-index: %v", err)
		}
	}
	return nil
}

// TestConcurrentReindexCancelsTheMove pins the race guard. An index pass that
// lands after the copy means the hot table now holds rows the cold copy never
// saw; deleting would be silent loss on data the operator believes is
// recoverable. The move must abort with the hot rows intact and report a
// normal "changed" outcome rather than an error.
func TestConcurrentReindexCancelsTheMove(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	const project = "/repo/alpha"
	seedProject(t, r.hot, project, 1000, 2)
	before := hotCounts(t, r.hot, project)

	mover := &archivesvc.Mover{
		Hot:       &reindexingHot{Store: r.store, hot: r.hot, t: t, project: project},
		Cold:      r.cold,
		BatchRows: 2,
	}
	out, err := mover.ArchiveCodeIntelProject(ctx, project)
	if err != nil {
		t.Fatalf("a concurrent re-index should be a normal outcome, got error: %v", err)
	}
	if out.Result != archivesvc.ResultChanged {
		t.Fatalf("result = %s, want changed", out.Result)
	}
	for tbl, n := range hotCounts(t, r.hot, project) {
		if n != before[tbl] {
			t.Errorf("%s changed despite the aborted move: %d -> %d", tbl, before[tbl], n)
		}
	}
	if _, found, _ := r.store.CodeIntelArchivedProject(ctx, project); found {
		t.Error("a marker was written for a move that was cancelled")
	}
}

// TestEmptyProjectIsNotMarked pins the honesty rule: a project with no rows is
// not "archived". Writing a marker would claim cold storage holds a recoverable
// copy when it holds nothing.
func TestEmptyProjectIsNotMarked(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	out, err := r.mover.ArchiveCodeIntelProject(ctx, "/repo/never-indexed")
	if err != nil {
		t.Fatalf("archive empty project: %v", err)
	}
	if out.Result != archivesvc.ResultEmpty {
		t.Fatalf("result = %s, want empty", out.Result)
	}
	if _, found, _ := r.store.CodeIntelArchivedProject(ctx, "/repo/never-indexed"); found {
		t.Error("an empty project got an archived marker")
	}
}

// TestSweepRespectsTheCapAndPicksTheColdest pins the bounded-batch behaviour
// end to end, including that the batch is the COLDEST projects rather than an
// arbitrary slice.
func TestSweepRespectsTheCapAndPicksTheColdest(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	// All three are stale (watermarks far in the past); /ancient is coldest.
	seedProject(t, r.hot, "/repo/ancient", 1000, 1)
	seedProject(t, r.hot, "/repo/middle", 2000, 1)
	seedProject(t, r.hot, "/repo/recent-ish", 3000, 1)

	res, err := r.mover.SweepCodeIntel(ctx, 1, archive.PlanOptions{MaxUnitsPerPass: 2})
	if err != nil {
		t.Fatalf("SweepCodeIntel: %v", err)
	}
	if res.Considered != 3 {
		t.Errorf("Considered = %d, want 3", res.Considered)
	}
	if res.Attempted != 2 || res.Archived != 2 {
		t.Errorf("Attempted/Archived = %d/%d, want 2/2", res.Attempted, res.Archived)
	}
	if res.RowsArchived <= 0 {
		t.Error("RowsArchived was not accumulated")
	}
	for _, p := range []string{"/repo/ancient", "/repo/middle"} {
		if _, found, _ := r.store.CodeIntelArchivedProject(ctx, p); !found {
			t.Errorf("%s should have been in the coldest-first batch", p)
		}
	}
	if _, found, _ := r.store.CodeIntelArchivedProject(ctx, "/repo/recent-ish"); found {
		t.Error("/repo/recent-ish was archived despite the cap of 2")
	}
	if n := countRows(t, r.hot, "codeintel_files", "/repo/recent-ish"); n == 0 {
		t.Error("/repo/recent-ish lost its hot rows despite not being in the batch")
	}
}

// TestSweepSkipsFreshProjects pins that the archive sweep inherits the delete
// sweep's conservatism unchanged: an actively indexed project is never a
// candidate, and neither is one that has never been successfully indexed.
func TestSweepSkipsFreshProjects(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	seedProject(t, r.hot, "/repo/fresh", 1<<40, 1) // watermark far in the future
	if _, err := r.hot.ExecContext(ctx,
		`INSERT INTO codeintel_files (project, path, lang, status, indexed_at)
		 VALUES ('/repo/pending', '/repo/pending/a.go', 'go', 'pending', 0)`); err != nil {
		t.Fatalf("seed pending: %v", err)
	}

	res, err := r.mover.SweepCodeIntel(ctx, 1, archive.PlanOptions{})
	if err != nil {
		t.Fatalf("SweepCodeIntel: %v", err)
	}
	if res.Considered != 0 || res.Archived != 0 {
		t.Fatalf("considered/archived = %d/%d, want 0/0 — fresh and never-indexed projects must not be candidates",
			res.Considered, res.Archived)
	}
}

// TestSweepDisabledHorizonIsANoOp pins the ≤0 short-circuit the config's
// default relies on.
func TestSweepDisabledHorizonIsANoOp(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	seedProject(t, r.hot, "/repo/alpha", 1000, 1)
	res, err := r.mover.SweepCodeIntel(ctx, 0, archive.PlanOptions{})
	if err != nil {
		t.Fatalf("SweepCodeIntel: %v", err)
	}
	if res.Considered != 0 || res.Archived != 0 {
		t.Fatalf("a disabled horizon archived something: %+v", res)
	}
	if n := countRows(t, r.hot, "codeintel_files", "/repo/alpha"); n != 1 {
		t.Fatalf("hot rows changed under a disabled horizon: %d", n)
	}
}

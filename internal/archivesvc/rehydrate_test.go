package archivesvc_test

import (
	"context"
	"database/sql"
	"fmt"
	"reflect"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/archive"
	"github.com/marmutapp/superbased-observer/internal/archivesvc"
	"github.com/marmutapp/superbased-observer/internal/codeintel"
)

// seedGraphProject writes a project whose CALLS edges point at REAL symbol
// names, so store.CodeIntelResolveCalls actually fills dst_id and the graph has
// traversable structure.
//
// The mover_test seed deliberately leaves edges unresolved (its subject is row
// fidelity); the rehydrate gate needs the opposite — a graph where a symbol id
// appearing on the wrong side of an edge would change an answer. That is the
// corruption an id-renumbering restore produces, and a graph of dangling edges
// could not detect it.
func seedGraphProject(t *testing.T, hot *sql.DB, project string, indexedAt int64) {
	t.Helper()
	ctx := context.Background()

	type node struct {
		id   int64
		name string
	}
	var nodes []node
	fileIDs := make([]int64, 0, 3)

	for f := 0; f < 3; f++ {
		path := fmt.Sprintf("%s/pkg%d/service.go", project, f)
		res, err := hot.ExecContext(ctx,
			`INSERT INTO codeintel_files (project, path, lang, content_hash, mtime, indexed_at, parser, status)
			 VALUES (?,?,'go',?,?,?,'goast','indexed')`,
			project, path, fmt.Sprintf("hash-%d", f), 2000+f, indexedAt)
		if err != nil {
			t.Fatalf("seed file: %v", err)
		}
		fileID, err := res.LastInsertId()
		if err != nil {
			t.Fatalf("file id: %v", err)
		}
		fileIDs = append(fileIDs, fileID)
		for n := 0; n < 3; n++ {
			name := fmt.Sprintf("Handle%dRequest%d", f, n)
			nres, err := hot.ExecContext(ctx,
				`INSERT INTO codeintel_nodes (project, file_id, kind, name, fqn, lang,
				   start_line, end_line, start_byte, end_byte, signature, sig_hash)
				 VALUES (?,?,'function',?,?,'go',?,?,?,?,?,?)`,
				project, fileID, name, fmt.Sprintf("pkg%d.%s", f, name),
				n*20, n*20+9, n*400, n*400+180,
				fmt.Sprintf("func %s(ctx context.Context) error", name),
				fmt.Sprintf("sig-%d-%d", f, n))
			if err != nil {
				t.Fatalf("seed node: %v", err)
			}
			id, err := nres.LastInsertId()
			if err != nil {
				t.Fatalf("node id: %v", err)
			}
			nodes = append(nodes, node{id: id, name: name})
		}
	}

	// Chain every symbol to its successor: node[i] CALLS node[i+1]. The edge
	// is written unresolved (dst_id=0) with the callee's real name on the
	// site, exactly as an index pass leaves it, so CodeIntelResolveCalls has
	// genuine work to do.
	for i := 0; i+1 < len(nodes); i++ {
		fileID := fileIDs[i/3]
		eres, err := hot.ExecContext(ctx,
			`INSERT INTO codeintel_edges (project, file_id, src_id, dst_id, kind, confidence, resolver_backend)
			 VALUES (?,?,?,0,'CALLS',1.0,'goast')`, project, fileID, nodes[i].id)
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
			 VALUES (?,?,?,?,?,?,?,'goast',1.0,'')`,
			project, edgeID, fileID, i, i*11,
			nodes[i+1].name+"(ctx)", nodes[i+1].name); err != nil {
			t.Fatalf("seed site: %v", err)
		}
	}

	// MinHash is NOT rebuilt by CodeIntelBuildDerived (it needs the file body,
	// which only an index pass has), so it MUST survive the archive round trip
	// on the cold copy alone. Seeding it here is what makes that load-bearing.
	for _, n := range nodes {
		for band := 0; band < 3; band++ {
			if _, err := hot.ExecContext(ctx,
				`INSERT INTO codeintel_minhash (node_id, project, band, hash) VALUES (?,?,?,?)`,
				n.id, project, band, n.id*7+int64(band)); err != nil {
				t.Fatalf("seed minhash: %v", err)
			}
		}
	}
}

// codeIntelAnswers is the observable behaviour the gate compares: what the
// symbol search, the file-scoped symbol lookup, and the graph traversal say.
// Row ids are part of every one of these, which is the point — an archive
// round trip that renumbered rows would keep the counts and change the ids.
type codeIntelAnswers struct {
	Search       []codeintel.SymbolMatch
	FindSymbols  []codeintel.SymbolMatch
	Callers      []codeintel.Ref
	Callees      []codeintel.Ref
	EdgesByKind  int
	SymbolsFile0 []codeintel.Symbol
}

func answersFor(t *testing.T, r *rig, project string, anchorID int64, file0 string) codeIntelAnswers {
	t.Helper()
	ctx := context.Background()
	var a codeIntelAnswers
	var err error

	if a.Search, err = r.store.CodeIntelSearch(ctx, project, "Handle", 50); err != nil {
		t.Fatalf("CodeIntelSearch: %v", err)
	}
	if a.FindSymbols, err = r.store.CodeIntelFindSymbols(ctx, file0, "", "", ""); err != nil {
		t.Fatalf("CodeIntelFindSymbols: %v", err)
	}
	if a.Callers, _, err = r.store.CodeIntelReachable(ctx, anchorID, codeintel.RelationCallers, 3, 50); err != nil {
		t.Fatalf("CodeIntelReachable(callers): %v", err)
	}
	if a.Callees, _, err = r.store.CodeIntelReachable(ctx, anchorID, codeintel.RelationCallees, 3, 50); err != nil {
		t.Fatalf("CodeIntelReachable(callees): %v", err)
	}
	if a.EdgesByKind, err = r.store.CodeIntelCountEdgesByKind(ctx, "CALLS"); err != nil {
		t.Fatalf("CodeIntelCountEdgesByKind: %v", err)
	}
	if a.SymbolsFile0, err = r.store.CodeIntelSymbolsInFile(ctx, file0); err != nil {
		t.Fatalf("CodeIntelSymbolsInFile: %v", err)
	}
	return a
}

// TestGateP2ArchivedThenRehydratedAnswersIdentically IS gate P2.
//
// "Archive, then rehydrate, then ask the same questions and get the same
// answers." Counting rows would not prove it: the failure mode that matters
// is a restore that keeps every row but renumbers the ids, which leaves every
// count intact while pointing every edge at the wrong symbol. So the gate
// compares the ANSWERS — search hits with their ids, file-scoped symbol
// lookups, and both directions of graph traversal from a fixed anchor.
func TestGateP2ArchivedThenRehydratedAnswersIdentically(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	const project = "/repo/gate"
	file0 := project + "/pkg0/service.go"

	seedGraphProject(t, r.hot, project, 1)
	if err := r.store.CodeIntelBuildDerived(ctx, project); err != nil {
		t.Fatalf("build derived: %v", err)
	}
	resolved, err := r.store.CodeIntelResolveCalls(ctx, project)
	if err != nil {
		t.Fatalf("resolve calls: %v", err)
	}
	if resolved == 0 {
		t.Fatal("seed produced no resolvable CALLS edges — the graph half of this gate would be vacuous")
	}

	var anchorID int64
	if err := r.hot.QueryRowContext(ctx,
		`SELECT id FROM codeintel_nodes WHERE project = ? AND name = 'Handle1Request1'`,
		project).Scan(&anchorID); err != nil {
		t.Fatalf("anchor id: %v", err)
	}

	before := answersFor(t, r, project, anchorID, file0)
	if len(before.Search) == 0 || len(before.FindSymbols) == 0 {
		t.Fatalf("baseline answers are empty (search=%d find=%d) — the gate would pass vacuously",
			len(before.Search), len(before.FindSymbols))
	}
	if len(before.Callers) == 0 && len(before.Callees) == 0 {
		t.Fatal("baseline traversal is empty — the graph half of the gate would pass vacuously")
	}
	beforeMinhash := countRows(t, r.hot, "codeintel_minhash", project)

	// --- archive ---------------------------------------------------------
	out, err := r.mover.ArchiveCodeIntelProject(ctx, project)
	if err != nil {
		t.Fatalf("archive: %v", err)
	}
	if out.Result != archivesvc.ResultArchived {
		t.Fatalf("archive result = %v, want archived", out.Result)
	}
	for _, table := range hotCodeIntelTables {
		if n := countRows(t, r.hot, table, project); n != 0 {
			t.Fatalf("after archive %s still holds %d rows", table, n)
		}
	}
	if _, found, _ := r.store.CodeIntelArchivedProject(ctx, project); !found {
		t.Fatal("archive left no marker")
	}

	// --- rehydrate -------------------------------------------------------
	reh, err := r.mover.RehydrateCodeIntelProject(ctx, project)
	if err != nil {
		t.Fatalf("rehydrate: %v", err)
	}
	if reh.Result != archivesvc.RehydrateRestored {
		t.Fatalf("rehydrate result = %v (%s), want restored", reh.Result, reh.Reason)
	}
	if reh.RowsRestored != out.RowsArchived {
		t.Fatalf("restored %d rows, archived %d", reh.RowsRestored, out.RowsArchived)
	}
	if _, found, _ := r.store.CodeIntelArchivedProject(ctx, project); found {
		t.Fatal("marker survived a successful rehydrate — the project would keep claiming it is archived")
	}

	// --- the gate --------------------------------------------------------
	after := answersFor(t, r, project, anchorID, file0)
	if !reflect.DeepEqual(before, after) {
		t.Errorf("rehydrated project answers differently than before it was archived:\n"+
			" search  before=%d after=%d\n find    before=%d after=%d\n"+
			" callers before=%d after=%d\n callees before=%d after=%d\n"+
			" edges   before=%d after=%d\n symbols before=%d after=%d",
			len(before.Search), len(after.Search),
			len(before.FindSymbols), len(after.FindSymbols),
			len(before.Callers), len(after.Callers),
			len(before.Callees), len(after.Callees),
			before.EdgesByKind, after.EdgesByKind,
			len(before.SymbolsFile0), len(after.SymbolsFile0))
		if len(before.Search) == len(after.Search) {
			for i := range before.Search {
				if !reflect.DeepEqual(before.Search[i], after.Search[i]) {
					t.Errorf("search hit %d: before=%+v after=%+v", i, before.Search[i], after.Search[i])
				}
			}
		}
	}

	// MinHash is the table CodeIntelBuildDerived cannot regenerate, so it is
	// the one that proves the cold copy — not the rebuild — carried the data.
	if n := countRows(t, r.hot, "codeintel_minhash", project); n != beforeMinhash {
		t.Errorf("codeintel_minhash rows before=%d after=%d — the non-regenerable "+
			"table did not survive the round trip", beforeMinhash, n)
	}
}

// TestRehydrateOfANeverArchivedProjectIsANoOp pins the common path: no marker
// means one indexed lookup and no archive access at all.
func TestRehydrateOfANeverArchivedProjectIsANoOp(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	const project = "/repo/live"
	seedProject(t, r.hot, project, 1, 2)
	before := hotCounts(t, r.hot, project)

	out, err := r.mover.RehydrateCodeIntelProject(ctx, project)
	if err != nil {
		t.Fatalf("rehydrate: %v", err)
	}
	if out.Result != archivesvc.RehydrateNotArchived {
		t.Fatalf("result = %v, want not-archived", out.Result)
	}
	if got := hotCounts(t, r.hot, project); !reflect.DeepEqual(before, got) {
		t.Errorf("a no-op rehydrate changed the hot rows: before=%v after=%v", before, got)
	}
}

// TestRehydrateRefusesToOverwriteALiveReindex is the "cold copy must never
// clobber current data" guard.
//
// The scenario is real: a project is archived, then the operator runs
// `observer index` on it by hand (the documented recovery path while P2 did
// not exist). The marker is now stale. A rehydrate that faithfully replayed
// the cold copy would REPLACE a current index with an older one — the worst
// outcome this path can produce, and one that looks like success.
func TestRehydrateRefusesToOverwriteALiveReindex(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	const project = "/repo/reindexed"

	seedProject(t, r.hot, project, 1, 2)
	if _, err := r.mover.ArchiveCodeIntelProject(ctx, project); err != nil {
		t.Fatalf("archive: %v", err)
	}
	// Stand in for a manual re-index: fresh rows, a NEWER watermark.
	seedProject(t, r.hot, project, 9999, 3)
	live := hotCounts(t, r.hot, project)

	out, err := r.mover.RehydrateCodeIntelProject(ctx, project)
	if err != nil {
		t.Fatalf("rehydrate: %v", err)
	}
	if out.Result != archivesvc.RehydrateAlreadyHot {
		t.Fatalf("result = %v, want already-hot", out.Result)
	}
	if got := hotCounts(t, r.hot, project); !reflect.DeepEqual(live, got) {
		t.Errorf("the live re-index was overwritten by the cold copy: live=%v after=%v", live, got)
	}
	if _, found, _ := r.store.CodeIntelArchivedProject(ctx, project); found {
		t.Error("the stale marker survived — the project would keep reporting itself archived")
	}
}

// TestRehydrateFallsBackToReindexOnAStaleParser pins P2.2's parser half.
//
// A codeintel row encodes the parser that produced it. A cold copy written by
// a backend this build no longer honours is stale in a way faithful copying
// cannot fix, so the honest answer is "re-index", not a confident restore of
// rows the current engine would never have produced.
func TestRehydrateFallsBackToReindexOnAStaleParser(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	const project = "/repo/oldparser"

	seedProject(t, r.hot, project, 1, 2)
	if _, err := r.mover.ArchiveCodeIntelProject(ctx, project); err != nil {
		t.Fatalf("archive: %v", err)
	}
	r.mover.AcceptParser = func(string) bool { return false }

	out, err := r.mover.RehydrateCodeIntelProject(ctx, project)
	if err != nil {
		t.Fatalf("rehydrate: %v", err)
	}
	if out.Result != archivesvc.RehydrateReindexRequired {
		t.Fatalf("result = %v, want reindex-required", out.Result)
	}
	if out.Reason == "" {
		t.Error("reindex-required carried no reason — the surface would have nothing honest to say")
	}
	if _, found, _ := r.store.CodeIntelArchivedProject(ctx, project); !found {
		t.Error("the marker was cleared on a failed rehydrate — the project would look never-indexed")
	}
	for _, table := range hotCodeIntelTables {
		if n := countRows(t, r.hot, table, project); n != 0 {
			t.Errorf("a refused rehydrate left %d rows in %s", n, table)
		}
	}
}

// TestRehydrateDetectsATruncatedColdCopy pins the marker's row-count check.
//
// The row-for-row digest cannot catch this on its own: both of its sides are
// read AFTER the fact, so a cold copy that quietly lost rows verifies happily
// against the hot copy of those same surviving rows. The marker's recorded
// count is the only witness to what was actually archived, and comparing
// against it is what turns "faithfully restored a truncated copy" into a
// refusal.
func TestRehydrateDetectsATruncatedColdCopy(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	const project = "/repo/truncated"

	seedProject(t, r.hot, project, 1, 3)
	if _, err := r.mover.ArchiveCodeIntelProject(ctx, project); err != nil {
		t.Fatalf("archive: %v", err)
	}
	// Lose rows from the cold copy behind the arc's back.
	if _, err := r.cold.DB().ExecContext(ctx,
		`DELETE FROM archive_codeintel_minhash WHERE project = ?`, project); err != nil {
		t.Fatalf("truncate cold copy: %v", err)
	}

	out, err := r.mover.RehydrateCodeIntelProject(ctx, project)
	if err != nil {
		t.Fatalf("rehydrate: %v", err)
	}
	if out.Result != archivesvc.RehydrateReindexRequired {
		t.Fatalf("result = %v (%s), want reindex-required", out.Result, out.Reason)
	}
	if _, found, _ := r.store.CodeIntelArchivedProject(ctx, project); !found {
		t.Error("the marker was cleared despite an unusable cold copy")
	}
	for _, table := range hotCodeIntelTables {
		if n := countRows(t, r.hot, table, project); n != 0 {
			t.Errorf("a refused rehydrate left %d rows in %s (partial replay was not rolled back)", n, table)
		}
	}
}

// TestRehydrateIsRerunnableAfterAPartialReplay pins the crash-re-runnability
// invariant on the inbound direction. A replay interrupted halfway leaves hot
// rows behind AND the marker set; the next attempt must clear them and produce
// a correct project, not duplicate the rows it already wrote.
//
// codeintel_minhash is the table that makes this real: it has no unique
// constraint hot-side, so a replay onto leftovers would DOUBLE its rows rather
// than overwrite them.
func TestRehydrateIsRerunnableAfterAPartialReplay(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	const project = "/repo/partial"

	seedProject(t, r.hot, project, 1, 2)
	if _, err := r.mover.ArchiveCodeIntelProject(ctx, project); err != nil {
		t.Fatalf("archive: %v", err)
	}
	// Simulate a crashed replay: some rows already back in the hot tables.
	sink := r.store.CodeIntelImportSink(project)
	if err := r.cold.StreamCodeIntelProject(ctx, project, 2, partialSink{ProjectSink: sink}); err != nil {
		t.Fatalf("partial replay: %v", err)
	}
	if countRows(t, r.hot, "codeintel_minhash", project) == 0 {
		t.Fatal("partial replay wrote nothing — this test would be vacuous")
	}

	out, err := r.mover.RehydrateCodeIntelProject(ctx, project)
	if err != nil {
		t.Fatalf("rehydrate: %v", err)
	}
	if out.Result != archivesvc.RehydrateRestored {
		t.Fatalf("result = %v (%s), want restored", out.Result, out.Reason)
	}

	var coldMinhash int
	if err := r.cold.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM archive_codeintel_minhash WHERE project = ?`, project).Scan(&coldMinhash); err != nil {
		t.Fatalf("count cold minhash: %v", err)
	}
	if got := countRows(t, r.hot, "codeintel_minhash", project); got != coldMinhash {
		t.Errorf("codeintel_minhash hot=%d cold=%d — the partial replay's rows were duplicated "+
			"rather than cleared", got, coldMinhash)
	}
}

// partialSink forwards files, nodes and minhash but drops the rest, standing
// in for a replay that died partway through.
type partialSink struct{ archive.ProjectSink }

func (p partialSink) WriteEdges(context.Context, []archive.EdgeRow) error { return nil }
func (p partialSink) WriteSites(context.Context, []archive.SiteRow) error { return nil }
func (p partialSink) WriteEmbeddings(context.Context, []archive.EmbeddingRow) error {
	return nil
}

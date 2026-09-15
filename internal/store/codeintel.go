package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/codeintel"
	"github.com/marmutapp/superbased-observer/internal/codeintel/resolve"
	"github.com/marmutapp/superbased-observer/internal/codeintel/semantic"
)

// This file is THE store seam for the code-intelligence module
// (internal/codeintel). All SQL touching the codeintel_* tables lives
// here and nowhere else (CLAUDE.md "one owner per table"). The
// codeintel index orchestrator and native engine depend on the narrow
// interfaces they define (codeintel.IndexStore / codeintel.EngineStore);
// *Store satisfies both. See docs/codeintel/schema.md.
//
// Privacy: these tables are NODE-LOCAL and never enter
// internal/store/orgpush.go — pinned by tests/invariant/privacy_test.go.

// Compile-time proof that *Store satisfies both codeintel seams; a
// drift in either interface fails the build here, not at a far call site.
var (
	_ codeintel.EngineStore = (*Store)(nil)
	_ codeintel.IndexStore  = (*Store)(nil)
)

// --- write / index side (codeintel.IndexStore) -----------------------

// CodeIntelListProjects returns the distinct projects that have at least
// one row in codeintel_files.
func (s *Store) CodeIntelListProjects(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT DISTINCT project FROM codeintel_files ORDER BY project`)
	if err != nil {
		return nil, fmt.Errorf("store.CodeIntelListProjects: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, fmt.Errorf("store.CodeIntelListProjects: scan: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// CodeIntelFileState returns the stored index bookkeeping for
// (project, path): content hash, status, and the mtime/indexed_at pair
// the indexer's stat-only fast path needs. found is false when no row
// exists yet.
func (s *Store) CodeIntelFileState(ctx context.Context, project, path string) (codeintel.FileState, bool, error) {
	var st codeintel.FileState
	row := s.db.QueryRowContext(ctx,
		`SELECT content_hash, status, mtime, indexed_at FROM codeintel_files WHERE project = ? AND path = ?`,
		project, path)
	switch err := row.Scan(&st.ContentHash, &st.Status, &st.MTime, &st.IndexedAt); {
	case err == nil:
		return st, true, nil
	case errors.Is(err, sql.ErrNoRows):
		return codeintel.FileState{}, false, nil
	default:
		return codeintel.FileState{}, false, fmt.Errorf("store.CodeIntelFileState: %w", err)
	}
}

// CodeIntelRegisterFile inserts a pending row for (project, path) if none
// exists (the cheap "observe-on-ingest" registration). Idempotent.
func (s *Store) CodeIntelRegisterFile(ctx context.Context, project, path, lang string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO codeintel_files(project, path, lang, status)
		 VALUES(?, ?, ?, 'pending')
		 ON CONFLICT(project, path) DO NOTHING`,
		project, path, lang)
	if err != nil {
		return fmt.Errorf("store.CodeIntelRegisterFile: %w", err)
	}
	return nil
}

// CodeIntelSetFileStatus updates the lifecycle status for (project, path).
func (s *Store) CodeIntelSetFileStatus(ctx context.Context, project, path, status string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE codeintel_files SET status = ? WHERE project = ? AND path = ?`,
		status, project, path)
	if err != nil {
		return fmt.Errorf("store.CodeIntelSetFileStatus: %w", err)
	}
	return nil
}

// CodeIntelSaveFile persists a completed parse for one file: it upserts
// the codeintel_files row to status=indexed with the new content hash /
// mtime / parser, and REPLACES the file's codeintel_nodes rows — all in
// one transaction so a reader never sees a half-updated file. mtime is
// unix seconds.
func (s *Store) CodeIntelSaveFile(ctx context.Context, res codeintel.FileResult) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.CodeIntelSaveFile: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	_, err = tx.ExecContext(ctx,
		`INSERT INTO codeintel_files(project, path, lang, content_hash, mtime, indexed_at, parser, status)
		 VALUES(?, ?, ?, ?, ?, ?, ?, 'indexed')
		 ON CONFLICT(project, path) DO UPDATE SET
		   lang=excluded.lang, content_hash=excluded.content_hash, mtime=excluded.mtime,
		   indexed_at=excluded.indexed_at, parser=excluded.parser, status='indexed'`,
		res.Project, res.Path, string(res.Lang), res.ContentHash, res.MTime, time.Now().Unix(), res.Parser)
	if err != nil {
		return fmt.Errorf("store.CodeIntelSaveFile: upsert file: %w", err)
	}

	var fileID int64
	if err := tx.QueryRowContext(ctx,
		`SELECT id FROM codeintel_files WHERE project = ? AND path = ?`,
		res.Project, res.Path).Scan(&fileID); err != nil {
		return fmt.Errorf("store.CodeIntelSaveFile: file id: %w", err)
	}

	// Clear this file's prior graph: nodes (Phase 1) + edges/sites
	// (Phase 3). Edges/sites are keyed by the OWNING file_id, so this
	// touches only this file's slice of the graph. The `project =` predicate
	// is load-bearing for performance, not just scoping: every file_id index
	// is (project, file_id, ...) — project-FIRST — so a bare `file_id = ?`
	// can't seek it and full-scans the table on EVERY file save. Pairing
	// project + file_id lets the composite index seek.
	for _, del := range []string{
		`DELETE FROM codeintel_sites WHERE project = ? AND file_id = ?`,
		`DELETE FROM codeintel_edges WHERE project = ? AND file_id = ?`,
		`DELETE FROM codeintel_nodes WHERE project = ? AND file_id = ?`,
	} {
		if _, err := tx.ExecContext(ctx, del, res.Project, fileID); err != nil {
			return fmt.Errorf("store.CodeIntelSaveFile: clear graph: %w", err)
		}
	}

	nodeStmt, err := tx.PrepareContext(ctx,
		`INSERT INTO codeintel_nodes(project, file_id, kind, name, fqn, lang,
		   start_line, end_line, start_byte, end_byte, signature, sig_hash)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("store.CodeIntelSaveFile: prepare nodes: %w", err)
	}
	defer nodeStmt.Close()
	// nodeIDs[i] is the inserted id of res.Nodes[i] — used to map a
	// CallSite.Enclosing index onto its src node.
	nodeIDs := make([]int64, len(res.Nodes))
	for i, n := range res.Nodes {
		r, err := nodeStmt.ExecContext(
			ctx,
			res.Project, fileID, n.Kind, n.Name, n.FQN, string(res.Lang),
			n.StartLine, n.EndLine, n.StartByte, n.EndByte, n.Signature, sigHash(n.Signature),
		)
		if err != nil {
			return fmt.Errorf("store.CodeIntelSaveFile: insert node: %w", err)
		}
		nodeIDs[i], _ = r.LastInsertId()
	}

	// Body-shingle MinHash buckets (W3 near-clone). Computed by the indexer
	// from the file content (only the band hashes reach the store — never the
	// body). Old rows for this file's nodes were cleared by the node DELETE
	// above (ON DELETE CASCADE). codeintel_minhash is owned HERE now, not by
	// CodeIntelBuildDerived.
	if len(res.BodyBuckets) > 0 {
		mhStmt, err := tx.PrepareContext(ctx,
			`INSERT INTO codeintel_minhash(node_id, project, band, hash) VALUES(?, ?, ?, ?)`)
		if err != nil {
			return fmt.Errorf("store.CodeIntelSaveFile: prepare minhash: %w", err)
		}
		defer mhStmt.Close()
		for i, buckets := range res.BodyBuckets {
			if i >= len(nodeIDs) {
				break
			}
			for band, h := range buckets {
				// SQLite INTEGER is signed 64-bit; store the bucket as a
				// signed bit-pattern (int64(uint64)) — comparisons stay exact.
				if _, err := mhStmt.ExecContext(ctx, nodeIDs[i], res.Project, band, int64(h)); err != nil {
					return fmt.Errorf("store.CodeIntelSaveFile: insert minhash: %w", err)
				}
			}
		}
	}

	// IMPORTS edges + sites (src/dst 0 — the target is an external
	// specifier carried on the site's target_name).
	for _, imp := range res.Imports {
		if imp.Path == "" {
			continue
		}
		if err := insertEdgeSite(ctx, tx, res.Project, fileID, 0, 0, "IMPORTS",
			res.Parser, imp.StartLine, imp.StartByte, imp.RawText, imp.Path, ""); err != nil {
			return err
		}
	}

	// CALLS edges + sites. src is the enclosing node (mapped via
	// nodeIDs); dst is left 0 and resolved by name in
	// CodeIntelResolveCalls. The site carries the callee name.
	for _, call := range res.Calls {
		if call.Name == "" {
			continue
		}
		var srcID int64
		if call.Enclosing >= 0 && call.Enclosing < len(nodeIDs) {
			srcID = nodeIDs[call.Enclosing]
		}
		if err := insertEdgeSite(ctx, tx, res.Project, fileID, srcID, 0, "CALLS",
			res.Parser, call.StartLine, call.StartByte, call.RawText, call.Name, call.RecvType); err != nil {
			return err
		}
	}

	// CONTAINS edges: intra-file parent -> child by span nesting (each
	// node's immediate enclosing node). dst is known here (same file), so
	// unlike CALLS there is no resolver pass and no evidence site — the
	// edge IS the structural fact.
	for child, parent := range containmentParents(res.Nodes) {
		if parent < 0 {
			continue
		}
		if err := insertContainsEdge(ctx, tx, res.Project, fileID, nodeIDs[parent], nodeIDs[child]); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store.CodeIntelSaveFile: commit: %w", err)
	}
	return nil
}

// insertEdgeSite inserts one edge and its single evidence site inside tx.
// recvType is the inferred local-var receiver type for a CALLS site
// (W2 §4.1; "" for imports and for calls with no inferred receiver) —
// carried so the scoped pass can bind x.M() to RecvType.M without touching
// the name-matched target_name.
func insertEdgeSite(ctx context.Context, tx *sql.Tx, project string, fileID, srcID, dstID int64, kind, backend string, startLine, startByte int, rawText, targetName, recvType string) error {
	r, err := tx.ExecContext(ctx,
		`INSERT INTO codeintel_edges(project, file_id, src_id, dst_id, kind, confidence, resolver_backend)
		 VALUES(?, ?, ?, ?, ?, 1.0, ?)`,
		project, fileID, srcID, dstID, kind, backend)
	if err != nil {
		return fmt.Errorf("store.CodeIntelSaveFile: insert edge: %w", err)
	}
	edgeID, _ := r.LastInsertId()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO codeintel_sites(project, edge_id, file_id, start_line, start_byte, raw_text, target_name, recv_type, resolver_backend, confidence)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, 1.0)`,
		project, edgeID, fileID, startLine, startByte, clampExcerpt(rawText), targetName, recvType, backend); err != nil {
		return fmt.Errorf("store.CodeIntelSaveFile: insert site: %w", err)
	}
	return nil
}

// insertContainsEdge inserts a structural CONTAINS edge (parent -> child)
// inside tx. dst is known (intra-file), so the edge carries no evidence
// site — the parent/child span nesting is the fact itself.
func insertContainsEdge(ctx context.Context, tx *sql.Tx, project string, fileID, srcID, dstID int64) error {
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO codeintel_edges(project, file_id, src_id, dst_id, kind, confidence, resolver_backend)
		 VALUES(?, ?, ?, ?, 'CONTAINS', 1.0, 'containment')`,
		project, fileID, srcID, dstID); err != nil {
		return fmt.Errorf("store.CodeIntelSaveFile: insert contains edge: %w", err)
	}
	return nil
}

// containmentParents returns, for each node index, the index of its
// IMMEDIATE enclosing node (the smallest strict span container) or -1 when
// the node is top-level / has no usable end span. Within one file every
// node shares a parser, so spans are uniformly exact (byte ends) or
// heuristic (line ends); strictlyContains handles both.
func containmentParents(nodes []codeintel.Node) []int {
	parents := make([]int, len(nodes))
	for i := range nodes {
		best, bestSize := -1, 0
		for j := range nodes {
			if i == j {
				continue
			}
			ok, size := strictlyContains(nodes[j], nodes[i])
			if ok && (best == -1 || size < bestSize) {
				best, bestSize = j, size
			}
		}
		parents[i] = best
	}
	return parents
}

// strictlyContains reports whether outer's span strictly contains inner's
// (and outer is strictly larger, so equal spans never nest), returning
// outer's span size for the smallest-container selection. Byte spans are
// used when available (exact backends); otherwise line spans (heuristic).
func strictlyContains(outer, inner codeintel.Node) (bool, int) {
	if outer.EndByte > outer.StartByte && inner.EndByte > inner.StartByte {
		if outer.StartByte <= inner.StartByte && inner.EndByte <= outer.EndByte {
			oSize, iSize := outer.EndByte-outer.StartByte, inner.EndByte-inner.StartByte
			if oSize > iSize {
				return true, oSize
			}
		}
		return false, 0
	}
	if outer.EndLine > outer.StartLine && inner.EndLine > 0 {
		if outer.StartLine <= inner.StartLine && inner.EndLine <= outer.EndLine {
			oSize, iSize := outer.EndLine-outer.StartLine, inner.EndLine-inner.StartLine
			if oSize > iSize {
				return true, oSize
			}
		}
	}
	return false, 0
}

// clampExcerpt bounds a raw call/import excerpt so a site never stores a
// large slice (CLAUDE.md "only paths, commands, excerpts").
func clampExcerpt(s string) string {
	const max = 300
	if len(s) > max {
		return s[:max]
	}
	return s
}

// CodeIntelDeleteProject removes every codeintel_* row for a project.
//
// It deletes each table explicitly by `project` rather than leaning on
// ON DELETE CASCADE from codeintel_files. The cascade seeks child rows by
// BARE file_id, but every file_id index is (project, file_id, ...) —
// project-first — so SQLite can't use it for the cascade and full-scans
// codeintel_{nodes,edges,sites} once PER deleted file: O(files × rows),
// measured at 20+ minutes / 100% CPU on a ~40k-file project. The
// per-`project` deletes here each ride a project-leading index instead, and
// FK enforcement is disabled for the operation so the (now-redundant)
// cascade machinery doesn't re-scan. Correctness is preserved because every
// child table is deleted explicitly — including codeintel_fts, a virtual
// table with NO foreign key that the old cascade-only delete leaked entirely.
//
// foreign_keys is toggled on a single pinned connection (the pragma is a
// no-op inside a transaction and is per-connection) and always restored
// before that connection returns to the pool.
func (s *Store) CodeIntelDeleteProject(ctx context.Context, project string) error {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("store.CodeIntelDeleteProject: conn: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, `PRAGMA foreign_keys=OFF`); err != nil {
		return fmt.Errorf("store.CodeIntelDeleteProject: disable fk: %w", err)
	}
	// Restore FK enforcement before the connection goes back to the pool,
	// using a background context so a cancelled ctx can't skip the restore.
	defer func() { _, _ = conn.ExecContext(context.Background(), `PRAGMA foreign_keys=ON`) }()

	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.CodeIntelDeleteProject: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := codeIntelDeleteProjectTx(ctx, tx, project); err != nil {
		return fmt.Errorf("store.CodeIntelDeleteProject: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store.CodeIntelDeleteProject: commit: %w", err)
	}
	return nil
}

// codeIntelProjectDeletes is the per-project delete fan-out, child-to-parent.
// It is a package-level list with exactly TWO callers — CodeIntelDeleteProject
// and the archive-completion path in archive.go — so "one owner per table"
// survives the arrival of cold storage: the archival move must not grow a
// second, quietly divergent copy of this statement list. In particular
// codeintel_fts is a virtual table with no foreign key, and a copy that
// forgets it leaks the whole FTS index (the bug this list's explicitness was
// introduced to fix).
var codeIntelProjectDeletes = []string{
	`DELETE FROM codeintel_fts WHERE project = ?`,
	`DELETE FROM codeintel_embeddings WHERE project = ?`,
	`DELETE FROM codeintel_minhash WHERE project = ?`,
	`DELETE FROM codeintel_sites WHERE project = ?`,
	`DELETE FROM codeintel_edges WHERE project = ?`,
	`DELETE FROM codeintel_nodes WHERE project = ?`,
	`DELETE FROM codeintel_files WHERE project = ?`,
}

// codeIntelDeleteProjectTx runs the fan-out inside a caller-owned transaction.
// The caller is responsible for the foreign_keys=OFF pinning documented on
// CodeIntelDeleteProject — without it, the cascade re-scan makes this O(files
// × rows).
func codeIntelDeleteProjectTx(ctx context.Context, tx *sql.Tx, project string) error {
	for _, del := range codeIntelProjectDeletes {
		if _, err := tx.ExecContext(ctx, del, project); err != nil {
			return err
		}
	}
	return nil
}

// CodeIntelDeleteProjectsUnder removes the code-intelligence index for
// root AND every indexed project nested beneath it, returning the
// project keys it deleted (root-first, then descendants in listing
// order). Matching is on normalized path boundaries — a project is a
// descendant only when it equals root or begins with root + a path
// separator — so "/a/b" never sweeps up the sibling "/a/bc". This is
// the store half of `observer index delete --recursive`: the
// one-command way to un-index a whole tree you never meant to index.
func (s *Store) CodeIntelDeleteProjectsUnder(ctx context.Context, root string) ([]string, error) {
	all, err := s.CodeIntelListProjects(ctx)
	if err != nil {
		return nil, fmt.Errorf("store.CodeIntelDeleteProjectsUnder: %w", err)
	}
	prefix := root + string(filepath.Separator)
	var targets []string
	for _, p := range all {
		if p == root || strings.HasPrefix(p, prefix) {
			targets = append(targets, p)
		}
	}
	for _, p := range targets {
		if err := s.CodeIntelDeleteProject(ctx, p); err != nil {
			return nil, fmt.Errorf("store.CodeIntelDeleteProjectsUnder: %w", err)
		}
	}
	return targets, nil
}

// CodeIntelPruneStaleProjects deletes every codeintel_* row for projects
// whose most recent index pass (MAX(codeintel_files.indexed_at), unix
// seconds) is older than retentionDays, returning the project keys it
// deleted. This is the [codeintel].retention_days sweep (Ticket B,
// docs/plans/claude-code-hook-stall-ticket-and-db-prune-plan-2026-07-12.md):
// the index is rebuildable from the repo, so age-pruning is safe, and each
// project deletes through the SAME CodeIntelDeleteProject path `observer
// index delete -r` uses (one owner per table — no second delete SQL).
//
// Conservative by construction:
//   - retentionDays ≤ 0 disables the sweep entirely (returns nil, nil).
//   - A project with NO successful index pass yet (MAX(indexed_at) = 0 —
//     e.g. freshly registered files still 'pending') is NEVER pruned; its
//     zero watermark says "not indexed", not "indexed long ago".
//   - An actively indexed project always carries a fresh indexed_at and
//     is untouched.
//
// Idempotent: a second run within the same horizon finds no stale
// projects and is a no-op.
func (s *Store) CodeIntelPruneStaleProjects(ctx context.Context, retentionDays int) ([]string, error) {
	candidates, err := s.CodeIntelStaleProjects(ctx, retentionDays)
	if err != nil {
		return nil, fmt.Errorf("store.CodeIntelPruneStaleProjects: %w", err)
	}
	stale := make([]string, 0, len(candidates))
	for _, c := range candidates {
		stale = append(stale, c.Project)
	}
	for _, p := range stale {
		if err := s.CodeIntelDeleteProject(ctx, p); err != nil {
			return nil, fmt.Errorf("store.CodeIntelPruneStaleProjects: %w", err)
		}
	}
	if len(stale) == 0 {
		return nil, nil
	}
	return stale, nil
}

// CodeIntelProjectStatus returns a count of files per status for a
// project (the substrate for `observer index status`).
func (s *Store) CodeIntelProjectStatus(ctx context.Context, project string) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT status, COUNT(*) FROM codeintel_files WHERE project = ? GROUP BY status`, project)
	if err != nil {
		return nil, fmt.Errorf("store.CodeIntelProjectStatus: %w", err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			return nil, fmt.Errorf("store.CodeIntelProjectStatus: scan: %w", err)
		}
		out[st] = n
	}
	return out, rows.Err()
}

// --- read / engine side (codeintel.EngineStore) ----------------------

// CodeIntelHasIndex reports whether any file is in the 'indexed' state —
// the native engine's Available() gate.
func (s *Store) CodeIntelHasIndex(ctx context.Context) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM codeintel_files WHERE status = 'indexed' LIMIT 1`).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("store.CodeIntelHasIndex: %w", err)
	}
	return n > 0, nil
}

// CodeIntelFileMeta returns the index metadata for an absolute path:
// whether it is indexed, its last index pass (unix), and stored hash.
func (s *Store) CodeIntelFileMeta(ctx context.Context, absPath string) (indexed bool, indexedAt int64, contentHash string, err error) {
	var status string
	row := s.db.QueryRowContext(ctx,
		`SELECT status, indexed_at, content_hash FROM codeintel_files WHERE path = ?`, absPath)
	switch e := row.Scan(&status, &indexedAt, &contentHash); e {
	case nil:
		return status == "indexed", indexedAt, contentHash, nil
	case sql.ErrNoRows:
		return false, 0, "", nil
	default:
		return false, 0, "", fmt.Errorf("store.CodeIntelFileMeta: %w", e)
	}
}

// userFacingKinds is the symbol-kind filter shared by the read queries —
// matches the codegraph wrapper's set so the native engine is a drop-in.
const codeIntelUserFacingKinds = "kind IN ('function','method','class','interface','type','enum')"

// CodeIntelSymbolsInFile returns the user-facing symbols defined in
// absPath, sorted by start_line for byte-stable output. It tries an exact
// path match first (the native Claude-Code path, which hands us the
// indexed absolute path); on a miss it falls back to a tolerant
// unique-suffix match so codex shell-read paths — which are relative or
// foreign-OS (Windows D:\ vs the WSL /mnt/d the index keys on) and never
// exact-match — still resolve to their symbols. Ambiguous suffixes are
// skipped, so we never collapse against the wrong file.
func (s *Store) CodeIntelSymbolsInFile(ctx context.Context, absPath string) ([]codeintel.Symbol, error) {
	syms, err := s.codeIntelSymbolsByPath(ctx, absPath)
	if err != nil || len(syms) > 0 {
		return syms, err
	}
	if resolved := s.codeIntelResolvePathBySuffix(ctx, absPath); resolved != "" {
		return s.codeIntelSymbolsByPath(ctx, resolved)
	}
	return nil, nil
}

// codeIntelSymbolsByPath is the exact-path symbol query backing
// [CodeIntelSymbolsInFile].
func (s *Store) codeIntelSymbolsByPath(ctx context.Context, absPath string) ([]codeintel.Symbol, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT n.name, n.kind, n.start_line, n.end_line, f.parser
		 FROM codeintel_nodes n JOIN codeintel_files f ON f.id = n.file_id
		 WHERE f.path = ? AND `+codeIntelUserFacingKinds+`
		 ORDER BY n.start_line ASC LIMIT 50`, absPath)
	if err != nil {
		return nil, nil // fail open
	}
	defer rows.Close()
	var out []codeintel.Symbol
	for rows.Next() {
		var sym codeintel.Symbol
		var parser string
		if err := rows.Scan(&sym.Name, &sym.Kind, &sym.StartLine, &sym.EndLine, &parser); err != nil {
			return nil, fmt.Errorf("store.CodeIntelSymbolsInFile: scan: %w", err)
		}
		if sym.Name == "" {
			continue
		}
		// ADR-0005: stamp exactness from the file's backend so the
		// aggressive compressor can refuse heuristic spans.
		sym.Exact = codeintel.ExactParser(parser)
		out = append(out, sym)
	}
	return out, rows.Err()
}

// codeIntelResolvePathBySuffix returns the indexed file path that uniquely
// shares the longest trailing path-component suffix with raw, or "" when
// there is no candidate or the best match is ambiguous (a tie). It lets a
// codex shell-read path (relative, or Windows-form against a WSL-keyed
// index) reconcile with the absolute, OS-native paths the index stores,
// without ever guessing when two files could match.
func (s *Store) codeIntelResolvePathBySuffix(ctx context.Context, raw string) string {
	norm := strings.Trim(strings.ReplaceAll(raw, "\\", "/"), "\"'")
	base := norm
	if i := strings.LastIndex(norm, "/"); i >= 0 {
		base = norm[i+1:]
	}
	if base == "" {
		return ""
	}
	// Candidate set: files whose path equals norm or ends in /<base>.
	// The exact Go suffix compare below is the real filter, so an over-
	// broad LIKE (underscores in base act as wildcards) only widens the
	// candidate pool harmlessly.
	rows, err := s.db.QueryContext(ctx,
		`SELECT DISTINCT path FROM codeintel_files WHERE path = ? OR path LIKE '%/' || ?`,
		norm, base)
	if err != nil {
		return ""
	}
	defer rows.Close()
	var candidates []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return ""
		}
		candidates = append(candidates, p)
	}
	if rows.Err() != nil {
		return ""
	}
	return uniqueLongestSuffixMatch(norm, candidates)
}

// uniqueLongestSuffixMatch returns the candidate sharing the most trailing
// path components with target, or "" when there are no candidates or two
// candidates tie for the longest match (ambiguous). Comparison is on
// forward-slash components.
func uniqueLongestSuffixMatch(target string, candidates []string) string {
	tc := splitPathComponents(target)
	best := ""
	bestN := 0
	tie := false
	for _, c := range candidates {
		n := commonSuffixComponents(tc, splitPathComponents(c))
		if n == 0 {
			continue
		}
		switch {
		case n > bestN:
			bestN, best, tie = n, c, false
		case n == bestN:
			tie = true
		}
	}
	if best == "" || tie {
		return ""
	}
	return best
}

// splitPathComponents splits p on / (after folding \ to /) into non-empty
// components.
func splitPathComponents(p string) []string {
	parts := strings.Split(strings.ReplaceAll(p, "\\", "/"), "/")
	out := make([]string, 0, len(parts))
	for _, s := range parts {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// commonSuffixComponents counts how many trailing components a and b share.
func commonSuffixComponents(a, b []string) int {
	n := 0
	for n < len(a) && n < len(b) && a[len(a)-1-n] == b[len(b)-1-n] {
		n++
	}
	return n
}

// CodeIntelFunctionsInFile returns the function names defined in absPath.
func (s *Store) CodeIntelFunctionsInFile(ctx context.Context, absPath string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT n.name FROM codeintel_nodes n JOIN codeintel_files f ON f.id = n.file_id
		 WHERE f.path = ? AND n.kind = 'function' ORDER BY n.start_line LIMIT 200`, absPath)
	if err != nil {
		return nil, nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("store.CodeIntelFunctionsInFile: scan: %w", err)
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

// CodeIntelFindSymbols mirrors codegraph.FindSymbols: matches in absFile
// filtered by the optional (name, fqn, kind) selectors. All-empty is
// discovery mode (every user-facing symbol).
func (s *Store) CodeIntelFindSymbols(ctx context.Context, absFile, name, fqn, kind string) ([]codeintel.SymbolMatch, error) {
	q := `SELECT n.id, n.name, n.fqn, n.kind, f.path, n.lang, n.start_line, n.end_line
	      FROM codeintel_nodes n JOIN codeintel_files f ON f.id = n.file_id
	      WHERE f.path = ?`
	args := []any{absFile}
	switch {
	case fqn != "":
		q += ` AND n.fqn = ?`
		args = append(args, fqn)
	case name != "":
		q += ` AND n.name = ?`
		args = append(args, name)
	default:
		q += ` AND ` + codeIntelUserFacingKinds
	}
	if kind != "" {
		q += ` AND n.kind = ?`
		args = append(args, kind)
	}
	q += ` ORDER BY n.start_line ASC LIMIT 50`

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, nil
	}
	defer rows.Close()
	var out []codeintel.SymbolMatch
	for rows.Next() {
		var m codeintel.SymbolMatch
		if err := rows.Scan(&m.ID, &m.Name, &m.FQN, &m.Kind, &m.File, &m.Language, &m.StartLine, &m.EndLine); err != nil {
			return nil, fmt.Errorf("store.CodeIntelFindSymbols: scan: %w", err)
		}
		if m.Name == "" {
			continue
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// CodeIntelResolveCalls is the project-level name-matched CALLS
// resolution sweep (docs/codeintel/resolution.md). It loads every
// defined symbol, then fills in dst_id for each CALLS edge still
// unresolved (dst_id=0) by matching its site's target_name. Returns the
// number of edges newly resolved. Run after a project's files are
// indexed; cheap to re-run (idempotent — already-resolved edges are
// skipped by the dst_id=0 filter).
func (s *Store) CodeIntelResolveCalls(ctx context.Context, project string) (int, error) {
	// 1. Build the name index from all project nodes.
	nrows, err := s.db.QueryContext(ctx,
		`SELECT id, name, file_id FROM codeintel_nodes WHERE project = ? AND name != ''`, project)
	if err != nil {
		return 0, fmt.Errorf("store.CodeIntelResolveCalls: load nodes: %w", err)
	}
	var nodes []resolve.NodeRef
	for nrows.Next() {
		var n resolve.NodeRef
		if err := nrows.Scan(&n.ID, &n.Name, &n.FileID); err != nil {
			nrows.Close()
			return 0, fmt.Errorf("store.CodeIntelResolveCalls: scan node: %w", err)
		}
		nodes = append(nodes, n)
	}
	nrows.Close()
	if err := nrows.Err(); err != nil {
		return 0, err
	}
	idx := resolve.BuildNameIndex(nodes)

	// 2. Load unresolved CALLS edges + their callee name + owning file.
	type pending struct {
		edgeID int64
		file   int64
		callee string
	}
	erows, err := s.db.QueryContext(ctx,
		`SELECT e.id, e.file_id, s.target_name
		 FROM codeintel_edges e JOIN codeintel_sites s ON s.edge_id = e.id
		 WHERE e.project = ? AND e.kind = 'CALLS' AND e.dst_id = 0`, project)
	if err != nil {
		return 0, fmt.Errorf("store.CodeIntelResolveCalls: load edges: %w", err)
	}
	var pend []pending
	for erows.Next() {
		var p pending
		if err := erows.Scan(&p.edgeID, &p.file, &p.callee); err != nil {
			erows.Close()
			return 0, fmt.Errorf("store.CodeIntelResolveCalls: scan edge: %w", err)
		}
		pend = append(pend, p)
	}
	erows.Close()
	if err := erows.Err(); err != nil {
		return 0, err
	}

	// 3. Resolve + update in one transaction.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store.CodeIntelResolveCalls: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	upd, err := tx.PrepareContext(ctx,
		`UPDATE codeintel_edges SET dst_id = ?, resolver_backend = 'name-matched', confidence = ? WHERE id = ?`)
	if err != nil {
		return 0, fmt.Errorf("store.CodeIntelResolveCalls: prepare: %w", err)
	}
	defer upd.Close()
	resolved := 0
	for _, p := range pend {
		dst, ok := idx.Resolve(p.callee, p.file)
		if !ok {
			continue
		}
		conf := 1.0
		if idx.Ambiguous(p.callee) {
			conf = 0.5 // name-ambiguous — a documented fidelity bound
		}
		if _, err := upd.ExecContext(ctx, dst, conf, p.edgeID); err != nil {
			return 0, fmt.Errorf("store.CodeIntelResolveCalls: update: %w", err)
		}
		resolved++
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store.CodeIntelResolveCalls: commit: %w", err)
	}
	return resolved, nil
}

// CodeIntelResolveScoped is the project-level SCOPED CALLS upgrade pass
// (W2; docs/codeintel/resolution.md "Scoped resolution"). It runs AFTER
// CodeIntelResolveCalls and upgrades the dominant unambiguous edges in
// place, raising confidence to ~0.9 and stamping
// resolver_backend='scoped'. Everything it is not sure about keeps its
// name-matched binding (no regression). Two models, dispatched on the
// language's registry membership (capability, never a hardcoded branch):
// the Go package-dir model (bare/qualified/receiver) and the TS/Python
// module-import model (imported-name + namespace binding). A language in
// neither registry is skipped. Returns the number of edges upgraded.
// Idempotent.
func (s *Store) CodeIntelResolveScoped(ctx context.Context, project string) (int, error) {
	upgraded := 0
	// Go-style package-dir model (bare/qualified/receiver binding).
	for _, lang := range resolve.PackageScopedLangs() {
		rules, ok := resolve.ScopeRulesFor(lang)
		if !ok {
			continue
		}
		n, err := s.resolveScopedLang(ctx, project, lang, rules)
		if err != nil {
			return upgraded, err
		}
		upgraded += n
	}
	// Module-import model (TS/Python: per-file imports, name-bound).
	for _, lang := range resolve.ModuleScopedLangs() {
		rules, ok := resolve.ModuleRulesFor(lang)
		if !ok {
			continue
		}
		n, err := s.resolveModuleLang(ctx, project, lang, rules)
		if err != nil {
			return upgraded, err
		}
		upgraded += n
	}
	return upgraded, nil
}

// applyScopedBindings applies a set of scoped CALLS upgrades in one
// transaction: each edge's dst is rebound, resolver_backend stamped
// 'scoped', and confidence raised. Shared by the package-dir and
// module-import resolvers (one owner for the codeintel_edges write).
func (s *Store) applyScopedBindings(ctx context.Context, bindings []resolve.Binding) (int, error) {
	if len(bindings) == 0 {
		return 0, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store.CodeIntelResolveScoped: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	upd, err := tx.PrepareContext(ctx,
		`UPDATE codeintel_edges SET dst_id = ?, resolver_backend = 'scoped', confidence = ? WHERE id = ?`)
	if err != nil {
		return 0, fmt.Errorf("store.CodeIntelResolveScoped: prepare: %w", err)
	}
	defer upd.Close()
	for _, b := range bindings {
		if _, err := upd.ExecContext(ctx, b.DstID, b.Confidence, b.EdgeID); err != nil {
			return 0, fmt.Errorf("store.CodeIntelResolveScoped: update: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store.CodeIntelResolveScoped: commit: %w", err)
	}
	return len(bindings), nil
}

// resolveScopedLang runs the scoped upgrade for one caller language.
func (s *Store) resolveScopedLang(ctx context.Context, project, lang string, rules resolve.ScopeRules) (int, error) {
	// 1. Target nodes for this language, with their package (file dir) and
	//    FQN (for receiver-method binding).
	nrows, err := s.db.QueryContext(ctx,
		`SELECT n.id, n.name, n.fqn, n.file_id, f.path
		 FROM codeintel_nodes n JOIN codeintel_files f ON f.id = n.file_id
		 WHERE n.project = ? AND f.lang = ? AND n.name != ''`, project, lang)
	if err != nil {
		return 0, fmt.Errorf("store.CodeIntelResolveScoped: load nodes: %w", err)
	}
	var nodes []resolve.ScopedNodeRef
	for nrows.Next() {
		var n resolve.ScopedNodeRef
		var path string
		if err := nrows.Scan(&n.ID, &n.Name, &n.FQN, &n.FileID, &path); err != nil {
			nrows.Close()
			return 0, fmt.Errorf("store.CodeIntelResolveScoped: scan node: %w", err)
		}
		n.Pkg = pkgDirOf(path)
		nodes = append(nodes, n)
	}
	nrows.Close()
	if err := nrows.Err(); err != nil {
		return 0, err
	}

	// 2. Per-file import bindings (unaliased: local name = path basename).
	irows, err := s.db.QueryContext(ctx,
		`SELECT s.file_id, s.target_name
		 FROM codeintel_sites s
		 JOIN codeintel_edges e ON e.id = s.edge_id
		 JOIN codeintel_files f ON f.id = s.file_id
		 WHERE e.project = ? AND e.kind = 'IMPORTS' AND f.lang = ? AND s.target_name != ''`,
		project, lang)
	if err != nil {
		return 0, fmt.Errorf("store.CodeIntelResolveScoped: load imports: %w", err)
	}
	imports := map[int64][]resolve.ImportBinding{}
	for irows.Next() {
		var fileID int64
		var path string
		if err := irows.Scan(&fileID, &path); err != nil {
			irows.Close()
			return 0, fmt.Errorf("store.CodeIntelResolveScoped: scan import: %w", err)
		}
		base := pkgBaseOf(path)
		imports[fileID] = append(imports[fileID], resolve.ImportBinding{Local: base, Pkg: base})
	}
	irows.Close()
	if err := irows.Err(); err != nil {
		return 0, err
	}

	// 3. CALLS edges authored in this language's files (incl. already
	//    name-matched ones — scoped is an in-place upgrade).
	crows, err := s.db.QueryContext(ctx,
		`SELECT e.id, e.file_id, s.target_name, s.raw_text, f.path, COALESCE(src.signature, ''), COALESCE(s.recv_type, '')
		 FROM codeintel_edges e
		 JOIN codeintel_sites s ON s.edge_id = e.id
		 JOIN codeintel_files f ON f.id = e.file_id
		 LEFT JOIN codeintel_nodes src ON src.id = e.src_id
		 WHERE e.project = ? AND e.kind = 'CALLS' AND f.lang = ?`, project, lang)
	if err != nil {
		return 0, fmt.Errorf("store.CodeIntelResolveScoped: load calls: %w", err)
	}
	var calls []resolve.ScopedCall
	for crows.Next() {
		var c resolve.ScopedCall
		var path string
		if err := crows.Scan(&c.EdgeID, &c.CallerFile, &c.Callee, &c.RawText, &path, &c.CallerSig, &c.RecvType); err != nil {
			crows.Close()
			return 0, fmt.Errorf("store.CodeIntelResolveScoped: scan call: %w", err)
		}
		c.CallerPkg = pkgDirOf(path)
		calls = append(calls, c)
	}
	crows.Close()
	if err := crows.Err(); err != nil {
		return 0, err
	}

	bindings := resolve.ScopedResolve(rules, nodes, imports, calls)
	return s.applyScopedBindings(ctx, bindings)
}

// resolveModuleLang runs the module-import scoped upgrade for one language
// (TS/Python): a node's scope key is its FILE path (not a directory), and a
// call binds through the importing file's imports (the imported names live
// in the import site's raw_text statement line) resolved to a unique
// indexed file. Unambiguous-only, same as the Go package model.
func (s *Store) resolveModuleLang(ctx context.Context, project, lang string, rules resolve.ModuleRules) (int, error) {
	// 1. Target nodes — scope key = the file path itself.
	nrows, err := s.db.QueryContext(ctx,
		`SELECT n.id, n.name, n.fqn, n.file_id, f.path
		 FROM codeintel_nodes n JOIN codeintel_files f ON f.id = n.file_id
		 WHERE n.project = ? AND f.lang = ? AND n.name != ''`, project, lang)
	if err != nil {
		return 0, fmt.Errorf("store.CodeIntelResolveScoped: load module nodes: %w", err)
	}
	var nodes []resolve.ScopedNodeRef
	for nrows.Next() {
		var n resolve.ScopedNodeRef
		var path string
		if err := nrows.Scan(&n.ID, &n.Name, &n.FQN, &n.FileID, &path); err != nil {
			nrows.Close()
			return 0, fmt.Errorf("store.CodeIntelResolveScoped: scan module node: %w", err)
		}
		n.Pkg = filepath.ToSlash(path) // scope = normalised file path
		nodes = append(nodes, n)
	}
	nrows.Close()
	if err := nrows.Err(); err != nil {
		return 0, err
	}

	// 2. Per-file imports: module path + the statement-line excerpt (carries
	//    the imported names, parsed in the pure resolver).
	irows, err := s.db.QueryContext(ctx,
		`SELECT s.file_id, s.target_name, s.raw_text
		 FROM codeintel_sites s
		 JOIN codeintel_edges e ON e.id = s.edge_id
		 JOIN codeintel_files f ON f.id = s.file_id
		 WHERE e.project = ? AND e.kind = 'IMPORTS' AND f.lang = ? AND s.target_name != ''`,
		project, lang)
	if err != nil {
		return 0, fmt.Errorf("store.CodeIntelResolveScoped: load module imports: %w", err)
	}
	imports := map[int64][]resolve.RawImport{}
	for irows.Next() {
		var fileID int64
		var ri resolve.RawImport
		if err := irows.Scan(&fileID, &ri.Path, &ri.RawText); err != nil {
			irows.Close()
			return 0, fmt.Errorf("store.CodeIntelResolveScoped: scan module import: %w", err)
		}
		imports[fileID] = append(imports[fileID], ri)
	}
	irows.Close()
	if err := irows.Err(); err != nil {
		return 0, err
	}

	// 3. CALLS edges (caller scope key = the file path).
	crows, err := s.db.QueryContext(ctx,
		`SELECT e.id, e.file_id, s.target_name, s.raw_text, f.path
		 FROM codeintel_edges e
		 JOIN codeintel_sites s ON s.edge_id = e.id
		 JOIN codeintel_files f ON f.id = e.file_id
		 WHERE e.project = ? AND e.kind = 'CALLS' AND f.lang = ?`, project, lang)
	if err != nil {
		return 0, fmt.Errorf("store.CodeIntelResolveScoped: load module calls: %w", err)
	}
	var calls []resolve.ScopedCall
	for crows.Next() {
		var c resolve.ScopedCall
		var path string
		if err := crows.Scan(&c.EdgeID, &c.CallerFile, &c.Callee, &c.RawText, &path); err != nil {
			crows.Close()
			return 0, fmt.Errorf("store.CodeIntelResolveScoped: scan module call: %w", err)
		}
		c.CallerPkg = filepath.ToSlash(path)
		calls = append(calls, c)
	}
	crows.Close()
	if err := crows.Err(); err != nil {
		return 0, err
	}

	// 4. The language's indexed file set (for module-path resolution).
	frows, err := s.db.QueryContext(ctx,
		`SELECT path FROM codeintel_files WHERE project = ? AND lang = ?`, project, lang)
	if err != nil {
		return 0, fmt.Errorf("store.CodeIntelResolveScoped: load module files: %w", err)
	}
	var files []string
	for frows.Next() {
		var p string
		if err := frows.Scan(&p); err != nil {
			frows.Close()
			return 0, fmt.Errorf("store.CodeIntelResolveScoped: scan module file: %w", err)
		}
		files = append(files, filepath.ToSlash(p))
	}
	frows.Close()
	if err := frows.Err(); err != nil {
		return 0, err
	}

	bindings := resolve.ModuleResolve(rules, nodes, imports, calls, files)
	return s.applyScopedBindings(ctx, bindings)
}

// pkgDirOf returns the directory portion of a stored file path (the Go
// package key), separator-agnostic so a Windows-stored ('\') or
// WSL/Unix-stored ('/') path both resolve correctly.
func pkgDirOf(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[:i]
	}
	return p
}

// pkgBaseOf returns the last segment of a path or import specifier (its
// basename), separator-agnostic.
func pkgBaseOf(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// CodeIntelImportsInFile returns the import specifiers referenced from
// absPath (the IMPORTS sites' target names).
func (s *Store) CodeIntelImportsInFile(ctx context.Context, absPath string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT DISTINCT s.target_name
		 FROM codeintel_sites s
		 JOIN codeintel_edges e ON e.id = s.edge_id
		 JOIN codeintel_files f ON f.id = s.file_id
		 WHERE e.kind = 'IMPORTS' AND f.path = ? AND s.target_name != ''
		 ORDER BY s.target_name LIMIT 200`, absPath)
	if err != nil {
		return nil, nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, fmt.Errorf("store.CodeIntelImportsInFile: scan: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// codeIntelRefSelect is the shared column list for caller/callee/reachable
// reads — keeps the Ref shape consistent across the three.
const codeIntelRefSelect = `COALESCE(n.id,0), COALESCE(n.name,''), COALESCE(n.fqn,''),
	COALESCE(n.kind,''), COALESCE(f.path,''), COALESCE(n.lang,''),
	COALESCE(n.start_line,0), COALESCE(n.end_line,0)`

func scanRefs(rows *sql.Rows) ([]codeintel.Ref, error) {
	defer rows.Close()
	var out []codeintel.Ref
	for rows.Next() {
		var r codeintel.Ref
		if err := rows.Scan(&r.ID, &r.Name, &r.FQN, &r.Kind, &r.File, &r.Language, &r.StartLine, &r.EndLine); err != nil {
			return nil, fmt.Errorf("store: scan ref: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CodeIntelCallersOfSymbol returns symbols that call symbolID via CALLS edges.
func (s *Store) CodeIntelCallersOfSymbol(ctx context.Context, symbolID int64, limit int) ([]codeintel.Ref, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+codeIntelRefSelect+`
		 FROM codeintel_edges e
		 JOIN codeintel_nodes n ON n.id = e.src_id
		 JOIN codeintel_files f ON f.id = n.file_id
		 WHERE e.kind = 'CALLS' AND e.dst_id = ? AND e.src_id != 0
		 ORDER BY n.start_line ASC, n.name ASC, n.id ASC LIMIT ?`, symbolID, limit)
	if err != nil {
		return nil, nil
	}
	return scanRefs(rows)
}

// CodeIntelCalleesOfSymbol returns symbols that symbolID calls.
func (s *Store) CodeIntelCalleesOfSymbol(ctx context.Context, symbolID int64, limit int) ([]codeintel.Ref, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+codeIntelRefSelect+`
		 FROM codeintel_edges e
		 JOIN codeintel_nodes n ON n.id = e.dst_id
		 JOIN codeintel_files f ON f.id = n.file_id
		 WHERE e.kind = 'CALLS' AND e.src_id = ? AND e.dst_id != 0
		 ORDER BY n.start_line ASC, n.name ASC, n.id ASC LIMIT ?`, symbolID, limit)
	if err != nil {
		return nil, nil
	}
	return scanRefs(rows)
}

// CodeIntelCountCallers returns the count of symbols calling symbolID.
func (s *Store) CodeIntelCountCallers(ctx context.Context, symbolID int64) (int, error) {
	return s.codeIntelCountEdges(ctx, "dst_id", symbolID)
}

// CodeIntelCountCallees returns the count of symbols symbolID calls.
func (s *Store) CodeIntelCountCallees(ctx context.Context, symbolID int64) (int, error) {
	return s.codeIntelCountEdges(ctx, "src_id", symbolID)
}

func (s *Store) codeIntelCountEdges(ctx context.Context, col string, symbolID int64) (int, error) {
	other := "src_id"
	if col == "src_id" {
		other = "dst_id"
	}
	// col ∈ {src_id, dst_id} — fixed identifiers, symbolID is bound.
	q := `SELECT COUNT(*) FROM codeintel_edges WHERE kind = 'CALLS' AND ` + col + ` = ? AND ` + other + ` != 0`
	var n int
	if err := s.db.QueryRowContext(ctx, q, symbolID).Scan(&n); err != nil {
		return 0, nil
	}
	return n, nil
}

// CodeIntelCountEdgesByKind returns the total edges of a kind.
func (s *Store) CodeIntelCountEdgesByKind(ctx context.Context, kind string) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM codeintel_edges WHERE kind = ?`, kind).Scan(&n); err != nil {
		return 0, nil
	}
	return n, nil
}

// CodeIntelCallersOf returns names of symbols that call functionName.
func (s *Store) CodeIntelCallersOf(ctx context.Context, functionName string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT DISTINCT src.name
		 FROM codeintel_edges e
		 JOIN codeintel_nodes dst ON dst.id = e.dst_id
		 JOIN codeintel_nodes src ON src.id = e.src_id
		 WHERE e.kind = 'CALLS' AND dst.name = ? AND src.name != ''
		 ORDER BY src.name LIMIT 200`, functionName)
	if err != nil {
		return nil, nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, fmt.Errorf("store.CodeIntelCallersOf: scan: %w", err)
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// CodeIntelReachable returns symbols reachable from anchorID via the
// chosen relation, up to maxDepth hops, capped at maxResults. Cycle-safe
// recursive CTE (shortest-path-wins). CALLS traversals ride the
// name-matched call graph; RelationContains rides the structural CONTAINS
// edges (parent -> child span nesting) populated at index time.
func (s *Store) CodeIntelReachable(ctx context.Context, anchorID int64, dir codeintel.RelationDirection, maxDepth, maxResults int) ([]codeintel.Ref, bool, error) {
	if anchorID == 0 {
		return nil, false, nil
	}
	if maxDepth <= 0 {
		maxDepth = 1
	}
	if maxResults <= 0 {
		maxResults = 1
	}
	var seedCol, recurseCol, edgeKind string
	switch dir {
	case codeintel.RelationCallers:
		seedCol, recurseCol, edgeKind = "dst_id", "src_id", "CALLS"
	case codeintel.RelationCallees:
		seedCol, recurseCol, edgeKind = "src_id", "dst_id", "CALLS"
	case codeintel.RelationContains:
		// CONTAINS is directed parent -> child: seed on the parent (src),
		// recurse to children (dst).
		seedCol, recurseCol, edgeKind = "src_id", "dst_id", "CONTAINS"
	default:
		return nil, false, nil
	}
	// seedCol/recurseCol ∈ {src_id,dst_id} (fixed); all user values bound.
	//nolint:gosec // G202: identifiers from a closed switch, values param-bound
	q := `WITH RECURSIVE reach(id, depth) AS (
		SELECT e.` + recurseCol + `, 1 FROM codeintel_edges e
		WHERE e.` + seedCol + ` = ? AND e.kind = ? AND e.` + recurseCol + ` != 0
		UNION
		SELECT e.` + recurseCol + `, r.depth+1 FROM reach r
		JOIN codeintel_edges e ON e.` + seedCol + ` = r.id
		WHERE e.kind = ? AND e.` + recurseCol + ` != 0 AND r.depth < ?
	)
	SELECT ` + codeIntelRefSelect + `, MIN(r.depth) AS d
	FROM reach r JOIN codeintel_nodes n ON n.id = r.id
	JOIN codeintel_files f ON f.id = n.file_id
	GROUP BY n.id
	ORDER BY d ASC, n.start_line ASC, n.name ASC, n.id ASC LIMIT ?`
	rows, err := s.db.QueryContext(ctx, q, anchorID, edgeKind, edgeKind, maxDepth, maxResults)
	if err != nil {
		return nil, false, nil
	}
	defer rows.Close()
	var out []codeintel.Ref
	for rows.Next() {
		var r codeintel.Ref
		if err := rows.Scan(&r.ID, &r.Name, &r.FQN, &r.Kind, &r.File, &r.Language, &r.StartLine, &r.EndLine, &r.Depth); err != nil {
			return nil, false, fmt.Errorf("store.CodeIntelReachable: scan: %w", err)
		}
		r.ViaEdge = edgeKind
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	return out, len(out) >= maxResults, nil
}

// --- Tier C: search / semantic / similarity (Phase 6) ----------------
//
// codeintel_fts / codeintel_embeddings / codeintel_minhash are DERIVED
// from codeintel_nodes. CodeIntelBuildDerived rebuilds them for a
// project in one transaction (DELETE-by-project then re-insert), so they
// self-heal whenever it runs — there is no per-file incremental
// bookkeeping. Because the rebuild is whole-project it is NOT free to
// re-run: the caller (index.IndexProject) runs it only when the pass
// changed a file, or when CodeIntelHasDerived reports the rows missing.
// The pure token/vector/LSH math lives in internal/codeintel/semantic;
// this seam only persists and queries.

// codeIntelDerivedText is the searchable/embeddable text for a node:
// name + fqn + signature. Bounded (signature is a declaration-line
// excerpt) — never a body.
func codeIntelDerivedText(name, fqn, signature string) string {
	return name + " " + fqn + " " + signature
}

// minEmbedTokens is the W4 floor on distinct tokens for a symbol to earn a
// semantic embedding row. Below it the feature-hashed vector is too sparse
// to be meaningful and only produces hash-collision noise in `related`
// (the measured `bytesTrimSpace`-class artifacts). FTS indexing is
// unaffected. See docs/codeintel/decisions.md ADR-0008.
const minEmbedTokens = 3

// CodeIntelHasDerived reports whether the project's nodes already carry
// their derived FTS rows. It is deliberately a SAMPLE, not a count: the
// rebuild below is one transaction (clear + reinsert commit together), so
// a project's derived rows are all-present or all-absent, and probing a
// single node id is enough to tell the two apart. Cost matters — this
// runs once per project on every `observer start`, so it must never scan.
//
// The probe is by ROWID (codeintel_fts.rowid IS the node id), the only
// cheap lookup an fts5 table offers: a `WHERE project = ?` predicate on
// an fts5 column is a full table scan, which is exactly the cost this
// guard exists to avoid.
//
// A project with no nodes has nothing to derive and reports true.
// Every node gets an FTS row (only embeddings are gated by
// minEmbedTokens), so FTS presence is the right signal.
func (s *Store) CodeIntelHasDerived(ctx context.Context, project string) (bool, error) {
	var nodeID int64
	err := s.db.QueryRowContext(ctx,
		`SELECT id FROM codeintel_nodes WHERE project = ? LIMIT 1`, project).Scan(&nodeID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return true, nil // nothing indexed => nothing to derive
	case err != nil:
		return false, fmt.Errorf("store.CodeIntelHasDerived: probe node: %w", err)
	}
	var one int
	err = s.db.QueryRowContext(ctx,
		`SELECT 1 FROM codeintel_fts WHERE rowid = ?`, nodeID).Scan(&one)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("store.CodeIntelHasDerived: probe fts: %w", err)
	}
	return true, nil
}

// CodeIntelBuildDerived rebuilds the FTS / embedding / MinHash rows for a
// project from its current nodes. Idempotent: clears the project's prior
// derived rows first, so re-running after any index pass is correct.
//
// It is also EXPENSIVE and whole-project: the DELETE-by-project on the
// fts5 table scans and rewrites the project's whole inverted index. Call
// it only when an index pass actually changed something (or when
// CodeIntelHasDerived says the rows are missing) — see
// index.IndexProject, which owns that decision.
func (s *Store) CodeIntelBuildDerived(ctx context.Context, project string) error {
	rows, err := s.db.QueryContext(ctx,
		`SELECT n.id, n.name, n.fqn, n.kind, n.lang, n.signature, n.start_line, n.end_line, f.path
		 FROM codeintel_nodes n JOIN codeintel_files f ON f.id = n.file_id
		 WHERE n.project = ?`, project)
	if err != nil {
		return fmt.Errorf("store.CodeIntelBuildDerived: load nodes: %w", err)
	}
	type derived struct {
		id                 int64
		name, fqn, kind    string
		lang, file         string
		startLine, endLine int
		tokens             string
		vec                []byte
		embeddable         bool
	}
	var ds []derived
	for rows.Next() {
		var d derived
		var sig string
		if err := rows.Scan(&d.id, &d.name, &d.fqn, &d.kind, &d.lang, &sig, &d.startLine, &d.endLine, &d.file); err != nil {
			rows.Close()
			return fmt.Errorf("store.CodeIntelBuildDerived: scan: %w", err)
		}
		text := codeIntelDerivedText(d.name, d.fqn, sig)
		toks := semantic.Tokenize(text) // distinct, camel-split tokens
		d.tokens = strings.Join(toks, " ")
		// W4: skip embedding symbols whose token set is too sparse to carry
		// semantic signal (<minEmbedTokens distinct tokens — e.g. String(),
		// id, ok). Their near-empty vectors otherwise hash-collide into
		// spurious `related` neighbours. They still get an FTS row, so name
		// search is unaffected; they simply have no semantic neighbours.
		if len(toks) >= minEmbedTokens {
			d.embeddable = true
			d.vec = semantic.Pack(semantic.Vectorize(text))
		}
		ds = append(ds, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.CodeIntelBuildDerived: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// NOTE: codeintel_minhash is NOT cleared/rebuilt here — it is owned by
	// CodeIntelSaveFile now (W3 body-shingle near-clone, computed at index
	// time from the file body; the store sweep has no body to MinHash).
	for _, del := range []string{
		`DELETE FROM codeintel_fts WHERE project = ?`,
		`DELETE FROM codeintel_embeddings WHERE project = ?`,
	} {
		if _, err := tx.ExecContext(ctx, del, project); err != nil {
			return fmt.Errorf("store.CodeIntelBuildDerived: clear: %w", err)
		}
	}

	ftsStmt, err := tx.PrepareContext(ctx,
		`INSERT INTO codeintel_fts(rowid, tokens, node_id, project, name, fqn, kind, lang, file, start_line, end_line)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("store.CodeIntelBuildDerived: prepare fts: %w", err)
	}
	defer ftsStmt.Close()
	embStmt, err := tx.PrepareContext(ctx,
		`INSERT INTO codeintel_embeddings(node_id, project, dim, vec) VALUES(?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("store.CodeIntelBuildDerived: prepare emb: %w", err)
	}
	defer embStmt.Close()

	for _, d := range ds {
		if _, err := ftsStmt.ExecContext(ctx, d.id, d.tokens, d.id, project,
			d.name, d.fqn, d.kind, d.lang, d.file, d.startLine, d.endLine); err != nil {
			return fmt.Errorf("store.CodeIntelBuildDerived: insert fts: %w", err)
		}
		if d.embeddable {
			if _, err := embStmt.ExecContext(ctx, d.id, project, semantic.Dim, d.vec); err != nil {
				return fmt.Errorf("store.CodeIntelBuildDerived: insert emb: %w", err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store.CodeIntelBuildDerived: commit: %w", err)
	}
	return nil
}

// CodeIntelSearch runs a full-text symbol search over codeintel_fts,
// scoped to project (empty project = all). The query is identifier-split
// the same way the index is, then OR-matched and ranked by FTS bm25.
func (s *Store) CodeIntelSearch(ctx context.Context, project, query string, limit int) ([]codeintel.SymbolMatch, error) {
	if limit <= 0 {
		limit = 20
	}
	toks := semantic.Tokenize(query)
	if len(toks) == 0 {
		return nil, nil
	}
	quoted := make([]string, len(toks))
	for i, t := range toks {
		quoted[i] = `"` + strings.ReplaceAll(t, `"`, `""`) + `"`
	}
	matchExpr := strings.Join(quoted, " OR ")

	q := `SELECT node_id, name, fqn, kind, file, lang, start_line, end_line
	      FROM codeintel_fts
	      WHERE codeintel_fts MATCH ?`
	args := []any{matchExpr}
	if project != "" {
		q += ` AND project = ?`
		args = append(args, project)
	}
	q += ` ORDER BY rank LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, nil // fail open
	}
	defer rows.Close()
	var out []codeintel.SymbolMatch
	for rows.Next() {
		var m codeintel.SymbolMatch
		if err := rows.Scan(&m.ID, &m.Name, &m.FQN, &m.Kind, &m.File, &m.Language, &m.StartLine, &m.EndLine); err != nil {
			return nil, fmt.Errorf("store.CodeIntelSearch: scan: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// CodeIntelSemanticNeighbors returns the symbols most semantically
// related to nodeID (cosine over the feature-hashed embeddings, scoped to
// the anchor's project). Brute-force cosine — fine for the index sizes we
// target and matches the shipping indexing embedder (ADR-0003).
func (s *Store) CodeIntelSemanticNeighbors(ctx context.Context, nodeID int64, limit int) ([]codeintel.SymbolMatch, error) {
	if limit <= 0 {
		limit = 10
	}
	var project string
	var anchorBlob []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT project, vec FROM codeintel_embeddings WHERE node_id = ?`, nodeID).Scan(&project, &anchorBlob)
	if err != nil {
		return nil, nil // unknown/unembedded anchor — fail open
	}
	anchor := semantic.Unpack(anchorBlob)
	if anchor == nil {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT node_id, vec FROM codeintel_embeddings WHERE project = ? AND node_id != ?`, project, nodeID)
	if err != nil {
		return nil, nil
	}
	defer rows.Close()
	type scored struct {
		id  int64
		sim float64
	}
	var scoredAll []scored
	for rows.Next() {
		var id int64
		var blob []byte
		if err := rows.Scan(&id, &blob); err != nil {
			return nil, fmt.Errorf("store.CodeIntelSemanticNeighbors: scan: %w", err)
		}
		sim := semantic.Cosine(anchor, semantic.Unpack(blob))
		if sim > 0 {
			scoredAll = append(scoredAll, scored{id, sim})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(scoredAll, func(i, j int) bool { return scoredAll[i].sim > scoredAll[j].sim })
	if len(scoredAll) > limit {
		scoredAll = scoredAll[:limit]
	}
	ids := make([]int64, len(scoredAll))
	for i, sc := range scoredAll {
		ids[i] = sc.id
	}
	return s.codeIntelSymbolsByIDs(ctx, ids)
}

// CodeIntelSimilarTo returns near-clone candidates for nodeID, ranked by
// the number of shared MinHash LSH buckets (the LSH proxy for Jaccard).
// Pure SQL self-join over codeintel_minhash.
func (s *Store) CodeIntelSimilarTo(ctx context.Context, nodeID int64, limit int) ([]codeintel.SymbolMatch, error) {
	if limit <= 0 {
		limit = 10
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT m2.node_id, COUNT(*) AS shared
		 FROM codeintel_minhash m1
		 JOIN codeintel_minhash m2
		   ON m1.project = m2.project AND m1.band = m2.band AND m1.hash = m2.hash
		 WHERE m1.node_id = ? AND m2.node_id != m1.node_id
		 GROUP BY m2.node_id
		 ORDER BY shared DESC, m2.node_id ASC
		 LIMIT ?`, nodeID, limit)
	if err != nil {
		return nil, nil
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		var shared int
		if err := rows.Scan(&id, &shared); err != nil {
			return nil, fmt.Errorf("store.CodeIntelSimilarTo: scan: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return s.codeIntelSymbolsByIDs(ctx, ids)
}

// codeIntelSymbolsByIDs fetches SymbolMatch rows for the given node ids,
// preserving the input order (the caller's ranking).
func (s *Store) codeIntelSymbolsByIDs(ctx context.Context, ids []int64) ([]codeintel.SymbolMatch, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	// nolint:gosec // placeholders is a fixed count of '?', values bound.
	q := `SELECT n.id, n.name, n.fqn, n.kind, f.path, n.lang, n.start_line, n.end_line
	      FROM codeintel_nodes n JOIN codeintel_files f ON f.id = n.file_id
	      WHERE n.id IN (` + placeholders + `)`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, nil
	}
	defer rows.Close()
	byID := map[int64]codeintel.SymbolMatch{}
	for rows.Next() {
		var m codeintel.SymbolMatch
		if err := rows.Scan(&m.ID, &m.Name, &m.FQN, &m.Kind, &m.File, &m.Language, &m.StartLine, &m.EndLine); err != nil {
			return nil, fmt.Errorf("store.codeIntelSymbolsByIDs: scan: %w", err)
		}
		byID[m.ID] = m
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]codeintel.SymbolMatch, 0, len(ids))
	for _, id := range ids {
		if m, ok := byID[id]; ok {
			out = append(out, m)
		}
	}
	return out, nil
}

// CodeIntelLoadGraph returns a project's full node + RESOLVED-edge
// snapshot for the pure analyze/ and query/ engines. Only edges with a
// resolved dst (dst_id != 0) are returned — unresolved/external CALLS and
// file-level IMPORTS have no target node to traverse.
func (s *Store) CodeIntelLoadGraph(ctx context.Context, project string) (codeintel.Graph, error) {
	g := codeintel.Graph{Project: project}

	nrows, err := s.db.QueryContext(ctx,
		`SELECT n.id, n.name, n.fqn, n.kind, f.path, n.lang, n.start_line, n.end_line
		 FROM codeintel_nodes n JOIN codeintel_files f ON f.id = n.file_id
		 WHERE n.project = ?
		 ORDER BY n.id ASC`, project)
	if err != nil {
		return g, fmt.Errorf("store.CodeIntelLoadGraph: nodes: %w", err)
	}
	for nrows.Next() {
		var n codeintel.GraphNode
		if err := nrows.Scan(&n.ID, &n.Name, &n.FQN, &n.Kind, &n.File, &n.Language, &n.StartLine, &n.EndLine); err != nil {
			nrows.Close()
			return g, fmt.Errorf("store.CodeIntelLoadGraph: scan node: %w", err)
		}
		g.Nodes = append(g.Nodes, n)
	}
	nrows.Close()
	if err := nrows.Err(); err != nil {
		return g, err
	}

	erows, err := s.db.QueryContext(ctx,
		`SELECT src_id, dst_id, kind, confidence FROM codeintel_edges
		 WHERE project = ? AND dst_id != 0 AND src_id != 0
		 ORDER BY src_id ASC, dst_id ASC`, project)
	if err != nil {
		return g, fmt.Errorf("store.CodeIntelLoadGraph: edges: %w", err)
	}
	for erows.Next() {
		var e codeintel.GraphEdge
		if err := erows.Scan(&e.Src, &e.Dst, &e.Kind, &e.Confidence); err != nil {
			erows.Close()
			return g, fmt.Errorf("store.CodeIntelLoadGraph: scan edge: %w", err)
		}
		g.Edges = append(g.Edges, e)
	}
	erows.Close()
	if err := erows.Err(); err != nil {
		return g, err
	}
	return g, nil
}

// sigHash returns a short stable hash of a signature excerpt for cheap
// change detection (codeintel_nodes.sig_hash).
func sigHash(sig string) string {
	if sig == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(sig))
	return hex.EncodeToString(sum[:8])
}

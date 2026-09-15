package store

import (
	"context"
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// codeinteldevorgrows.go is the W2.4 org-wire seam for the per-developer/
// project code-intelligence feature. It OWNS the codeintel_files /
// codeintel_nodes / codeintel_edges read for the enterprise per-dev path —
// codeintelsummary.go already owns these tables for the teams-tier
// CodeintelSummaryRow aggregate, and both files are allowed to read the
// same tables (module-boundary discipline is about ONE OWNER PER WRITE
// SEAM / one function-call composition point into orgpush.go, not "only
// one reader in the whole binary"). orgpush.go never touches codeintel_*
// directly either way.
//
// Reuses hashCodeintelProject (defined in codeintelsummary.go, same
// package) rather than duplicating it — unlike the verbosity exemplar's
// sumInt64Map, there is no package-boundary reason to fork this helper.
//
// The aggregation is a superset of SelectCodeintelSummaries: same
// COUNT(DISTINCT ...) triple-join over (project, lang), plus
// MAX(indexed_at) for LastIndexed, which the per-dev row needs but the
// admin-only summary doesn't carry. No time-window filter — like the
// summary, this is a full-snapshot recompute of the node's current local
// index (there is no meaningful "day" for a codeintel state).

// SelectCodeintelDevRows aggregates the node-local codeintel index into the
// W2.4 per-developer wire rows: one row per (project-hash, language) with
// file / symbol / edge counts plus the most recent successful index pass.
// Content-free by construction — no bodies are selected.
func (s *Store) SelectCodeintelDevRows(ctx context.Context) ([]orgcontract.CodeintelDevRow, error) {
	// The two child relations (nodes, edges) are INDEPENDENT one-to-many
	// fan-outs off the same parent file. Joining both directly
	// (files ⋈ nodes ⋈ edges) multiplies them: the intermediate rowset is
	// Σ_file (nodes_f × edges_f), which COUNT(DISTINCT …) then de-dups back
	// down — the distinct-count masks the explosion but SQLite still
	// materialises and externally sorts the Cartesian product first. On a
	// large local index that spilled to the VdbeSorter on every push cycle
	// (the disk/compute-audit residual-CPU finding, 2026-08-26).
	//
	// Pre-aggregate each child by file_id FIRST (one row per file), then
	// join those one-to-one to the parent. Each node/edge has exactly one
	// owning file_id, so SUM over the per-file counts equals the distinct
	// count across the (project, lang) group — arithmetically identical to
	// the old COUNT(DISTINCT), but the intermediate is O(files) not
	// O(Σ nodes×edges), and no Cartesian product is ever built.
	rows, err := s.db.QueryContext(ctx, `
		SELECT f.project, f.lang,
		       COUNT(*),
		       COALESCE(SUM(nc.n), 0),
		       COALESCE(SUM(ec.n), 0),
		       COALESCE(MAX(f.indexed_at), 0)
		FROM codeintel_files f
		LEFT JOIN (SELECT file_id, COUNT(*) AS n FROM codeintel_nodes GROUP BY file_id) nc ON nc.file_id = f.id
		LEFT JOIN (SELECT file_id, COUNT(*) AS n FROM codeintel_edges GROUP BY file_id) ec ON ec.file_id = f.id
		GROUP BY f.project, f.lang
		ORDER BY f.project, f.lang`)
	if err != nil {
		return nil, fmt.Errorf("store.SelectCodeintelDevRows: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []orgcontract.CodeintelDevRow{}
	for rows.Next() {
		var (
			project, lang                    string
			files, symbols, edges, indexedAt int64
		)
		if err := rows.Scan(&project, &lang, &files, &symbols, &edges, &indexedAt); err != nil {
			return nil, fmt.Errorf("store.SelectCodeintelDevRows: scan: %w", err)
		}
		out = append(out, orgcontract.CodeintelDevRow{
			ProjectHash: hashCodeintelProject(project),
			// The raw git-root path rides alongside the hash — this wire
			// is shipsRawContent()-gated, and the enterprise posture
			// carries raw paths to the admin (plan §0.1).
			ProjectRoot: project,
			// ...and the PROJECT-IDENTITY hash rides alongside both, so the
			// server can join this row to sessions / org projects at all.
			// ProjectHash above is domain-separated into its own hash space
			// (that is the point of it) and can never match a
			// project_root_hash; projectRootHashForPath is the one that can.
			ProjectRootHash: projectRootHashForPath(project),
			Language:        lang,
			Files:           files,
			Symbols:         symbols,
			Edges:           edges,
			LastIndexed:     indexedAt,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.SelectCodeintelDevRows: %w", err)
	}
	return out, nil
}

// probeCodeintel is the Track R2 change-detection probe SHARED by both wires
// fed from the code index: codeintel_dev (this file) and codeintel_summary
// (codeintelsummary.go). It lives here — with the other codeintel_* SQL — so
// orgsnapgate.go and orgpush.go stay free of the table names the privacy
// sentinel forbids there.
//
// PROBE: (MAX(id), COUNT(*), MAX(indexed_at)) over codeintel_files, plus a
// bare MAX(id) on codeintel_nodes and codeintel_edges.
//
// WHY THAT REFLECTS MUTATION: an index pass DELETEs and reinserts a file's
// symbols and edges, and AUTOINCREMENT never reuses ids, so ANY reindex
// advances the node/edge maxima — which is why the (much larger) child tables
// need only an O(1) endpoint seek. codeintel_files carries the file COUNT (so a
// deleted file is seen even with no reinsert) and MAX(indexed_at) (so a
// re-index that happens to reproduce identical counts is still seen); it is the
// small parent table, one row per source file.
//
// RESIDUAL, BOUNDED BY THE FRESHNESS FLOOR: the resolver's in-place
// `UPDATE codeintel_edges SET dst_id` passes change no count and no id — but
// this wire ships STRUCTURE COUNTS only (files / symbols / edges per project ×
// language), which call resolution does not alter, so that update is invisible
// to the wire by construction rather than merely deferred. A file status
// UPDATE is likewise not shipped. snapGate's maxSkipAge remains the backstop.
//
// This is finding F1's wire — the Cartesian recompute that dominated the first
// pprof profile — so skipping it on an unchanged index is the second-largest
// saving the gate makes.
func (s *Store) probeCodeintel(ctx context.Context) (string, error) {
	return s.snapProbeScalar(ctx, `
		SELECT 'cf' || (SELECT COALESCE(MAX(id), 0) || '/' || COUNT(*) || '/' || COALESCE(MAX(indexed_at), 0)
		                  FROM codeintel_files) ||
		       ':cn' || (SELECT COALESCE(MAX(id), 0) FROM codeintel_nodes) ||
		       ':ce' || (SELECT COALESCE(MAX(id), 0) FROM codeintel_edges)`)
}

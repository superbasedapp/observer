package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// Arc 4 P5f codeintel-detail aggregation. This file — NOT orgpush.go — owns the
// codeintel_* read (the privacy sentinel forbids the codeintel_* table names
// from ever appearing in orgpush.go; the push path composes this aggregate via
// a function call). The output is AGGREGATE ONLY: per (project-hash × language)
// counts of files, symbols (nodes) and edges. It NEVER carries a symbol name, a
// fully-qualified name, a signature excerpt, or a raw file/project path — the
// project path is one-way domain-separated-hashed here, so the org sees the
// SHAPE of the source tree (how many files/symbols/edges, in which languages)
// but never its contents. It ships only under the codeintel_detail tier
// (node opt-in on an individual node, admin-raised on a managed one via the
// DISTINCT extract.codeintel authority).

// domainCodeintelProject domain-separates the project-path hash so the digest
// can never collide with (or be reversed against) a hash minted for another
// purpose. The raw project path never leaves the node.
const domainCodeintelProject = "codeintel:project:v1:"

// hashCodeintelProject one-way hashes an absolute project (git-root) path into
// the opaque grouping key the aggregate ships. Empty in → empty out.
func hashCodeintelProject(project string) string {
	if project == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(domainCodeintelProject + project))
	return hex.EncodeToString(sum[:])
}

// projectRootHashForPath mints the PROJECT-IDENTITY hash for a codeintel
// project path — the same digest `projects.root_path_hash` holds and therefore
// the same value orgcontract.SessionRow.ProjectRootHash ships for that root.
//
// It is deliberately the composition upsertProjectBase performs, in the same
// order (normalize, THEN hash), and reuses those two functions rather than
// re-implementing either: the org server resolves /projects/{id} by a 16-char
// prefix of this digest (rollup.ProjectIDFromHash), so a codeintel row whose
// hash disagreed by one byte — a trailing "/.git" left on, say — would link to
// a project that does not exist. codeintelsummary_test.go pins the equality
// against what UpsertProject actually wrote.
//
// This is NOT hashCodeintelProject's replacement: that one is domain-separated
// and stays the codeintel wire's own grouping/dedup key. The two hashes answer
// different questions and both ship on CodeintelDevRow.
func projectRootHashForPath(project string) string {
	return sha256Hex(normalizeProjectRoot(project))
}

// codeintelSummaryQuery is the SelectCodeintelSummaries read, held as a const
// so codeintelsummary_test.go can assert its EXPLAIN QUERY PLAN against the
// exact string production runs (a copy in the test would silently drift away
// from the query whose plan it claims to pin).
//
// This carried the identical Cartesian shape that a8d802421 fixed in the
// sibling SelectCodeintelDevRows, and for the identical reason: nodes and
// edges are INDEPENDENT one-to-many fan-outs off the same parent file, so
// joining both directly (files ⋈ nodes ⋈ edges) multiplies them into an
// intermediate of Σ_file (nodes_f × edges_f) rows. COUNT(DISTINCT …) then
// de-dups the result back to the right numbers — so the bug was never visible
// in the OUTPUT, only in the cost — while SQLite still built the product, plus
// a runtime AUTOMATIC COVERING INDEX per join and one temp b-tree per DISTINCT.
// The old comment's claim that "the join cost is acceptable" was what the
// 2026-08-26 compute/CPU audit (F4) disproved: this runs full-table on every
// push tick.
//
// Pre-aggregate each child by file_id FIRST (one row per file), then join those
// one-to-one to the parent. Each node/edge has exactly one owning file_id, so
// SUM over the per-file counts equals the distinct count across the
// (project, lang) group — arithmetically identical, but the intermediate is
// O(files) and no Cartesian product is ever built.
//
// No migration is needed: each pre-aggregate is served by an existing COVERING
// index (idx_codeintel_nodes_file / idx_codeintel_edges_file). Note it is a
// covering SCAN plus a bounded GROUP BY sort, NOT a seek — both indexes lead
// with `project`, so a global GROUP BY file_id cannot walk them in file_id
// order. That is O(nodes)+O(edges) over a narrow index against the old
// O(Σ nodes×edges) product, so it is not worth a new index; stated explicitly
// so the next reader does not assume a seek.
const codeintelSummaryQuery = `
		SELECT f.project, f.lang,
		       COUNT(*),
		       COALESCE(SUM(nc.n), 0),
		       COALESCE(SUM(ec.n), 0)
		FROM codeintel_files f
		LEFT JOIN (SELECT file_id, COUNT(*) AS n FROM codeintel_nodes GROUP BY file_id) nc ON nc.file_id = f.id
		LEFT JOIN (SELECT file_id, COUNT(*) AS n FROM codeintel_edges GROUP BY file_id) ec ON ec.file_id = f.id
		GROUP BY f.project, f.lang
		ORDER BY f.project, f.lang`

// SelectCodeintelSummaries aggregates the node-local codeintel index into the
// P5f wire rows: one row per (project-hash, language) with file / symbol /
// edge counts. Content-free by construction — no bodies are selected.
func (s *Store) SelectCodeintelSummaries(ctx context.Context) ([]orgcontract.CodeintelSummaryRow, error) {
	rows, err := s.db.QueryContext(ctx, codeintelSummaryQuery)
	if err != nil {
		return nil, fmt.Errorf("store.SelectCodeintelSummaries: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []orgcontract.CodeintelSummaryRow{}
	for rows.Next() {
		var (
			project, lang         string
			files, symbols, edges int64
		)
		if err := rows.Scan(&project, &lang, &files, &symbols, &edges); err != nil {
			return nil, fmt.Errorf("store.SelectCodeintelSummaries: scan: %w", err)
		}
		out = append(out, orgcontract.CodeintelSummaryRow{
			ProjectHash: hashCodeintelProject(project),
			Lang:        lang,
			Files:       files,
			Symbols:     symbols,
			Edges:       edges,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.SelectCodeintelSummaries: %w", err)
	}
	return out, nil
}

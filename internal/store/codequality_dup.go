//go:build !sbo_omit_codeintel

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/codequality"
)

// LoadCodeQualityDuplication reads what the Projects page's duplication
// figure needs from the codeintel index (docs/projects-page.md "Quality
// metrics"): the index facts, every eligible function and method (kind in
// codequality.EligibleKinds, at least codequality.MinSymbolLines lines,
// capped at codequality.MaxSymbols) and their MinHash band buckets.
//
// keys are the candidate codeintel project keys for one project root (the
// stored root and its normalized forms; codeintel keys a project by its
// absolute git root). The key with the most indexed files wins. No body,
// signature or excerpt is read: names, paths, spans and band hashes only.
func (s *Store) LoadCodeQualityDuplication(ctx context.Context, keys []string) (codequality.DuplicationInput, error) {
	var in codequality.DuplicationInput
	facts, ok, err := s.codeQualityIndex(ctx, keys)
	in.Index = facts
	if err != nil || !ok {
		if err != nil {
			err = fmt.Errorf("store.LoadCodeQualityDuplication: %w", err)
		}
		return in, err
	}
	key := facts.Key

	kinds := codequality.EligibleKinds
	kph := strings.TrimSuffix(strings.Repeat("?,", len(kinds)), ",")
	symArgs := []any{key}
	for _, k := range kinds {
		symArgs = append(symArgs, k)
	}
	symArgs = append(symArgs, codequality.MinSymbolLines-1, codequality.MaxSymbols+1)
	// nolint:gosec // kph is a fixed count of '?', values bound.
	rows, err := s.db.QueryContext(ctx,
		`SELECT n.id, f.path, n.name, n.kind, n.start_line, n.end_line
		   FROM codeintel_nodes n JOIN codeintel_files f ON f.id = n.file_id
		  WHERE n.project = ? AND n.kind IN (`+kph+`)
		    AND n.start_line > 0 AND n.end_line - n.start_line >= ?
		  ORDER BY n.id LIMIT ?`, symArgs...)
	if err != nil {
		return in, fmt.Errorf("store.LoadCodeQualityDuplication: symbols: %w", err)
	}
	for rows.Next() {
		var sy codequality.Symbol
		if err := rows.Scan(&sy.ID, &sy.File, &sy.Name, &sy.Kind, &sy.StartLine, &sy.EndLine); err != nil {
			rows.Close()
			return in, fmt.Errorf("store.LoadCodeQualityDuplication: scan symbol: %w", err)
		}
		in.Symbols = append(in.Symbols, sy)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return in, fmt.Errorf("store.LoadCodeQualityDuplication: symbols: %w", err)
	}
	rows.Close()
	if len(in.Symbols) > codequality.MaxSymbols {
		in.Symbols = in.Symbols[:codequality.MaxSymbols]
		in.Index.Truncated = true
	}
	if len(in.Symbols) == 0 {
		return in, nil
	}

	bArgs := []any{key}
	for _, k := range kinds {
		bArgs = append(bArgs, k)
	}
	bArgs = append(bArgs, codequality.MinSymbolLines-1)
	// nolint:gosec // kph is a fixed count of '?', values bound.
	brows, err := s.db.QueryContext(ctx,
		`SELECT m.node_id, m.band, m.hash
		   FROM codeintel_minhash m JOIN codeintel_nodes n ON n.id = m.node_id
		  WHERE m.project = ? AND n.kind IN (`+kph+`)
		    AND n.start_line > 0 AND n.end_line - n.start_line >= ?`, bArgs...)
	if err != nil {
		return in, fmt.Errorf("store.LoadCodeQualityDuplication: buckets: %w", err)
	}
	defer brows.Close()
	for brows.Next() {
		var b codequality.Bucket
		if err := brows.Scan(&b.NodeID, &b.Band, &b.Hash); err != nil {
			return in, fmt.Errorf("store.LoadCodeQualityDuplication: scan bucket: %w", err)
		}
		in.Buckets = append(in.Buckets, b)
	}
	if err := brows.Err(); err != nil {
		return in, fmt.Errorf("store.LoadCodeQualityDuplication: buckets: %w", err)
	}
	return in, nil
}

// codeQualityIndex resolves a project's candidate codeintel keys (the
// stored root and its normalized forms; codeintel keys a project by its
// absolute git root) to the key with the most indexed files and that
// index's facts. ok is false when no key has an indexed file; the facts
// then say whether a key's index was archived.
func (s *Store) codeQualityIndex(ctx context.Context, keys []string) (codequality.IndexFacts, bool, error) {
	var facts codequality.IndexFacts
	keys = dedupeNonEmpty(keys)
	if len(keys) == 0 {
		return facts, false, nil
	}
	ph := strings.TrimSuffix(strings.Repeat("?,", len(keys)), ",")
	args := make([]any, len(keys))
	for i, k := range keys {
		args[i] = k
	}
	var key string
	var files int
	var last int64
	// nolint:gosec // ph is a fixed count of '?', values bound.
	err := s.db.QueryRowContext(ctx,
		`SELECT project, COUNT(*), MAX(indexed_at) FROM codeintel_files
		  WHERE project IN (`+ph+`) AND status = 'indexed'
		  GROUP BY project ORDER BY COUNT(*) DESC, project LIMIT 1`, args...).Scan(&key, &files, &last)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		for _, k := range keys {
			if _, archived, err := s.CodeIntelArchivedProject(ctx, k); err != nil {
				return facts, false, err
			} else if archived {
				facts.Archived, facts.Key = true, k
				break
			}
		}
		return facts, false, nil
	case err != nil:
		return facts, false, fmt.Errorf("files: %w", err)
	}
	facts.Key, facts.IndexedFiles = key, files
	if last > 0 {
		facts.LastIndexedAt = time.Unix(last, 0).UTC()
	}
	return facts, true, nil
}

// dedupeNonEmpty drops empty and repeated strings, keeping first order.
func dedupeNonEmpty(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

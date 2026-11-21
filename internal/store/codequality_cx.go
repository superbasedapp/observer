//go:build !sbo_omit_codeintel

package store

import (
	"context"
	"fmt"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/codeintel"
	"github.com/marmutapp/superbased-observer/internal/codeintel/parse/complexity"
	"github.com/marmutapp/superbased-observer/internal/codequality"
)

// LoadCodeQualityComplexity reads what the Projects page's complexity
// figure needs from the codeintel index (docs/projects-page.md "Quality
// metrics"): the index facts, the project's indexed files classified by
// whether their language and parser have a complexity counter and whether
// they were indexed with counting on, every counted function's figure
// (codeintel_nodes.complexity, migration 215; capped at
// codequality.MaxSymbols) and the codequality.TopComplexLimit most complex
// functions with their names and spans.
//
// keys are resolved as for LoadCodeQualityDuplication. No body, signature
// or excerpt is read: names, paths, spans and numbers only.
func (s *Store) LoadCodeQualityComplexity(ctx context.Context, keys []string) (codequality.ComplexityInput, error) {
	var in codequality.ComplexityInput
	facts, ok, err := s.codeQualityIndex(ctx, keys)
	in.Index = facts
	if err != nil || !ok {
		if err != nil {
			err = fmt.Errorf("store.LoadCodeQualityComplexity: %w", err)
		}
		return in, err
	}
	key := facts.Key

	// Files: a counter exists when an exact-span backend parsed the file
	// and its language has a rule table (a capability, decided by the
	// codeintel packages, never by naming a language here).
	frows, err := s.db.QueryContext(ctx,
		`SELECT lang, parser, extract_version >= ?, COUNT(*) FROM codeintel_files
		  WHERE project = ? AND status = 'indexed'
		  GROUP BY lang, parser, extract_version >= ?`,
		codeintel.ExtractVersion, key, codeintel.ExtractVersion)
	if err != nil {
		return in, fmt.Errorf("store.LoadCodeQualityComplexity: files: %w", err)
	}
	type fileKey struct {
		lang             string
		counter, current bool
	}
	groups := map[fileKey]int{}
	var order []fileKey
	for frows.Next() {
		var lang, parser string
		var current bool
		var n int
		if err := frows.Scan(&lang, &parser, &current, &n); err != nil {
			frows.Close()
			return in, fmt.Errorf("store.LoadCodeQualityComplexity: scan files: %w", err)
		}
		k := fileKey{lang: lang, counter: codeintel.ExactParser(parser) && complexity.Supported(codeintel.Language(lang)), current: current}
		if _, seen := groups[k]; !seen {
			order = append(order, k)
		}
		groups[k] += n
	}
	if err := frows.Err(); err != nil {
		frows.Close()
		return in, fmt.Errorf("store.LoadCodeQualityComplexity: files: %w", err)
	}
	frows.Close()
	for _, k := range order {
		in.Files = append(in.Files, codequality.ComplexityFiles{Lang: k.lang, Counter: k.counter, Current: k.current, Files: groups[k]})
	}

	kinds := complexity.Kinds
	kph := strings.TrimSuffix(strings.Repeat("?,", len(kinds)), ",")
	vArgs := []any{key}
	for _, k := range kinds {
		vArgs = append(vArgs, k)
	}
	// nolint:gosec // kph is a fixed count of '?', values bound.
	vrows, err := s.db.QueryContext(ctx,
		`SELECT lang, complexity FROM codeintel_nodes
		  WHERE project = ? AND kind IN (`+kph+`) AND complexity IS NOT NULL
		  ORDER BY id LIMIT ?`, append(vArgs, codequality.MaxSymbols+1)...)
	if err != nil {
		return in, fmt.Errorf("store.LoadCodeQualityComplexity: values: %w", err)
	}
	for vrows.Next() {
		var v codequality.FuncValue
		if err := vrows.Scan(&v.Lang, &v.Complexity); err != nil {
			vrows.Close()
			return in, fmt.Errorf("store.LoadCodeQualityComplexity: scan value: %w", err)
		}
		in.Values = append(in.Values, v)
	}
	if err := vrows.Err(); err != nil {
		vrows.Close()
		return in, fmt.Errorf("store.LoadCodeQualityComplexity: values: %w", err)
	}
	vrows.Close()
	if len(in.Values) > codequality.MaxSymbols {
		in.Values = in.Values[:codequality.MaxSymbols]
		in.Index.Truncated = true
	}
	if len(in.Values) == 0 {
		return in, nil
	}

	// nolint:gosec // kph is a fixed count of '?', values bound.
	trows, err := s.db.QueryContext(ctx,
		`SELECT n.name, n.kind, n.lang, f.path, n.start_line, n.end_line, n.complexity
		   FROM codeintel_nodes n JOIN codeintel_files f ON f.id = n.file_id
		  WHERE n.project = ? AND n.kind IN (`+kph+`) AND n.complexity IS NOT NULL
		  ORDER BY n.complexity DESC, f.path, n.start_line LIMIT ?`, append(vArgs, codequality.TopComplexLimit)...)
	if err != nil {
		return in, fmt.Errorf("store.LoadCodeQualityComplexity: top: %w", err)
	}
	defer trows.Close()
	for trows.Next() {
		var f codequality.ComplexFunction
		if err := trows.Scan(&f.Name, &f.Kind, &f.Lang, &f.File, &f.StartLine, &f.EndLine, &f.Complexity); err != nil {
			return in, fmt.Errorf("store.LoadCodeQualityComplexity: scan top: %w", err)
		}
		in.Top = append(in.Top, f)
	}
	if err := trows.Err(); err != nil {
		return in, fmt.Errorf("store.LoadCodeQualityComplexity: top: %w", err)
	}
	return in, nil
}

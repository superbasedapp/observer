//go:build !sbo_omit_security

package store

import (
	"context"
	"fmt"
)

// secbox.go: the one read the sandbox box-ref walk needs (security plan
// 4.8 "Copy workspaces", M7; lane sec-box). A box commit's run row
// carries a target naming the commit (secsvc.BoxCommitTarget, written by
// secsvc.RecordRun when the context carries a box commit), so a commit
// the return step already scanned, or an earlier walk of a box ref, is not
// walked again after a daemon restart.

// maxBoxCommitQuery bounds the commits one SecBoxCommitsScanned call asks
// about.
const maxBoxCommitQuery = 500

// SecBoxCommitsScanned returns which of shas already hold a commit-scope
// box run of any outcome (an unknown one included: a commit is walked
// once, as the HEAD walk does) for the project. At most maxBoxCommitQuery
// ids are asked; the rest read as not scanned.
func (s *Store) SecBoxCommitsScanned(ctx context.Context, rootHash string, shas []string) (map[string]bool, error) {
	out := map[string]bool{}
	if rootHash == "" || len(shas) == 0 {
		return out, nil
	}
	if len(shas) > maxBoxCommitQuery {
		shas = shas[:maxBoxCommitQuery]
	}
	args := []any{rootHash}
	for _, sha := range shas {
		args = append(args, sha)
	}
	//nolint:gosec // G202: only a placeholder list is concatenated.
	// The CASE keeps json_extract off every other row's target (an empty
	// or a non-box target), whatever order SQLite evaluates the WHERE in.
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT c FROM (
		SELECT CASE WHEN target_json LIKE '{"box":true%' THEN json_extract(target_json, '$.commit') END AS c
		FROM sec_scan_runs WHERE project_root_hash = ? AND scope = 'commit')
		WHERE c IN (`+placeholders(len(shas))+`)`, args...)
	if err != nil {
		return nil, fmt.Errorf("store.SecBoxCommitsScanned: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var sha string
		if err := rows.Scan(&sha); err != nil {
			return nil, fmt.Errorf("store.SecBoxCommitsScanned: %w", err)
		}
		out[sha] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.SecBoxCommitsScanned: %w", err)
	}
	return out, nil
}

package store

import (
	"context"
	"fmt"
	"strings"
)

// CodingProjectRow is one of the machine's coding projects behind a service
// (the cross-plane link, Plane A W4-3 lane C3).
type CodingProjectRow struct {
	ID     int64
	Root   string
	Remote string
	// ByRoot is true when the service reported this checkout itself; false
	// for another checkout of the same git remote.
	ByRoot bool
}

// CodingProjectsForRoots returns the projects whose root is one of roots,
// then every other project sharing one of their git remotes (another clone
// or worktree of the same repository on this machine). Exact path equality:
// a service reports its project root the way the machine recorded it.
func (s *Store) CodingProjectsForRoots(ctx context.Context, roots []string) ([]CodingProjectRow, error) {
	if len(roots) == 0 {
		return nil, nil
	}
	args := make([]any, 0, len(roots))
	for _, r := range roots {
		args = append(args, r)
	}
	in := strings.TrimSuffix(strings.Repeat("?,", len(roots)), ",")
	//nolint:gosec // G202: the IN list is placeholders; values bind via ?.
	rows, err := s.db.QueryContext(ctx, `SELECT id, root_path, COALESCE(git_remote,'') FROM projects WHERE root_path IN (`+in+`) ORDER BY root_path`, args...)
	if err != nil {
		return nil, fmt.Errorf("store.CodingProjectsForRoots: %w", err)
	}
	var out []CodingProjectRow
	seen := map[int64]bool{}
	var remotes []any
	for rows.Next() {
		var p CodingProjectRow
		if err := rows.Scan(&p.ID, &p.Root, &p.Remote); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("store.CodingProjectsForRoots: scan: %w", err)
		}
		p.ByRoot = true
		seen[p.ID] = true
		out = append(out, p)
		if p.Remote != "" {
			remotes = append(remotes, p.Remote)
		}
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return nil, fmt.Errorf("store.CodingProjectsForRoots: %w", err)
	}
	if len(remotes) == 0 {
		return out, nil
	}
	rin := strings.TrimSuffix(strings.Repeat("?,", len(remotes)), ",")
	//nolint:gosec // G202: the IN list is placeholders; values bind via ?.
	sib, err := s.db.QueryContext(ctx, `SELECT id, root_path, git_remote FROM projects WHERE git_remote IN (`+rin+`) ORDER BY root_path`, remotes...)
	if err != nil {
		return nil, fmt.Errorf("store.CodingProjectsForRoots: siblings: %w", err)
	}
	defer sib.Close()
	for sib.Next() {
		var p CodingProjectRow
		if err := sib.Scan(&p.ID, &p.Root, &p.Remote); err != nil {
			return nil, fmt.Errorf("store.CodingProjectsForRoots: sibling scan: %w", err)
		}
		if !seen[p.ID] {
			seen[p.ID] = true
			out = append(out, p)
		}
	}
	return out, sib.Err()
}

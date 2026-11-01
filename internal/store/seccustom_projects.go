package store

import (
	"context"
	"fmt"
	"time"
)

// RecentActiveProjectRoots lists up to limit projects with a session started
// within the last sinceDays days, the most recently active first (the
// latest session start or end, newest first; ties by id, newest first).
// The custom scanner schedule scans this set, so a cap keeps the projects
// a developer is working in now rather than the oldest ids. limit <= 0
// means no cap; sinceDays <= 0 means no time bound.
func (s *Store) RecentActiveProjectRoots(ctx context.Context, sinceDays, limit int) ([]ProjectRoot, error) {
	cutoff := ""
	if sinceDays > 0 {
		cutoff = timestamp(time.Now().UTC().AddDate(0, 0, -sinceDays))
	}
	lim := -1 // SQLite: a negative LIMIT is no limit.
	if limit > 0 {
		lim = limit
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT p.id, p.root_path
		  FROM projects p
		  JOIN sessions s ON s.project_id = p.id
		 WHERE p.root_path <> '' AND s.started_at >= ?
		 GROUP BY p.id, p.root_path
		 ORDER BY MAX(MAX(s.started_at, COALESCE(s.ended_at, ''))) DESC, p.id DESC
		 LIMIT ?`, cutoff, lim)
	if err != nil {
		return nil, fmt.Errorf("store.RecentActiveProjectRoots: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []ProjectRoot
	for rows.Next() {
		var r ProjectRoot
		if err := rows.Scan(&r.ID, &r.RootPath); err != nil {
			return nil, fmt.Errorf("store.RecentActiveProjectRoots: scan: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.RecentActiveProjectRoots: rows: %w", err)
	}
	return out, nil
}

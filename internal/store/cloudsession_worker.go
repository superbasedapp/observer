package store

import (
	"context"
	"fmt"
	"time"
)

// SessionIDsActiveSince returns the ids of the sessions a customer-compute
// worker run touched (cloud-agents lane CA-C4): sessions that started at or
// after since, plus sessions with a proxied turn (api_turns) at or after
// since that have a session row. Sorted, distinct. The worker stamps them
// execution_location=customer_worker through SetSessionExecution, the one
// writer of that column.
//
// Timestamps are stored as UTC RFC 3339 with a variable fraction, which does
// not sort as text within one second, so the bound is the start of since's
// second (a few sessions of that one second before since are included, never
// a later one excluded).
func (s *Store) SessionIDsActiveSince(ctx context.Context, since time.Time) ([]string, error) {
	bound := since.UTC().Truncate(time.Second).Format("2006-01-02T15:04:05")
	rows, err := s.db.QueryContext(ctx, `
		SELECT id FROM sessions WHERE started_at >= ?
		UNION
		SELECT DISTINCT t.session_id FROM api_turns t
		  JOIN sessions s ON s.id = t.session_id
		 WHERE t.timestamp >= ? AND t.session_id IS NOT NULL AND t.session_id != ''
		ORDER BY 1`, bound, bound)
	if err != nil {
		return nil, fmt.Errorf("store.SessionIDsActiveSince: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("store.SessionIDsActiveSince: scan: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.SessionIDsActiveSince: %w", err)
	}
	return ids, nil
}

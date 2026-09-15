package store

import (
	"context"
	"fmt"
	"time"
)

// CountAPITurnsSince reports how many proxied API turns landed at or after
// since — the "is a coding session routing through this daemon right now?"
// signal the dashboard's restart confirm dialog shows before it drops
// in-flight proxy requests (docs/plans/dashboard-config-management-plan-
// 2026-08-28.md §3.3 item 3). Metadata only: a count, never a row.
func (s *Store) CountAPITurnsSince(ctx context.Context, since time.Time) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM api_turns WHERE timestamp >= ?`,
		timestamp(since.UTC())).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store.CountAPITurnsSince: %w", err)
	}
	return n, nil
}

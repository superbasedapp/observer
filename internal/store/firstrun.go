package store

import (
	"context"
	"fmt"
)

// HasSessions reports whether the database holds at least one session. The
// daemon asks once at start, before the watcher's initial scan, to record
// whether this install is fresh (internal/firstrunstate, T-922).
func (s *Store) HasSessions(ctx context.Context) (bool, error) {
	var found bool
	if err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM sessions)`).Scan(&found); err != nil {
		return false, fmt.Errorf("store.HasSessions: %w", err)
	}
	return found, nil
}

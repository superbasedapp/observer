package store

import (
	"context"
	"fmt"
)

// CapturedSessionForTool checks an externally identified session against the
// captured corpus. It deliberately imposes no launch-time window: a resumed
// session can predate its terminal and a new session can be written much later.
func (s *Store) CapturedSessionForTool(ctx context.Context, sessionID, tool string) (bool, error) {
	if sessionID == "" || tool == "" {
		return false, nil
	}
	var found bool
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM sessions WHERE id = ? AND tool = ? COLLATE NOCASE)`, sessionID, tool).Scan(&found)
	if err != nil {
		return false, fmt.Errorf("store.CapturedSessionForTool: %w", err)
	}
	return found, nil
}

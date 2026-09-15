package store

import "context"

// CursorUsageNote identifies counts recovered from an interrupted/retried CLI
// turn. The CLI reports only its last attempt, so these are a lower bound.
func (s *Store) CursorUsageNote(ctx context.Context, sessionID string) (string, error) {
	var partial bool
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS (
		SELECT 1 FROM token_usage WHERE session_id = ? AND tool = 'cursor'
		AND source_event_id LIKE 'cursor-cli-outcome:%' AND reliability = 'unreliable'
	)`, sessionID).Scan(&partial)
	if err != nil || !partial {
		return "", err
	}
	return "Partial usage: Cursor's log recovered the final attempt of an interrupted or retried turn. Earlier attempts may be missing; token counts and estimated cost shown are a lower bound.", nil
}

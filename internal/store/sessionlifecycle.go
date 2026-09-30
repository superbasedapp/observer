package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/sessionend"
)

// refreshSessionEnded recomputes sessions.ended_at for sessions whose
// ingest batch carried a lifecycle action (internal/sessionend: session_end
// closes, a later user_prompt / session_start reopens). It is the ONE
// writer of ended_at on the ingest path: before it existed no adapter path
// wrote the column at all, so every session - including every one with a
// session_end row - read as never closed, and the node page said "session
// in progress" for ten minutes after a clean exit.
//
// The decision is sessionend.EndedAt over the session's latest close and
// reopen timestamps (by event type, never by tool); a session with no
// session_end row is left untouched.
func (s *Store) refreshSessionEnded(ctx context.Context, sessionIDs map[string]struct{}) error {
	if len(sessionIDs) == 0 {
		return nil
	}
	closers := sessionend.ActionTypes(sessionend.RoleClose)
	reopeners := sessionend.ActionTypes(sessionend.RoleReopen)
	for sid := range sessionIDs {
		var f sessionend.Facts
		var err error
		if f.LastClose, err = s.latestActionTimestamp(ctx, sid, closers); err != nil {
			return fmt.Errorf("store.refreshSessionEnded: %w", err)
		}
		if f.LastClose == "" {
			continue
		}
		if f.LastReopen, err = s.latestActionTimestamp(ctx, sid, reopeners); err != nil {
			return fmt.Errorf("store.refreshSessionEnded: %w", err)
		}
		value, ok := sessionend.EndedAt(f)
		if !ok {
			continue
		}
		var arg any
		if value != "" {
			arg = value
		}
		if _, err := s.db.ExecContext(ctx,
			`UPDATE sessions SET ended_at = ? WHERE id = ? AND ended_at IS NOT ?`, arg, sid, arg); err != nil {
			return fmt.Errorf("store.refreshSessionEnded: update: %w", err)
		}
	}
	return nil
}

// latestActionTimestamp returns the latest stored timestamp of a session's
// actions of the given types ("" when none). julianday orders RFC3339Nano
// strings chronologically regardless of their fractional-second width.
func (s *Store) latestActionTimestamp(ctx context.Context, sessionID string, actionTypes []string) (string, error) {
	args := make([]any, 0, len(actionTypes)+1)
	args = append(args, sessionID)
	for _, t := range actionTypes {
		args = append(args, t)
	}
	//nolint:gosec // G202: only the ?-placeholder list is concatenated; every value binds via args.
	q := `SELECT timestamp FROM actions WHERE session_id = ? AND action_type IN (` + sessionIDPlaceholders(len(actionTypes)) + `)
		ORDER BY julianday(timestamp) DESC, id DESC LIMIT 1`
	var ts string
	err := s.db.QueryRowContext(ctx, q, args...).Scan(&ts)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return ts, err
}

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// sessionholds.go is the one owner of local_session_holds (agent migration
// 251, plan 07 M8.8): the sessions this node's own retention must keep.
// internal/retention reads the table by name inside its delete predicates
// (it may not import this package); nothing else reads or writes it, and
// it never reaches the org push wire.

// maxSessionHoldNote bounds a hold's note.
const maxSessionHoldNote = 500

// ErrSessionHoldNoteTooLong is returned when a note exceeds the bound.
var ErrSessionHoldNoteTooLong = fmt.Errorf("store: a hold note is at most %d characters", maxSessionHoldNote)

// SessionHold is one held session.
type SessionHold struct {
	SessionID string    `json:"session_id"`
	HeldAt    time.Time `json:"held_at"`
	Note      string    `json:"note"`
	// Exists reports whether the session still has a sessions row.
	Exists bool `json:"exists"`
}

// HoldSession places a hold on the session with exactly this id, so node
// retention keeps it. The session must exist. Holding a held session keeps
// its original time and replaces the note only when note is non-empty.
// created reports whether the hold is new.
func (s *Store) HoldSession(ctx context.Context, sessionID, note string, now time.Time) (created bool, err error) {
	sessionID = strings.TrimSpace(sessionID)
	note = strings.TrimSpace(note)
	if sessionID == "" {
		return false, fmt.Errorf("store.HoldSession: empty session id")
	}
	if len([]rune(note)) > maxSessionHoldNote {
		return false, ErrSessionHoldNoteTooLong
	}
	ok, err := s.sessionExists(ctx, sessionID)
	if err != nil {
		return false, fmt.Errorf("store.HoldSession: %w", err)
	}
	if !ok {
		return false, fmt.Errorf("store.HoldSession: %w: %q", ErrSessionNotFound, sessionID)
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO local_session_holds (session_id, held_at, note) VALUES (?, ?, ?)
		 ON CONFLICT (session_id) DO NOTHING`, sessionID, timestamp(now), note)
	if err != nil {
		return false, fmt.Errorf("store.HoldSession: %w", err)
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return true, nil
	}
	if note != "" {
		if _, err := s.db.ExecContext(ctx, `UPDATE local_session_holds SET note = ? WHERE session_id = ?`, note, sessionID); err != nil {
			return false, fmt.Errorf("store.HoldSession: note: %w", err)
		}
	}
	return false, nil
}

// ReleaseSessionHold removes the hold on sessionID and reports whether one
// existed. Releasing deletes no data: the next retention pass decides.
func (s *Store) ReleaseSessionHold(ctx context.Context, sessionID string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM local_session_holds WHERE session_id = ?`, strings.TrimSpace(sessionID))
	if err != nil {
		return false, fmt.Errorf("store.ReleaseSessionHold: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("store.ReleaseSessionHold: %w", err)
	}
	return n > 0, nil
}

// ListSessionHolds returns every hold, newest first.
func (s *Store) ListSessionHolds(ctx context.Context) ([]SessionHold, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT h.session_id, h.held_at, h.note, EXISTS (SELECT 1 FROM sessions s WHERE s.id = h.session_id)
  FROM local_session_holds h
 ORDER BY h.held_at DESC, h.session_id`)
	if err != nil {
		return nil, fmt.Errorf("store.ListSessionHolds: %w", err)
	}
	defer rows.Close()
	var out []SessionHold
	for rows.Next() {
		var (
			h      SessionHold
			heldAt string
		)
		if err := rows.Scan(&h.SessionID, &heldAt, &h.Note, &h.Exists); err != nil {
			return nil, fmt.Errorf("store.ListSessionHolds: %w", err)
		}
		if t, err := time.Parse(time.RFC3339Nano, heldAt); err == nil {
			h.HeldAt = t
		}
		out = append(out, h)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.ListSessionHolds: %w", err)
	}
	return out, nil
}

// IsSessionHeld reports whether sessionID is held.
func (s *Store) IsSessionHeld(ctx context.Context, sessionID string) (bool, error) {
	var one int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM local_session_holds WHERE session_id = ?`, sessionID).Scan(&one)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return false, fmt.Errorf("store.IsSessionHeld: %w", err)
}

package store

import (
	"context"
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/cursorusage"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// CursorUsageNote identifies counts recovered from an interrupted/retried CLI
// turn. The CLI reports only its last attempt, so these are a lower bound.
func (s *Store) CursorUsageNote(ctx context.Context, sessionID string) (string, error) {
	var partial bool
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS (
		SELECT 1 FROM token_usage WHERE session_id = ? AND tool = 'cursor'
		AND source_event_id LIKE ? AND reliability = 'unreliable'
	)`, sessionID, cursorusage.SourceEventOutcomePrefix+"%").Scan(&partial)
	if err != nil || !partial {
		return "", err
	}
	return cursorusage.PartialUsageNote, nil
}

// CursorUsageNoteBatch is CursorUsageNote's N-session sibling (one
// chunked `session_id IN (...)` sweep instead of one query per session —
// SOL-F18(b), see internal/store/taskflow.go's chunkSessionIDs). A
// session with no partial-usage rows is simply absent from the map;
// callers must treat a missing key as "", never an error.
func (s *Store) CursorUsageNoteBatch(ctx context.Context, sessionIDs []string) (map[string]string, error) {
	out := make(map[string]string, len(sessionIDs))
	for _, chunk := range chunkSessionIDs(sessionIDs) {
		//nolint:gosec // G202: only the ?-placeholder list is concatenated; every value binds via args.
		q := `
			SELECT DISTINCT session_id FROM token_usage
			 WHERE session_id IN (` + sessionIDPlaceholders(len(chunk)) + `) AND tool = 'cursor'
			   AND source_event_id LIKE ? AND reliability = 'unreliable'`
		rows, err := s.db.QueryContext(ctx, q, append(sessionIDArgs(chunk), cursorusage.SourceEventOutcomePrefix+"%")...)
		if err != nil {
			return nil, fmt.Errorf("store.CursorUsageNoteBatch: %w", err)
		}
		for rows.Next() {
			var sid string
			if err := rows.Scan(&sid); err != nil {
				rows.Close()
				return nil, fmt.Errorf("store.CursorUsageNoteBatch: scan: %w", err)
			}
			out[sid] = cursorusage.PartialUsageNote
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, fmt.Errorf("store.CursorUsageNoteBatch: rows: %w", err)
		}
		rows.Close()
	}
	return out, nil
}

// CursorUsageEvidence loads what the store knows about WHY a Cursor session
// has no token usage: the prompt and afterAgentResponse hook rows, and the
// turn / attempt evidence rows the cursor adapter records from the
// cursor-agent debug log. It selects plain rows and hands them to
// cursorusage.Tally, the one owner of the row identity (the org rollup
// runs the same fold over the rows it received), so the node and the org
// can never count the same session differently. Pure read;
// internal/cursorusage.Explain turns the result into banner text.
func (s *Store) CursorUsageEvidence(ctx context.Context, sessionID string) (cursorusage.Evidence, error) {
	types := cursorusage.EvidenceActionTypes
	args := make([]any, 0, len(types)+2)
	args = append(args, sessionID, models.ToolCursor)
	for _, t := range types {
		args = append(args, t)
	}
	//nolint:gosec // G202: only the ?-placeholder list is concatenated; every value binds via args.
	q := `SELECT action_type, COALESCE(source_event_id, ''), COALESCE(error_message, '')
		FROM actions WHERE session_id = ? AND tool = ? AND action_type IN (` + sessionIDPlaceholders(len(types)) + `)
		ORDER BY timestamp ASC, id ASC`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return cursorusage.Evidence{}, fmt.Errorf("store.CursorUsageEvidence: %w", err)
	}
	defer rows.Close()
	var in []cursorusage.Row
	for rows.Next() {
		var r cursorusage.Row
		if err := rows.Scan(&r.ActionType, &r.SourceEventID, &r.ErrorMessage); err != nil {
			return cursorusage.Evidence{}, fmt.Errorf("store.CursorUsageEvidence: scan: %w", err)
		}
		in = append(in, r)
	}
	if err := rows.Err(); err != nil {
		return cursorusage.Evidence{}, fmt.Errorf("store.CursorUsageEvidence: rows: %w", err)
	}
	return cursorusage.Tally(in), nil
}

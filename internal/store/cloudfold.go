package store

import (
	"context"
	"fmt"
)

// Read seam for the CA-D12 token precedence fold on project figures
// (cloud-agents lane CA-C1, decision CA-D21). Read-only.

// TokenSourceKey identifies one token_usage row the cost engine reported as a
// turn: its session and its source_event_id (cost.TurnRow.TurnID for a
// transcript-path row).
type TokenSourceKey struct {
	SessionID     string
	SourceEventID string
}

// LoadTokenSources returns token_usage.source for every row of sessionIDs
// whose source is NOT the per-turn transcript ('jsonl') and whose
// source_event_id is set. A row absent from the map is a transcript row (or
// has no event id), which the precedence fold ranks as the per-turn tier, so
// the map stays small: only provider run totals, telemetry and report rows.
func (s *Store) LoadTokenSources(ctx context.Context, sessionIDs []string) (map[TokenSourceKey]string, error) {
	out := map[TokenSourceKey]string{}
	for start := 0; start < len(sessionIDs); start += sessionExecutionChunk {
		end := start + sessionExecutionChunk
		if end > len(sessionIDs) {
			end = len(sessionIDs)
		}
		chunk := sessionIDs[start:end]
		args := make([]any, len(chunk))
		for i, id := range chunk {
			args[i] = id
		}
		//nolint:gosec // G202: the IN list is placeholders only; every value is bound.
		rows, err := s.db.QueryContext(ctx,
			`SELECT session_id, source_event_id, source
			   FROM token_usage
			  WHERE session_id IN (`+placeholders(len(chunk))+`)
			    AND source <> 'jsonl'
			    AND source_event_id IS NOT NULL AND source_event_id <> ''`, args...)
		if err != nil {
			return nil, fmt.Errorf("store.LoadTokenSources: %w", err)
		}
		for rows.Next() {
			var k TokenSourceKey
			var src string
			if err := rows.Scan(&k.SessionID, &k.SourceEventID, &src); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("store.LoadTokenSources: scan: %w", err)
			}
			out[k] = src
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("store.LoadTokenSources: rows: %w", err)
		}
		_ = rows.Close()
	}
	return out, nil
}

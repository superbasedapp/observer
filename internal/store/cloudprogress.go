package store

import (
	"context"
	"fmt"
	"strings"
)

// CloudEnrichmentProgress is node-local request progress, not hosted worker status.
// Sent means awaiting a result; only a stored result can establish completion.
type CloudEnrichmentProgress struct {
	State     string `json:"state"`
	LastError string `json:"last_error,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// LoadCloudEnrichmentProgress batches content-free progress for a page of sessions.
// Active uploads take precedence over history. A result resolves older sent rows;
// a later request remains visible while the previous result is still available.
func (s *Store) LoadCloudEnrichmentProgress(ctx context.Context, sessionIDs []string) (map[string]*CloudEnrichmentProgress, error) {
	out := make(map[string]*CloudEnrichmentProgress, len(sessionIDs))
	for start := 0; start < len(sessionIDs); start += cloudEnrichedTitlesChunkSize {
		end := min(start+cloudEnrichedTitlesChunkSize, len(sessionIDs))
		args := make([]any, 0, end-start)
		for _, id := range sessionIDs[start:end] {
			args = append(args, id)
		}
		placeholders := strings.TrimRight(strings.Repeat("?,", len(args)), ",")
		//nolint:gosec // Only bound-parameter placeholders are concatenated.
		rows, err := s.db.QueryContext(ctx, `
			SELECT s.id, COALESCE(o.state, ''), COALESCE(o.last_error, ''),
			       COALESCE(o.updated_at, ''),
			       COALESCE((SELECT r.received_at FROM cloud_results r
			         WHERE r.session_id = s.id AND r.superseded_by IS NULL
			         ORDER BY r.received_at DESC, r.id DESC LIMIT 1), '')
			  FROM sessions s LEFT JOIN cloud_outbox o
			    ON o.session_id = s.id AND o.kind = 'session_evidence'
			 WHERE s.id IN (`+placeholders+`)
			 ORDER BY o.updated_at DESC, o.id DESC`, args...)
		if err != nil {
			return nil, fmt.Errorf("store.LoadCloudEnrichmentProgress: %w", err)
		}
		for rows.Next() {
			var id, state, lastError, updated, received string
			if err := rows.Scan(&id, &state, &lastError, &updated, &received); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("store.LoadCloudEnrichmentProgress: %w", err)
			}
			mergeCloudEnrichmentProgress(out, id, state, lastError, updated, received)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("store.LoadCloudEnrichmentProgress: %w", err)
		}
		_ = rows.Close()
	}
	return out, nil
}

func mergeCloudEnrichmentProgress(out map[string]*CloudEnrichmentProgress, id, state, lastError, updated, received string) {
	current := out[id]
	if current == nil {
		current = &CloudEnrichmentProgress{State: "idle"}
		if received != "" {
			current.State = "complete"
			current.UpdatedAt = received
		}
		out[id] = current
	}
	if state == "" {
		return
	}
	// An upload may coexist with an older result. A later result resolves
	// sent and historical terminal rows, but never cancels a live upload.
	liveUpload := state == "pending" || state == "sending" || state == "failed_retryable"
	if !liveUpload && received != "" && !cloudParseTime(updated).After(cloudParseTime(received)) {
		return
	}
	if cloudProgressPriority(state) < cloudProgressPriority(current.State) ||
		(cloudProgressPriority(state) == cloudProgressPriority(current.State) && cloudParseTime(updated).After(cloudParseTime(current.UpdatedAt))) {
		out[id] = &CloudEnrichmentProgress{State: state, LastError: lastError, UpdatedAt: updated}
	}
}

func cloudProgressPriority(state string) int {
	switch state {
	case "pending", "sending", "failed_retryable", "sent":
		return 0
	case "idle", "complete":
		return 2
	default:
		return 1
	}
}

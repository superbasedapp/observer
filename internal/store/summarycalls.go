package store

import (
	"context"
	"fmt"
	"time"
)

// SummaryCallRow is one rolling-summary LLM call (the summarizer's own
// spend), priced by the caller, for the summary_calls table (migration 016).
type SummaryCallRow struct {
	// SessionID is the proxied session the summary was for; "" stores NULL.
	SessionID           string
	At                  time.Time
	Model               string
	InputTokens         int64
	OutputTokens        int64
	CacheReadTokens     int64
	CacheCreationTokens int64
	CostUSD             float64
}

// InsertSummaryCall writes one summary_calls row. It is the table's one
// insert seam (the rolling summarizer's recorder, internal/messagesummary,
// reaches it through a writer func cmd/observer injects); the repricer
// (reprice.go) and the component purge (componentpurge.go) are its other
// writers.
func (s *Store) InsertSummaryCall(ctx context.Context, row SummaryCallRow) error {
	var sessionID any
	if row.SessionID != "" {
		sessionID = row.SessionID
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO summary_calls
		   (session_id, timestamp, model, input_tokens, output_tokens,
		    cache_read_tokens, cache_creation_tokens, cost_usd)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		sessionID, row.At.UTC().Format(time.RFC3339Nano),
		row.Model, row.InputTokens, row.OutputTokens,
		row.CacheReadTokens, row.CacheCreationTokens, row.CostUSD)
	if err != nil {
		return fmt.Errorf("store.InsertSummaryCall: %w", err)
	}
	return nil
}

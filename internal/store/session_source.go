package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// reassignSessionSource heals a transcript previously folded into its parent.
// Exact source-file ownership is required; no time-window inference is used.
// IDs, outputs, failures and usage stay intact. Replays are no-ops.
func (s *Store) reassignSessionSource(ctx context.Context, lin models.SessionLineage) error {
	if lin.SourceFile == "" || lin.SessionID == "" || lin.ParentThreadID == "" || lin.SessionID == lin.ParentThreadID {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.reassignSessionSource: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	// Reference-bearing secondary records follow the same exact rows. Cache
	// entries are provider-prefix state shared across sessions, not a ledger.
	queries := []string{
		`UPDATE failure_context SET session_id=? WHERE session_id=? AND action_id IN
		 (SELECT id FROM actions WHERE source_file=? AND is_sidechain=1)`,
		`UPDATE cache_segments SET session_id=? WHERE session_id=? AND token_usage_id IN
		 (SELECT id FROM token_usage WHERE source_file=? AND is_sidechain=1)`,
		`UPDATE cache_events SET session_id=? WHERE session_id=? AND message_id IN
		 (SELECT message_id FROM token_usage WHERE source_file=? AND is_sidechain=1)`,
		`UPDATE actions SET session_id=?, is_sidechain=0 WHERE session_id=? AND source_file=? AND is_sidechain=1`,
		`UPDATE token_usage SET session_id=?, is_sidechain=0 WHERE session_id=? AND source_file=? AND is_sidechain=1`,
	}
	for _, q := range queries {
		if _, err := tx.ExecContext(ctx, q, lin.SessionID, lin.ParentThreadID, lin.SourceFile); err != nil {
			return fmt.Errorf("store.reassignSessionSource: transfer: %w", err)
		}
	}
	if lin.AgentID != "" {
		if _, err := tx.ExecContext(ctx, `UPDATE actions SET metadata=json_set(COALESCE(NULLIF(metadata,''),'{}'), '$.agent_id', ?, '$.is_subagent', json('true'))
		 WHERE session_id=? AND source_file=? AND COALESCE(json_extract(metadata,'$.agent_id'),'')<>?`,
			lin.AgentID, lin.SessionID, lin.SourceFile, lin.AgentID); err != nil {
			return fmt.Errorf("store.reassignSessionSource: identity: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store.reassignSessionSource: commit: %w", err)
	}
	return nil
}

// transcriptChildForRequest handles the inverse arrival order: a proxy response
// captured after the child's transcript. An exact request/message ID and an
// existing parent-child edge are both required. Ambiguous matches stay put.
func (s *Store) transcriptChildForRequest(ctx context.Context, parent, request string) (string, error) {
	if parent == "" || request == "" {
		return parent, nil
	}
	var child string
	err := s.db.QueryRowContext(ctx, `SELECT MIN(t.session_id) FROM token_usage t JOIN sessions c ON c.id=t.session_id
	 WHERE c.parent_thread_id=? AND t.message_id=? HAVING COUNT(DISTINCT t.session_id)=1`, parent, request).Scan(&child)
	if errors.Is(err, sql.ErrNoRows) {
		return parent, nil
	}
	if err != nil {
		return parent, fmt.Errorf("store.transcriptChildForRequest: %w", err)
	}
	return child, nil
}

// reconcileSourceAPITurns handles proxy-before-transcript capture without
// duplicating usage between the parent and the newly discovered child.
func (s *Store) reconcileSourceAPITurns(ctx context.Context, lin models.SessionLineage) error {
	if lin.SourceFile == "" || lin.SessionID == "" || lin.ParentThreadID == "" {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.reconcileSourceAPITurns: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `UPDATE api_turns SET session_id=? WHERE session_id=? AND request_id IN
	 (SELECT message_id FROM token_usage WHERE session_id=? AND source_file=? AND COALESCE(message_id,'')<>'')`, lin.SessionID, lin.ParentThreadID, lin.SessionID, lin.SourceFile); err != nil {
		return fmt.Errorf("store.reconcileSourceAPITurns: turns: %w", err)
	}
	for _, q := range []string{
		`UPDATE cache_segments SET session_id=? WHERE session_id=? AND api_turn_id IN (SELECT id FROM api_turns WHERE session_id=?)`,
		`UPDATE cache_events SET session_id=? WHERE session_id=? AND api_turn_id IN (SELECT id FROM api_turns WHERE session_id=?)`,
	} {
		if _, err := tx.ExecContext(ctx, q, lin.SessionID, lin.ParentThreadID, lin.SessionID); err != nil {
			return fmt.Errorf("store.reconcileSourceAPITurns: cache: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store.reconcileSourceAPITurns: commit: %w", err)
	}
	return nil
}

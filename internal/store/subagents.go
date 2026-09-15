package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// ChildSubagent is a separately addressable runtime with exact transcript
// ownership. Unlike legacy windows, simultaneous runtimes cannot mix usage.
type ChildSubagent struct {
	SessionID, AgentID, StartedAt, LastSeenAt                       string
	ActionCount, ErrorCount                                         int
	InputTokens, OutputTokens, CacheReadTokens, CacheCreationTokens int64
	CostUSD                                                         float64
}

// ChildSubagentsForSession loads only the linked children of this parent.
func (s *Store) ChildSubagentsForSession(ctx context.Context, parent string) ([]ChildSubagent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT s.id, s.started_at,
	 COALESCE((SELECT MAX(timestamp) FROM actions WHERE session_id=s.id),s.started_at),
	 COALESCE((SELECT json_extract(metadata,'$.agent_id') FROM actions WHERE session_id=s.id AND json_extract(metadata,'$.agent_id') IS NOT NULL LIMIT 1),''),
	 (SELECT COUNT(*) FROM actions WHERE session_id=s.id),
	 (SELECT COUNT(*) FROM actions WHERE session_id=s.id AND success=0),
	 COALESCE((SELECT SUM(input_tokens) FROM token_usage WHERE session_id=s.id AND is_sidechain=0),0),
	 COALESCE((SELECT SUM(output_tokens) FROM token_usage WHERE session_id=s.id AND is_sidechain=0),0),
	 COALESCE((SELECT SUM(cache_read_tokens) FROM token_usage WHERE session_id=s.id AND is_sidechain=0),0),
	 COALESCE((SELECT SUM(cache_creation_tokens) FROM token_usage WHERE session_id=s.id AND is_sidechain=0),0),
	 COALESCE((SELECT SUM(estimated_cost_usd) FROM token_usage WHERE session_id=s.id AND is_sidechain=0),0)
	 FROM sessions s WHERE s.parent_thread_id=? AND s.thread_source='subagent' ORDER BY s.started_at,s.id`, parent)
	if err != nil {
		return nil, fmt.Errorf("store.ChildSubagentsForSession: %w", err)
	}
	defer rows.Close()
	var out []ChildSubagent
	for rows.Next() {
		var c ChildSubagent
		if err := rows.Scan(&c.SessionID, &c.StartedAt, &c.LastSeenAt, &c.AgentID, &c.ActionCount, &c.ErrorCount, &c.InputTokens, &c.OutputTokens, &c.CacheReadTokens, &c.CacheCreationTokens, &c.CostUSD); err != nil {
			return nil, fmt.Errorf("store.ChildSubagentsForSession: scan: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// subagents.go — read seam for the session-detail sub-agents view.
//
// The legacy inline sub-agent model keeps activity on the PARENT's row, marked per-action
// by is_sidechain=1; lifecycle brackets arrive as spawn_subagent /
// subagent_start / subagent_stop actions. This seam loads that material in
// chronological order; the grouping into per-sub-agent summaries is pure
// logic in internal/intelligence/dashboard (buildSubagentSummaries).
//
// Since migration 087 token_usage rows carry the same is_sidechain flag, so
// SidechainTokenUsageForSession loads the usage half (tokens + cost) and the
// builder buckets it into the same windows.
// Dedicated Claude runtime transcripts now use linked child sessions, read by
// ChildSubagentsForSession; these legacy queries only load the remainder.

// SidechainActionsForSession returns the session's sidechain activity plus
// its lifecycle bracket actions, oldest first. The bracket types are
// included even when unflagged so a window is never left open by a hook
// event that arrived without the sidechain bit.
func (s *Store) SidechainActionsForSession(ctx context.Context, sessionID string) ([]models.SubagentActionRef, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, timestamp, action_type, COALESCE(target, ''), success,
		       COALESCE(duration_ms, 0), COALESCE(raw_tool_name, ''),
		       COALESCE(metadata, ''), is_sidechain
		  FROM actions
		 WHERE session_id = ?
		   AND (is_sidechain = 1
		        OR action_type IN (?, ?, ?))
		 ORDER BY timestamp ASC, id ASC`,
		sessionID,
		models.ActionSpawnSubagent, models.ActionSubagentStart, models.ActionSubagentStop)
	if err != nil {
		return nil, fmt.Errorf("store.SidechainActionsForSession: %w", err)
	}
	defer rows.Close()
	var out []models.SubagentActionRef
	for rows.Next() {
		var a models.SubagentActionRef
		var ts string
		var metadata string
		if err := rows.Scan(
			&a.ID, &ts, &a.ActionType, &a.Target, &a.Success, &a.DurationMs,
			&a.RawToolName, &metadata, &a.IsSidechain,
		); err != nil {
			return nil, fmt.Errorf("store.SidechainActionsForSession: scan: %w", err)
		}
		a.Timestamp = parseStamp(ts)
		if metadata != "" {
			// Malformed metadata must not kill the whole listing — the
			// window grouping falls back to time brackets without a label.
			m := &models.ActionMetadata{}
			if json.Unmarshal([]byte(metadata), m) == nil {
				a.Metadata = m
			}
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// SidechainTokenUsageForSession returns the session's sidechain token_usage
// rows (migration 087's is_sidechain flag), oldest first, as lean
// [models.SubagentTokenRef] projections — usage magnitudes only, never model
// ids or source paths. Main-thread rows (the default-0 majority) never touch
// this scan; idx_token_usage_session_sidechain keeps it a single index range.
func (s *Store) SidechainTokenUsageForSession(ctx context.Context, sessionID string) ([]models.SubagentTokenRef, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT timestamp,
		       COALESCE(input_tokens, 0), COALESCE(output_tokens, 0),
		       COALESCE(cache_read_tokens, 0), COALESCE(cache_creation_tokens, 0),
		       COALESCE(estimated_cost_usd, 0)
		  FROM token_usage
		 WHERE session_id = ?
		   AND is_sidechain = 1
		 ORDER BY timestamp ASC, id ASC`,
		sessionID)
	if err != nil {
		return nil, fmt.Errorf("store.SidechainTokenUsageForSession: %w", err)
	}
	defer rows.Close()
	var out []models.SubagentTokenRef
	for rows.Next() {
		var t models.SubagentTokenRef
		var ts string
		if err := rows.Scan(
			&ts, &t.InputTokens, &t.OutputTokens,
			&t.CacheReadTokens, &t.CacheCreationTokens, &t.EstimatedCostUSD,
		); err != nil {
			return nil, fmt.Errorf("store.SidechainTokenUsageForSession: scan: %w", err)
		}
		t.Timestamp = parseStamp(ts)
		out = append(out, t)
	}
	return out, rows.Err()
}

package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// ChildSubagent is a separately addressable runtime with exact transcript
// ownership. Unlike legacy windows, simultaneous runtimes cannot mix usage.
//
// Its token figures are the child session's own SpendTurns - the one session
// rule, so they equal the child's session header - and Turns carries them
// for a caller that prices the child the way the header does. CostUSD sums
// their RECORDED cost only.
type ChildSubagent struct {
	SessionID, AgentID, StartedAt, LastSeenAt                       string
	ActionCount, ErrorCount                                         int
	InputTokens, OutputTokens, CacheReadTokens, CacheCreationTokens int64
	CostUSD                                                         float64
	Turns                                                           []SpendTurn
}

// ChildSubagentsForSession loads only the linked children of this parent.
func (s *Store) ChildSubagentsForSession(ctx context.Context, parent string) ([]ChildSubagent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT s.id, s.started_at,
	 COALESCE((SELECT MAX(timestamp) FROM actions WHERE session_id=s.id),s.started_at),
	 COALESCE((SELECT json_extract(metadata,'$.agent_id') FROM actions WHERE session_id=s.id AND json_extract(metadata,'$.agent_id') IS NOT NULL LIMIT 1),''),
	 (SELECT COUNT(*) FROM actions WHERE session_id=s.id),
	 (SELECT COUNT(*) FROM actions WHERE session_id=s.id AND success=0)
	 FROM sessions s WHERE s.parent_thread_id=? AND s.thread_source='subagent' ORDER BY s.started_at,s.id`, parent)
	if err != nil {
		return nil, fmt.Errorf("store.ChildSubagentsForSession: %w", err)
	}
	var out []ChildSubagent
	for rows.Next() {
		var c ChildSubagent
		if err := rows.Scan(&c.SessionID, &c.StartedAt, &c.LastSeenAt, &c.AgentID, &c.ActionCount, &c.ErrorCount); err != nil {
			rows.Close()
			return nil, fmt.Errorf("store.ChildSubagentsForSession: scan: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("store.ChildSubagentsForSession: %w", err)
	}
	rows.Close()
	ids := make([]string, len(out))
	for i := range out {
		ids[i] = out[i].SessionID
	}
	spend, err := s.LoadSessionsSpendTurns(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("store.ChildSubagentsForSession: %w", err)
	}
	for i := range out {
		turns := spend[out[i].SessionID]
		tot := SumSpendTurns(turns)
		out[i].InputTokens, out[i].OutputTokens = tot.InputTokens, tot.OutputTokens
		out[i].CacheReadTokens, out[i].CacheCreationTokens = tot.CacheReadTokens, tot.CacheWriteTokens
		out[i].CostUSD = tot.RecordedCostUSD
		out[i].Turns = turns
	}
	return out, nil
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

// SidechainTokenUsageForSession returns the session's sidechain spend rows
// (migration 087's is_sidechain flag), oldest first, as lean
// [models.SubagentTokenRef] projections — usage magnitudes only, never model
// ids or source paths. They are the session's SpendTurns flagged sidechain:
// the one session rule, so a sidechain turn the proxy captured counts once
// (its proxy row, attributed through its transcript partner's flag) and an
// output-only shadow duplicate not at all. EstimatedCostUSD is the recorded
// cost only; a caller that prices reads LoadSessionSpendTurns itself.
func (s *Store) SidechainTokenUsageForSession(ctx context.Context, sessionID string) ([]models.SubagentTokenRef, error) {
	turns, err := s.LoadSessionSpendTurns(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("store.SidechainTokenUsageForSession: %w", err)
	}
	var out []models.SubagentTokenRef
	for _, t := range turns {
		if !t.Sidechain {
			continue
		}
		out = append(out, models.SubagentTokenRef{
			Timestamp: t.Ts, InputTokens: t.InputTokens, OutputTokens: t.OutputTokens,
			CacheReadTokens: t.CacheReadTokens, CacheCreationTokens: t.CacheWriteTokens,
			EstimatedCostUSD: t.RecordedCostUSD,
		})
	}
	return out, nil
}

package mcp

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// -----------------------------------------------------------------------------
// list_actions_around (G33 — three-layer progressive disclosure, Tier 3)
// -----------------------------------------------------------------------------

type listActionsAroundTool struct{ db *sql.DB }

func newListActionsAroundTool(db *sql.DB) Tool { return &listActionsAroundTool{db: db} }

func (*listActionsAroundTool) Name() string { return "list_actions_around" }
func (*listActionsAroundTool) Description() string {
	return "Return ±N actions chronologically adjacent to a given action_id within the same session, with summary fields only (id, timestamp, tool, action_type, target, success, freshness). Use as the middle layer between search_past_outputs (FTS5 full-text hit) and get_action_details (full row + excerpt body): browse the session timeline around an interesting hit before paying for full details. Returns empty when the target action_id doesn't exist."
}

func (*listActionsAroundTool) InputSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"action_id": map[string]any{
				"type":        "integer",
				"description": "The pivot action ID. The response includes this row plus its before/after neighbours.",
			},
			"before": map[string]any{
				"type":        "integer",
				"description": "How many actions before the target to include. Default 5, max 20.",
				"minimum":     0,
				"maximum":     20,
			},
			"after": map[string]any{
				"type":        "integer",
				"description": "How many actions after the target to include. Default 5, max 20.",
				"minimum":     0,
				"maximum":     20,
			},
		},
		"required": []string{"action_id"},
	}
}

type listActionRow struct {
	ID         int64     `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	Tool       string    `json:"tool"`
	ActionType string    `json:"action_type"`
	Target     string    `json:"target"`
	Success    bool      `json:"success"`
	Freshness  string    `json:"freshness,omitempty"`
	Position   string    `json:"position"`
}

func (t *listActionsAroundTool) Invoke(ctx context.Context, raw json.RawMessage) (any, error) {
	var args struct {
		ActionID int64 `json:"action_id"`
		Before   int   `json:"before"`
		After    int   `json:"after"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}
	if args.ActionID <= 0 {
		return nil, errors.New("action_id is required and must be positive")
	}
	if args.Before == 0 {
		args.Before = 5
	}
	if args.After == 0 {
		args.After = 5
	}
	if args.Before < 0 {
		args.Before = 0
	}
	if args.After < 0 {
		args.After = 0
	}
	if args.Before > 20 {
		args.Before = 20
	}
	if args.After > 20 {
		args.After = 20
	}

	// Look up the target row first to get its session_id + timestamp;
	// neighbour windows scope to the same session so we don't surface
	// unrelated actions from other sessions that happened to overlap.
	var sessionID, ts string
	err := t.db.QueryRowContext(
		ctx,
		`SELECT session_id, timestamp FROM actions WHERE id = ?`,
		args.ActionID,
	).Scan(&sessionID, &ts)
	if errors.Is(err, sql.ErrNoRows) {
		return map[string]any{
			"action_id": args.ActionID,
			"before":    args.Before,
			"after":     args.After,
			"actions":   []listActionRow{},
			"found":     false,
		}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("target lookup: %w", err)
	}

	const cols = `id, session_id, timestamp, tool, action_type, COALESCE(target,''), success, COALESCE(freshness,'')`

	beforeRows, err := t.db.QueryContext(ctx,
		`SELECT `+cols+` FROM actions
		 WHERE session_id = ? AND id != ? AND (timestamp < ? OR (timestamp = ? AND id < ?))
		 ORDER BY timestamp DESC, id DESC LIMIT ?`,
		sessionID, args.ActionID, ts, ts, args.ActionID, args.Before)
	if err != nil {
		return nil, fmt.Errorf("before query: %w", err)
	}
	before, err := scanListActionRows(beforeRows, "before")
	if err != nil {
		return nil, err
	}
	// Reverse to chronological order.
	for i, j := 0, len(before)-1; i < j; i, j = i+1, j-1 {
		before[i], before[j] = before[j], before[i]
	}

	afterRows, err := t.db.QueryContext(ctx,
		`SELECT `+cols+` FROM actions
		 WHERE session_id = ? AND id != ? AND (timestamp > ? OR (timestamp = ? AND id > ?))
		 ORDER BY timestamp ASC, id ASC LIMIT ?`,
		sessionID, args.ActionID, ts, ts, args.ActionID, args.After)
	if err != nil {
		return nil, fmt.Errorf("after query: %w", err)
	}
	after, err := scanListActionRows(afterRows, "after")
	if err != nil {
		return nil, err
	}

	targetRows, err := t.db.QueryContext(ctx,
		`SELECT `+cols+` FROM actions WHERE id = ?`, args.ActionID)
	if err != nil {
		return nil, fmt.Errorf("target re-query: %w", err)
	}
	target, err := scanListActionRows(targetRows, "target")
	if err != nil {
		return nil, err
	}

	out := make([]listActionRow, 0, len(before)+len(target)+len(after))
	out = append(out, before...)
	out = append(out, target...)
	out = append(out, after...)
	return map[string]any{
		"action_id":  args.ActionID,
		"session_id": sessionID,
		"before":     args.Before,
		"after":      args.After,
		"actions":    out,
		"found":      true,
	}, nil
}

func scanListActionRows(rows *sql.Rows, position string) ([]listActionRow, error) {
	defer rows.Close()
	var out []listActionRow
	for rows.Next() {
		var r listActionRow
		var sessionID, ts string
		var success int
		if err := rows.Scan(&r.ID, &sessionID, &ts, &r.Tool, &r.ActionType, &r.Target, &success, &r.Freshness); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		r.Success = success == 1
		if parsed, perr := time.Parse(time.RFC3339Nano, ts); perr == nil {
			r.Timestamp = parsed
		}
		r.Position = position
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows: %w", err)
	}
	return out, nil
}

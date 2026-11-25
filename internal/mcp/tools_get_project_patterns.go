package mcp

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

// -----------------------------------------------------------------------------
// get_project_patterns
// -----------------------------------------------------------------------------

type getProjectPatternsTool struct{ db *sql.DB }

func newGetProjectPatternsTool(db *sql.DB) Tool { return &getProjectPatternsTool{db: db} }

func (*getProjectPatternsTool) Name() string { return "get_project_patterns" }
func (*getProjectPatternsTool) Description() string {
	return "Hot files (most-accessed paths), common commands (most-run command strings), and any patterns the intelligence layer has derived for this project. Use as a quick orientation when starting work in an unfamiliar repo."
}

func (*getProjectPatternsTool) InputSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"project_root": map[string]any{
				"type": "string",
			},
			"limit": map[string]any{
				"type":    "integer",
				"minimum": 1,
				"maximum": 50,
			},
		},
		"required": []string{"project_root"},
	}
}

type patternRow struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

type derivedPattern struct {
	Type           string  `json:"type"`
	Data           string  `json:"data"`
	Confidence     float64 `json:"confidence"`
	LastReinforced string  `json:"last_reinforced_at,omitempty"`
}

func (t *getProjectPatternsTool) Invoke(ctx context.Context, raw json.RawMessage) (any, error) {
	var args struct {
		ProjectRoot string `json:"project_root"`
		Limit       int    `json:"limit"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}
	if args.ProjectRoot == "" {
		return nil, errors.New("project_root is required")
	}
	limit := args.Limit
	if limit <= 0 {
		limit = 10
	}
	if limit > 50 {
		limit = 50
	}

	var pid int64
	if err := t.db.QueryRowContext(
		ctx,
		`SELECT id FROM projects WHERE root_path = ?`, args.ProjectRoot,
	).Scan(&pid); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return map[string]any{
				"project_root":     args.ProjectRoot,
				"hot_files":        []patternRow{},
				"common_commands":  []patternRow{},
				"derived_patterns": []derivedPattern{},
			}, nil
		}
		return nil, fmt.Errorf("project lookup: %w", err)
	}

	hot, err := topKeys(ctx, t.db,
		`SELECT target, COUNT(*) FROM actions
		 WHERE project_id = ? AND action_type IN ('read_file', 'edit_file', 'write_file') AND target != ''
		 GROUP BY target ORDER BY COUNT(*) DESC LIMIT ?`,
		pid, limit)
	if err != nil {
		return nil, err
	}
	commands, err := topKeys(ctx, t.db,
		`SELECT target, COUNT(*) FROM actions
		 WHERE project_id = ? AND action_type = 'run_command' AND target != ''
		 GROUP BY target ORDER BY COUNT(*) DESC LIMIT ?`,
		pid, limit)
	if err != nil {
		return nil, err
	}

	prows, err := t.db.QueryContext(ctx,
		`SELECT pattern_type, pattern_data, COALESCE(confidence,0), COALESCE(last_reinforced_at,'')
		 FROM project_patterns WHERE project_id = ?
		 ORDER BY confidence DESC LIMIT ?`,
		pid, limit)
	if err != nil {
		return nil, fmt.Errorf("derived patterns: %w", err)
	}
	defer prows.Close()
	var derived []derivedPattern
	for prows.Next() {
		var d derivedPattern
		if err := prows.Scan(&d.Type, &d.Data, &d.Confidence, &d.LastReinforced); err != nil {
			return nil, fmt.Errorf("scan derived: %w", err)
		}
		derived = append(derived, d)
	}

	return map[string]any{
		"project_root":     args.ProjectRoot,
		"hot_files":        hot,
		"common_commands":  commands,
		"derived_patterns": derived,
	}, nil
}

func topKeys(ctx context.Context, db *sql.DB, query string, queryArgs ...any) ([]patternRow, error) {
	rows, err := db.QueryContext(ctx, query, queryArgs...)
	if err != nil {
		return nil, fmt.Errorf("topKeys: %w", err)
	}
	defer rows.Close()
	var out []patternRow
	for rows.Next() {
		var p patternRow
		if err := rows.Scan(&p.Key, &p.Count); err != nil {
			return nil, fmt.Errorf("topKeys scan: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

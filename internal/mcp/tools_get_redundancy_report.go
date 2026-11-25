package mcp

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// -----------------------------------------------------------------------------
// get_redundancy_report
// -----------------------------------------------------------------------------

type getRedundancyReportTool struct{ db *sql.DB }

func newGetRedundancyReportTool(db *sql.DB) Tool { return &getRedundancyReportTool{db: db} }

func (*getRedundancyReportTool) Name() string { return "get_redundancy_report" }
func (*getRedundancyReportTool) Description() string {
	return "Counts of stale file reads (read again with no intervening change) and repeated commands within recent sessions. Use to identify wasted tool calls. Phase 4 will add token-cost estimates."
}

func (*getRedundancyReportTool) InputSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"project_root": map[string]any{
				"type":        "string",
				"description": "Optional project filter.",
			},
			"days": map[string]any{
				"type":        "integer",
				"description": "Look back N days. Default 7.",
				"minimum":     1,
				"maximum":     90,
			},
		},
	}
}

type redundancyResult struct {
	ProjectRoot      string       `json:"project_root,omitempty"`
	Days             int          `json:"days"`
	StaleReads       int          `json:"stale_reads"`
	ChangedBySelf    int          `json:"changed_by_self_reads"`
	RepeatedCommands int          `json:"repeated_commands"`
	TopStaleFiles    []patternRow `json:"top_stale_files"`
	TopRepeatedCmds  []patternRow `json:"top_repeated_commands"`
}

func (t *getRedundancyReportTool) Invoke(ctx context.Context, raw json.RawMessage) (any, error) {
	var args struct {
		ProjectRoot string `json:"project_root"`
		Days        int    `json:"days"`
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, fmt.Errorf("invalid arguments: %w", err)
		}
	}
	if args.Days <= 0 {
		args.Days = 7
	}
	if args.Days > 90 {
		args.Days = 90
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -args.Days).Format(time.RFC3339Nano)
	res := redundancyResult{ProjectRoot: args.ProjectRoot, Days: args.Days}

	whereProj := ""
	queryArgs := []any{cutoff}
	if args.ProjectRoot != "" {
		whereProj = " AND p.root_path = ?"
		queryArgs = append(queryArgs, args.ProjectRoot)
	}

	// Stale reads.
	_ = t.db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM actions a JOIN projects p ON p.id = a.project_id
		 WHERE a.action_type = 'read_file' AND a.freshness = 'stale' AND a.timestamp >= ?`+whereProj,
		queryArgs...,
	).Scan(&res.StaleReads)
	_ = t.db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM actions a JOIN projects p ON p.id = a.project_id
		 WHERE a.action_type = 'read_file' AND a.freshness = 'changed_by_self' AND a.timestamp >= ?`+whereProj,
		queryArgs...,
	).Scan(&res.ChangedBySelf)

	// Repeated commands within the same session (count - 1 per group).
	_ = t.db.QueryRowContext(
		ctx,
		`SELECT COALESCE(SUM(c - 1), 0) FROM (
		   SELECT COUNT(*) AS c FROM actions a JOIN projects p ON p.id = a.project_id
		   WHERE a.action_type = 'run_command' AND a.timestamp >= ?`+whereProj+`
		   GROUP BY a.session_id, a.target_hash
		 )`,
		queryArgs...,
	).Scan(&res.RepeatedCommands)

	// Top offenders (limited to 10 each).
	stale, err := topKeys(
		ctx, t.db,
		`SELECT a.target, COUNT(*) FROM actions a JOIN projects p ON p.id = a.project_id
		 WHERE a.action_type = 'read_file' AND a.freshness = 'stale' AND a.timestamp >= ?`+whereProj+`
		 GROUP BY a.target ORDER BY COUNT(*) DESC LIMIT 10`,
		queryArgs...,
	)
	if err != nil {
		return nil, err
	}
	res.TopStaleFiles = stale
	repeated, err := topKeys(
		ctx, t.db,
		`SELECT a.target, COUNT(*) FROM actions a JOIN projects p ON p.id = a.project_id
		 WHERE a.action_type = 'run_command' AND a.timestamp >= ?`+whereProj+`
		 GROUP BY a.session_id, a.target_hash, a.target HAVING COUNT(*) > 1
		 ORDER BY COUNT(*) DESC LIMIT 10`,
		queryArgs...,
	)
	if err != nil {
		return nil, err
	}
	res.TopRepeatedCmds = repeated
	return res, nil
}

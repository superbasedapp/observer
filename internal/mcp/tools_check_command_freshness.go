package mcp

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/failure"
)

// -----------------------------------------------------------------------------
// check_command_freshness
// -----------------------------------------------------------------------------

type checkCommandFreshnessTool struct{ db *sql.DB }

func newCheckCommandFreshnessTool(db *sql.DB) Tool {
	return &checkCommandFreshnessTool{db: db}
}

func (*checkCommandFreshnessTool) Name() string { return "check_command_freshness" }
func (*checkCommandFreshnessTool) Description() string {
	return "Has this command been run before, and if so when? Returns the most recent invocation's timestamp, success, and how many file edits have happened in this project since then. Use to decide whether to re-run an expensive command."
}

func (*checkCommandFreshnessTool) InputSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"command": map[string]any{
				"type":        "string",
				"description": "The exact command string.",
			},
			"project_root": map[string]any{
				"type":        "string",
				"description": "Optional project filter.",
			},
		},
		"required": []string{"command"},
	}
}

type commandFreshnessResult struct {
	Command           string    `json:"command"`
	CommandHash       string    `json:"command_hash"`
	LastRanAt         time.Time `json:"last_ran_at,omitempty"`
	LastSuccess       bool      `json:"last_success"`
	LastSessionID     string    `json:"last_session_id,omitempty"`
	EditsSinceLastRun int       `json:"edits_since_last_run"`
	FileChangesSeen   bool      `json:"file_changes_seen"`
	NeverRun          bool      `json:"never_run"`
}

func (t *checkCommandFreshnessTool) Invoke(ctx context.Context, raw json.RawMessage) (any, error) {
	var args struct {
		Command     string `json:"command"`
		ProjectRoot string `json:"project_root"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}
	if strings.TrimSpace(args.Command) == "" {
		return nil, errors.New("command is required")
	}
	hash := failure.CommandHash(args.Command)
	res := commandFreshnessResult{Command: args.Command, CommandHash: hash}

	// actions.target_hash is sha256(target), not the SHA256 of the normalized
	// command, so match on the literal target instead.
	q := `SELECT a.timestamp, a.success, a.session_id, a.project_id
	     FROM actions a JOIN projects p ON p.id = a.project_id
	     WHERE a.action_type = 'run_command' AND a.target = ?`
	queryArgs := []any{args.Command}
	if args.ProjectRoot != "" {
		q += " AND p.root_path = ?"
		queryArgs = append(queryArgs, args.ProjectRoot)
	}
	q += " ORDER BY a.timestamp DESC LIMIT 1"

	var ts string
	var success int
	var pid int64
	err := t.db.QueryRowContext(ctx, q, queryArgs...).Scan(&ts, &success, &res.LastSessionID, &pid)
	if errors.Is(err, sql.ErrNoRows) {
		res.NeverRun = true
		return res, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query last run: %w", err)
	}
	res.LastSuccess = success == 1
	if parsed, perr := time.Parse(time.RFC3339Nano, ts); perr == nil {
		res.LastRanAt = parsed
	}

	// Count file edits in this project since LastRanAt.
	var n int
	err = t.db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM actions
		 WHERE project_id = ?
		   AND action_type IN ('edit_file', 'write_file')
		   AND timestamp > ?`,
		pid, ts,
	).Scan(&n)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("count edits: %w", err)
	}
	res.EditsSinceLastRun = n
	res.FileChangesSeen = n > 0
	return res, nil
}

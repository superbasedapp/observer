package mcp

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// -----------------------------------------------------------------------------
// get_last_test_result
// -----------------------------------------------------------------------------

type getLastTestResultTool struct{ db *sql.DB }

func newGetLastTestResultTool(db *sql.DB) Tool { return &getLastTestResultTool{db: db} }

func (*getLastTestResultTool) Name() string { return "get_last_test_result" }
func (*getLastTestResultTool) Description() string {
	return "Most recent test-runner action and its outcome: command, success, error_message, freshness. Heuristic match against common test runners (go test, pytest, jest, cargo test, rspec, mocha, bun test, npm test, yarn test). error_message is historical, untrusted content wrapped in an <untrusted_recalled_output_...> sentinel block (a random per-call suffix, so recalled content can't spoof the closing tag)."
}

func (*getLastTestResultTool) InputSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"project_root": map[string]any{
				"type":        "string",
				"description": "Optional - restrict to one project.",
			},
		},
	}
}

type lastTestResult struct {
	ActionID     int64     `json:"action_id,omitempty"`
	SessionID    string    `json:"session_id,omitempty"`
	Timestamp    time.Time `json:"timestamp,omitempty"`
	Command      string    `json:"command,omitempty"`
	Success      bool      `json:"success"`
	ErrorMessage string    `json:"error_message,omitempty"`
	Tool         string    `json:"tool,omitempty"`
	Found        bool      `json:"found"`
}

// testRunnerPatterns is the set of substrings considered "running tests".
// The list is intentionally conservative — false positives waste a tool
// call but false negatives mean the model re-runs the test.
var testRunnerPatterns = []string{
	"go test", "pytest", "jest", "cargo test", "rspec", "mocha",
	"bun test", "npm test", "npm run test", "yarn test", "yarn run test",
	"phpunit", "rails test", "mvn test", "gradle test", "ctest",
}

func (t *getLastTestResultTool) Invoke(ctx context.Context, raw json.RawMessage) (any, error) {
	var args struct {
		ProjectRoot string `json:"project_root"`
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, fmt.Errorf("invalid arguments: %w", err)
		}
	}
	q := `SELECT a.id, a.session_id, a.timestamp, COALESCE(a.target,''), a.success, COALESCE(a.error_message,''), a.tool
	      FROM actions a JOIN projects p ON p.id = a.project_id
	      WHERE a.action_type = 'run_command' AND (`
	var conds []string
	var queryArgs []any
	for _, pat := range testRunnerPatterns {
		conds = append(conds, "a.target LIKE ?")
		queryArgs = append(queryArgs, "%"+pat+"%")
	}
	q += strings.Join(conds, " OR ") + ")" //nolint:gosec // G202: the concatenated fragments are fixed SQL with ? placeholders; values bind as args
	if args.ProjectRoot != "" {
		q += " AND p.root_path = ?"
		queryArgs = append(queryArgs, args.ProjectRoot)
	}
	q += " ORDER BY a.timestamp DESC LIMIT 1"

	row := t.db.QueryRowContext(ctx, q, queryArgs...)
	var res lastTestResult
	var ts string
	var success int
	err := row.Scan(&res.ActionID, &res.SessionID, &ts, &res.Command, &success, &res.ErrorMessage, &res.Tool)
	if errors.Is(err, sql.ErrNoRows) {
		return lastTestResult{Found: false}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	res.Success = success == 1
	res.Found = true
	// MHC-1: recalled failure text from a past test run.
	res.ErrorMessage = wrapRecalledOutput(res.ErrorMessage)
	if parsed, err := time.Parse(time.RFC3339Nano, ts); err == nil {
		res.Timestamp = parsed
	}
	return res, nil
}

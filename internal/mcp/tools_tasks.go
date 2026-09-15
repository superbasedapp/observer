package mcp

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/taskflow"
	"github.com/marmutapp/superbased-observer/internal/taskreport"
)

// getSessionTasksTool surfaces the Phase-2 session-level task/todo/plan
// tracking report (docs/task-tracking.md "Phase 2") to the AI client —
// registered unconditionally like cache_status, with the [tasks].enabled
// gate checked inside Invoke rather than at registration time, so a
// client that toggles the config mid-session sees the change without a
// server restart changing which tools exist.
type getSessionTasksTool struct {
	db     *sql.DB
	engine *cost.Engine
	tasks  config.TasksConfig
}

func newGetSessionTasksTool(db *sql.DB, engine *cost.Engine, tasks config.TasksConfig) Tool {
	return &getSessionTasksTool{db: db, engine: engine, tasks: tasks}
}

func (*getSessionTasksTool) Name() string { return "get_session_tasks" }

func (*getSessionTasksTool) Description() string {
	return "Session-level task/todo/plan checklist tracking: per-task tokens, cost, elapsed time, action count, and lifecycle status (pending/in_progress/completed/vanished) for one session's todo/plan tool calls (claude-code TaskCreate/TaskUpdate/TodoWrite, codex update_plan, kiro-cli todo_list, copilot manage_todo_list, and others). Includes the between_tasks and shared buckets for token/action rows that couldn't be attributed to one specific task — only ~52% of a session's tokens are attributable to a single task on average, so those are first-class, not a rounding residual. Read-only, node-local, no new capture surface."
}

func (*getSessionTasksTool) InputSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"session_id": map[string]any{
				"type":        "string",
				"description": "The session id to report on.",
			},
		},
		"required": []string{"session_id"},
	}
}

type getSessionTasksArgs struct {
	SessionID string `json:"session_id"`
}

func (t *getSessionTasksTool) Invoke(ctx context.Context, raw json.RawMessage) (any, error) {
	if !t.tasks.Enabled {
		return map[string]any{
			"enabled": false,
			"message": "session-level task tracking is disabled ([tasks].enabled = false)",
		}, nil
	}
	var args getSessionTasksArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, err
		}
	}
	if args.SessionID == "" {
		return nil, fmt.Errorf("session_id is required")
	}
	// opts is built directly from t.tasks (the config this server was
	// constructed with) — NOT read off store.New(t.db).TasksOptions(),
	// which would silently return the zero value: that fresh store
	// instance never had SetTasksOptions called on it (see
	// taskreport.LoadSessionTaskReport's doc comment).
	opts := taskflow.Options{
		MatchMode:             t.tasks.MatchMode,
		ConcurrentAttribution: t.tasks.ConcurrentAttribution,
		IncludeSidechains:     t.tasks.IncludeSidechains,
	}
	rep, err := taskreport.LoadSessionTaskReport(ctx, store.New(t.db), t.engine, args.SessionID, opts)
	if err != nil {
		return nil, err
	}
	return rep, nil
}

package mcp

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
)

// -----------------------------------------------------------------------------
// get_cost_summary
// -----------------------------------------------------------------------------

type getCostSummaryTool struct {
	db     *sql.DB
	engine *cost.Engine
}

func newGetCostSummaryTool(db *sql.DB, engine *cost.Engine) Tool {
	return &getCostSummaryTool{db: db, engine: engine}
}

func (*getCostSummaryTool) Name() string { return "get_cost_summary" }
func (*getCostSummaryTool) Description() string {
	return "Token / cost totals from api_turns (proxy = accurate) and token_usage (logs = approximate). Group by session, model, day, project, or tool. Use to spot expensive models or runaway sessions. Costs are computed via the embedded pricing table (spec §15.4) so rows are non-zero even when api_turns.cost_usd is NULL."
}

func (*getCostSummaryTool) InputSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"group_by": map[string]any{
				"type":        "string",
				"description": "One of: session, model, day, project, tool, none. Default: model.",
			},
			"days": map[string]any{
				"type":        "integer",
				"description": "Restrict to the last N days. Default 30.",
				"minimum":     1,
				"maximum":     365,
			},
			"project_root": map[string]any{
				"type":        "string",
				"description": "Optional project filter.",
			},
			"source": map[string]any{
				"type":        "string",
				"description": "Token source: auto (default - prefer proxy, fall back to JSONL), proxy, jsonl.",
			},
		},
	}
}

func (t *getCostSummaryTool) Invoke(ctx context.Context, raw json.RawMessage) (any, error) {
	var args struct {
		GroupBy     string `json:"group_by"`
		Days        int    `json:"days"`
		ProjectRoot string `json:"project_root"`
		Source      string `json:"source"`
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, fmt.Errorf("invalid arguments: %w", err)
		}
	}
	if args.Days <= 0 {
		args.Days = 30
	}
	if args.Days > 365 {
		args.Days = 365
	}

	groupBy, err := parseMCPGroupBy(args.GroupBy)
	if err != nil {
		return nil, err
	}
	source, err := parseMCPSource(args.Source)
	if err != nil {
		return nil, err
	}

	summary, err := t.engine.Summary(ctx, t.db, cost.Options{
		Days:        args.Days,
		GroupBy:     groupBy,
		Source:      source,
		ProjectRoot: args.ProjectRoot,
	})
	if err != nil {
		return nil, err
	}

	rows := make([]map[string]any, 0, len(summary.Rows))
	for _, r := range summary.Rows {
		rows = append(rows, map[string]any{
			"key":                   r.Key,
			"input_tokens":          r.Tokens.Input,
			"output_tokens":         r.Tokens.Output,
			"cache_read_tokens":     r.Tokens.CacheRead,
			"cache_creation_tokens": r.Tokens.CacheCreation,
			"cost_usd":              r.CostUSD,
			"turn_count":            r.TurnCount,
			"source":                r.Source,
			"reliability":           r.Reliability,
			"unknown_models":        r.UnknownModels,
		})
	}
	return map[string]any{
		"group_by":            args.GroupBy,
		"days":                args.Days,
		"source":              string(summary.Source),
		"rows":                rows,
		"total_input_tokens":  summary.TotalTokens.Input,
		"total_output_tokens": summary.TotalTokens.Output,
		"total_cost_usd":      summary.TotalCost,
		"reliability":         summary.Reliability,
		"unknown_model_count": summary.UnknownModelCount,
	}, nil
}

func parseMCPGroupBy(s string) (cost.GroupBy, error) {
	switch s {
	case "", "model":
		return cost.GroupByModel, nil
	case "session":
		return cost.GroupBySession, nil
	case "day":
		return cost.GroupByDay, nil
	case "project":
		return cost.GroupByProject, nil
	case "tool":
		return cost.GroupByTool, nil
	case "none":
		return cost.GroupByNone, nil
	default:
		return "", fmt.Errorf("group_by must be one of: model, session, day, project, tool, none; got %q", s)
	}
}

func parseMCPSource(s string) (cost.Source, error) {
	switch s {
	case "", "auto":
		return cost.SourceAuto, nil
	case "proxy":
		return cost.SourceProxy, nil
	case "jsonl":
		return cost.SourceJSONL, nil
	default:
		return "", fmt.Errorf("source must be one of: auto, proxy, jsonl; got %q", s)
	}
}

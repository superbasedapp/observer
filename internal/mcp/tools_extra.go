package mcp

import (
	"database/sql"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
)

// extraBuiltinTools returns the second batch of MCP tools (spec §11.2).
// Combined with the four in tools.go they make the full 12-tool set,
// plus the later additions: list_actions_around (G33), get_suggestions
// (advisor §15.7), and the two model-routing P0 advisory tools
// (model-routing spec §R17.5).
func extraBuiltinTools(db *sql.DB, engine *cost.Engine, cacheWarm config.CacheWarmConfig, tasksCfg config.TasksConfig) []Tool {
	return []Tool{
		newCacheStatusTool(db, engine, cacheWarm),
		newGetSessionTasksTool(db, engine, tasksCfg),
		newGetActionDetailsTool(db),
		newGetFailureContextTool(db),
		newGetLastTestResultTool(db),
		newGetCostSummaryTool(db, engine),
		newCheckCommandFreshnessTool(db),
		newGetSessionRecoveryContextTool(db),
		newGetProjectPatternsTool(db),
		newGetRedundancyReportTool(db),
		newListActionsAroundTool(db),
		NewGetSuggestionsTool(db),
		newGetModelRecommendationTool(db, engine),
		newGetRoutingStatusTool(db),
	}
}

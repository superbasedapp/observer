package integration

import "strings"

// Provider selectors (surface-gap arc CC-10).
//
// Some tools carry environment switches that move them off the provider
// API their proxy route covers: with one set, the routed base URL stops
// deciding where the traffic goes. Claude Code's are the CLAUDE_CODE_USE_*
// backend switches: each points it at a cloud provider's own endpoint
// (Bedrock, Mantle, Agent Platform, Foundry, Claude Platform on AWS), and
// ANTHROPIC_BASE_URL is then not read. A launch with one of them enabled is
// not proxy-proven, and a hook-time login snapshot cannot label it.
//
// This table is the one owner. The launcher's budget-admission proof
// (cmd/observer claudeBackendEnvKeys) and the hook's account-observation
// overrides (internal/hook accountSnapshotSpecs) both read it, so a new
// selector lands once. Only on/off switches belong here: a provider's own
// base-URL override (ANTHROPIC_AWS_BASE_URL, ANTHROPIC_BEDROCK_BASE_URL and
// the rest) only takes effect once its selector is on, so it is not a
// selector of its own.
//
// Grounded 2026-10-25 against https://code.claude.com/docs/en/env-vars (the
// CLAUDE_CODE_USE_* rows) and the generated settings catalogue
// (internal/agentconfig catalog_claude_code.gen.go). The claude-code
// registry row's route comment points here.
var providerSelectorEnvKeys = map[string][]string{
	"claude-code": {
		"CLAUDE_CODE_USE_ANTHROPIC_AWS",
		"CLAUDE_CODE_USE_BEDROCK",
		"CLAUDE_CODE_USE_FOUNDRY",
		"CLAUDE_CODE_USE_MANTLE",
		"CLAUDE_CODE_USE_VERTEX",
	},
}

// ProviderSelectorEnvKeys returns the environment switches that take tool
// off its routed provider API, in a stable order (a copy). A "-windows"
// cross-OS target reads its tool's row; a tool with no grounded selector
// returns nil.
func ProviderSelectorEnvKeys(tool string) []string {
	keys := providerSelectorEnvKeys[strings.TrimSuffix(tool, "-windows")]
	if len(keys) == 0 {
		return nil
	}
	return append([]string(nil), keys...)
}

// Route trade-offs (surface-gap arc CC-11): what a tool switches off by
// itself while its persisted proxy route is in force. The route consent
// names it so the developer accepts it knowingly, instead of finding it
// later and stripping the route.
//
// Claude Code: as of v2.1.196 Remote Control is disabled whenever
// ANTHROPIC_BASE_URL points at a host other than api.anthropic.com (the
// ANTHROPIC_BASE_URL row of https://code.claude.com/docs/en/env-vars,
// read 2026-10-25), and server-managed settings are not fetched (D-114).
//
// Claude Desktop (cowork): its only route is gateway mode
// (inferenceProvider gateway, inferenceGatewayBaseUrl), which needs a
// gateway credential and drops Anthropic-hosted cloud environments and
// Remote Control (https://code.claude.com/docs/en/llm-gateway-connect
// "Desktop app", read 2026-10-25; surface-gap CC-1, decision D1).
var routeTradeoffs = map[string]string{
	"claude-code": "Claude Code turns Remote Control off while ANTHROPIC_BASE_URL points at a host other than api.anthropic.com " +
		"(v2.1.196 and later), and it stops fetching claude.ai server-managed settings; skip the route to keep both.",
	"cowork": "Claude Desktop routes only in gateway mode, which needs a gateway credential (an API key a credential helper prints, " +
		"not a claude.ai sign-in) and drops Anthropic-hosted cloud environments and Remote Control; skip the route to keep them.",
}

// RouteTradeoff returns the one-sentence trade-off tool's persisted proxy
// route carries, or "" when none is grounded. A "-windows" cross-OS target
// reads its tool's row.
func RouteTradeoff(tool string) string {
	return routeTradeoffs[strings.TrimSuffix(tool, "-windows")]
}

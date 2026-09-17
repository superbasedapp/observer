package mcp

import "sort"

// ContractTier names a tool's stability tier in the published MCP contract
// (docs/mcp-contract.md). The tier is a PROMISE about the tool's name,
// required parameters, and result invariants across releases — not a
// statement about how useful or how well-tested the tool is.
type ContractTier string

const (
	// TierStable: the tool's name, its required parameters, and the
	// documented result invariants hold across every semver-MINOR release.
	// Removal or a breaking rename happens only at a MAJOR, and only after
	// at least one minor has shipped carrying a deprecation notice.
	TierStable ContractTier = "stable"
	// TierConditional: the tool's SHAPE carries the same promise as stable,
	// but its PRESENCE is config-gated — an operator (or an org's config)
	// can turn it off, so an integrator must tolerate its absence from
	// tools/list. Registration is never silent: `observer doctor` and the
	// server startup log report which conditional tools registered.
	TierConditional ContractTier = "conditional"
	// TierExperimental: no cross-release promise yet. The name is expected
	// to hold, but result fields may be added, renamed, or removed in a
	// minor. New tools land here and are promoted to stable once their
	// result field-set has ridden at least one minor unchanged.
	TierExperimental ContractTier = "experimental"
)

// ContractTool is one row of the published tool-stability table: the tool's
// wire name, its stability tier, and whether its PRESENCE depends on
// operator config (the conditional tier's distinguishing property).
type ContractTool struct {
	// Name is the tool's wire name — what a client passes as
	// `tools/call.name` and sees in `tools/list`.
	Name string `json:"name"`
	// Tier is the stability promise attached to this tool.
	Tier ContractTier `json:"tier"`
	// ConfigGated is true when the tool is registered only if its own
	// config flag (and the [intelligence.mcp].features allow-list) permit
	// it. Always true for TierConditional rows and false for every other
	// tier — the flag is carried explicitly so a machine consumer never has
	// to re-derive it from the tier string.
	ConfigGated bool `json:"config_gated"`
}

// contractTools is THE tool-stability table — the single owner of the tier
// assignment consumed by BOTH `observer contract --json` and
// docs/mcp-contract.md, so the emitter and the doc cannot drift silently.
//
// Rows are kept in alphabetical order to match the order tools/list emits.
// Adding a tool to the server WITHOUT adding it here fails
// TestContractCoversEveryRegisteredTool; renaming or dropping a stable-tier
// tool fails TestStableToolNamesPinned.
var contractTools = []ContractTool{
	{Name: "cache_status", Tier: TierStable},
	{Name: "check_command_freshness", Tier: TierStable},
	{Name: "check_file_freshness", Tier: TierStable},
	// continue_session / get_session_message are the two session-handoff
	// pull tools. Both are ALWAYS registered (a deterministic tool surface)
	// but degrade with an honest error when the host injected no runner, and
	// their result vocabulary is still growing (the `carry` mode set went
	// 4 → 5 in v1.16.0) — so neither carries a cross-release promise yet.
	{Name: "continue_session", Tier: TierExperimental},
	{Name: "get_action_details", Tier: TierStable},
	{Name: "get_cost_summary", Tier: TierStable},
	{Name: "get_failure_context", Tier: TierStable},
	{Name: "get_file", Tier: TierConditional, ConfigGated: true},
	{Name: "get_file_history", Tier: TierStable},
	{Name: "get_last_test_result", Tier: TierStable},
	{Name: "get_model_recommendation", Tier: TierStable},
	// get_output_composition (v1.13.0) reports a byte-split whose
	// `authored_captured` half depends on a capture backfill a stock install
	// may not have run, and its by-category / channel key set is still
	// settling — experimental until the field-set rides a minor unchanged.
	{Name: "get_output_composition", Tier: TierExperimental},
	// get_project_guidance (agent-guidance inventory) is new: its row
	// vocabulary (the Kind set, the front-matter map, the content caps) has
	// not ridden a minor release unchanged yet, so it lands experimental —
	// the tier every new tool starts at, promoted once the field-set settles.
	{Name: "get_project_guidance", Tier: TierExperimental},
	{Name: "get_project_patterns", Tier: TierStable},
	{Name: "get_redundancy_report", Tier: TierStable},
	{Name: "get_relations", Tier: TierConditional, ConfigGated: true},
	{Name: "get_routing_status", Tier: TierStable},
	{Name: "get_session_message", Tier: TierExperimental},
	{Name: "get_session_recovery_context", Tier: TierStable},
	{Name: "get_session_summary", Tier: TierStable},
	// get_session_tasks (Phase 2 of docs/task-tracking.md) is new and its
	// per-task attribution rule + bucket vocabulary (attributed_single /
	// between_tasks / shared) hasn't ridden a minor release unchanged yet —
	// experimental until the field set settles, same posture as
	// get_output_composition.
	{Name: "get_session_tasks", Tier: TierExperimental},
	{Name: "get_suggestions", Tier: TierStable},
	{Name: "get_symbols", Tier: TierConditional, ConfigGated: true},
	{Name: "list_actions_around", Tier: TierStable},
	{Name: "retrieve_stashed", Tier: TierConditional, ConfigGated: true},
	{Name: "search_past_outputs", Tier: TierStable},
	{Name: "search_symbols", Tier: TierStable},
}

// ContractTools returns the published tool-stability table, sorted by name
// (the same order tools/list emits). The returned slice is a copy — callers
// may sort or filter it without disturbing the table.
func ContractTools() []ContractTool {
	out := make([]ContractTool, len(contractTools))
	copy(out, contractTools)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// StableToolNames returns the names of every TierStable tool, sorted. These
// are the names carrying the strongest promise in docs/mcp-contract.md: an
// integrator may hard-code them, and they may not be renamed or removed
// under a semver-minor release.
func StableToolNames() []string {
	var out []string
	for _, t := range contractTools {
		if t.Tier == TierStable {
			out = append(out, t.Name)
		}
	}
	sort.Strings(out)
	return out
}

// ContractTierFor reports the published tier for a tool name. The second
// result is false when the name is absent from the contract table — an
// honest "not published", never a fabricated tier.
func ContractTierFor(name string) (ContractTier, bool) {
	for _, t := range contractTools {
		if t.Name == name {
			return t.Tier, true
		}
	}
	return "", false
}

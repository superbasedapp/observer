package policy

// MCP security rules R-301…R-305 (spec §5.5, §9) — the config-layer
// half of the guard: MCP server pinning, rug-pull detection, tool-
// description poisoning, and agent edits to MCP registries.
//
// Two evaluation shapes share the catalog block:
//
//   - R-301/302/303/305 consume Event.MCPFindings — pin-diff and
//     poisoning results computed at the owner (guard/mcpsec, which
//     holds the config parse and pin state) and stamped onto a
//     KindConfigChange event, exactly like Taint and Secrets. The
//     rows themselves never read configs: this package stays pure.
//     All four are flag-in-both-modes — the scan observes config
//     state after the fact, so there is nothing to block; the
//     enforcement lever is the taint system (an unapproved server's
//     results mark mcp_unpinned taint, arming T-501/T-505) plus the
//     operator's `observer guard mcp approve`.
//   - R-304 is an ordinary action-stream path rule (the R-160
//     pattern): an agent session writing an MCP registry file is the
//     easiest server-injection vector, and the hook seam can block it
//     pre-execution in enforce mode.
//
// Severity rationale: a NEW server (R-301) is routine operator
// activity → warn; a pinned server whose tools or binary CHANGED
// under the same name (R-302/R-305) is the rug-pull shape → critical;
// poisoning heuristics (R-303) are honest structural checks with a
// real FP floor → high (F7: heuristics never deny).

// MCPFinding kind vocabulary (MCPFinding.Kind values). Stable strings —
// they appear in verdict reasons and tests.
const (
	// MCPFindingNewServer fires R-301: a server appeared in a client
	// config (or in observed traffic) with no pin record, after that
	// client already had a pin baseline.
	MCPFindingNewServer = "new_unpinned_server"
	// MCPFindingDescriptionDrift fires R-302: a pinned server's
	// declared tool names/descriptions changed (rug-pull shape).
	MCPFindingDescriptionDrift = "description_drift"
	// MCPFindingPoisoning fires R-303: a poisoning heuristic hit in a
	// tool description.
	MCPFindingPoisoning = "poisoning"
	// MCPFindingBinaryChanged fires R-305: a pinned server's
	// command/binary/URL changed under the same name.
	MCPFindingBinaryChanged = "binary_changed"
	// MCPFindingUnapprovedServer fires R-306 (Agent Access P4, doc3
	// §12.6): an MCP tool call addressed to a server the compiled node
	// decision table does not approve for this node/principal. Stamped by
	// the guard layer's MCP-access seam on a KindMCPCall event (hook
	// PreToolUse, watcher ingest, proxy response inspection alike); this
	// package only matches on it.
	MCPFindingUnapprovedServer = "unapproved_server"
	// MCPFindingOrgGrantDenied fires R-307 (doc3 §12.6): an MCP tool call
	// the org's signed `tools.mcp_access` grant explicitly DENIES (a deny
	// row matched, or an ask row on a channel that cannot ask) — as
	// opposed to a server the table simply does not know.
	MCPFindingOrgGrantDenied = "org_grant_denied"
)

// MCPFinding is one MCP config-layer finding stamped onto an Event by
// the guard composition layer (guard/mcpsec computes them; this
// package only matches on them). It carries no config content —
// Server/Client name the subject, Detail is a bounded human-readable
// description for the verdict reason.
type MCPFinding struct {
	// Kind is one of the MCPFindingXxx constants.
	Kind string
	// Server is the MCP server name the finding concerns.
	Server string
	// Client is the AI client whose config carried the server
	// ("observed" for servers seen only in proxy traffic).
	Client string
	// Detail is a bounded human-readable specifics string.
	Detail string
}

// mcpConfigPathPatterns is the R-304 surface: the MCP registry files
// an agent could edit to inject a server (per-client user-level paths
// mirroring internal/mcp/locate, plus the project-scoped registries
// the locator deliberately doesn't enumerate). ~/.codex/config.toml
// is ALSO in R-160's observerConfigPatterns (it carries hook config
// too); R-160 wins ties by table position and both deny in enforce —
// the overlap is deliberate, pinned by TestMCPRules_CodexOverlap.
//
// FP profile: an operator-requested "set up MCP for this project"
// task legitimately writes .mcp.json — observe mode only flags, and
// enforce mode's deny is approvable (`observer guard approve R-304`).
var mcpConfigPathPatterns = []pathPattern{
	{"~/.claude.json", "Claude Code MCP registry"},
	{"?:/users/*/.claude.json", "Claude Code MCP registry"},
	{"~/.cursor/mcp.json", "Cursor MCP registry"},
	{"?:/users/*/.cursor/mcp.json", "Cursor MCP registry"},
	{"**/.cursor/mcp.json", "Cursor project MCP registry"},
	{"**/.mcp.json", "project MCP registry"},
	{"~/.codex/config.toml", "Codex configuration (MCP servers)"},
}

// matchMCPFinding builds an event-scoped matcher that hits when the
// stamped findings carry the given kind. The guard layer emits one
// event per finding, so a verdict's reason names exactly one subject.
func matchMCPFinding(kind string) MatchFn {
	return func(ctx *MatchContext) (bool, string) {
		for i := range ctx.Event.MCPFindings {
			f := &ctx.Event.MCPFindings[i]
			if f.Kind != kind {
				continue
			}
			detail := "server " + f.Server
			if f.Client != "" {
				detail += " (client " + f.Client + ")"
			}
			if f.Detail != "" {
				detail += ": " + f.Detail
			}
			return true, detail
		}
		return false, ""
	}
}

// mcpRules assembles the §5.5 table rows in catalog order.
func mcpRules() []Rule {
	faCfg := []EventKind{KindFileAccess, KindConfigChange}
	shell := []EventKind{KindShellExec}
	cfgScan := []EventKind{KindConfigChange}
	mcpCall := []EventKind{KindMCPCall}
	return []Rule{
		{
			ID: "R-301", Category: CategoryMCP, Severity: SeverityWarn,
			AppliesTo: cfgScan, Match: matchMCPFinding(MCPFindingNewServer),
			Observe: DecisionFlag, Enforce: DecisionFlag,
			Doc:    "new MCP server appeared without an approved pin",
			Advice: "Review the server's source and tools, then `observer guard mcp approve <server>` to trust it; unapproved servers' results taint the session.",
		},
		{
			ID: "R-302", Category: CategoryMCP, Severity: SeverityCritical,
			AppliesTo: cfgScan, Match: matchMCPFinding(MCPFindingDescriptionDrift),
			Observe: DecisionFlag, Enforce: DecisionFlag,
			Doc:    "pinned MCP server's declared tools or descriptions changed (rug-pull shape)",
			Advice: "Diff the server's tool descriptions against what you originally approved; if the update is legitimate, re-approve with `observer guard mcp approve <server>`.",
		},
		{
			ID: "R-303", Category: CategoryMCP, Severity: SeverityHigh,
			AppliesTo: cfgScan, Match: matchMCPFinding(MCPFindingPoisoning),
			Observe: DecisionFlag, Enforce: DecisionFlag,
			Doc:    "MCP tool description carries a poisoning-shaped pattern",
			Advice: "Read the named tool's full description; tool-shadowing instructions, hidden text, or exfil-shaped parameters in a description steer the model, not you.",
		},
		{
			ID: "R-304", Category: CategoryMCP, Severity: SeverityCritical,
			AppliesTo: faCfg, Match: faPathMatch(mcpConfigPathPatterns, true),
			Observe: DecisionFlag, Enforce: DecisionDeny,
			Doc:    "agent modifying an MCP server registry file",
			Advice: "MCP server registration is operator-owned; review the change and add the server yourself, or approve R-304 for this session.",
		},
		{
			ID: "R-304", Category: CategoryMCP, Severity: SeverityCritical,
			AppliesTo: shell, MatchCmd: shPathMatch(mcpConfigPathPatterns, true),
			Observe: DecisionFlag, Enforce: DecisionDeny,
			Doc:    "shell command modifying an MCP server registry file",
			Advice: "MCP server registration is operator-owned; review the change and add the server yourself, or approve R-304 for this session.",
		},
		{
			ID: "R-305", Category: CategoryMCP, Severity: SeverityCritical,
			AppliesTo: cfgScan, Match: matchMCPFinding(MCPFindingBinaryChanged),
			Observe: DecisionFlag, Enforce: DecisionFlag,
			Doc:    "pinned MCP server's command/binary or URL changed under the same name",
			Advice: "A same-name binary swap is the classic supply-chain shape; verify the new command is yours, then `observer guard mcp approve <server>`.",
		},
		// Agent Access P4 (doc3 §12.6): the two node-side enforcement rows
		// over the compiled tools.mcp_access decision table. Both apply
		// to the MCP CALL itself (KindMCPCall: hook PreToolUse — the one
		// pre-execution channel — plus the post-hoc watcher/proxy
		// paths), deny in enforce, flag in observe. The proxy's tools[]
		// strip (R-306) and hosted-connector refusal (R-307) cite the
		// same ids from their own seam; the ids are the audit vocabulary.
		{
			ID: "R-306", Category: CategoryMCP, Severity: SeverityHigh,
			AppliesTo: mcpCall, Match: matchMCPFinding(MCPFindingUnapprovedServer),
			Observe: DecisionFlag, Enforce: DecisionDeny,
			Doc:    "MCP tool call to a server not approved by the node's compiled tools.mcp_access table",
			Advice: "Route the server through the org MCP gateway (observer mcp-relay status lists the approved servers) or ask your admin to add a grant for it.",
		},
		{
			ID: "R-307", Category: CategoryMCP, Severity: SeverityCritical,
			AppliesTo: mcpCall, Match: matchMCPFinding(MCPFindingOrgGrantDenied),
			Observe: DecisionFlag, Enforce: DecisionDeny,
			Doc:    "MCP tool call denied by the organization's tools.mcp_access grant",
			Advice: "The org policy explicitly denies this tool for your principal; the relay's decision record names the grant. Ask your admin if the call is legitimate.",
		},
	}
}

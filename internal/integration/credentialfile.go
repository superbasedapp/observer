package integration

import (
	"sort"
	"strings"
)

// The D-268 credential-file exception (HookSpec.HooksShareCredentialFile):
// the grounding for every row whose hook writer read-modify-writes a vendor
// file that also holds plaintext credentials. The audit behind this list
// (Integration 6, T-375) walked every hook writer in internal/hook and
// checked the file it rewrites against the agentconfig catalogue: a file is
// credential-bearing when the catalogue carries a Secret row for it or says
// it holds literal keys. Writers that own a dedicated hooks file (Cursor,
// Codex hooks.json, Grok, Copilot CLI, Goose, Open Interpreter, Droid,
// Antigravity CLI, Cascade, Mistral Vibe hooks.toml, Command Code's mod
// file, the plugin shims) are not flagged. Gemini CLI and Qoder settings.json
// carry no catalogued credential slot and are not flagged either.
//
//nolint:gosec // G101: grounding prose that names a credential slot, not a credential.
const (
	credFileClaudeCode = "~/.claude/settings.json: its env block can carry ANTHROPIC_API_KEY, ANTHROPIC_AUTH_TOKEN and the other credential variables the agentconfig catalogue marks Secret (claude-code/settings env.*)."
	credFileCodex      = "~/.codex/config.toml: [features].hooks lives in the file that can hold a literal bearer token (features.multi_agent_v2.message_board_remote.bearer_token, a catalogue Secret row) beside the provider settings."
	credFileQwenCode   = "~/.qwen/settings.json: security.auth.apiKey (a catalogue Secret row) and the env block can hold a literal provider key."
	credFileCrush      = "~/.config/crush/crush.json: providers.<id>.api_key may be a literal key (the vendor schema's providers block, catalogue row crush/providers)."
	credFileJunie      = "~/.junie/config.json: byok holds literal BYOK API keys (catalogue Secret row junie/byok)."
	credFilePoolside   = "~/.config/poolside/settings.yaml: web_search.api_key and agent_servers can hold credentials (catalogue Secret rows)."
	credFileHermes     = "~/.hermes/config.yaml: the plugins.enabled entry the hook plugin needs shares the file with provider api_key values and request headers (catalogue Secret rows)."
	credFileZcode      = "~/.zcode/cli/config.json: the vendor stores hooks alongside plaintext provider keys (docs/zcode-adapter.md); Observer edits only the hooks key."
	credFileKimiCode   = "~/.kimi-code/config.toml: the vendor's only hooks file ([[hooks]] tables) also holds [providers.<name>].api_key and services.*.api_key as plaintext (catalogue Secret rows); Observer edits only its own [[hooks]] tables (T-378, D-270)."
	credFileAutohand   = "~/.autohand/config.json: the vendor's only user-level hooks location (hooks.hooks[]) shares the file with provider API keys, auth.token and api.companySecret (autohand-cli 0.9.8, hook probe 2026-10-21); Observer splices only the hooks member."
	credFileCodeBuddy  = "~/.codebuddy/settings.json: Claude Code's settings schema, whose env block can carry the CODEBUDDY_API_KEY the CLI reads (codebuddy 2.171.0, hook probe 2026-10-21); Observer splices only the hooks member."
)

// The MCP half of the exception (MCPTarget.SharesCredentialFile, review
// T-384): every MCP config file Observer writes keeps the user's OTHER
// servers beside observer's entry, and those carry env blocks and request
// headers that hold literal tokens (each vendor's MCP config documents an
// env map), so every implemented MCP target is declared.
//
//nolint:gosec // G101: grounding prose that names a credential slot, not a credential.
const (
	mcpCredClaudeCode  = "~/.claude.json: mcpServers.<name>.env and headers hold literal tokens for the user's other servers, beside the account state the file keeps."
	mcpCredCursor      = "~/.cursor/mcp.json: mcpServers.<name>.env and headers hold literal tokens for the user's other servers."
	mcpCredCodex       = "~/.codex/config.toml: [mcp_servers.<name>] env and http_headers, and the provider settings, can hold literal keys (the hook-side reason applies too)."
	mcpCredOpenCode    = "~/.config/opencode/opencode.json: provider.<id>.options.apiKey and mcp.<name>.environment / headers can hold literal keys."
	mcpCredCline       = "cline_mcp_settings.json: mcpServers.<name>.env holds literal tokens for the user's other servers."
	mcpCredHermes      = "~/.hermes/config.yaml: mcp_servers.<name>.env shares the file with provider api_key values (the hook-side reason applies too)."
	mcpCredDroid       = "~/.factory/mcp.json: mcpServers.<name>.env and headers hold literal tokens for the user's other servers."
	mcpCredCommandCode = "~/.commandcode/mcp.json: mcpServers.<name>.env and headers hold literal tokens for the user's other servers."
)

// The route half of the exception (ProxyRoute.SharesCredentialFile,
// surface-gap FU-33 / D9): every persisted route writer whose file also
// holds plaintext credentials. A launcher that writes its own provider entry
// before exec (cline-cli, pi, prime-agent, hermes) counts too: it is a
// writer into that file all the same.
//
//nolint:gosec // G101: grounding prose that names a credential slot, not a credential.
const (
	routeCredClaudeCode      = credFileClaudeCode
	routeCredCodex           = "~/.codex/config.toml: [model_providers.<id>] and the feature tables can hold literal keys and bearer tokens (catalogue Secret rows) beside the provider Observer adds."
	routeCredCline           = "~/.cline/data/globalState.json: extension-managed state beside the provider settings, credential-adjacent (D9); Observer sets only the active provider's base-URL member."
	routeCredClineCLI        = "~/.cline/data/settings/providers.json: OAuth tokens and provider API keys (a file the catalogue lists as never readable); the launcher sets only settings.baseUrl."
	routeCredPi              = "~/.pi/agent/models.json: a provider apiKey may be a literal key (catalogue Secret row pi providers); the launcher writes only its own observer provider."
	routeCredPrimeAgent      = "~/.prime/agent/models.json: a provider apiKey may be a literal key (catalogue Secret row, live 2026-10-03); the launcher writes only its own observer provider."
	routeCredHermes          = credFileHermes
	routeCredQwenCode        = credFileQwenCode
	routeCredKimiCode        = credFileKimiCode
	routeCredCrush           = credFileCrush
	routeCredOpenInterpreter = "~/.openinterpreter/config.toml (INTERPRETER_HOME): provider settings that hold plaintext keys (the registry never reads it; D16 allows a member-only route write)."
	routeCredStakpak         = "~/.stakpak/config.toml: each profile's api_key and provider auth are plaintext (catalogue row stakpak/user-config, never read)."
	routeCredGoose           = "~/.config/goose/config.yaml (GOOSE_PATH_ROOT): a provider key can sit there as a plaintext root key (catalogue note); the default-provider writer edits only OPENAI_HOST."
)

// RouteSharesCredentialFile reports whether tool's route writer (its
// ProxyProbe binding or its verified Proxy route) is declared under the
// credential-file exception. A "-windows" cross-OS target answers for its
// base row.
func RouteSharesCredentialFile(tool string) bool {
	c, ok := For(strings.TrimSuffix(tool, "-windows"))
	if !ok {
		return false
	}
	for _, r := range []*ProxyRoute{c.Proxy, c.ProxyProbe} {
		if r != nil && r.SharesCredentialFile {
			return true
		}
	}
	return false
}

// CredentialFileRouteTools lists, sorted, every registry row whose route
// writer carries the credential-file exception.
func CredentialFileRouteTools() []string {
	var out []string
	for _, c := range Capabilities() {
		if RouteSharesCredentialFile(c.Tool) {
			out = append(out, c.Tool)
		}
	}
	sort.Strings(out)
	return out
}

// MCPSharesCredentialFile reports whether tool's MCP config file is declared
// under the credential-file exception. A "-windows" cross-OS target answers
// for its base row. An unknown tool, or a row with no MCP target, is false.
func MCPSharesCredentialFile(tool string) bool {
	c, ok := For(strings.TrimSuffix(tool, "-windows"))
	return ok && c.MCP != nil && c.MCP.SharesCredentialFile
}

// HooksShareCredentialFile reports whether tool's hook writer works under
// the D-268 credential-file exception. A "-windows" cross-OS target answers
// for its base row (the bridge writes the same file shape on the Windows
// side). An unknown tool is false.
func HooksShareCredentialFile(tool string) bool {
	c, ok := For(strings.TrimSuffix(tool, "-windows"))
	return ok && c.Hook.HooksShareCredentialFile
}

// CredentialFileHookTools lists, sorted, every registry row that carries
// the credential-file exception.
func CredentialFileHookTools() []string {
	var out []string
	for _, c := range Capabilities() {
		if c.Hook.HooksShareCredentialFile {
			out = append(out, c.Tool)
		}
	}
	sort.Strings(out)
	return out
}

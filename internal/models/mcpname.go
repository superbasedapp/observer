package models

// ObserverMCPServerName is the one name Observer's MCP server is registered
// under in every AI tool's MCP config: the per-node writers
// (internal/mcpregister: [mcp_servers.observer] in Codex config.toml,
// mcpServers.observer in Claude Code and the JSON clients) and the Rail B
// managed generators (internal/managedsettings: the Codex managed_config.toml
// pin and its requirements.toml identity template, the Claude Code
// managed-mcp.json pin and its allowedMcpServers entry). One name means one
// server per client, not two at twice the schema overhead, and an admin
// allowlist naming it admits the server whichever writer put it there
// (surface-gap review CX-8). It lives here, the leaf every writer already
// imports, so no writer package has to import another.
const ObserverMCPServerName = "observer"

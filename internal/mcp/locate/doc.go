// Package locate is the single owner of "where does each AI client
// keep its user-level MCP server configuration" (guard spec §9.1).
//
// Two consumers share this table so the knowledge is never re-derived:
//
//   - internal/mcp's Registrar (observer init) writes the observer MCP
//     entry into these files;
//   - internal/guard/mcpsec (G10) reads the same files to inventory
//     and pin every configured MCP server.
//
// The package is deliberately a leaf: mcpsec sits under internal/guard,
// which internal/store imports, so it must not pull the full internal/mcp
// dependency tree (an import cycle through store would result). Its
// non-stdlib imports are internal/agentconfig, the owner of a file's
// relocation rules (surface-gap Wave 0.4), and internal/platform/crossmount
// for the pinned-home environment rule (HomeEnvAt); neither imports store
// or guard. Path or format knowledge for a new client is added HERE, nowhere
// else: a row names the client's agentconfig FileRow artifacts (its MCP
// file and its install signal), and every path is expanded through
// agentconfig.ResolveArtifact, so a relocation rule on a row moves it here
// with no edit (surface-gap Wave 4).
//
// Scope: USER-LEVEL configs only. Project-scoped MCP registries
// (claude-code's <root>/.mcp.json, cursor's <root>/.cursor/mcp.json)
// are watched by the R-304 policy rule but are not inventoried —
// enumerating every project root is the watcher's domain, not a
// static locator's (documented approximation, revisit if §9 grows a
// per-project inventory).
package locate

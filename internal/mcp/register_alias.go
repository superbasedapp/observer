package mcp

import "github.com/marmutapp/superbased-observer/internal/mcpregister"

// The client-config registrar lives in internal/mcpregister (lane MP-L1H,
// T-715), so it stays in a build without the MCP server. These names keep
// existing callers of the old names compiling unchanged; new code imports
// internal/mcpregister directly.

// RegisterOptions is mcpregister.RegisterOptions.
type RegisterOptions = mcpregister.RegisterOptions

// ServerName is mcpregister.ServerName.
const ServerName = mcpregister.ServerName

// NewRegistrar is mcpregister.NewRegistrar.
func NewRegistrar(opts RegisterOptions) (*mcpregister.Registrar, error) {
	return mcpregister.NewRegistrar(opts)
}

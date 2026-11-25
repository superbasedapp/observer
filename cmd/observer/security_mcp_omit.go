//go:build sbo_omit_security || sbo_omit_integration_mcp_server

package main

import (
	"database/sql"
	"log/slog"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// securityMCPToolsAt adds nothing: the security module or the MCP server is
// not in this build.
func securityMCPToolsAt(config.Config, *sql.DB, *slog.Logger, string) []securityMCPTool {
	return nil
}

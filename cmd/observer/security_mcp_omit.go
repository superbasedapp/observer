//go:build sbo_omit_security || sbo_omit_integration_mcp_server

package main

import (
	"database/sql"
	"log/slog"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// securityMCPTools adds nothing: the security module or the MCP server is
// not in this build.
func securityMCPTools(config.Config, *sql.DB, *slog.Logger) []securityMCPTool { return nil }

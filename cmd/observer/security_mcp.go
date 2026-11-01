//go:build !sbo_omit_security && !sbo_omit_integration_mcp_server

package main

import (
	"context"
	"database/sql"
	"log/slog"
	"os"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secmcp"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_mcp.go composes the security pillar's MCP tools
// (get_security_findings and check_change, internal/secmcp; security
// pillar plan section 6.1, lane sec-c3) into `observer serve`. They are
// registered only while the `security` module is active and
// [security.mcp].tools is on; MCP itself stays opt-in (observer init), so
// with the module or MCP off they are absent.

// securityMCPTools returns the tools to add to the MCP server, none while
// the module is inactive or the setting is off.
func securityMCPTools(cfg config.Config, database *sql.DB, logger *slog.Logger) []securityMCPTool {
	if !cfg.Security.MCP.Tools || !componentSnapshotForConfig(cfg).ModuleActive("security") {
		return nil
	}
	wd, _ := os.Getwd()
	st := store.New(database)
	deps := secmcp.Deps{WorkDir: wd, Findings: secmcp.NewFindingsReader(git.FindRoot, git.FindCheckoutRoot,
		func(ctx context.Context, root string) ([]secfinding.Finding, error) {
			return st.ListSecFindings(ctx, store.SecFindingFilter{
				ProjectRootHash: secposture.ProjectRootHash(root), Status: policy.FindingStatusOpen, Limit: 1000,
			})
		})}
	var out []securityMCPTool
	for _, t := range secmcp.Tools(deps) {
		out = append(out, t)
	}
	if logger != nil {
		logger.Info("security: MCP tools registered", "tools", "get_security_findings,check_change")
	}
	return out
}

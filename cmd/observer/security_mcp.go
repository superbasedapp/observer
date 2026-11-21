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
	"github.com/marmutapp/superbased-observer/internal/secdepdetail/projectfs"
	"github.com/marmutapp/superbased-observer/internal/secexploit"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secmcp"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secrank"
	"github.com/marmutapp/superbased-observer/internal/secreachsvc"
	"github.com/marmutapp/superbased-observer/internal/secsignal"
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
	return securityMCPToolsAt(cfg, database, logger, "")
}

// securityMCPToolsAt is securityMCPTools with the config path the OSV store
// sits beside ("": the default path).
func securityMCPToolsAt(cfg config.Config, database *sql.DB, logger *slog.Logger, configPath string) []securityMCPTool {
	if !cfg.Security.MCP.Tools || !componentSnapshotForConfig(cfg).ModuleActive("security") {
		return nil
	}
	wd, _ := os.Getwd()
	st := store.New(database)
	record := securityLocalOSVLookup(configPath)
	deps := secmcp.Deps{
		WorkDir: wd, Findings: secmcp.NewFindingsReader(git.FindRoot, git.FindCheckoutRoot,
			func(ctx context.Context, root string) ([]secfinding.Finding, error) {
				// Worst severity first, so the store's cap keeps the worst.
				return st.ListSecFindings(ctx, store.SecFindingFilter{
					ProjectRootHash: secposture.ProjectRootHash(root), Status: policy.FindingStatusOpen, Limit: 1000,
					Sort: store.SecSortSeverity, Desc: true,
				})
			}),
		Evidence: func(ctx context.Context, id string) (string, error) {
			ev, _, _, err := st.SecFindingEvidence(ctx, id)
			return ev, err
		},
		ReadFile: func(root, rel string) ([]byte, error) {
			return projectfs.Read(root, rel, projectfs.MaxLockfileBytes)
		},
		LookupRecord: record,
		Enrich:       securityMCPEnricher(st, record, securityLocalExploitLookup(configPath), secreachsvc.NewCache(0), securitySymbolDir(configPath)),
	}
	var out []securityMCPTool
	for _, t := range secmcp.Tools(deps) {
		out = append(out, t)
	}
	if logger != nil {
		logger.Info("security: MCP tools registered", "tools", "get_security_findings,check_change")
	}
	return out
}

// securityMCPEnricher is get_security_findings's reach, kev and epss
// (plan section 14.8): secsignal.Compute over the finding, its dependency
// evidence, the local OSV record read and the installed exploit data. The
// import list is cached per project for the MCP server's lifetime TTL
// (secreachsvc.Cache), prefers the codeintel index when it holds the whole
// project, and a cold parse is bounded by secreachsvc's limits. The Go
// symbol checks a dependency scan stored under symbolDir
// (secreachsvc.LoadSymbolRuns) move a tier to called or not_called. No
// request is made. kev is omitted when the KEV data is unavailable (never "not
// listed"), and epss when no installed score names the finding.
func securityMCPEnricher(st *store.Store, record func(eco, id string) ([]byte, error), exploit func([]string) secexploit.Exploit, cache *secreachsvc.Cache, symbolDir string) secmcp.Enricher {
	return func(ctx context.Context, in secmcp.EnrichInput) secmcp.Enrichment {
		f := in.Finding
		if f.Category != policy.FindingVulnerableDependency {
			return secmcp.Enrichment{}
		}
		ev, err := st.SecDependencyEvidence(ctx, []string{f.ID})
		if err != nil {
			ev = nil
		}
		sig, ok := secsignal.Compute(ctx, secsignal.Inputs{
			Root: in.Root, Findings: []secfinding.Finding{f}, Evidence: ev, Record: record, Exploit: exploit,
			Reach:     []secreachsvc.Option{secreachsvc.WithCache(cache), secreachsvc.WithCodeIntel(st), secreachsvc.PreferCodeIntel()},
			Symbol:    secreachsvc.LoadSymbolRuns(symbolDir, secposture.ProjectRootHash(in.Root)),
			Sightings: st.SecFindingSightings,
		})[f.ID]
		if !ok {
			return secmcp.Enrichment{}
		}
		return securityMCPEnrichment(sig)
	}
}

// securitySymbolDir is the security directory beside configPath (the Go
// symbol checks' record, secreachsvc.SymbolPath), "" when it cannot be
// resolved.
func securitySymbolDir(configPath string) string {
	resolved, err := config.ResolveGlobalPath(configPath)
	if err != nil {
		return ""
	}
	return secposture.LayoutFor(resolved).Dir
}

// securityMCPEnrichment is one signal as the MCP answer's fields.
func securityMCPEnrichment(sig secsignal.Signal) secmcp.Enrichment {
	out := secmcp.Enrichment{Reach: secrank.ReachToken(sig.Reach)}
	x := sig.Exploit
	if x.KEVAvailable {
		k := &secmcp.KEV{Listed: x.KEV != nil}
		if x.KEV != nil {
			k.DateAdded = x.KEV.DateAdded
		}
		out.KEV = k
	}
	if x.EPSSAvailable && x.EPSS != nil {
		v := x.EPSS.Score
		out.EPSS = &v
	}
	return out
}

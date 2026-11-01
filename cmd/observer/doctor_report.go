package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/proxyroute"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// doctorReportInput is one `observer doctor [scope]` run's inputs.
type doctorReportInput struct {
	Config         config.Config
	DB             *sql.DB
	Binary         string
	ConfigPath     string
	Scope          string
	ForceIntegrity bool
	// HomeDir overrides $HOME for the diag checks ("" in production).
	HomeDir string
}

// buildDoctorReport is THE assembly of an `observer doctor [scope]` report:
// the diag checks plus the extra checks only cmd/observer can build, then,
// for a scope that names an adapter, the focused per-adapter view (capture
// check, control coverage, minimum runtime, and the general checks that name
// the tool); for any other scope, the substring filter. The CLI and the
// dashboard's per-tool "Run checks" (T-421 item 3, wired as
// dashapi.Options.ToolDoctor) both call it, so the two surfaces cannot
// drift. An unscoped run returns every check.
func buildDoctorReport(ctx context.Context, in doctorReportInput) (diag.Report, error) {
	cfg, database, binary, configPath := in.Config, in.DB, in.Binary, in.ConfigPath
	// The sandbox section and the hook_block lines read one probe: the
	// lines' fallback channel is sandbox_enforce only where a sandbox can
	// be built here.
	sandboxChecks, sandboxAvailable := sandboxDoctorSection(ctx, cfg, configPath)
	report := diag.Run(ctx, diag.DoctorOptions{
		Config:         cfg,
		DB:             database,
		BinaryPath:     registrationCommand(binary),
		RealBinaryPath: binary,
		CLIVersion:     version,
		HomeDir:        in.HomeDir,
		Scope:          in.Scope,
		ForceIntegrity: in.ForceIntegrity,
		// T-915: the route rows read the component selection route
		// maintenance acts on, so a tool the policy did not select is "not
		// selected by policy" and, with the route writer off, every tool is
		// "routing switched off by policy", never route drift.
		RouteSelection: routeSelection(componentSnapshotForConfig(cfg)),
		// Fold the obs-plane admission health checks (judge
		// reachability + audit-chain verify) into doctor, built in the
		// one obs wiring file so diag never imports internal/obs.
		ExtraChecks: append(append(append(
			obsAdmissionDoctorChecks(ctx, cfg, database, slog.Default()),
			oversizeCaptureCheck(ctx, cfg, database),
			// T-830: rows retention keeps only because the org push has
			// not accepted them, so a stuck push is visible.
			retentionPushHoldCheck(ctx, cfg, database),
			otlpIngressPostureCheck(cfg),
			// R-188 F5: hook activity records skipped while the hook spool
			// was past its cap with nothing draining it.
			hookSpoolCheck(configPath),
			// CLI-4: a tool home variable the login shell sets but this process
			// does not (lane w4-homes-b).
			loginEnvDriftCheck(),
			// T-536: which exporting tools the proxy owns tokens for;
			// none when this node serves no proxy (REVIEW-4 P4-18).
			otlpTokenOwnerCheck(cfg,
				proxyServingReason(cfg, componentSnapshotForConfig(cfg).Active("capture.proxy")),
				proxyroute.ApplyActiveProvider(proxyroute.InspectRoutes(doctorHome(in.HomeDir)))),
			// T-323: a user guard-policy.toml the guard drops is a
			// doctor ERROR naming the file, line and parse error.
			guardUserPolicyDoctorCheck(cfg, userHomeOrEmpty(), os.ReadFile, userPolicyFailClosedOnNode(configPath)),
			// Code security (security pillar plan section 4.11): one line
			// while the module is not active.
			securityDoctorCheck(ctx, configPath, doctorStore(database)),
			// Package checks (security.deps): online state, disclosure,
			// index kinds and the not-set-up state.
			securityDepsDoctorCheck(ctx, configPath),
			// Code rules (security.scan.opengrep): the engine's
			// verification and the rule pack; nothing started.
			securityCodeDoctorCheck(ctx, configPath),
			// SARIF import and actionlint (security.scan.sarif-import and
			// security.scan.actionlint, lane sec-g5): one line each,
			// nothing read or started.
			securitySARIFImportDoctorCheck(ctx, configPath),
			securityActionlintDoctorCheck(ctx, configPath),
			securityIaCDoctorCheck(ctx, configPath),
		),
			// One line per hook_block tool: does its tool-gate hook
			// hold on this node, or what it falls back to and why
			// (toolgate_node.go, the launch decision's own source).
			toolGateEnforcementChecks(sandboxAvailable, func(tool string) nodeToolGateState {
				return nodeToolGate(binary, configPath, tool)
			})...),
			// The Components section (modular packaging 7.3, T-661):
			// selection, build, policy, signature, leftovers, then one
			// row per separately installed artifact (lane MP-ART, T-601).
			append(append(componentsDoctorChecksFor(ctx, configPath), componentsArtifactChecksFor(configPath, in.HomeDir)...),
				// The sandbox module's section (sandbox plan v2 11.6).
				sandboxChecks...)...),
	})
	scope := in.Scope
	if scope == "" {
		return report, nil
	}
	// A known adapter name gets a focused, per-adapter capture check
	// (detection + watch path + proxy-routing for the routable ones).
	// Otherwise fall back to a substring filter over the general checks
	// (org, hooks, db, ...).
	c, ok := diag.CheckAdapterIn(scope, cfg, doctorHome(in.HomeDir))
	if !ok {
		report = report.Filter(scope)
		if report.Matched() == 0 {
			return report, fmt.Errorf("no doctor checks or adapters match %q (adapters: claude-code, codex, opencode, cursor, cline, copilot, gemini-cli, …; checks: org, hooks, db, mcp, governance)", scope)
		}
		return report, nil
	}
	// General checks that name this tool (e.g. the cursor.hooks
	// registration health check) ride along: the adapter capture check
	// alone cannot see a hook registration that points at a dead receiver.
	general := report.Filter(scope).Checks
	report = diag.Report{Checks: []diag.Check{c}}
	// Control coverage (2026-09-22 investigation, internal/controlcoverage):
	// "what actually controls this developer's use of this tool" - the
	// tool-call block channel, the prompt-submit channel, and the budget
	// channel + route proof - is a separate question from the
	// capture-health notes CheckAdapter already prints, so it lands as its
	// own check rather than another Details line. Always StatusOK: this is
	// informational, never a capture defect.
	if line, ok := controlCoverageLineObserved(ctx, database, scope); ok {
		report.Checks = append(report.Checks, diag.Check{
			Name:    scope + ".control-coverage",
			Status:  diag.StatusOK,
			Message: line,
		})
	}
	// Minimum host runtime (runtime_preflight.go): the same check the
	// launcher refuses on and the guided install refuses before installing.
	// A runtime too old to start the tool is a WARN, not a capture defect.
	if line, details, blocking, ok := runtimeDoctorLine(scope); ok {
		st := diag.StatusOK
		if blocking {
			st = diag.StatusWarn
		}
		report.Checks = append(report.Checks, diag.Check{
			Name:    scope + ".runtime",
			Status:  st,
			Message: line,
			Details: details,
		})
	}
	report.Checks = append(report.Checks, general...)
	return report, nil
}

// dashboardToolDoctor is the dashboard's per-tool doctor seam
// (dashapi.Options.ToolDoctor): buildDoctorReport scoped to one tool, with
// the running binary and the daemon's config path, on the dashboard's own
// loaded config and database handle.
func dashboardToolDoctor(configPath string) func(ctx context.Context, cfg config.Config, database *sql.DB, tool string) (diag.Report, error) {
	return func(ctx context.Context, cfg config.Config, database *sql.DB, tool string) (diag.Report, error) {
		binary, err := absoluteBinaryPath()
		if err != nil {
			return diag.Report{}, err
		}
		return buildDoctorReport(ctx, doctorReportInput{
			Config: cfg, DB: database, Binary: binary, ConfigPath: configPath, Scope: tool,
		})
	}
}

// doctorStore wraps the doctor's database handle, nil when there is none.
func doctorStore(database *sql.DB) *store.Store {
	if database == nil {
		return nil
	}
	return store.New(database)
}

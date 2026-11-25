package main

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"

	"github.com/marmutapp/superbased-observer/internal/cloudagentssvc"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/planlimitssvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// dashboard_options.go is the ONE construction of the node dashboard's
// dashapi.Options that `observer start` (start.go) and the standalone
// `observer dashboard` (dashboard.go) share (CMD-01). The two commands used to
// build the ~90-field literal twice and had drifted: only the standalone one
// wired the Findings tab's Explain, its suggest-a-fix and the affected-worker
// notice, so the dashboard most people run (the daemon's) answered 404 for
// Explain and hid the notice. Every field both commands serve is set here; the
// daemon then adds only the fields in daemonOnlyDashboardFields
// (dashboard_options_test.go compares the two wirings and fails on a field
// set by one command and not the other without a reason).
//
// No build tag: start.go builds the options in every build (a build without
// the dashboard refuses at newDaemonDashboard), and every seam called here has
// its own omit stub.

// nodeDashboardDeps is what both dashboard commands hand the shared builder:
// the process's config, database and terminal stack, plus the few values that
// are one process-wide service in the daemon and a fresh one standalone.
type nodeDashboardDeps struct {
	// Ctx is the command's context (the daemon's root context, which a
	// dashboard restart cancels).
	Ctx context.Context
	// Cfg is the loaded config (in the daemon, after the components' inert
	// overlay).
	Cfg config.Config
	// ConfigPath is the --config flag value as given; ResolvedConfigPath is
	// the global config file it resolves to.
	ConfigPath         string
	ResolvedConfigPath string
	DB                 *sql.DB
	// Surfaces is the process's one terminal stack (buildTerminalSurfaces).
	Surfaces terminalSurfaces
	// Remote is the remote-access substrate (buildRemoteController); nil
	// unless [remote] is enabled and a pairing secret is provisioned.
	Remote dashapi.RemoteController
	// Governance is the process's one node.governance install seam.
	Governance *nodeGovernanceHandle
	// ProcessArchive is the cold-storage reader for archived process trails
	// (the caller owns its closer).
	ProcessArchive dashapi.ProcessArchiveReader
	// Plans and CloudAgents are the daemon's process-wide services (the same
	// ones its loops run) or, standalone, fresh ones.
	Plans       *planlimitssvc.Service
	CloudAgents *cloudagentssvc.Service
	// EnrolManager is Settings > Enrolment management; the daemon's says a
	// push loop runs and retires its budget rail on Leave.
	EnrolManager dashapi.EnrolmentManager
	// OrgIntelChanged is called after a Settings > Cloud Intelligence write
	// (the daemon invalidates its rail gate's live opt-in read); nil
	// standalone.
	OrgIntelChanged func()
}

// nodeDashboardOptions builds every dashapi.Options field the daemon's
// dashboard and the standalone dashboard both serve.
func nodeDashboardOptions(d nodeDashboardDeps) dashapi.Options {
	cfg := d.Cfg
	database := d.DB
	surfaces := d.Surfaces
	logger := slog.Default()
	// Projects-page ROI + commit-alignment arc (docs/plans/
	// projects-page-roi-and-commit-alignment-plan-2026-09-21.md §4 W3): the
	// §3.6 "J" judge-tier seam is build-tag-split (projects_wire.go /
	// projects_judge_wire.go).
	projectsJudgeGrade, projectsJudgeGradeReason := projectsDashboardOptions(&cfg)
	return dashapi.Options{
		ProcessArchive: d.ProcessArchive,
		Projects:       cfg.Projects,
		// Plans & limits / Cloud agents: see nodeDashboardDeps.
		Plans:       d.Plans,
		CloudAgents: d.CloudAgents,
		// CommitAlignmentAvailability (cloud_gradecommit.go) is the SAME
		// function `observer cloud grade-commit` itself calls, so the
		// dashboard and the CLI never disagree about why cloud grading is
		// unavailable.
		CloudGradeAvailability: CommitAlignmentAvailability,
		JudgeGrade:             projectsJudgeGrade,
		JudgeGradeReason:       projectsJudgeGradeReason,
		JudgeGradePlace:        projectsJudgeGradePlace(&cfg, projectsJudgeGrade != nil),
		// Projects page "Rescan now" (commitscan_wire.go): the daemon's own
		// commit scanner, nil when [projects].commit_scan is off.
		CommitRescan: commitRescanWithDelivery(cfg, database),
		// Package checks card (security_deps_dash.go): the install gate's
		// state and the dashboard accept of its disclosure.
		PackageChecks: packageChecksDash(d.ResolvedConfigPath, database),
		// Scanners card (security_scan_dash.go): the OSV database download's
		// one-time accept (PT-19).
		ScannerDB: scannerDBDash(d.ResolvedConfigPath, database),
		// SARIF upload (security_sarifimport.go): one file the developer
		// picked, through the CLI's own import (lane SEC-P4).
		SARIFImport: sarifImportDash(database),
		// Code security "Scan now" (security_scan_now.go): one manual run of
		// a selected scanner on one project, the same run its CLI verb starts.
		SecurityScanNow: securityScanNowDash(d.ResolvedConfigPath, database),
		// DAST card (security_dast_dashboard.go) and Projects tab SBOM export
		// (security_sbom_dashboard.go), security coverage gaps plan.
		SecurityDAST:        securityDASTDash(d.ResolvedConfigPath, database),
		SecurityProjectSBOM: securityProjectSBOMDash(d.ResolvedConfigPath),
		// Code rules card (security_opengrep_dash.go): the guided install with
		// its size consent (lane SEC-G2).
		Opengrep: opengrepDash(d.ResolvedConfigPath, database),
		IaC:      iacDash(d.ResolvedConfigPath, database),
		// AI change records card (security_provenance_cmd.go, lane sec-f2a).
		Provenance: provenanceDash(d.ResolvedConfigPath, database),
		// The one security opt-in rule (security_optin.go): the components
		// state's security_selected (which Settings rows and the Explain
		// button show), and the trust, git hooks and scanner routes.
		SecuritySelected: securitySelected,
		// The Components page's view with the modules' own rules
		// (components_gate.go), so a removed sandbox root reads as off there
		// as in `observer components status` (P-057).
		ComponentStateView: componentStateView,
		// The launch row's Observer-entry test (launch_trust_own.go), so the
		// New Terminal trust chip leaves out what the launch leaves out.
		RepoTrustOwn: repoTrustDashboardOwn,
		// The launch row's conditional rows (trust_conditions.go), so the
		// review lists N2's initializeCommand row as the launch reads it.
		RepoTrustPaths: repoTrustDashboardPaths(d.ResolvedConfigPath),
		// The Findings tab's Explain and suggest-a-fix (security.feedback,
		// lane sec-h) and the affected-worker notice
		// (security_orgnotice_dash.go, lane SEC-E3). Until CMD-01 only the
		// standalone dashboard set these three.
		SecurityExplain:    securityExplainDash(d.ResolvedConfigPath, database),
		SecurityExplainFix: securityExplainFixDash(d.ResolvedConfigPath, database),
		SecurityOrgShare:   securityOrgShareDash(cfg.OrgClient.Share.Security),
		// Delivery (delivery_wire.go, D-689): the [delivery] tunables and the
		// one process-wide delivery service the poll loop also runs.
		Delivery:        cfg.Delivery,
		DeliveryService: deliveryDashOption(cfg, database),
		// Admin-controlled Plane B (spec §3.5): the ONE seam the dashboard has
		// onto governance, so the route guard, the SPA and the P0-6 report
		// can never disagree about what this node applies.
		Governance: d.Governance.Effective,
		DB:         database,
		DBPath:     cfg.Observer.DBPath,
		CostEngine: acquireProcessCostEngine(d.Ctx, cfg, database, logger),
		// Production read caches: page loads fan several spend panels out at
		// once and share one row read; watcher health is served SWR
		// (optimization review 2026-09-27, findings N4/N5).
		ReadCaches: true,
		Predict:    cfg.Predict,
		Scoring:    cfg.Intelligence.Scoring,
		CacheWarm:  cfg.CacheWarm,
		Tasks:      cfg.Tasks,
		// LOC editor endpoint credential: generated on first start into
		// [loc].editor_token_file, read back after. Never fatal: an
		// unreadable file yields "" and the endpoint keeps its loopback-only
		// posture.
		LocEditorToken:         resolveLocEditorToken(locEditorTokenPath(cfg), logger),
		LocEditorTokenRequired: cfg.Loc.EditorTokenRequired,
		Dashboard:              cfg.Dashboard,
		MonthlyBudgetUSD:       cfg.Intelligence.MonthlyBudgetUSD,
		ConfigPath:             d.ResolvedConfigPath,
		RecognizesSessionFile:  recognizesSessionFile(),
		CursorSemanticsFor:     cursorSemanticsFor(),
		ToolCatalog:            toolCatalog(),
		// Connected tools hooks probe: the daemon's own auto-registration
		// options (T-376).
		HookRegistryOptions: hookProbeOptionsSeam(d.ConfigPath),
		// Connected tools per-tool "Run checks" (T-421 item 3): the same
		// report builder `observer doctor <tool>` prints.
		ToolDoctor: dashboardToolDoctor(d.ConfigPath),
		// Cloud account seam (cloudaccount_wire.go): local sign-in probe +
		// `observer cloud login|logout` subprocess runner behind the Settings
		// → Cloud Intelligence Sign-in button. Spawns the CLI; links nothing
		// new.
		CloudAccount:   newCloudAccountSeams(d.ResolvedConfigPath),
		ArenaAdmission: arenaBudgetAdmissionSeam(d.ResolvedConfigPath),
		ArenaPreflight: arenaPreflightSeam(d.ResolvedConfigPath),
		// OSH-R-005: may an Arena drive skip the harness's permission checks.
		ArenaPermissionBypass: arenaPermissionBypassSeam(d.ResolvedConfigPath),
		StashDir:              cfg.Compression.Conversation.Stash.Dir,
		GuardEnabled:          cfg.Guard.Enabled,
		GuardMode:             cfg.Guard.Mode,
		GuardStrict:           cfg.Guard.Strict,
		GuardHookFailure:      guardHookFailureSeam(d.ConfigPath),
		GuardToolGates:        guardToolGatesSeam(d.ConfigPath, surfaces.sandboxProber),
		Version:               version,
		// Session handoff (docs/session-handoff.md P2): the shared handoffsvc
		// runner behind /api/session/<id>/handoff*.
		BuildHandoff: handoffRunner(cfg, database),
		// P6.7: demo mode — temp DB seeded from embedded fixtures; never
		// touches the real observer.db.
		DemoSeeder: demoSeeder(logger),
		// Embedded web-terminal launcher (docs/session-handoff.md launch
		// section). Nil when [handoff].allow_dashboard_launch is false →
		// endpoints 503, button hidden.
		LaunchManager:  surfaces.launchMgr,
		TerminalStatus: surfaces.launchStatus,
		// Node-intervention policy-stop explanation (policystop.go). Nil
		// unless the launch manager is also wired: a policy stop only ever
		// concerns a dashboard-launched PTY run.
		PolicyStop: surfaces.policyStop,
		// B9 sandboxed terminals: the availability probe behind GET
		// /api/terminal/sandbox + the fail-closed launch validation. Nil
		// unless [terminal.sandbox].enabled → endpoint reports disabled and
		// a sandbox request 501s.
		SandboxProber:      surfaces.sandboxProber,
		LoopbackCallerGate: surfaces.loopbackCallerGate,
		LaunchCaller:       surfaces.launchCaller,
		PendingLaunches:    surfaces.pendingLaunches,
		// Sandbox setup (sandbox installation lifecycle plan, P-249): nil in
		// a build without the sandbox module, so the setup routes answer 501.
		SandboxSetup: newSandboxSetup(sandboxSetupOptions{ConfigPath: d.ResolvedConfigPath, Surface: "dashboard", Ledger: surfaces.toolInstalls, Logger: logger, Spawn: func(_ context.Context, argv []string, label string) (string, int, error) {
			if surfaces.launchMgr == nil {
				return "", -1, errors.New("the dashboard terminal is off ([handoff].allow_dashboard_launch)")
			}
			h, err := surfaces.launchMgr.CreateSetup(dashapi.SetupSpec{Argv: argv, Label: label})
			return h, -1, err
		}}),
		// The New Terminal "project policy" line (lane sec-p2b): reads the
		// project match record; shown only when the node holds a project
		// delivery.
		ProjectPolicy: terminalProjectPolicySeam(cfg, store.New(database)),
		// Tool-binary-resolution seams (tool-binary-resolution arc §5):
		// pre-launch verdict + guided install. Plain funcs so the dashboard
		// package never imports internal/toolresolve.
		ToolPreflight:    toolPreflightSeam(d.ResolvedConfigPath, allowToolInstallSeam(d.ResolvedConfigPath)),
		AllowToolInstall: allowToolInstallSeam(d.ResolvedConfigPath),
		ToolInstallHint:  toolInstallHintSeam(),
		// Refuse a guided install whose grounded prerequisites (unzip,
		// bzip2, ...) are missing, with the fix.
		ToolInstallBlocked: toolInstallBlockedSeam(),
		// The record of guided installs this dashboard ran + the matching
		// uninstall (tool_installs, agent migration 149).
		ToolInstalls: surfaces.toolInstalls,
		// Command wrapping (backlog item 7): the one shim / start-up-file
		// applier, behind the Settings -> Terminal card.
		ShellWrap: newShellWrapService(d.ResolvedConfigPath, dashResolveEnv),
		// Windows-home init (T-421 item 4): `observer init --windows-*-home`
		// behind Connected tools, WSL only.
		WindowsHomes: newWindowsHomeService(d.ResolvedConfigPath, cfg.Proxy.Port),
		// Re-pricing stored costs (PRICE-REPRICE-1): the one plan/apply/
		// revert service `observer reprice` also uses, behind the Settings
		// card.
		Reprice: newRepriceService(d.Ctx, cfg, database, logger, d.Governance.Effective),
		// New Terminal model picker (B5): recent-usage history over this
		// database, composed with the capability registry's Known examples by
		// modelSuggestionsFor.
		RecentModels: recentModelsSeam(database),
		// Per-terminal project panel (Arc A): token→root resolver from
		// termsvc. Nil when the launch manager is absent → 404.
		ProjectRootResolver: projectRootResolver(surfaces.launchMgr),
		// Per-terminal session cockpit (Session Cockpit): token→run/
		// session-link resolver from termsvc. Nil when the launch manager is
		// absent → cockpit 404s.
		SessionResolver: sessionResolver(surfaces.launchMgr),
		// The agent-run security assessments' relaxations read the guard's
		// own lock and decision per rule and project (fail closed when
		// unreadable).
		RuleRelaxation:     dashboardRuleRelaxation(d.ResolvedConfigPath, database),
		SandboxGatewayPort: sandboxGatewayPortFunc(),
		// Remote-access substrate (plan §4). Nil unless [remote] is enabled
		// AND a pairing secret is provisioned, so a non-loopback dashboard
		// bind stays fail-closed.
		Remote:      d.Remote,
		RemoteAudit: remoteAuditSink(database),
		// Settings > Enrolment management (backlog item 6): enrol / consent /
		// status / grant / push-now / leave through the CLI's own code paths.
		EnrolManager:       d.EnrolManager,
		ConnectStatus:      connectStatusSeam(database),                         // plan 07 M8.4: the front door's one sentence
		Components:         dashboardComponents(d.ResolvedConfigPath, database), // Settings > Components + route guard (MP-DASH)
		SetupExtras:        dashboardSetupExtras(d.ResolvedConfigPath),          // cli-parity L2: status line, start at login, browser capture setup
		ComponentArtifacts: dashboardComponentArtifacts(d.ResolvedConfigPath),   // artifact_states on /api/components (T-707)
		BinaryInstall:      dashboardBinaryInstall,                              // binary_install on /api/components (U12)
		// Settings > Cloud Intelligence (org plane): the same functions
		// `observer intel` runs.
		OrgIntel: newOrgIntelDashboard(d.ResolvedConfigPath, d.OrgIntelChanged),
	}
}

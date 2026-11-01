//go:build !sbo_omit_ui_dashboard

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/intelligence/dashboard"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// newDashboardCmd wires `observer dashboard` — embedded HTML + /api/* JSON
// endpoints served on http://localhost:<port> (spec §15.6).
func newDashboardCmd() *cobra.Command {
	var (
		configPath string
		port       int
		addr       string
	)
	cmd := &cobra.Command{
		Use:   "dashboard",
		Short: "Serve the local dashboard on its own, without the daemon",
		Long: "Serves the same node dashboard `observer start` serves (every page:\n" +
			"Overview, Sessions, Cost, Tools, Security, Settings and the rest) from\n" +
			"this machine's observer database, on 127.0.0.1 by default. Use it to\n" +
			"browse captured data when the daemon is not running. It does not\n" +
			"capture: no watcher, no proxy and no org push run in this process, so\n" +
			"pages that report live capture say so. The dashboard reads its data\n" +
			"from local /api/* JSON endpoints, which a script on this machine can\n" +
			"also read.",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Match `observer start`: every child process launched by this
			// standalone dashboard must resolve the same explicit config and DB.
			// setDaemonConfigPath also absolutizes relative paths before a child
			// changes its working directory to the selected project.
			setDaemonConfigPath(configPath)

			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()

			resolvedConfigPath, _ := config.ResolveGlobalPath(configPath)
			surfaces, err := buildTerminalSurfaces(cmd.Context(), cfg, database, slog.Default(), nil)
			if err != nil {
				return err
			}
			defer surfaces.close()
			launchMgr, launchStatus, policyStop := surfaces.launchMgr, surfaces.launchStatus, surfaces.policyStop
			remoteCtrl := buildRemoteController(cfg, database)
			// Wire the §4.δ remote-execute authorizer onto the launch manager
			// (no-op + fail-closed unless BOTH the [remote] substrate and the PTY
			// launcher exist). Same assembly as `observer start`.
			wireRemoteExecuteTier(cfg, launchMgr, remoteCtrl)
			// Admin-controlled Plane B: this command runs no policy poller,
			// so it installs the node.governance family from its verified
			// on-disk LKG cache. Without this, `observer dashboard` would be
			// an ungoverned surface a governed developer could just run
			// instead of `observer start`.
			govStore := store.New(database)
			ngov := newNodeGovernanceHandle(governanceIdentityLoader(govStore), slog.Default())
			loadNodeGovernanceLKG(cmd.Context(), cfg, govStore, ngov, slog.Default())
			processArchive, closeArchive := openProcessArchiveReader(cmd.Context(), cfg)
			defer closeArchive()
			// Projects-page ROI + commit-alignment arc (docs/plans/
			// projects-page-roi-and-commit-alignment-plan-2026-09-21.md
			// §4 W3) — same wiring as `observer start`.
			projectsJudgeGrade, projectsJudgeGradeReason := projectsDashboardOptions(&cfg)
			// D-MU1: the Connected-tools catalog reads every adapter's
			// WatchPaths before the listener binds; discovery walks run in
			// the background, as in `observer start`.
			configureAdapterDiscovery(cmd.Context(), cfg, componentSnapshotForConfig(cfg).AdapterActive)
			server, err := dashboard.New(withInstallSignals(dashapi.Options{
				ProcessArchive: processArchive,
				Governance:     ngov.Effective,
				DB:             database,
				DBPath:         cfg.Observer.DBPath,
				CostEngine:     acquireProcessCostEngine(cmd.Context(), cfg, database, slog.Default()),
				// Production read caches: page loads fan several spend panels out at
				// once and share one row read; watcher health is served SWR
				// (optimization review 2026-09-27, findings N4/N5).
				ReadCaches:             true,
				Predict:                cfg.Predict,
				Scoring:                cfg.Intelligence.Scoring,
				CacheWarm:              cfg.CacheWarm,
				Tasks:                  cfg.Tasks,
				Projects:               cfg.Projects,
				Plans:                  newPlansService(cfg, database, slog.Default()),
				CloudGradeAvailability: CommitAlignmentAvailability,
				JudgeGrade:             projectsJudgeGrade,
				JudgeGradeReason:       projectsJudgeGradeReason,
				// Projects page "Rescan now" (commitscan_wire.go): the daemon's own
				// commit scanner, nil when [projects].commit_scan is off.
				CommitRescan: commitRescanWithDelivery(cfg, database),
				// Package checks card (security_deps_dash.go): the install
				// gate's state and the dashboard accept of its disclosure.
				PackageChecks: packageChecksDash(resolvedConfigPath, database),
				// Scanners card (security_scan_dash.go): the OSV database
				// download's one-time accept (PT-19).
				ScannerDB: scannerDBDash(resolvedConfigPath, database),
				// SARIF upload (security_sarifimport.go): one file the
				// developer picked, through the CLI's own import (lane SEC-P4).
				SARIFImport: sarifImportDash(database),
				// Code rules card (security_opengrep_dash.go): the guided
				// install with its size consent (lane SEC-G2).
				Opengrep: opengrepDash(resolvedConfigPath, database),
				IaC:      iacDash(resolvedConfigPath, database),
				// AI change records card (security_provenance_cmd.go, lane sec-f2a).
				Provenance: provenanceDash(resolvedConfigPath, database),
				// The one security opt-in rule (security_optin.go): the
				// components state's security_selected (which Settings rows and
				// the Explain button show), and the trust, git hooks and
				// scanner routes.
				SecuritySelected: securitySelected,
				// The Components page's view with the modules' own rules
				// (components_gate.go), so a removed sandbox root reads as off there
				// as in `observer components status` (P-057).
				ComponentStateView: componentStateView,
				// The launch row's Observer-entry test (launch_trust_own.go), so
				// the New Terminal trust chip leaves out what the launch leaves out.
				RepoTrustOwn: repoTrustDashboardOwn,
				// The launch row's conditional rows (trust_conditions.go), so the
				// review lists N2's initializeCommand row as the launch reads it.
				RepoTrustPaths: repoTrustDashboardPaths(resolvedConfigPath),
				// The Findings tab's Explain (security.feedback, lane sec-h).
				SecurityExplain: securityExplainDash(resolvedConfigPath, database),
				// The affected-worker notice (security_orgnotice_dash.go, lane SEC-E3).
				SecurityOrgShare: securityOrgShareDash(cfg.OrgClient.Share.Security),
				// Delivery (delivery_wire.go, D-689): the [delivery] tunables and the
				// one process-wide delivery service the poll loop also runs.
				Delivery:        cfg.Delivery,
				DeliveryService: deliveryDashOption(cfg, database),
				// LOC editor endpoint credential — same resolution as
				// `observer start`, so a developer running the dashboard
				// standalone gets the identical posture.
				LocEditorToken:         resolveLocEditorToken(locEditorTokenPath(cfg), slog.Default()),
				LocEditorTokenRequired: cfg.Loc.EditorTokenRequired,
				Dashboard:              cfg.Dashboard,
				MonthlyBudgetUSD:       cfg.Intelligence.MonthlyBudgetUSD,
				ConfigPath:             resolvedConfigPath,
				RecognizesSessionFile:  recognizesSessionFile(),
				CursorSemanticsFor:     cursorSemanticsFor(),
				StashDir:               cfg.Compression.Conversation.Stash.Dir,
				// Cloud account seam (cloudaccount_wire.go): local sign-in probe +
				// `observer cloud login|logout` subprocess runner behind the Settings
				// → Cloud Intelligence Sign-in button. Spawns the CLI; links nothing new.
				CloudAccount:   newCloudAccountSeams(resolvedConfigPath),
				ArenaAdmission: arenaBudgetAdmissionSeam(resolvedConfigPath),
				ArenaPreflight: arenaPreflightSeam(resolvedConfigPath),
				// OSH-R-005: may an Arena drive skip the harness's permission checks.
				ArenaPermissionBypass: arenaPermissionBypassSeam(resolvedConfigPath),
				GuardEnabled:          cfg.Guard.Enabled,
				GuardMode:             cfg.Guard.Mode,
				GuardStrict:           cfg.Guard.Strict,
				GuardHookFailure:      guardHookFailureSeam(configPath),
				GuardToolGates:        guardToolGatesSeam(configPath, surfaces.sandboxProber),
				ToolCatalog:           toolCatalog(),
				// Connected tools hooks probe: the daemon's own
				// auto-registration options (T-376).
				HookRegistryOptions: hookProbeOptionsSeam(configPath),
				// Connected tools per-tool "Run checks" (T-421 item 3): the
				// same report builder `observer doctor <tool>` prints.
				ToolDoctor: dashboardToolDoctor(configPath),
				Version:    version,
				// Session handoff (docs/session-handoff.md P2): the shared
				// handoffsvc runner behind /api/session/<id>/handoff*.
				BuildHandoff: handoffRunner(cfg, database),
				// P6.7: demo mode — temp DB seeded from embedded
				// fixtures; never touches the real observer.db.
				DemoSeeder: demoSeeder(slog.Default()),
				// Embedded web-terminal launcher (docs/session-handoff.md
				// launch section). Nil when [handoff].allow_dashboard_launch
				// is false → the endpoints 503 and the button hides.
				LaunchManager:  launchMgr,
				TerminalStatus: launchStatus,
				// Node-intervention policy-stop explanation (policystop.go).
				// Nil unless the launch manager is also wired — a policy stop
				// only ever concerns a dashboard-launched PTY run.
				PolicyStop: policyStop,
				// B9 sandboxed terminals: the availability probe behind
				// GET /api/terminal/sandbox + the fail-closed launch validation.
				// Nil unless [terminal.sandbox].enabled → endpoint reports
				// disabled and a sandbox request 501s (fail closed).
				SandboxProber: surfaces.sandboxProber,
				// The New Terminal "project policy" line (lane sec-p2b): reads the
				// project match record; shown only when the node holds a project delivery.
				ProjectPolicy: terminalProjectPolicySeam(cfg, store.New(database)),
				// Tool-binary-resolution seams (tool-binary-resolution arc §5):
				// pre-launch verdict + guided install. Defined as plain funcs so
				// the dashboard package never imports internal/toolresolve.
				ToolPreflight:    toolPreflightSeam(resolvedConfigPath, allowToolInstallSeam(resolvedConfigPath)),
				AllowToolInstall: allowToolInstallSeam(resolvedConfigPath),
				ToolInstallHint:  toolInstallHintSeam(),
				// Refuse a guided install whose grounded prerequisites
				// (unzip, bzip2, ...) are missing, with the fix.
				ToolInstallBlocked: toolInstallBlockedSeam(),
				// The record of guided installs this dashboard ran + the
				// matching uninstall (tool_installs, agent migration 149).
				ToolInstalls: surfaces.toolInstalls,
				// Command wrapping (backlog item 7): the one shim / start-up-file
				// applier, behind the Settings -> Terminal card.
				ShellWrap: newShellWrapService(resolvedConfigPath, dashResolveEnv),
				// Windows-home init (T-421 item 4), WSL only.
				WindowsHomes: newWindowsHomeService(resolvedConfigPath, cfg.Proxy.Port),
				// Settings > Enrolment management; no push loop runs in this
				// process, so an enrolment's outcome says a daemon start is needed.
				EnrolManager: enrolManagerFor(resolvedConfigPath, false, ngov),
				// Settings > Components and the route guard (modular packaging
				// P1, lane MP-DASH): the same service `observer start` wires.
				Components:         dashboardComponents(resolvedConfigPath, database),
				ComponentArtifacts: dashboardComponentArtifacts(resolvedConfigPath), // artifact_states (T-707)
				BinaryInstall:      dashboardBinaryInstall,                          // binary_install (U12)
				// Settings > Cloud Intelligence (org plane): `observer intel` behind
				// the consent screen; the same functions the CLI runs.
				OrgIntel: newOrgIntelDashboard(resolvedConfigPath, nil),
				// Re-pricing stored costs (PRICE-REPRICE-1): the one plan/apply/
				// revert service `observer reprice` also uses, behind the Settings card.
				Reprice: newRepriceService(cmd.Context(), cfg, database, slog.Default(), ngov.Effective),
				// New Terminal model picker (B5): same seam `observer start`
				// wires — recent token_usage history + registry Known examples.
				RecentModels: recentModelsSeam(database),
				// Per-terminal project panel (Arc A): token→root resolver from
				// termsvc. Nil when the launch manager is absent → panel 404s.
				ProjectRootResolver: projectRootResolver(launchMgr),
				// Per-terminal session cockpit (Session Cockpit): token→run/
				// session-link resolver from termsvc. Nil when the launch
				// manager is absent → cockpit 404s.
				SessionResolver: sessionResolver(launchMgr),
				// Remote-access substrate (plan §4). Nil unless [remote] is
				// enabled AND a pairing secret is provisioned — so a
				// non-loopback bind stays fail-closed until Phase 2 exposure.
				Remote:      remoteCtrl,
				RemoteAudit: remoteAuditSink(database),
			}))
			if err != nil {
				return err
			}
			// Standing-takeover provenance hook — same wiring as `observer
			// start`, so the [remote].revoke_standing_on_takeover opt-in works
			// under the standalone dashboard too (review MED: it previously
			// silently never fired here while the UI claimed it was live).
			if surfaces.mgr != nil {
				surfaces.mgr.SetOnStandingLocalTakeover(server.OnStandingLocalTakeover)
			}
			// Durable-listen-address precedence (issue #8): the explicit
			// --addr flag wins, then --port, then OBSERVER_DASHBOARD_ADDR env,
			// then [dashboard].addr config, then the built-in default. Use the
			// cobra Changed check so an unset flag doesn't mask env/config.
			flagAddr := ""
			switch {
			case cmd.Flags().Changed("addr"):
				flagAddr = addr
			case cmd.Flags().Changed("port"):
				flagAddr = fmt.Sprintf("127.0.0.1:%d", port)
			}
			listen := resolveDashboardAddr(flagAddr, cfg.Dashboard.Addr, fmt.Sprintf("127.0.0.1:%d", port))
			// Fail closed on a non-loopback bind (plan §4.6): remote exposure
			// requires the [remote] security substrate, not yet wired here, so
			// `--addr 0.0.0.0:8080` refuses with a clear message rather than
			// exposing an unauthenticated surface. No RemoteController is wired
			// in this path (pre-Phase-2), so pass nil.
			// D-514 / D-516: never refuse; bind loopback and say why once.
			listen = feasibleDashboardAddr(listen, remoteCtrl, cmd.ErrOrStderr())
			noteDashboardListen(listen)
			ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer cancel()
			// Same default-off, loopback-only profiling knob as `observer
			// start` (pprof.go), so a standalone dashboard can be profiled
			// against a copy of the DB without touching a live daemon.
			maybeServePprof(ctx, os.Getenv(pprofEnvVar), cmd.OutOrStdout(), cmd.ErrOrStderr())
			fmt.Fprintf(cmd.OutOrStdout(),
				"dashboard listening on http://%s - ctrl-c to stop\n", listen)
			// Phase 2 (plan §4.4): when [remote] is armed in tailscale mode,
			// also serve the dedicated loopback tailnet-serve backend (auth for
			// every request) alongside the owner-trusted direct listener. Errors
			// on the backend goroutine are best-effort logged, never fatal to
			// the local dashboard.
			if remoteCtrl != nil && remoteCtrl.Ready() &&
				strings.EqualFold(strings.TrimSpace(cfg.Remote.Mode), "tailscale") &&
				strings.TrimSpace(cfg.Remote.TailscaleBackendAddr) != "" {
				backendAddr := strings.TrimSpace(cfg.Remote.TailscaleBackendAddr)
				fmt.Fprintf(cmd.OutOrStdout(),
					"remote (tailnet backend) listening on %s (loopback; via `tailscale serve`)\n", backendAddr)
				go func() {
					if err := server.ListenAndServeTailnetBackend(ctx, backendAddr); err != nil && !errors.Is(err, context.Canceled) {
						slog.Default().Warn("remote tailnet backend stopped", "err", err)
					}
				}()
			}
			if err := server.ListenAndServe(ctx, listen); err != nil && !errors.Is(err, context.Canceled) {
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().IntVar(&port, "port", 8080, "Port to listen on (ignored if --addr is set)")
	cmd.Flags().StringVar(&addr, "addr", "", "Listen address (e.g. 127.0.0.1:8080)")
	return cmd
}

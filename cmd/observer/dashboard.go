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
		Short: "Serve the local analytics dashboard (embedded HTML + /api/* JSON)",
		Long: "Runs a single-file HTML dashboard served by net/http against the\n" +
			"observer DB. Endpoints: /api/status, /api/cost, /api/sessions,\n" +
			"/api/discover, /api/patterns. Content-Type-agnostic clients (e.g.\n" +
			"curl) can consume the /api/* JSON directly.",
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
			server, err := dashboard.New(dashboard.Options{
				ProcessArchive: processArchive,
				Governance:     ngov.Effective,
				DB:             database,
				DBPath:         cfg.Observer.DBPath,
				CostEngine:     acquireProcessCostEngine(cmd.Context(), cfg, database, slog.Default()),
				Predict:        cfg.Predict,
				CacheWarm:      cfg.CacheWarm,
				Tasks:          cfg.Tasks,
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
				GuardEnabled:   cfg.Guard.Enabled,
				GuardMode:      cfg.Guard.Mode,
				GuardStrict:    cfg.Guard.Strict,
				ToolCatalog:    toolCatalog(),
				Version:        version,
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
				// Tool-binary-resolution seams (tool-binary-resolution arc §5):
				// pre-launch verdict + guided install. Defined as plain funcs so
				// the dashboard package never imports internal/toolresolve.
				ToolPreflight:    toolPreflightSeam(resolvedConfigPath, allowToolInstallSeam(resolvedConfigPath)),
				AllowToolInstall: allowToolInstallSeam(resolvedConfigPath),
				ToolInstallHint:  toolInstallHintSeam(),
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
			})
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
			if err := dashboard.CheckRemoteBind(listen, remoteCtrl); err != nil {
				return err
			}
			ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer cancel()
			fmt.Fprintf(cmd.OutOrStdout(),
				"dashboard listening on http://%s — ctrl-c to stop\n", listen)
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

// resolveDashboardAddr applies the durable dashboard listen-address precedence
// (issue #8): an explicit flag override wins, then the OBSERVER_DASHBOARD_ADDR
// environment variable, then [dashboard].addr from config, then the caller's
// built-in default. flagVal must be non-empty ONLY when the caller's address
// flag was actually set (checked via cobra's Flags().Changed) — an unset flag
// must fall through to the env/config layers rather than mask them. A
// MALFORMED env value is IGNORED (falls through to config/default), matching
// config.Load's silent-drop of the same env var, so a bad env value can never
// produce a garbage bind addr or shadow a valid config value. The resolved
// address is still subject to dashboard.CheckRemoteBind, so a non-loopback
// value does not bypass the remote-exposure guard.
func resolveDashboardAddr(flagVal, configAddr, defaultAddr string) string {
	if v := strings.TrimSpace(flagVal); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("OBSERVER_DASHBOARD_ADDR")); v != "" && config.ValidateDashboardAddr(v) == nil {
		return v
	}
	if v := strings.TrimSpace(configAddr); v != "" {
		return v
	}
	return defaultAddr
}

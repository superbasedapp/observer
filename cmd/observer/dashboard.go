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
			launchMgr := surfaces.launchMgr
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
			// D-MU1: the Connected-tools catalog reads every adapter's
			// WatchPaths before the listener binds; discovery walks run in
			// the background, as in `observer start`.
			configureAdapterDiscovery(cmd.Context(), cfg, componentSnapshotForConfig(cfg).AdapterActive)
			// The one construction `observer start` also uses
			// (dashboard_options.go, CMD-01), so the two dashboards serve
			// the same pages; this process adds nothing of its own (no
			// watcher, proxy, push loop or restart runs here).
			server, err := dashboard.New(withInstallSignals(nodeDashboardOptions(nodeDashboardDeps{
				Ctx: cmd.Context(), Cfg: cfg, ConfigPath: configPath, ResolvedConfigPath: resolvedConfigPath,
				DB: database, Surfaces: surfaces, Remote: remoteCtrl, Governance: ngov,
				ProcessArchive: processArchive,
				// No loops run here, so fresh services, not the daemon's.
				Plans:       newPlansService(cfg, database, slog.Default()),
				CloudAgents: newCloudAgentsService(cfg, database, slog.Default()),
				// No push loop runs in this process, so an enrolment's
				// outcome says a daemon start is needed.
				EnrolManager: enrolManagerFor(resolvedConfigPath, false, ngov),
			})))
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
			// A standalone dashboard records its address beside the
			// database too (its own per-process file, never the daemon's),
			// so a sandboxed CLI launch's Landlock plan denies its port
			// (cli-1b fixes-4; terminal_sandbox_landlock.go).
			if removeRecord, rerr := writeStandaloneDashboardListenRecord(cfg.Observer.DBPath, listen); rerr == nil {
				defer removeRecord()
			} else {
				slog.Default().Warn("dashboard: could not record the listen address", "err", rerr)
			}
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

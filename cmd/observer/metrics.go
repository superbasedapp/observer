package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/metrics"
)

// newMetricsCmd wires `observer metrics` — a long-running HTTP server that
// exposes `/metrics` in Prometheus text format (spec §25 — Prometheus
// metrics export). Mirrors the shape of `observer dashboard`.
func newMetricsCmd() *cobra.Command {
	var (
		configPath string
		port       int
		addr       string
		window     int
	)
	cmd := &cobra.Command{
		Use:   "metrics",
		Short: "Serve Prometheus /metrics on http://localhost:<port>",
		Long: "Renders observer state as Prometheus text exposition derived from\n" +
			"diag.Snapshot, cost.Engine.Summary, and the session_pid_bridge table.\n" +
			"Scrape target: `http://<addr>/metrics`. Default listen address is\n" +
			"127.0.0.1:9090. The cost rollup window defaults to 5 minutes and is\n" +
			"reported via the `window` label on cost / token / compression series.",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()

			server, err := metrics.New(metrics.Options{
				DB:                database,
				DBPath:            cfg.Observer.DBPath,
				CostEngine:        acquireProcessCostEngine(cmd.Context(), cfg, database, slog.Default()),
				CostWindowMinutes: window,
			})
			if err != nil {
				return err
			}
			listen := addr
			if listen == "" {
				listen = fmt.Sprintf("127.0.0.1:%d", port)
			}
			ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer cancel()
			fmt.Fprintf(cmd.OutOrStdout(),
				"metrics listening on http://%s/metrics — ctrl-c to stop\n", listen)
			if err := server.ListenAndServe(ctx, listen); err != nil && !errors.Is(err, context.Canceled) {
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().IntVar(&port, "port", 9090, "Port to listen on (ignored if --addr is set)")
	cmd.Flags().StringVar(&addr, "addr", "", "Listen address (e.g. 127.0.0.1:9090)")
	cmd.Flags().IntVar(&window, "window-minutes", 5, "Cost rollup window in minutes (appears as the `window` label)")
	return cmd
}

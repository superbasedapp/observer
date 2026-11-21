package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudmetrics"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudmetricshttp"
)

// startMetricsListener is the serve and worker processes' optional
// Prometheus listener (FR-4 follow-up; docs/saas-monitoring.md "Cloud
// metrics"). SBCI_METRICS_LISTEN empty (the default) opens nothing and
// returns a nil registry, so every counter call is a no-op. Otherwise it
// validates the address (never the public listen address; a malformed value
// refuses to start), binds it now, and serves GET /metrics from a fresh
// registry of the process until ctx ends. The deploy kit's port contract:
// cloud-api 9470, cloud-worker 9471, published on the monitoring address.
func startMetricsListener(ctx context.Context, log *slog.Logger, getenv func(string) string, p cloudmetrics.Process, publicListen string) (*cloudmetrics.Registry, error) {
	listen, err := cloudmetricshttp.ParseListen(getenv(cloudmetricshttp.EnvListen), publicListen)
	if err != nil {
		return nil, err
	}
	if listen == "" {
		log.Info("observer-cloud: metrics listener off (" + cloudmetricshttp.EnvListen + " unset)")
		return nil, nil
	}
	reg := cloudmetrics.New(p)
	if err := cloudmetricshttp.Start(ctx, cloudmetricshttp.NewServer(listen, reg), func(err error) {
		log.Error("observer-cloud: metrics listener stopped", "err", err)
	}); err != nil {
		return nil, err
	}
	log.Info("observer-cloud: metrics listener", "addr", listen, "path", cloudmetricshttp.Path, "process", string(p))
	return reg, nil
}

// metricsGetenv is os.Getenv; a variable so tests can swap it.
var metricsGetenv = os.Getenv

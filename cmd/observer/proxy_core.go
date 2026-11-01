package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"

	"github.com/marmutapp/superbased-observer/internal/cachetrack"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// proxy_core.go is the core view of the API proxy (lane MP-L1L, T-715): what
// `observer start`, `observer proxy start` and the benchmark harness need from
// buildProxy, in types that do not name internal/proxy. proxy.go builds the
// real proxy; proxy_omit.go (-tags sbo_omit_capture_proxy) builds the inert
// stand-in, so a build without capture.proxy starts with the proxy off and
// one reason (D-514) instead of failing to compile or refusing to start.

// daemonProxy is the part of *proxy.Proxy the callers of buildProxy use: the
// gateway.providers lane-table seam, the shared cache engine and the
// listener (and its handler, which the in-process integration tests serve).
type daemonProxy interface {
	SetLaneTable(upstreams map[string]string, autoDefaultLane string) error
	LaneTable() (upstreams map[string]string, autoDefaultLane string)
	// SetRouteLanes / ResolvableLanes are the node-local route-lane seam of
	// managed route maintenance (route_maintenance.go, lane P1).
	SetRouteLanes(lanes map[string]string) error
	ResolvableLanes() map[string]bool
	SetRoutingSnapshotWithFallback(upstreams map[string]string, autoDefaultLane, mode, primary string, fallbacks []string, terminal string, custodyAck bool) error
	CacheEngine() *cachetrack.Engine
	Handler() http.Handler
	ListenAndServe(ctx context.Context, addr string) error
}

// proxyWiring is everything buildProxy hands its caller (plan section 9 hot
// spot 4, lane MP-ADP): one struct instead of an eight-value return, so a
// component's wiring can add a field without touching every call site, and
// a caller names only what it uses. The zero value is what an error returns.
type proxyWiring struct {
	// Proxy is the constructed proxy, ready to ListenAndServe.
	Proxy daemonProxy
	// Cleanup releases the self-obs sink and closes the database.
	Cleanup func()
	// Addr is the resolved listen address.
	Addr string
	// ProfilesReload is the compression-profiles hot-reload hook (nil when
	// conversation compression is off at boot).
	ProfilesReload func()
	// RoutingDemotions is the live router's demotion accessor (nil when
	// routing is not wired).
	RoutingDemotions func() map[string]string
	// Admission carries the one admission service (nil when admission is
	// off).
	Admission *obsAdmissionHandle
	// Routing is the routing state handle (nil when routing is not wired).
	Routing *RoutingStateHandle
}

// buildCacheTrackEngine builds the cache-observation engine (spec §8 / §11)
// and hands it to the store so Tier-2 (watcher / backfill) observations
// advance the shared CacheModel state (§24.4: single engine, multiple feed
// paths). buildProxy also binds it as the proxy's Tier-1 feed; a build
// without capture.proxy keeps the Tier-2 feed, so transcript-only sessions
// still show their cache status (lane MP-L1L, T-715). Returns nil (with a log
// line) when [cachetrack] is disabled.
func buildCacheTrackEngine(cfg config.Config, s *store.Store, logger *slog.Logger) *cachetrack.Engine {
	if !cfg.CacheTrack.Enabled {
		logger.Info("cachetrack: disabled by config")
		return nil
	}
	// Install the PUBLISHED min-cacheable prefixes before the engine starts
	// observing, so the very first turn is graded against the same thresholds
	// every later one will be (mincacheable_wire.go). No-op when neither the
	// embedded snapshot nor a node-local feed names a model.
	applyMinCacheableOverrides(context.Background(), s, logger)
	engine := cachetrack.NewEngine(cfg.CacheTrack.MaxTrackedSessions)
	// C10 wiring: hand the SAME engine instance to the store so Tier-2
	// (watcher / backfill) observations advance the shared CacheModel state.
	// CacheEventExistsForMessage is the cross-tier dedup so a Tier-1 message
	// can't be double-observed by Tier-2.
	s.SetCacheEngine(engine)
	logger.Info("cachetrack: engine wired", "max_tracked_sessions", cfg.CacheTrack.MaxTrackedSessions)
	path := cfg.CacheTrack.CalibrateLogPath
	if path == "" {
		return engine
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		logger.Warn("cachetrack: calibrate log path open failed", "path", path, "err", err)
		return engine
	}
	engine.EnableCalibrateSink(f)
	logger.Info("cachetrack: calibrate sidecar wired",
		"path", path, "cap_blocks", cachetrack.CalibrateBlockCap)
	// File handle leaks until process exit, intentionally; the sidecar is a
	// soak-time diagnostic, not a steady-state surface. Auto-stop trips after
	// CalibrateBlockCap writes; the operator unsets the config and restarts.
	return engine
}

//go:build sbo_omit_capture_proxy

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/cachetrack"
	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/selfobs/emit"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// proxy_omit.go stands in for proxy.go, proxy_profiles.go,
// gateway_route_wire.go and the proxy halves of the guard, MCP relay, obs
// and routing wiring in a build without capture.proxy (-tags
// sbo_omit_capture_proxy, lane MP-L1L, T-715, ruling D-518): internal/proxy
// is not linked, and neither are its compression, routing, guard-scan, MCP
// tools[] and limit-sink seams.
//
// Operator rule D-514: a [proxy] block this build cannot honour never stops
// `observer start`. buildProxy still opens the DB and builds what the rest of
// the daemon shares through it (the cache engine for transcript ingest, the
// MCP relay handle, the admission service for the org policy rail), but
// nothing listens on the proxy port: the gated "proxy" loop is skipped with
// the one reason ("capture.proxy is not in this build; ..."), the start
// banner says the proxy is inactive, `observer proxy` answers "not in this
// build" (exit 3), and a launcher says so instead of routing a tool at a
// dead port (launch_proxy_feasible.go).
func init() { components.MarkOmitted("capture.proxy") }

// newProxyCmd registers `observer proxy` as a compiled-out verb.
func newProxyCmd() *cobra.Command {
	return compiledOutVerb("proxy", "API reverse proxy (not in this build)", "capture.proxy")
}

// errProxyNotInBuild is what the inert proxy's listener answers, so a caller
// that tries to serve it (the benchmark harness) fails with the reason.
var errProxyNotInBuild = errors.New("the API proxy (capture.proxy) is not in this build; " + components.DistrosHaving("capture.proxy"))

// inertProxy is the stand-in daemonProxy: no lanes to set, the shared cache
// engine (nil when [cachetrack] is off), and a listener that refuses.
type inertProxy struct{ engine *cachetrack.Engine }

// SetLaneTable accepts and drops an org lane table: there is no proxy to
// route.
func (inertProxy) SetLaneTable(map[string]string, string) error { return nil }

// LaneTable reports no lanes.
func (inertProxy) LaneTable() (map[string]string, string) { return nil, "" }

// SetRouteLanes accepts and drops route lanes (there is no proxy to route).
func (inertProxy) SetRouteLanes(map[string]string) error { return nil }

// ResolvableLanes reports no lane: nothing resolves without a proxy.
func (inertProxy) ResolvableLanes() map[string]bool { return nil }

// SetRoutingSnapshotWithFallback accepts and drops a routing snapshot.
func (inertProxy) SetRoutingSnapshotWithFallback(map[string]string, string, string, string, []string, string, bool) error {
	return nil
}

// CacheEngine is the engine the watcher's store shares.
func (p inertProxy) CacheEngine() *cachetrack.Engine { return p.engine }

// Handler answers every request 501 with the reason.
func (inertProxy) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, errProxyNotInBuild.Error(), http.StatusNotImplemented)
	})
}

// ListenAndServe binds nothing and names the build.
func (inertProxy) ListenAndServe(context.Context, string) error { return errProxyNotInBuild }

// buildProxy builds the proxy-free part of the daemon assembly. recipeName is
// ignored: the deprecated `--recipe` alias only names compression profiles,
// which need the proxy.
func buildProxy(ctx context.Context, configPath, _ string, portOverride int, bindAddr string, relay orgJudgeRelayFunc) (proxyWiring, error) {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		return proxyWiring{}, fmt.Errorf("load config: %w", err)
	}
	cfg = applyProxyComponentGate(cfg)
	if err := os.MkdirAll(filepath.Dir(cfg.Observer.DBPath), 0o755); err != nil {
		return proxyWiring{}, fmt.Errorf("ensure db dir: %w", err)
	}
	database, err := db.Open(ctx, db.Options{Path: cfg.Observer.DBPath})
	if err != nil {
		return proxyWiring{}, fmt.Errorf("open db %s: %w", cfg.Observer.DBPath, err)
	}
	s := store.New(database)
	logger := newLogger(cfg.Observer.LogLevel)
	port := cfg.Proxy.Port
	if portOverride > 0 {
		port = portOverride
	}
	if port <= 0 || port > 65535 {
		// D-516: nothing binds the port in this build.
		port = config.Default().Proxy.Port
	}
	engine := buildCacheTrackEngine(cfg, s, logger)
	// The per-process Guard the watcher store shares, acquired first so the
	// MCP relay binds its access lookup on the same instance (as buildProxy
	// does in a build with the proxy).
	acquireProcessGuard(ctx, cfg, s, logger)
	wireMCPRelay(cfg, s, nil, lookupProcessGuard(cfg.Observer.DBPath), logger)
	admissionHandle := wireAdmission(ctx, cfg, database, relay, logger, emit.Nop())
	// The org prompt judge's node lane has no proxy seam in this build, but
	// the hook lane (lane adm-2) still judges every prompt-gate tool through
	// it, so bind the engine, the org relay and the audit writer here too.
	configurePlaneBNodeLane(relay, s, logger)
	return proxyWiring{
		Proxy:     inertProxy{engine: engine},
		Cleanup:   func() { _ = database.Close() },
		Addr:      net.JoinHostPort(bindAddr, strconv.Itoa(port)),
		Admission: admissionHandle,
	}, nil
}

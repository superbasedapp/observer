package main

import (
	"context"
	"os"
	"strings"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/config"
)

// dashboard_addr.go is the part of the dashboard wiring every build keeps
// (lane MP-L1M, T-715): the listen-address precedence other verbs share,
// the server interface `observer start` drives, and the one note a CLI
// prints instead of a dashboard link when ui.dashboard is not in this
// build (D-514).

// daemonDashboard is the part of the dashboard server `observer start`
// drives: the loopback listener, the tailnet backend listener and the
// standing-takeover provenance hook. ui_dashboard.go builds it;
// ui_dashboard_omit.go never does.
type daemonDashboard interface {
	ListenAndServe(ctx context.Context, addr string) error
	ListenAndServeTailnetBackend(ctx context.Context, addr string) error
	OnStandingLocalTakeover(handle, revokedHolder string)
}

// resolveDashboardAddr applies the durable dashboard listen-address precedence
// (issue #8): an explicit flag override wins, then the OBSERVER_DASHBOARD_ADDR
// environment variable, then [dashboard].addr from config, then the caller's
// built-in default. flagVal must be non-empty ONLY when the caller's address
// flag was actually set (checked via cobra's Flags().Changed): an unset flag
// must fall through to the env/config layers rather than mask them. A
// MALFORMED env value is IGNORED (falls through to config/default), matching
// config.Load's silent drop of the same env var, so a bad env value can never
// produce a garbage bind addr or shadow a valid config value. The resolved
// address is still subject to checkRemoteBind, so a non-loopback value does
// not bypass the remote-exposure guard.
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

// dashboardNotInBuildNote is what a CLI says in place of a dashboard link in
// a build without the dashboard; "" when this build carries it.
func dashboardNotInBuildNote() string {
	if dashboardInBuild {
		return ""
	}
	return "the local dashboard (ui.dashboard) is not in this build; " + components.DistrosHaving("ui.dashboard")
}

// processDashboardListen is the address this process's dashboard listens on,
// once `observer start` or `observer dashboard` resolved it (a
// --dashboard-addr or --addr override included). One owner:
// noteDashboardListen writes it, resolvedDashboardListen reads it.
var processDashboardListen struct {
	mu   sync.Mutex
	addr string
}

// noteDashboardListen records the address this process's dashboard listens on.
func noteDashboardListen(addr string) {
	processDashboardListen.mu.Lock()
	defer processDashboardListen.mu.Unlock()
	processDashboardListen.addr = addr
}

// resolvedDashboardListen is the address noteDashboardListen recorded, ""
// before the dashboard's address was resolved in this process.
func resolvedDashboardListen() string {
	processDashboardListen.mu.Lock()
	defer processDashboardListen.mu.Unlock()
	return processDashboardListen.addr
}

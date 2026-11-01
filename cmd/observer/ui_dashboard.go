//go:build !sbo_omit_ui_dashboard

package main

import (
	"time"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/intelligence/dashboard"
)

// ui_dashboard.go is the constructor seam of the ui.dashboard component
// (modular packaging, lane MP-L1M, T-715). Everything cmd/observer shares
// with the dashboard is core vocabulary in internal/dashapi; the dashboard
// package itself is reached only through the functions below (and the
// `observer dashboard` verb in dashboard.go), so a build with
// -tags sbo_omit_ui_dashboard leaves it, and its embedded web app, out of
// the binary. ui_dashboard_omit.go is the twin.

// dashboardInBuild reports whether this binary carries the node dashboard.
const dashboardInBuild = true

var _ daemonDashboard = (*dashboard.Server)(nil)

// newDaemonDashboard builds the dashboard server from opts. On error it
// returns a nil interface, never a typed nil, so callers can test for nil.
func newDaemonDashboard(opts dashapi.Options) (daemonDashboard, error) {
	srv, err := dashboard.New(withInstallSignals(opts))
	if err != nil {
		return nil, err
	}
	return srv, nil
}

// setTerminalPingPolicy applies the [terminal].ws_ping_* liveness bounds to
// the dashboard's terminal websocket bridges.
func setTerminalPingPolicy(interval, timeout time.Duration, failuresAllowed int) {
	dashboard.SetTerminalPingPolicy(interval, timeout, failuresAllowed)
}

// checkRemoteBind is the dashboard's one owner of "may this address be
// exposed": a non-loopback bind needs a ready remote substrate.
func checkRemoteBind(addr string, rc dashapi.RemoteController) error {
	return dashboard.CheckRemoteBind(addr, rc)
}

// withInstallSignals wires the install-signal probe (installsignal.go) the
// Claude Code setup snapshot reads (WINNODE2 16b), unless the caller set
// one.
func withInstallSignals(opts dashapi.Options) dashapi.Options {
	if opts.InstallSignalTools == nil {
		opts.InstallSignalTools = func() []string { return installSignalToolsFor("") }
	}
	return opts
}

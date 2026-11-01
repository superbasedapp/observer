package diag

import (
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/proxyroute"
	"github.com/marmutapp/superbased-observer/internal/supervisor"
)

// checkSupervisor warns when this machine's daemon keeps AI tool routes
// through its proxy (lane P1 managed route maintenance) and no process
// supervisor was found to restart it. The routes stay in the tools' configs
// while the daemon is down, so those tools get ConnectionRefused until
// someone restarts it. A warning only: Observer never requires a supervisor.
//
// The probe is the installed-template rows only (doctor is a separate
// process, so its own environment says nothing about the daemon's).
func checkSupervisor(homeDir string, probe supervisor.Probe) Check {
	const name = "proxy.supervisor"
	if !proxyroute.ManagedRoutesMaintained(homeDir) {
		return Check{Name: name, Status: StatusOK, Message: "the daemon keeps no AI tool routes here; a supervisor is optional"}
	}
	probe.Getenv = nil
	probe.HomeDir = homeDir
	if res := supervisor.Detect(probe); res.Detected {
		return Check{Name: name, Status: StatusOK, Message: fmt.Sprintf("routes are kept through the proxy and a %s supervisor is installed (%s)", res.Mechanism, res.Evidence)}
	}
	return Check{
		Name:    name,
		Status:  StatusWarn,
		Message: "your organization keeps AI tools routed through this daemon's proxy, but no process supervisor was found",
		Details: []string{
			"while the daemon is down (a crash, a failed update, a reboot) the routed tools get ConnectionRefused",
			"to restart it automatically, " + supervisor.TemplateHint,
		},
	}
}

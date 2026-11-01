//go:build sbo_omit_integration_shell_wrap

package main

import (
	"context"
	"io"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/toolresolve"
)

// shellwrap_omit.go stands in for shellwrap.go and shellwrap_bridge.go in a
// build without the integration.shell-wrap component (-tags
// sbo_omit_integration_shell_wrap, lane MP-L1E, T-715): internal/shellwrap
// and internal/shellwrapsvc are not linked, so this binary writes no shim and
// no shell start-up block. `observer shell-wrap` answers "not in this build"
// (exit 3); remove a previous install's shims and blocks with a build that
// has the component (`observer shell-wrap disable`). Launchers still skip
// those shims: the guard is core (internal/shimguard).
func init() { components.MarkOmitted("integration.shell-wrap") }

// newShellWrapService returns no service: the dashboard routes refuse.
func newShellWrapService(string, func() toolresolve.Env) dashapi.ShellWrapService { return nil }

// newShellWrapMaintenance builds no step: this build cannot apply a wrap
// (CLI-1b).
func newShellWrapMaintenance(string, func(context.Context) govern.ShellWrapPostureVerdict, io.Writer, io.Writer) routeMaintenanceStep {
	return nil
}

// withShellWrapMaintenance is the route step alone.
func withShellWrapMaintenance(routes, _ routeMaintenanceStep) routeMaintenanceStep { return routes }

// addShellWrapPosture reports shell_wrap_missing whenever the organization
// keeps command wrapping on: this build cannot apply it (CLI-1b).
func addShellWrapPosture(_ context.Context, v govern.ShellWrapPostureVerdict, _ string, report *orgcontract.ManagedIntegrityReport) {
	if v.Posture == govern.ShellWrapPostureMaintain {
		report.CaptureRisks = appendLabel(report.CaptureRisks, orgcontract.CaptureRiskShellWrapMissing)
	}
}

// refreshShellWrapShims refreshes nothing.
func refreshShellWrapShims(context.Context, io.Writer, io.Writer, string) {}

// newShellWrapCmd registers `observer shell-wrap` as a compiled-out verb.
func newShellWrapCmd() *cobra.Command {
	return compiledOutVerb("shell-wrap", "Command wrapping shims (not in this build)", "integration.shell-wrap")
}

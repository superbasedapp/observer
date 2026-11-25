//go:build sbo_omit_org_update

package main

import (
	"context"
	"database/sql"
	"log/slog"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// update_omitted.go stands in for the update*.go wiring in a build without
// the org.update component (-tags sbo_omit_org_update, lane MP-GOV4, T-711):
// internal/update is not linked, `observer update` answers "not in this
// build" (exit 3), the dashboard's update routes answer 404
// component_not_installed through the route gate, and `observer start` wires
// no updater. The drain gate the proxy takes stays (update_core.go): nothing
// closes it here.

// updateRuntime is empty: there is no updater in this build. Every method is
// nil-safe and does nothing, so start.go's call sites are unchanged.
type updateRuntime struct{}

// updateRuntimeFor returns nil: start.go skips its post-listener update
// block on nil, and the dashboard seams below are nil (the routes belong to
// an omitted component and never reach them).
func updateRuntimeFor(config.Config, string, *store.Store, *orgclient.Client, terminalLiveCounter, *slog.Logger) *updateRuntime {
	return nil
}

// currentUpdateRuntime returns nil: there is no runtime.
func currentUpdateRuntime() *updateRuntime { return nil }

// handshakeChildNonce returns "": a build without the updater is never the
// child of an update handshake it could report to.
func handshakeChildNonce() string { return "" }

// ApplySeam returns no apply seam.
func (*updateRuntime) ApplySeam() func(context.Context, dashapi.UpdateApplyRequest) (dashapi.UpdateApplyResult, error) {
	return nil
}

// StatusSeam returns no status seam.
func (*updateRuntime) StatusSeam() func(context.Context) (dashapi.UpdateStatusResult, error) {
	return nil
}

// ExtensionVersionSeam returns no extension-version seam.
func (*updateRuntime) ExtensionVersionSeam() func(string) { return nil }

// PublishPosture publishes nothing.
func (*updateRuntime) PublishPosture() {}

// RecoverAtBoot recovers nothing.
func (*updateRuntime) RecoverAtBoot(context.Context) {}

// ReportChildSelfCheck reports nothing.
func (*updateRuntime) ReportChildSelfCheck(context.Context) {}

// AutoApplyLoop runs no loop.
func (*updateRuntime) AutoApplyLoop(context.Context) {}

// SetReleaseListeners keeps nothing: no apply ever hands the listeners over.
func (*updateRuntime) SetReleaseListeners(func()) {}

// ListenersReleased is false: no apply ever releases the listeners.
func (*updateRuntime) ListenersReleased() bool { return false }

// newUpdateCmd registers `observer update` as a compiled-out verb.
func newUpdateCmd() *cobra.Command {
	return compiledOutVerb("update", "Self-update from the org server (not in this build)", "org.update")
}

// updateHandoverDoctorChecks adds no doctor row: there is no updater in this
// build, so nothing hands over.
func updateHandoverDoctorChecks(context.Context, config.Config, *sql.DB) []diag.Check { return nil }

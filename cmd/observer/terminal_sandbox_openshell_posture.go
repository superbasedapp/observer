//go:build !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"errors"
	"io/fs"
	"os"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandboxopenshell"
)

// terminal_sandbox_openshell_posture.go connects the managed gateway's
// config read-back (lane O2's record and render) to the core posture seam
// (sandbox_gateway_posture.go, lane O4): the gateway.toml Observer wrote for
// its private gateway is compared with the digest of what that gateway was
// started with and with what this install renders now. It reads two small
// files under the row's state dir and starts nothing. In external mode
// there is no Observer-owned gateway config (decision D3), so nothing is
// recorded and nothing is reported.

func init() { sandboxGatewayDriftObserved = openShellGatewayDriftObserved }

// openShellDriftRuntimePlaceholder is passed to LayoutFor for the read-back:
// only the layout's state paths (config and record) are read, and those do
// not depend on the runtime dir, so the daemon's XDG_RUNTIME_DIR is not
// needed for it.
const openShellDriftRuntimePlaceholder = "/run/observer-openshell-drift-unused"

// openShellDriftVerdict maps the planner's drift value onto the seam's.
var openShellDriftVerdict = map[sandboxopenshell.GatewayDrift]sandboxGatewayDrift{
	sandboxopenshell.GatewayDriftNone:    sandboxGatewayDriftClean,
	sandboxopenshell.GatewayDriftMatch:   sandboxGatewayDriftClean,
	sandboxopenshell.GatewayDriftChanged: sandboxGatewayDriftChanged,
	sandboxopenshell.GatewayDriftUnknown: sandboxGatewayDriftUnknown,
}

// openShellGatewayDriftObserved is the registered read-back for the daemon
// config at configPath (its own file, no governance overlay is needed: the
// state dir is a machine path no organization sets).
func openShellGatewayDriftObserved(configPath string) sandboxGatewayDrift {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath, GovernanceSidecar: config.NoGovernanceSidecar})
	if err != nil {
		// The state dir may be a custom [terminal.sandbox.openshell].state_dir
		// this failed load cannot name; reading the default one instead would
		// find nothing there and report clean. Unknown is never clean.
		return sandboxGatewayDriftUnknown
	}
	stateDir := openShellStateDir(sandboxObserverDirFor(cfg), cfg.Terminal.Sandbox.OpenShell.StateDir)
	d, _ := sandboxopenshell.ClassifyGatewayDrift(openShellGatewayDriftFacts(stateDir, openShellRenderGatewayConfig))
	// Lane FU8 (OSH-40): the settings the private gateway keeps in its own
	// database, as the last managed probe read them, fold in.
	d = sandboxopenshell.FoldGatewayDrift(d, openShellManagedDBDrift())
	if v, ok := openShellDriftVerdict[d]; ok {
		return v
	}
	return sandboxGatewayDriftUnknown
}

// openShellGatewayDriftFacts gathers the read-back's facts from the row's
// state dir; render is what this install renders for a gateway under a
// sandbox namespace label, called with the label the recorded gateway runs
// under (sandboxopenshell.RunningSandboxLabel), so a gateway in its own
// namespace is compared with its own render.
func openShellGatewayDriftFacts(stateDir string, render openShellRenderFn) sandboxopenshell.GatewayDriftFacts {
	none := sandboxopenshell.GatewayDriftFacts{Read: sandboxopenshell.GatewayConfigMissing}
	if !openShellGatewayRecorded(stateDir) {
		return none
	}
	installID := openShellReadInstallID(stateDir)
	id, err := sandboxopenshell.IdentityFor(installID)
	if err != nil {
		// A gateway dir with no readable install id: what was started there
		// cannot be named.
		return sandboxopenshell.GatewayDriftFacts{Recorded: true, Read: sandboxopenshell.GatewayConfigUnreadable}
	}
	layout, err := sandboxopenshell.LayoutFor(stateDir, openShellDriftRuntimePlaceholder, id)
	if err != nil {
		return sandboxopenshell.GatewayDriftFacts{Recorded: true, Read: sandboxopenshell.GatewayConfigUnreadable}
	}
	var f sandboxopenshell.GatewayDriftFacts
	if _, err := os.Lstat(layout.RecordPath); err == nil {
		f.Recorded = true
	}
	if _, err := os.Lstat(layout.DBPath); err == nil {
		f.DatabasePresent = true
	}
	rec := openShellReadGatewayRecord(layout.RecordPath)
	f.RecordValid = rec != nil
	b, err := openShellReadOwned(layout.ConfigPath, 1<<20)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		f.Read = sandboxopenshell.GatewayConfigMissing
		return f
	case err != nil:
		f.Read = sandboxopenshell.GatewayConfigUnreadable
		return f
	}
	f.Read = sandboxopenshell.GatewayConfigReadOK
	if rec != nil {
		f.MatchesRecord = sandboxopenshell.GatewayConfigDigest(string(b), rec.DockerHost) == rec.ConfigDigest
	}
	label := sandboxopenshell.RunningSandboxLabel(id.Name, rec, openShellRecordDigestFor(id, rec, render))
	recVersion := ""
	if rec != nil {
		recVersion = rec.Version
	}
	if want, err := render(id, label, recVersion); err == nil {
		f.MatchesWanted = string(b) == want
	}
	return f
}

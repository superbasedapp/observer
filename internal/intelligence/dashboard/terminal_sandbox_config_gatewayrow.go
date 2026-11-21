package dashboard

import (
	"strings"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// terminal_sandbox_config_gatewayrow.go is the Settings card's editor for
// [terminal.sandbox.openshell] (lanes O1A and O2; the panel is lane O4's),
// the one dashboard file allowed to name the block
// (tests/invariant/openshell_boundary_test.go): the payload is embedded in
// terminalSandboxConfigPayload, so its key sits at the top of the JSON body
// beside the other sandbox keys. The block names this machine's own gateway
// and files only; Observer never writes the user's own OpenShell gateway
// config from it (decision D3). The whole block is checked by the one
// config validation on save (validateTerminalSandboxOpenShell).

// terminalSandboxGatewayRowPayload carries the block, a pointer so a
// client that predates it (and so omits it) keeps the saved values.
type terminalSandboxGatewayRowPayload struct {
	OpenShell *terminalSandboxOpenShellPayload `json:"openshell,omitempty"`
}

// terminalSandboxOpenShellPayload is the dashboard shape of
// [terminal.sandbox.openshell].
type terminalSandboxOpenShellPayload struct {
	GatewayMode string `json:"gateway_mode"`
	Endpoint    string `json:"endpoint"`
	Version     string `json:"version"`
	StateDir    string `json:"state_dir"`
}

// gatewayRowPayloadFor is the GET shape of the block.
func gatewayRowPayloadFor(c config.TerminalSandboxConfig) terminalSandboxGatewayRowPayload {
	o := c.OpenShell
	return terminalSandboxGatewayRowPayload{OpenShell: &terminalSandboxOpenShellPayload{
		GatewayMode: o.GatewayMode, Endpoint: o.Endpoint, Version: o.Version, StateDir: o.StateDir,
	}}
}

// applyTo writes a sent block into next, trimmed.
func (p terminalSandboxGatewayRowPayload) applyTo(next *config.TerminalSandboxConfig) {
	if p.OpenShell == nil {
		return
	}
	next.OpenShell = config.TerminalSandboxOpenShellConfig{
		GatewayMode: strings.TrimSpace(p.OpenShell.GatewayMode),
		Endpoint:    strings.TrimSpace(p.OpenShell.Endpoint),
		Version:     strings.TrimSpace(p.OpenShell.Version),
		StateDir:    strings.TrimSpace(p.OpenShell.StateDir),
	}
}

// keepUnsent puts the saved block back when the save did not send one.
func (p terminalSandboxGatewayRowPayload) keepUnsent(next *config.TerminalSandboxConfig, saved config.TerminalSandboxConfig) {
	if p.OpenShell == nil {
		next.OpenShell = saved.OpenShell
	}
}

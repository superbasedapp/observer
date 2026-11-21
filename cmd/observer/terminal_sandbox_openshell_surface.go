//go:build !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxopenshell"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// terminal_sandbox_openshell_surface.go is lane O4's part of the openshell
// driver: the probe fields the dashboard shows and the gateway_modes floor
// judges. The gateway mode is reported even while the row is not listed
// (nothing runs to read it: it is the config's effective mode), so the
// picker and the Settings card can say what the row would do before its
// first use.

// openShellModeVocab maps the config's effective gateway mode onto the
// closed posture vocabulary.
var openShellModeVocab = map[string]vocab.GatewayMode{
	config.OpenShellGatewayManaged:  vocab.GatewayManagedLocal,
	config.OpenShellGatewayExternal: vocab.GatewayExternal,
}

// openShellPrerequisite is decision D4's prerequisite (OB-040), said
// plainly: the probe's own hint names which of them this host has once the
// gateway's driver is read (row P6).
const openShellPrerequisite = "Needs Docker Engine through the docker group, which is root-equivalent on this machine (anyone in it can act as root); rootless Podman 5 is preferred where available, but it is not measured yet, so the probe refuses it (row P6)."

// openShellSurface adds the dashboard fields to a probe answer.
func openShellSurface(p sandboxselect.Probe, cfg config.TerminalSandboxOpenShellConfig) sandboxselect.Probe {
	p.GatewayMode = openShellModeVocab[cfg.EffectiveGatewayMode()]
	p.Prerequisite = openShellPrerequisite
	p.VersionPins = openShellVersionPins()
	return p
}

// openShellDisclosureRows are the row's disclosure sentences per gateway
// mode (decision D3, OB-040): Observer owns its managed gateway's config and
// never writes the user's own.
var openShellDisclosureRows = []sandboxDisclosureRow{
	{
		sandboxbackend.DiscloseGatewayBindMounts, vocab.GatewayManagedLocal,
		"Observer turns on OpenShell's gateway-wide bind-mount opt-in (allow_driver_config and enable_bind_mounts) on its own private gateway only, whose config it owns and writes; that gateway runs only Observer's sandboxes. Your own OpenShell gateway and its gateway.toml are never read or written.",
	},
	{
		sandboxbackend.DiscloseGatewayBindMounts, vocab.GatewayExternal,
		"Your OpenShell gateway must allow driver config and bind mounts (allow_driver_config and enable_bind_mounts in its gateway.toml), and that applies to every sandbox it runs, not only Observer's. Observer never writes your gateway config: turning the opt-in on, and off again, is your own step (docs/sandbox-openshell.md, \"The gateway-wide bind-mount opt-in\").",
	},
	{
		sandboxbackend.DiscloseCLITelemetry, vocab.GatewayManagedLocal,
		"OpenShell's telemetry is on by default upstream; Observer forces it off on its private gateway.",
	},
	{
		sandboxbackend.DiscloseCLITelemetry, vocab.GatewayExternal,
		"OpenShell's telemetry is on by default upstream. Your gateway is yours, so Observer cannot see or change it and reports it as unknown; set OPENSHELL_TELEMETRY_ENABLED=false in the gateway's environment to turn it off.",
	},
}

func init() { addSandboxDisclosureRows(openShellDisclosureRows...) }

// openShellVersionPins are the values [terminal.sandbox.openshell].version
// may usefully take, served for the Settings card's pin picker: the tested
// versions (a pin must equal the installed gateway's version, and an
// untested one is refused by the version table anyway, so no other pin can
// ever make the row usable).
func openShellVersionPins() []string {
	tested := sandboxopenshell.TestedVersions()
	out := make([]string, 0, len(tested))
	for _, r := range tested {
		out = append(out, r.Version.String())
	}
	return out
}

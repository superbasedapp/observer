//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// sandbox_disclosures.go is the one owner of the sentences the dashboard
// shows for a row's registry disclosures (OpenShell lane O4): the New
// Terminal picker and the Settings card render them as served, never
// restating them in web/. A sentence is chosen by the closed disclosure id
// and the row's gateway mode (a capability the driver reports), never by a
// backend name.

// sandboxDisclosureRow is one row of the table: a disclosure, the gateway
// mode it applies to ("" for any mode, including a row with no gateway),
// and its sentence.
type sandboxDisclosureRow struct {
	id   sandboxbackend.Disclosure
	mode vocab.GatewayMode
	text string
}

// sandboxDisclosureRows is walked top-down; the first row whose id matches
// and whose mode is the row's (or "") wins, so a mode-specific row sits
// above its fallback. A driver adds its own mode-specific rows from init
// (addSandboxDisclosureRows), which puts them above every fallback here.
// Decision D3 (OB-040): Observer never writes a gateway config it does not
// own.
var sandboxDisclosureRows = []sandboxDisclosureRow{
	{
		sandboxbackend.DiscloseGatewayBindMounts, "",
		"The backend's gateway must allow host bind mounts, and that applies to every sandbox it runs, not only Observer's. Observer never writes a gateway config it does not own: turning that setting on, and off again, is your own step.",
	},
	{
		sandboxbackend.DiscloseCLITelemetry, "",
		"The backend's own command-line tool may send its vendor's telemetry; Observer cannot see or change it.",
	},
	{
		sandboxbackend.DiscloseSharedHomeTmpfs, "",
		"The box's home is a tmpfs owned by root with mode 1777 and the sticky bit, not a directory owned by you: a second user id inside the box could create files in it, but not delete or replace yours.",
	},
	{
		sandboxbackend.DiscloseAccountLogin, "",
		"Needs a sign-in to the backend's own account.",
	},
	{
		sandboxbackend.DiscloseDataLeaves, "",
		"The workspace leaves this machine for the provider's.",
	},
	{
		sandboxbackend.DisclosePaidTier, "",
		"Needs a paid plan with the provider.",
	},
	{
		sandboxbackend.DiscloseRegionOutsideOrg, "",
		"The box may run in a region your organization has not listed.",
	},
	{
		sandboxbackend.DiscloseOrgCompute, "",
		"The box runs on your organization's machines, and its administrators can see into it.",
	},
	{
		sandboxbackend.DiscloseOrgSharedGateway, "",
		"Several developers' boxes share one gateway and one kernel on your organization's machines.",
	},
	{
		sandboxbackend.DiscloseHostMutation, "",
		"Changes a setting of this machine before first use.",
	},
	{
		// The hosted rows (lane UX, item H9): the consent screen states the
		// same sentence (sandboxremote.HostedHookNote, one owner).
		sandboxbackend.DiscloseNoHookGating, "",
		sandboxremote.HostedHookNote,
	},
}

// addSandboxDisclosureRows puts a driver's mode-specific rows above the
// fallbacks (called from a driver's init).
func addSandboxDisclosureRows(rows ...sandboxDisclosureRow) {
	sandboxDisclosureRows = append(append([]sandboxDisclosureRow{}, rows...), sandboxDisclosureRows...)
}

// sandboxDisclosureText is the sentence for one disclosure on a row with
// gateway mode mode ("" when the table has none).
func sandboxDisclosureText(id sandboxbackend.Disclosure, mode vocab.GatewayMode) string {
	for _, r := range sandboxDisclosureRows {
		if r.id == id && (r.mode == "" || r.mode == mode) {
			return r.text
		}
	}
	return ""
}

// sandboxDisclosuresFor is the served list for one row.
func sandboxDisclosuresFor(row sandboxbackend.Capability, mode vocab.GatewayMode) []dashapi.SandboxDisclosure {
	var out []dashapi.SandboxDisclosure
	for _, d := range row.Discloses {
		out = append(out, dashapi.SandboxDisclosure{ID: string(d), Text: sandboxDisclosureText(d, mode)})
	}
	return out
}

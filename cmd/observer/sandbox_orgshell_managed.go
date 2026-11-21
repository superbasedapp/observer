//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"strings"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
)

// sandbox_orgshell_managed.go is the managed body consumer of the org-hosted
// OpenShell gateway (tracker F-019, g1-design.md sections 8.1 and 8.3, lane
// G4): one row of the managed composition table that turns the verified
// body's org_openshell field into the row's provider table and its published
// facts, and the one exception to the managed list's filter rule. Data only:
// the field never enables the row; the component, the backends list and an
// explicit choice still decide. Withdrawal is D-016: a body without the field
// composes nothing, so the row is no longer offered.

// sandboxManagedPublishedKey is the composition row's config key.
const sandboxManagedPublishedKey = "terminal.sandbox.hosted.openshell-org"

// sandboxManagedComposePublished composes org_openshell onto the effective
// config: the front as an org-published endpoint with its pin and the org's
// region label, and every published fact the probe, the consent screen and
// the launch read.
func sandboxManagedComposePublished(dst *config.TerminalSandboxConfig, p orgcontract.SandboxManagedPolicyV1, _ sandboxManagedEnv) (bool, string) {
	o := p.OrgOpenShell
	if o == nil {
		return false, ""
	}
	front := strings.ToLower(strings.TrimSuffix(o.FrontURL, "/"))
	dst.Hosted.OpenShellOrg.Provider = config.TerminalSandboxHostedProviderConfig{
		Endpoint: front, EndpointSPKISHA256: o.FrontTLSSPKISHA256, OrgPublished: true,
		Region: o.Region, Template: o.Image,
		// The org bakes the in-box observer into its box image (design 4.5):
		// the node uploads nothing and checks the version in the box.
		BoxBinaryInImage: o.BoxBinary == orgcontract.OrgOpenShellBoxBinaryImage,
	}
	dst.Hosted.OpenShellOrg.Published = config.TerminalSandboxOrgShellPublished{
		Offered: true, FrontURL: front, FrontSPKISHA256: o.FrontTLSSPKISHA256,
		GatewayID: o.GatewayID, Issuer: o.Issuer, Version: o.Version, Image: o.Image, IsoClass: o.IsoClass, Region: o.Region,
		Tiers: append([]string(nil), o.Tiers...), EgressAllowHosts: append([]string(nil), o.EgressAllowHosts...),
		AllowCIDRs: append([]string(nil), o.AllowCIDRs...), BlockedCIDRs: append([]string(nil), o.BlockedCIDRs...),
		CloneRepositories: append([]string(nil), o.CloneRepositories...), BoxBinary: o.BoxBinary,
		LaptopRelay: o.LaptopRelay, HoldPolicy: o.HoldPolicy, MaxHoldHours: o.MaxHoldHours,
		ReturnToNode: o.ReturnToNode, MaxRunMinutes: o.MaxRunMinutes, DailyBoxMinutesPerMember: o.QuotaSummary.DailyBoxMinutesPerMember,
	}
	return true, ""
}

// sandboxManagedPublishesRow reports whether the body may add row id to the
// managed backends list (design 8.3): only a row whose endpoint exists only
// as one the organization publishes (the vendor capability OrgEndpoint), and
// only while the same verified body publishes it. The server serves the
// field only to an allowed, managed-tenancy member (8.4).
func sandboxManagedPublishesRow(p orgcontract.SandboxManagedPolicyV1, id string) bool {
	v, ok := sandboxremote.VendorFor(id)
	return ok && v.OrgEndpoint && p.OrgOpenShell != nil
}

// sandboxManagedNoteAuthority records on the effective config that no
// managed sandbox body applies because the enrolment's grant lacks the
// sandbox rail's authority (FX1 item 7, live finding F-B2), so the
// org-hosted row's not-offered verdict can say so. Both compositions call
// it when no body is in force; it offers nothing.
func sandboxManagedNoteAuthority(dst *config.TerminalSandboxConfig, missing bool) {
	dst.Hosted.OpenShellOrg.Published.SandboxAuthorityMissing = missing
}

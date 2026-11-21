//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"slices"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
)

// TestOrgShellManagedCompose (lane G4, design 8.1 and 8.3): the body's
// org_openshell field composes the row's provider table and published facts
// (data only, never the backends list), a body without it composes nothing,
// and the managed list may add the row only while the same body publishes
// it; any other ExplicitOnly row is still filtered.
func TestOrgShellManagedCompose(t *testing.T) {
	o := &orgcontract.SandboxManagedOrgOpenShellV1{
		FrontURL: "https://Sandbox.Example.com/", FrontTLSSPKISHA256: "ab", GatewayID: "gw1", Version: "0.1.6",
		Image: "r/box@sha256:00", Region: "eu-west", Tiers: []string{"proxy_only"}, BlockedCIDRs: []string{"10.0.0.0/8"},
		LaptopRelay: "allowed", HoldPolicy: "on_disconnect", MaxHoldHours: 24, ReturnToNode: true, MaxRunMinutes: 90,
	}
	var dst config.TerminalSandboxConfig
	set, why := sandboxManagedComposePublished(&dst, orgcontract.SandboxManagedPolicyV1{OrgOpenShell: o}, sandboxManagedEnv{})
	p := dst.Hosted.OpenShellOrg
	if !set || why != "" || !p.Published.Offered || p.Provider.Endpoint != "https://sandbox.example.com" || !p.Provider.OrgPublished ||
		p.Provider.Region != "eu-west" || p.Published.MaxRunMinutes != 90 || !slices.Equal(p.Published.BlockedCIDRs, []string{"10.0.0.0/8"}) {
		t.Fatalf("composed %+v %v %q", p, set, why)
	}
	if len(dst.Backends) != 0 {
		t.Error("the field enabled a backend")
	}
	var none config.TerminalSandboxConfig
	if set, _ := sandboxManagedComposePublished(&none, orgcontract.SandboxManagedPolicyV1{}, sandboxManagedEnv{}); set || none.Hosted.OpenShellOrg.Published.Offered {
		t.Error("a body without the field composed something")
	}
	with := orgcontract.SandboxManagedPolicyV1{OrgOpenShell: o}
	kept, dropped := filterManagedBackends([]string{sandboxbackend.BackendOpenShellOrg, sandboxbackend.BackendOpenShell}, nil, func(id string) bool { return sandboxManagedPublishesRow(with, id) })
	if !slices.Equal(kept, []string{sandboxbackend.BackendOpenShellOrg}) || !dropped {
		t.Errorf("with the field: kept %v dropped %v", kept, dropped)
	}
	kept, _ = filterManagedBackends([]string{sandboxbackend.BackendOpenShellOrg}, nil, func(id string) bool { return sandboxManagedPublishesRow(orgcontract.SandboxManagedPolicyV1{}, id) })
	if len(kept) != 0 {
		t.Errorf("without the field the row was added: %v", kept)
	}
}

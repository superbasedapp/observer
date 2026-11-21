package sandboxselect

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// TestFloorReasonsUseTheOrgFloorPhrase (lane FU10 fix round 1, audit
// FU10-A3): the two floor rules whose reason names an organization floor by
// its key build it with OrgFloorPhrase, which the boundary relabels with
// the floor's admin label. One case per rule.
func TestFloorReasonsUseTheOrgFloorPhrase(t *testing.T) {
	bwrap, _ := sandboxbackend.Get(sandboxbackend.BackendBwrap)
	openshell, _ := sandboxbackend.Get(sandboxbackend.BackendOpenShell)
	cases := []struct {
		name string
		row  sandboxbackend.Capability
		in   Input
		rule string
		key  string
	}{
		{"S7e", bwrap, Input{
			Request: Request{Backend: bwrap.ID, Tier: vocab.TierHost, Interactive: true, Custody: vocab.CustodyHostBound, AcceptReducedCapture: true},
			Host:    sandboxbackend.HostLinux,
			Floors:  Floors{RequireRefusalAudit: true, FloorAcceptsBeta: true},
			Probes:  map[string]Probe{bwrap.ID: {Compiled: true, Verdict: VerdictAvailable}},
			Tool:    Tool{Mapped: true, ProxyRouted: true, CredentialInReach: true},
		}, "S7e", "require_refusal_audit"},
		{"S7g", openshell, Input{
			Request: Request{Backend: openshell.ID, Tier: vocab.TierProxyOnly, Interactive: true, Custody: vocab.CustodyHostBound, AcceptReducedCapture: true},
			Host:    sandboxbackend.HostLinux,
			Floors:  Floors{AllowedGatewayModes: []vocab.GatewayMode{vocab.GatewayManagedLocal}, FloorAcceptsBeta: true},
			Probes:  map[string]Probe{openshell.ID: {Compiled: true, Verdict: VerdictAvailable, GatewayMode: vocab.GatewayExternal}},
			Tool:    Tool{Mapped: true, ProxyRouted: true, CredentialInReach: true},
		}, "S7g", "gateway_modes"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, dropped := FloorDrop(c.row, c.in, false)
			if !dropped || d.Rule != c.rule || !strings.Contains(d.Reason, OrgFloorPhrase(c.key)) {
				t.Fatalf("drop = %+v (dropped %v), want rule %s naming %q", d, dropped, c.rule, OrgFloorPhrase(c.key))
			}
		})
	}
}

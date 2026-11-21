//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// TestSandboxDropReasonNamesTheFloorByLabel (lane FU10, F-050): the N4-L1
// live pass printed "the organization's floor require_refusal_audit is in
// force" on a CLI launch the floor refused, while the row and the link-loss
// 503 name "Require refusal audit". A drop by a floor rule now names the
// floor by its admin label with the key in parentheses, from the one floor
// table; a reason that names no floor key is kept. The floor drops are made
// by sandboxselect itself (fix round 1, audit FU10-A3), so a change of the
// rules' wording cannot leave this test passing on stale literals. One case
// per shape.
func TestSandboxDropReasonNamesTheFloorByLabel(t *testing.T) {
	floorDrop := func(t *testing.T, row sandboxbackend.Capability, in sandboxselect.Input) sandboxselect.Drop {
		t.Helper()
		d, dropped := sandboxselect.FloorDrop(row, in, false)
		if !dropped {
			t.Fatalf("no floor drop for %s", row.ID)
		}
		return d
	}
	bwrap, _ := sandboxbackend.Get(sandboxbackend.BackendBwrap)
	openshell, _ := sandboxbackend.Get(sandboxbackend.BackendOpenShell)
	tool := sandboxselect.Tool{Mapped: true, ProxyRouted: true, CredentialInReach: true}
	cases := []struct {
		name   string
		drop   func(t *testing.T) sandboxselect.Drop
		want   string
		absent string
	}{
		{"require_refusal_audit (S7e)", func(t *testing.T) sandboxselect.Drop {
			return floorDrop(t, bwrap, sandboxselect.Input{
				Request: sandboxselect.Request{Backend: bwrap.ID, Tier: vocab.TierHost, Interactive: true, Custody: vocab.CustodyHostBound, AcceptReducedCapture: true},
				Host:    sandboxbackend.HostLinux,
				Floors:  sandboxselect.Floors{RequireRefusalAudit: true, FloorAcceptsBeta: true},
				Probes:  map[string]sandboxselect.Probe{bwrap.ID: {Compiled: true, Verdict: sandboxselect.VerdictAvailable}},
				Tool:    tool,
			})
		}, `your organization's sandbox setting "Require refusal audit" (require_refusal_audit) is in force`, sandboxselect.OrgFloorPhrase("require_refusal_audit")},
		{"gateway_modes (S7g)", func(t *testing.T) sandboxselect.Drop {
			return floorDrop(t, openshell, sandboxselect.Input{
				Request: sandboxselect.Request{Backend: openshell.ID, Tier: vocab.TierProxyOnly, Interactive: true, Custody: vocab.CustodyHostBound, AcceptReducedCapture: true},
				Host:    sandboxbackend.HostLinux,
				Floors:  sandboxselect.Floors{AllowedGatewayModes: []vocab.GatewayMode{vocab.GatewayManagedLocal}, FloorAcceptsBeta: true},
				Probes:  map[string]sandboxselect.Probe{openshell.ID: {Compiled: true, Verdict: sandboxselect.VerdictAvailable, GatewayMode: vocab.GatewayExternal}},
				Tool:    tool,
			})
		}, `your organization's sandbox setting "Allowed sandbox gateway modes" (gateway_modes) allows only`, sandboxselect.OrgFloorPhrase("gateway_modes")},
		{"a floor verdict whose reason names no key", func(*testing.T) sandboxselect.Drop {
			return sandboxselect.Drop{Verdict: sandboxselect.VerdictRegionNotAllowed, Reason: `region "eu" is not allowed`}
		}, `region "eu" is not allowed`, "setting"},
		{"not a floor verdict", func(*testing.T) sandboxselect.Drop {
			return sandboxselect.Drop{Verdict: sandboxselect.VerdictEgressUnsupported, Reason: "this backend does not offer the none tier"}
		}, "this backend does not offer the none tier", "setting"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := sandboxDropReason(c.drop(t))
			if !strings.Contains(got, c.want) || strings.Contains(got, c.absent) {
				t.Fatalf("sandboxDropReason = %q, want it to contain %q and not %q", got, c.want, c.absent)
			}
		})
	}
	if !strings.Contains(egressRefusalClosedReason, `"Require refusal audit" (require_refusal_audit)`) {
		t.Fatalf("the link-loss 503 does not name the floor from the table: %s", egressRefusalClosedReason)
	}
}

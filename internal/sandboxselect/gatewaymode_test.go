package sandboxselect

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// TestGatewayModeFloorS7g walks rule S7g (OpenShell lane O4), one case per
// branch: no floor, a listed mode, an unlisted mode, and a row whose probe
// reports no gateway (never judged).
func TestGatewayModeFloorS7g(t *testing.T) {
	row, _ := sandboxbackend.Get(sandboxbackend.BackendOpenShell)
	managedOnly := []vocab.GatewayMode{vocab.GatewayManagedLocal}
	for _, tc := range []struct {
		name    string
		floor   []vocab.GatewayMode
		mode    vocab.GatewayMode
		dropped bool
	}{
		{"no floor", nil, vocab.GatewayExternal, false},
		{"listed mode", managedOnly, vocab.GatewayManagedLocal, false},
		{"unlisted mode", managedOnly, vocab.GatewayExternal, true},
		{"no gateway on the row", managedOnly, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := Input{
				Request: Request{Backend: row.ID, Tier: vocab.TierProxyOnly, Interactive: true, Custody: vocab.CustodyHostBound, AcceptReducedCapture: true},
				Host:    sandboxbackend.HostLinux,
				Floors:  Floors{AllowedGatewayModes: tc.floor, FloorAcceptsBeta: true},
				Probes:  map[string]Probe{row.ID: {Compiled: true, Verdict: VerdictAvailable, GatewayMode: tc.mode}},
				Tool:    Tool{Mapped: true, ProxyRouted: true, CredentialInReach: true},
			}
			d, dropped := FloorDrop(row, in, false)
			if dropped != tc.dropped {
				t.Fatalf("dropped = %v (%+v), want %v", dropped, d, tc.dropped)
			}
			if dropped && (d.Rule != "S7g" || d.Verdict != VerdictGatewayModeNotAllowed || !IsFloorRule(d.Rule)) {
				t.Fatalf("drop = %+v", d)
			}
		})
	}
	if !(Floors{AllowedGatewayModes: managedOnly}).InForce() {
		t.Fatal("a gateway_modes floor alone is not in force")
	}
}

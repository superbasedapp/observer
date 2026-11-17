package sandboxbackend

import (
	"slices"
	"testing"

	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// TestOpenShellOrgRow (lane G4, g1-design.md section 3.1): the org-hosted
// row's field table, one case per field the design fixes.
func TestOpenShellOrgRow(t *testing.T) {
	c, ok := Get(BackendOpenShellOrg)
	if !ok {
		t.Fatal("no openshell-org row")
	}
	cases := []struct {
		field string
		ok    bool
	}{
		{"label", c.Label == "OpenShell (org-hosted)"},
		{"maturity preview, phase G", c.Maturity == MaturityPreview && c.Phase == "G" && c.Offered()},
		{"explicit only", c.ExplicitOnly},
		{"class container, documented", c.Iso.Class == vocab.ClassContainer && c.Iso.ClassSource == vocab.SourceDocumented},
		{"remote, per run", c.Iso.Location == vocab.LocationRemote && c.Iso.Tenancy == TenancyPerRun},
		{"Linux and WSL2 daemons", slices.Equal(c.Iso.Hosts, []HostKind{HostLinux, HostWSL2})},
		{"go sdk, vendor preview, 0.1.6 authenticated", c.Control.Interface == InterfaceGoSDK && c.Control.Stability == StabilityVendorPreview &&
			c.Control.Pins.RequiredMin == "0.1.6" && c.Control.Pins.TestedLow == "0.1.6" && c.Control.Pins.TestedHigh == "0.1.6" && c.Control.Pins.RequireAuthenticatedVersion},
		{"terminal", c.Term == Terminal{PTYOwner: PTYBackendExec, Resize: ResizeBackendAPI, Reattach: ReattachNone, RelayReattach: RelaySeparateStream, Transport: TransportExecStdio}},
		{"tiers internet, proxy_only, none, no host", slices.Equal(c.Net.Egress, []vocab.Tier{vocab.TierInternet, vocab.TierProxyOnly, vocab.TierNone}) && !c.OffersTier(vocab.TierHost)},
		{"enforcer openshell_proxy", c.Net.Enforcer == EnforcerOpenShellProxy},
		{"no refusal audit in v1", len(c.Net.RefusalAuditTiers) == 0 && c.Net.RefusalAuditSource == ""},
		{"home_relay custody only", slices.Equal(c.Net.KeyCustody, []vocab.KeyCustody{vocab.CustodyHomeRelay})},
		{"capture full through the relay", c.Capture == Capture{Ceiling: vocab.CaptureFull, HookPath: HookRelay, Relay: RelayExecStdio}},
		{"read back provider", c.ReadBack == ReadBackProvider},
		{"lifetime 7200 fixed", c.LifetimeCapSeconds == 7200},
		{"disclosures", slices.Equal(c.Discloses, []Disclosure{DiscloseDataLeaves, DiscloseAccountLogin, DiscloseOrgCompute, DiscloseOrgSharedGateway})},
		{"no paid tier", !slices.Contains(c.Discloses, DisclosePaidTier)},
		{"keystore grant service", slices.Equal(c.KeystoreServices, []string{"sbo-openshell-org-grant-v1"})},
		{"beta on Linux and WSL2 with the G-L register", func() bool {
			for _, h := range []HostKind{HostLinux, HostWSL2} {
				v, ok := c.VerificationOn(h)
				if !ok || v.Kind != vocab.VerifiedDoc || v.RegisterRef != orgHostedRegister {
					return false
				}
			}
			return true
		}()},
	}
	for _, tc := range cases {
		if !tc.ok {
			t.Errorf("openshell-org: %s does not hold (%+v)", tc.field, c)
		}
	}
}

// TestOrgHostedRowLeavesHostedRowAlone: the wrapper does not change the
// three vendor rows' shape (they keep phase P7 and the paid tier).
func TestOrgHostedRowLeavesHostedRowAlone(t *testing.T) {
	for _, id := range []string{BackendE2B, BackendModal, BackendVercelSandbox, BackendDockerSandboxes, BackendInstaBox, BackendDaytona} {
		c, _ := Get(id)
		if c.Phase != "P7" || !slices.Contains(c.Discloses, DisclosePaidTier) || c.Net.Enforcer != EnforcerProvider {
			t.Errorf("%s changed: %+v", id, c)
		}
	}
}

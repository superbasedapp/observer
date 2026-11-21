package sandboxremote

import (
	"context"
	"slices"
	"testing"

	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// TestOrgShellVendorRow (lane G4): the org-hosted vendor row carries the
// three capability flags, no stored or environment credential, no default
// endpoint, the two deliveries, and resolves only an org-published https
// endpoint, recording the org's own region label.
func TestOrgShellVendorRow(t *testing.T) {
	v, ok := VendorFor(VendorOpenShellOrg)
	if !ok {
		t.Fatal("no openshell-org vendor row")
	}
	if !v.MintedCredential || !v.UploadViaExec || !v.OrgEndpoint {
		t.Errorf("capability flags %v %v %v", v.MintedCredential, v.UploadViaExec, v.OrgEndpoint)
	}
	if v.DefaultEndpoint != "" || len(v.EnvCredential) != 0 || v.Price.USDPerHour != 0 {
		t.Errorf("an org row names a vendor endpoint, env credential or price: %+v", v)
	}
	if !slices.Equal(v.Deliveries, []string{"sync", "remote_clone"}) {
		t.Errorf("deliveries %v", v.Deliveries)
	}
	if v.MinLifetimeMinutes() != 120 || v.GuestPTY || v.Reattach || !v.RelayStdin {
		t.Errorf("lifetime or terminal facts: %+v", v)
	}
	if _, ok := v.Tiers[vocab.TierHost]; ok || v.Tiers[vocab.TierNone].Relay {
		t.Errorf("tiers %+v", v.Tiers)
	}
	cases := []struct {
		name         string
		region, ep   string
		orgPublished bool
		wantOK       bool
		wantRegion   string
	}{
		{"org-published https origin", "eu-west", "https://sandbox.example.com", true, true, "eu-west"},
		{"empty region kept empty", "", "https://sandbox.example.com/", true, true, ""},
		{"not org-published", "eu-west", "https://sandbox.example.com", false, false, ""},
		{"no endpoint", "", "", true, false, ""},
		{"plain http", "", "http://sandbox.example.com", true, false, ""},
		{"a path", "", "https://sandbox.example.com/x", true, false, ""},
		{"user info", "", "https://u@sandbox.example.com", true, false, ""},
		{"a query", "", "https://sandbox.example.com?x=1", true, false, ""},
		{"a fragment", "", "https://sandbox.example.com#x", true, false, ""},
		{"an empty query mark", "", "https://sandbox.example.com?", true, false, ""},
	}
	for _, tc := range cases {
		r, ep, ok := v.ResolveEndpoint(tc.region, tc.ep, tc.orgPublished)
		if ok != tc.wantOK || (ok && (r != tc.wantRegion || ep != "https://sandbox.example.com")) {
			t.Errorf("%s: got %q %q %v", tc.name, r, ep, ok)
		}
	}
}

// TestMintedCredentialLeaksNothing: a minted credential holds no field, so
// Secrets, the stored encoding and every fmt verb carry no token.
func TestMintedCredentialLeaksNothing(t *testing.T) {
	c := Credential{Provider: VendorOpenShellOrg, Source: SourceMinted, Endpoint: "https://sandbox.example.com", Minted: fixedSource("sbo-run-token-SENTINEL-0000")}
	if len(c.Secrets()) != 0 || c.String() != "credential(openshell-org, minted)" {
		t.Errorf("minted credential %v %v", c.Secrets(), c.String())
	}
}

type fixedSource string

func (f fixedSource) Token(context.Context) (string, error) { return string(f), nil }

// TestOrgShellLayoutUsesTheFixedBoxPaths (ruling A3): the org row's layout
// never names the laptop's path, so any machine's resume uses the same
// paths; the file-API vendors keep the same-path workspace.
func TestOrgShellLayoutUsesTheFixedBoxPaths(t *testing.T) {
	v, _ := VendorFor(VendorOpenShellOrg)
	l := v.Layout("/home/dev/projects/app")
	if l.Workspace != "/sandbox/workspace" || l.RunDir != "/sandbox/run" || l.Binary != "/sandbox/run/bin/observer" || !v.NoRootExec {
		t.Errorf("org layout %+v", l)
	}
	e2b, _ := VendorFor(VendorE2B)
	if l := e2b.Layout("/home/dev/app"); l.Workspace != "/home/dev/app" || l.Binary != e2b.BoxHome+"/.observer-box/bin/observer" || e2b.NoRootExec {
		t.Errorf("e2b layout changed: %+v", l)
	}
}

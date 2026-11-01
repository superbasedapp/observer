package sandboxremote

import (
	"errors"
	"strings"
	"testing"
)

// TestResolveEndpoint (lane SBX-UPD, SBX-GOV-2): a local endpoint stays on
// the vendor's own domain; only an org-published one may leave it; only a
// vendor whose region is its endpoint takes one.
func TestResolveEndpoint(t *testing.T) {
	e2b, _ := VendorFor(VendorE2B)
	modal, _ := VendorFor(VendorModal)
	if r, ep, ok := e2b.ResolveEndpoint("", "", false); !ok || r != "us-west-1" || ep != "https://api.e2b.app" {
		t.Fatalf("default = %s %s %v", r, ep, ok)
	}
	if r, ep, ok := e2b.ResolveEndpoint("", "https://api.e2b.app/", false); !ok || r != "us-west-1" || ep != "https://api.e2b.app" {
		t.Fatalf("the listed endpoint = %s %s %v", r, ep, ok)
	}
	if r, _, ok := e2b.ResolveEndpoint("", "https://eu.api.e2b.app", false); !ok || r != RegionCustomEndpoint {
		t.Fatalf("a vendor-domain endpoint = %s %v", r, ok)
	}
	if _, _, ok := e2b.ResolveEndpoint("", "https://api.e2b.corp.example", false); ok {
		t.Fatal("a local endpoint off the vendor's domain was accepted")
	}
	if r, ep, ok := e2b.ResolveEndpoint("", "https://api.e2b.corp.example", true); !ok || r != RegionOrgPublished || ep != "https://api.e2b.corp.example" {
		t.Fatalf("an org-published endpoint = %s %s %v", r, ep, ok)
	}
	if _, _, ok := e2b.ResolveEndpoint("", "http://api.e2b.app", true); ok {
		t.Fatal("a plain-http endpoint was accepted")
	}
	if _, _, ok := modal.ResolveEndpoint("", "https://api.modal.com", false); ok {
		t.Fatal("Modal took an endpoint")
	}
}

// TestOrgEndpointCredentialBinding (SBX-GOV-4): the stored key connected for
// E2B's own cloud and the environment key are never sent to an
// org-published endpoint (credential_endpoint_mismatch); a credential
// connected for that origin is; a pinned endpoint also needs the same pin.
func TestOrgEndpointCredentialBinding(t *testing.T) {
	v, _ := VendorFor(VendorE2B)
	org := "https://api.e2b.corp.example"
	cloud := Credential{Provider: VendorE2B, Fields: map[string]string{"E2B_API_KEY": "k"}, Endpoint: "https://api.e2b.app", Source: SourceKeystore}
	env := Credential{Provider: VendorE2B, Fields: map[string]string{"E2B_API_KEY": "k"}, Endpoint: "https://api.e2b.app", Source: SourceEnv}
	for _, c := range []Credential{cloud, env} {
		if err := CheckBindingPinned(c, v, org, ""); !errors.Is(err, ErrCredentialEndpointMismatch) || !strings.Contains(err.Error(), "credential_endpoint_mismatch") {
			t.Fatalf("%s credential to the org endpoint: %v", c.Source, err)
		}
	}
	mine := Credential{Provider: VendorE2B, Fields: map[string]string{"E2B_API_KEY": "k"}, Endpoint: org, Source: SourceKeystore}
	if err := CheckBindingPinned(mine, v, org, ""); err != nil {
		t.Fatalf("a credential connected for the endpoint: %v", err)
	}
	pin := strings.Repeat("b", 64)
	if err := CheckBindingPinned(mine, v, org, pin); !errors.Is(err, ErrCredentialEndpointMismatch) {
		t.Fatalf("an unpinned credential to a pinned endpoint: %v", err)
	}
	mine.SPKISHA256 = pin
	if err := CheckBindingPinned(mine, v, org, pin); err != nil {
		t.Fatalf("a pinned credential: %v", err)
	}
	b, _ := EncodeStored(mine)
	back, err := DecodeStored(VendorE2B, b)
	if err != nil || back.SPKISHA256 != pin || back.Endpoint != org {
		t.Fatalf("the stored pin did not round-trip: %+v %v", back, err)
	}
}

// TestConsentNamesTheOrgEndpoint: the consent screen shows an org-published
// endpoint and what it may not do.
func TestConsentNamesTheOrgEndpoint(t *testing.T) {
	v, _ := VendorFor(VendorE2B)
	scr := BuildConsentScreen(v, ConsentFacts{Provider: VendorE2B, Endpoint: "https://api.e2b.corp.example", Region: RegionOrgPublished, Capture: "full"}, Manifest{}, v.EstimateCost(5))
	found := false
	for _, l := range scr.Lines {
		if l.Label == "Endpoint" && strings.Contains(l.Value, "published by your organization") && strings.Contains(l.Value, "https://api.e2b.corp.example") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no endpoint line: %+v", scr.Lines)
	}
	plain := BuildConsentScreen(v, ConsentFacts{Provider: VendorE2B, Endpoint: "https://api.e2b.app", Region: "us-west-1", Capture: "full"}, Manifest{}, v.EstimateCost(5))
	for _, l := range plain.Lines {
		if l.Label == "Endpoint" {
			t.Fatal("an endpoint line on a run with no org endpoint")
		}
	}
}

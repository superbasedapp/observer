//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"reflect"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
)

// TestManagedE2BEndpointApplied (lane SBX-UPD, SBX-GOV-2, the node apply):
// an org-published E2B endpoint lands on the node's E2B table marked
// org-published, never enables the row (backends untouched), resolves as
// the org's endpoint; the same endpoint written locally does not resolve;
// a body without it changes nothing.
func TestManagedE2BEndpointApplied(t *testing.T) {
	local := config.Default().Terminal.Sandbox
	local.Backends = []string{"bwrap"}
	p := orgcontract.SandboxManagedPolicyV1{
		Schema:    orgcontract.SandboxManagedSchema,
		HostedE2B: &orgcontract.SandboxManagedE2BV1{Origin: "https://API.e2b.corp.example/", SPKISHA256: strings.Repeat("c", 64), Template: "corp-base"},
	}
	got, refused := composeSandboxManaged(local, p, sandboxManagedEnv{})
	if len(refused) != 0 {
		t.Fatalf("refused %+v", refused)
	}
	e := got.Hosted.E2B
	if e.Endpoint != "https://api.e2b.corp.example" || !e.OrgPublished || e.EndpointSPKISHA256 != strings.Repeat("c", 64) || e.Template != "corp-base" {
		t.Fatalf("e2b table = %+v", e)
	}
	if !reflect.DeepEqual(got.Backends, local.Backends) || got.Enabled != local.Enabled {
		t.Fatalf("the endpoint enabled something: backends %v enabled %v", got.Backends, got.Enabled)
	}
	v, _ := sandboxremote.VendorFor(sandboxremote.VendorE2B)
	if r, ep, ok := hostedResolve(v, e); !ok || r != sandboxremote.RegionOrgPublished || ep != "https://api.e2b.corp.example" {
		t.Fatalf("resolve = %s %s %v", r, ep, ok)
	}
	// The same endpoint written locally (no org) is refused at resolve.
	e.OrgPublished = false
	if _, _, ok := hostedResolve(v, e); ok {
		t.Fatal("a local endpoint off E2B's domain resolved")
	}
	if same, _ := composeSandboxManaged(local, orgcontract.SandboxManagedPolicyV1{Schema: orgcontract.SandboxManagedSchema}, sandboxManagedEnv{}); !reflect.DeepEqual(same, local) {
		t.Fatal("a body without the endpoint changed the config")
	}
}

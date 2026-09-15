package main

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/govern"
)

// TestIntelRailEnabledResolver pins the org-served Cloud Intelligence result-
// rail gate resolver (org-served-cloud-intelligence plan §2.1/W5): node-
// authored [intelligence].org_enrichment on an individual node, raisable on a
// managed node that holds extract.intel. It is the single func
// orgclient.Client.SetIntelRail is bound to in start.go.
func TestIntelRailEnabledResolver(t *testing.T) {
	const key = "intelligence.org_enrichment"
	managedNoIntel := govern.Effective{Managed: true, Authority: []string{govern.AuthorityExtractCache}}
	individualWithIntel := govern.Effective{Managed: false, Authority: []string{govern.AuthorityExtractIntel}}
	// A managed node holding extract.intel: the RAISE still requires the org's
	// OWN share directive to be true (MergeBoolGated), exactly like every other
	// tier — the authority alone is not enough (finding 4).
	managedIntelNoDirective := govern.Effective{Managed: true, Authority: []string{govern.AuthorityExtractIntel}}
	managedIntelDirectiveTrue := govern.Effective{
		Managed: true, Authority: []string{govern.AuthorityExtractIntel},
		Share: map[string]any{key: true},
	}
	managedIntelDirectiveFalse := govern.Effective{
		Managed: true, Authority: []string{govern.AuthorityExtractIntel},
		Share: map[string]any{key: false},
	}
	zero := govern.Effective{}

	cases := []struct {
		name  string
		local bool
		eff   govern.Effective
		want  bool
	}{
		{name: "individual node + config false -> off", local: false, eff: zero, want: false},
		{name: "individual node + config true -> on (node-authored)", local: true, eff: zero, want: true},
		{name: "managed node without extract.intel + config false -> off", local: false, eff: managedNoIntel, want: false},
		// The raise is gated on the ORG's own share directive, not the authority
		// alone: authority + no directive is OFF, just like every sibling tier.
		{name: "managed + extract.intel, no org directive, config false -> off", local: false, eff: managedIntelNoDirective, want: false},
		{name: "managed + extract.intel + org directive true -> on (raise)", local: false, eff: managedIntelDirectiveTrue, want: true},
		{name: "managed + extract.intel + org directive false -> off (org withholds)", local: false, eff: managedIntelDirectiveFalse, want: false},
		// Belt-and-braces: an individual grant that somehow named extract.intel
		// is still inert (RaiseBool is managed-only; ExtractionAuthorized also
		// requires Managed), so only the node's own config can turn it on.
		{name: "individual node + stray extract.intel + config false -> off", local: false, eff: individualWithIntel, want: false},
		// Node-authored true survives when there is no org directive (LowerBool
		// with no directive keeps the local value).
		{name: "managed + extract.intel + config true, no directive -> on", local: true, eff: managedIntelNoDirective, want: true},
		// The org can LOWER even a node-authored true: an explicit directive false
		// withdraws it.
		{name: "managed + extract.intel + org directive false + config true -> off", local: true, eff: managedIntelDirectiveFalse, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := intelRailEnabled(tc.local, tc.eff); got != tc.want {
				t.Errorf("intelRailEnabled(%v, %+v) = %v, want %v", tc.local, tc.eff, got, tc.want)
			}
		})
	}
}

// TestManagedRaiseHonorsShareDirective is the adopted adversarial PROOF D: on an
// enterprise-managed node (which D11 auto-grants extract.intel) the rail must NOT
// be ON when the org's own share directive says false and the node config says
// false — the sibling tiers use MergeBoolGated, and so must this one (finding 4).
func TestManagedRaiseHonorsShareDirective(t *testing.T) {
	eff := govern.Effective{
		Managed: true, Authority: []string{govern.AuthorityExtractIntel},
		Share: map[string]any{"intelligence.org_enrichment": false},
	}
	if intelRailEnabled(false, eff) {
		t.Fatalf("rail ON with local=false and org directive=false; MergeBoolGated would give %v",
			eff.MergeBoolGated("intelligence.org_enrichment", false))
	}
}

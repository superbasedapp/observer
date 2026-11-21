package govern

import "testing"

// TestManagedPolicyTiersAreForcedOn pins the 2026-11-12 ruling (managed
// policy visibility G1): on a managed node a policy tier is on whatever the
// local switch, the grant's tokens or a lowering directive say; an individual
// node and a non-policy tier keep the ordinary algebra.
func TestManagedPolicyTiersAreForcedOn(t *testing.T) {
	t.Parallel()
	managedLowers := Effective{Managed: true, Share: map[string]any{"policy_state": false, "routing_summary": false, "terminal_detail": false, "cache_detail": false}}
	individual := Effective{Share: map[string]any{"policy_state": false}}
	for _, key := range ManagedPolicyTierKeys() {
		if !managedLowers.MergeBoolGated(key, false) {
			t.Errorf("%s: a managed node must ship it", key)
		}
		if got := managedLowers.SourceForBoolGated(key, false); got != ShareSourceOrgRaised {
			t.Errorf("%s: source %q, want %q", key, got, ShareSourceOrgRaised)
		}
	}
	if managedLowers.MergeBoolGated("cache_detail", true) {
		t.Error("a non-policy tier keeps the org's lowering")
	}
	if individual.MergeBoolGated("policy_state", true) {
		t.Error("an individual node keeps the org's lowering")
	}
	if (Effective{}).MergeBoolGated("policy_state", false) {
		t.Error("an individual node that did not opt in stays off")
	}
}

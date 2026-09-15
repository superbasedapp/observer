package govern

import "testing"

// TestShareTierTable_PolicyStateAndTargetActionsAreStrict extends
// TestShareTierTable_TableDriven's existing umbrella-insensitivity cases
// (sharetiers_test.go already pins "never authorized under the umbrella
// alone") with the missing POSITIVE case: policy_state and
// target_action_allowlist ARE authorized once the node grants their own
// specific extraction token. Both use the STRICT gate (grantsExtraction, no
// umbrella clause) — this is the concrete demonstration of that STRICT
// classification, not just its negative half.
func TestShareTierTable_PolicyStateAndTargetActionsAreStrict(t *testing.T) {
	managedUmbrella := Effective{Managed: true, Authority: []string{AuthorityExtractManaged}}
	managedPolicyState := Effective{Managed: true, Authority: []string{AuthorityExtractPolicyState}}
	managedTargetActions := Effective{Managed: true, Authority: []string{AuthorityExtractTargetActions}}
	unmanagedPolicyState := Effective{Managed: false, Authority: []string{AuthorityExtractPolicyState}}
	unmanagedTargetActions := Effective{Managed: false, Authority: []string{AuthorityExtractTargetActions}}

	cases := []struct {
		name string
		eff  Effective
		key  string
		want bool
	}{
		{name: "policy_state authorized via its OWN token", eff: managedPolicyState, key: "policy_state", want: true},
		{name: "policy_state still refused under the umbrella alone", eff: managedUmbrella, key: "policy_state", want: false},
		{name: "policy_state's own token is inert when unmanaged", eff: unmanagedPolicyState, key: "policy_state", want: false},
		{name: "policy_state's own token does not leak into a different key", eff: managedPolicyState, key: "target_action_allowlist", want: false},

		{name: "target_action_allowlist authorized via its OWN token", eff: managedTargetActions, key: "target_action_allowlist", want: true},
		{name: "target_action_allowlist still refused under the umbrella alone", eff: managedUmbrella, key: "target_action_allowlist", want: false},
		{name: "target_action_allowlist's own token is inert when unmanaged", eff: unmanagedTargetActions, key: "target_action_allowlist", want: false},
		{name: "target_action_allowlist's own token does not leak into a different key", eff: managedTargetActions, key: "policy_state", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ExtractionAuthorized(tc.eff, tc.key); got != tc.want {
				t.Errorf("ExtractionAuthorized(%+v, %q) = %v, want %v", tc.eff, tc.key, got, tc.want)
			}
		})
	}
}

// TestShareTierTable_ObsEgressIsHeadline is the deliberate contrast case to
// the STRICT pair above: obs.egress is the one member of this Plane-B group
// that IS reachable via the umbrella alone (grantsExtractionOrManaged), on
// top of its own dedicated token — matching its seven obs.* siblings, whose
// umbrella-eligibility this key must not lose just because it also got a
// dedicated token for symmetry with policy_state/target_action_allowlist.
func TestShareTierTable_ObsEgressIsHeadline(t *testing.T) {
	managedUmbrella := Effective{Managed: true, Authority: []string{AuthorityExtractManaged}}
	managedObsEgress := Effective{Managed: true, Authority: []string{AuthorityExtractObsEgress}}
	unmanagedUmbrella := Effective{Managed: false, Authority: []string{AuthorityExtractManaged}}
	unmanagedObsEgress := Effective{Managed: false, Authority: []string{AuthorityExtractObsEgress}}
	managedUnrelated := Effective{Managed: true, Authority: []string{AuthorityExtractCache}}

	cases := []struct {
		name string
		eff  Effective
		want bool
	}{
		{name: "authorized via its own dedicated token", eff: managedObsEgress, want: true},
		{name: "ALSO authorized via the umbrella alone, unlike policy_state/target_action_allowlist", eff: managedUmbrella, want: true},
		{name: "umbrella is inert when unmanaged", eff: unmanagedUmbrella, want: false},
		{name: "own token is inert when unmanaged", eff: unmanagedObsEgress, want: false},
		{name: "an unrelated per-tier grant does not authorize it", eff: managedUnrelated, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ExtractionAuthorized(tc.eff, "obs.egress"); got != tc.want {
				t.Errorf("ExtractionAuthorized(%+v, %q) = %v, want %v", tc.eff, "obs.egress", got, tc.want)
			}
		})
	}
}

// TestShareTierTable_IntelIsStrict pins the org-served Cloud Intelligence
// result-rail gate (intelligence.org_enrichment, org-served-cloud-intelligence
// plan §2.1/W5) to the STRICT posture of its codeintel/process/terminal/tasks/
// tool_accounts siblings: only extract.intel (on a managed node) authorizes the
// raise; the umbrella extract.managed NEVER does, and the token is inert on the
// individual plane. This is the resolver's managed-raise gate.
func TestShareTierTable_IntelIsStrict(t *testing.T) {
	managedIntel := Effective{Managed: true, Authority: []string{AuthorityExtractIntel}}
	managedUmbrella := Effective{Managed: true, Authority: []string{AuthorityExtractManaged}}
	unmanagedIntel := Effective{Managed: false, Authority: []string{AuthorityExtractIntel}}
	managedUnrelated := Effective{Managed: true, Authority: []string{AuthorityExtractCache}}

	cases := []struct {
		name string
		eff  Effective
		key  string
		want bool
	}{
		{name: "authorized via its OWN token on a managed node", eff: managedIntel, key: "intelligence.org_enrichment", want: true},
		{name: "refused under the umbrella alone (strict)", eff: managedUmbrella, key: "intelligence.org_enrichment", want: false},
		{name: "own token is inert when unmanaged", eff: unmanagedIntel, key: "intelligence.org_enrichment", want: false},
		{name: "an unrelated per-tier grant does not authorize it", eff: managedUnrelated, key: "intelligence.org_enrichment", want: false},
		{name: "own token does not leak into a different key", eff: managedIntel, key: "task_detail", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ExtractionAuthorized(tc.eff, tc.key); got != tc.want {
				t.Errorf("ExtractionAuthorized(%+v, %q) = %v, want %v", tc.eff, tc.key, got, tc.want)
			}
			// GrantsIntelExtraction is the predicate the share-tier row and
			// the cmd/observer resolver both read; it must agree for the key.
			if tc.key == "intelligence.org_enrichment" {
				if got := tc.eff.GrantsIntelExtraction(); got != tc.want {
					t.Errorf("GrantsIntelExtraction(%+v) = %v, want %v", tc.eff, got, tc.want)
				}
			}
		})
	}
}

// TestEnterpriseAuthoritySetContainsIntel pins decision D11 (operator ruling
// 2026-09-11): extract.intel IS a member of the extract.* family, so the
// enterprise enrolment grant sweeps it up fleet-wide with no per-node admin
// act. This is the ACCEPTED fleet-wide auto-grant — the node's own config key
// still defaults false, so nothing is pulled until the org enables the feature.
func TestEnterpriseAuthoritySetContainsIntel(t *testing.T) {
	found := false
	for _, tok := range EnterpriseAuthoritySet() {
		if tok == AuthorityExtractIntel {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("EnterpriseAuthoritySet() omits %q — decision D11 requires the fleet-wide auto-grant", AuthorityExtractIntel)
	}
	// Every token it returns must be either a real extraction authority (the
	// set is sourced from the extract.* family) or one of the TWO governing
	// tokens the enterprise posture exists to carry (W7, 2026-09-13:
	// settings.pin makes the default node.governance pins land, enforce.budget
	// makes the org's cap authoritative). Anything else is drift.
	governing := map[string]bool{AuthoritySettingsPin: false, AuthorityEnforceBudget: false}
	for _, tok := range EnterpriseAuthoritySet() {
		if _, ok := governing[tok]; ok {
			governing[tok] = true
			continue
		}
		if !ExtractionAuthority(tok) {
			t.Errorf("EnterpriseAuthoritySet() contains %q, which is neither an extraction authority nor a governing token", tok)
		}
	}
	for tok, present := range governing {
		if !present {
			t.Errorf("EnterpriseAuthoritySet() omits the governing token %q — an enterprise org would sign governance nothing applies", tok)
		}
	}
}

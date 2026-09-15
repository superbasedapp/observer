package govern

import (
	"reflect"
	"testing"
)

// allKnownAuthorityTokens mirrors KnownAuthority's switch exactly (types.go).
// Keeping a literal, hand-maintained list here — rather than trying to
// reflect the switch itself — is the same idiom the rest of this package
// uses for closed vocabularies; TestGovernedFamilies_EveryKnownAuthorityMapsOrIsExempt
// double-checks it against KnownAuthority so a token added to one but not
// the other is loud, not silent.
var allKnownAuthorityTokens = []string{
	AuthorityDashboardVisibility,
	AuthoritySettingsPin,
	AuthorityCaptureRaise,
	AuthorityCapturePin,
	AuthorityFeatureLock,
	AuthorityEnforceRouting,
	AuthorityEnforceAdmission,
	AuthorityEnforceEgress,
	AuthorityEnforceBudget,
	AuthorityExtractManaged,
	AuthorityExtractCodeintel,
	AuthorityExtractProcess,
	AuthorityExtractTerminal,
	AuthorityExtractToolBodies,
	AuthorityExtractFolders,
	AuthorityExtractTraces,
	AuthorityExtractCache,
	AuthorityExtractRouting,
	AuthorityExtractPredictions,
}

func TestGovernedFamilies_TableDriven(t *testing.T) {
	cases := []struct {
		name      string
		authority []string
		want      []string
	}{
		{name: "nil authority", authority: nil, want: nil},
		{name: "empty authority", authority: []string{}, want: nil},
		{
			name:      "single node.governance token",
			authority: []string{AuthorityDashboardVisibility},
			want:      []string{familyNodeGovernance},
		},
		{
			name:      "enforce.admission maps to admission.input",
			authority: []string{AuthorityEnforceAdmission},
			want:      []string{familyAdmissionInput},
		},
		{
			name:      "enforce.egress maps to egress.routing_guardrail",
			authority: []string{AuthorityEnforceEgress},
			want:      []string{familyEgressGuardrail},
		},
		{
			name:      "enforce.routing maps to gateway.providers",
			authority: []string{AuthorityEnforceRouting},
			want:      []string{familyGatewayProviders},
		},
		{
			name:      "mixed authority set, deduplicated and sorted",
			authority: []string{AuthorityExtractToolBodies, AuthorityEnforceAdmission},
			want:      []string{familyAdmissionInput, familyNodeGovernance},
		},
		{
			name:      "two node.governance tokens dedupe to one family",
			authority: []string{AuthorityDashboardVisibility, AuthoritySettingsPin, AuthorityCapturePin},
			want:      []string{familyNodeGovernance},
		},
		{
			name:      "all three enforce tokens plus a node.governance token",
			authority: []string{AuthorityEnforceRouting, AuthorityEnforceAdmission, AuthorityEnforceEgress, AuthorityFeatureLock},
			want:      []string{familyAdmissionInput, familyEgressGuardrail, familyGatewayProviders, familyNodeGovernance},
		},
		{
			name:      "retired capture.raise contributes nothing",
			authority: []string{AuthorityCaptureRaise},
			want:      nil,
		},
		{
			name:      "unknown token contributes nothing",
			authority: []string{"some.future.token"},
			want:      nil,
		},
		{
			name:      "a retired token alongside a real one: only the real family counts",
			authority: []string{AuthorityCaptureRaise, AuthorityExtractFolders},
			want:      []string{familyNodeGovernance},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := GovernedFamilies(tc.authority)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("GovernedFamilies(%v) = %v, want %v", tc.authority, got, tc.want)
			}
		})
	}
}

// TestGovernedFamilies_EveryKnownAuthorityMapsOrIsExempt is the drift guard:
// every token KnownAuthority recognises either maps to at least one family,
// or is named in exemptFromFamilyMapping. A future authority token that maps
// to nothing must be a conscious addition to the exemption list, never a
// silent fallthrough.
func TestGovernedFamilies_EveryKnownAuthorityMapsOrIsExempt(t *testing.T) {
	for _, tok := range allKnownAuthorityTokens {
		if !KnownAuthority(tok) {
			t.Fatalf("allKnownAuthorityTokens contains %q, but KnownAuthority(%q) is false - "+
				"the two lists have drifted, fix allKnownAuthorityTokens in this test", tok, tok)
		}
		families := GovernedFamilies([]string{tok})
		if len(families) == 0 && !exemptFromFamilyMapping[tok] {
			t.Errorf("KnownAuthority token %q maps to no policy family and is not in exemptFromFamilyMapping - "+
				"add a row to authorityFamilyTable, or a conscious exemption with a reason", tok)
		}
		if len(families) > 0 && exemptFromFamilyMapping[tok] {
			t.Errorf("KnownAuthority token %q is in exemptFromFamilyMapping but ALSO maps to %v - "+
				"remove it from the exemption list, or remove its authorityFamilyTable row", tok, families)
		}
	}
}

func TestGovernedFamilies_UnknownTokensNeverFabricated(t *testing.T) {
	got := GovernedFamilies([]string{"admission.input", "node.governance", "definitely-not-a-real-token"})
	if got != nil {
		t.Errorf("GovernedFamilies must never fabricate a family for a token outside authorityFamilyTable, got %v", got)
	}
}

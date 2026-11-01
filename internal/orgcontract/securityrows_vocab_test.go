package orgcontract_test

import (
	"slices"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/policyfam/securityscanning"
)

// TestSecurityWireVocabulariesMatchPolicy pins the vocabularies spelled in
// securityrows.go to their owners (internal/policy and the security.scanning
// family), so a new value added there is caught here.
func TestSecurityWireVocabulariesMatchPolicy(t *testing.T) {
	strs := func(in any) []string {
		var out []string
		switch v := in.(type) {
		case []policy.FindingCategory:
			for _, x := range v {
				out = append(out, string(x))
			}
		case []policy.FindingSeverity:
			for _, x := range v {
				out = append(out, string(x))
			}
		case []policy.FindingConfidence:
			for _, x := range v {
				out = append(out, string(x))
			}
		case []policy.FindingScope:
			for _, x := range v {
				out = append(out, string(x))
			}
		case []policy.FindingBaseline:
			for _, x := range v {
				out = append(out, string(x))
			}
		case []policy.FindingStatus:
			for _, x := range v {
				out = append(out, string(x))
			}
		case []policy.FindingAttribution:
			for _, x := range v {
				out = append(out, string(x))
			}
		}
		return out
	}
	pairs := []struct {
		name string
		wire []string
		own  []string
	}{
		{"categories", orgcontract.SecurityFindingCategories, strs(policy.FindingCategories())},
		{"severities", orgcontract.SecurityFindingSeverities, strs(policy.FindingSeverities())},
		{"confidences", orgcontract.SecurityFindingConfidences, strs(policy.FindingConfidences())},
		{"scopes", orgcontract.SecurityFindingScopes, strs(policy.FindingScopes())},
		{"baselines", orgcontract.SecurityFindingBaselines, strs(policy.FindingBaselines())},
		{"statuses", orgcontract.SecurityFindingStatuses, strs(policy.FindingStatuses())},
		{"attributions", orgcontract.SecurityFindingAttributions, strs(policy.FindingAttributions())},
		{"floor states", orgcontract.SecurityFloorStates, []string{securityscanning.StateApplied, securityscanning.StateNotApplicable, securityscanning.StateRefused}},
		{"floor reasons", orgcontract.SecurityFloorReasons, []string{
			securityscanning.ReasonComponentAbsent, securityscanning.ReasonIndividualNode, securityscanning.ReasonNotBuilt, securityscanning.ReasonModuleInactive,
			// The node's own correction for a managed node (cmd/observer
			// securityManagedRefusedKeys).
			"managed_node_uses_org_mirror",
		}},
		{"share levels", orgcontract.SecurityShareLevels, orgcontract.SecurityManagedFindingShares},
	}
	for _, p := range pairs {
		if !slices.Equal(p.wire, p.own) {
			t.Errorf("%s: wire %v, owner %v", p.name, p.wire, p.own)
		}
	}
}

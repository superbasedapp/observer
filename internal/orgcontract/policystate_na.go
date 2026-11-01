package orgcontract

import (
	"fmt"
	"regexp"
	"slices"
)

// policystate_na.go is the gen8 policy-state field (security plan 4.9 and
// 7.2, SECP-10, lane LEFT-SHARED): on the security.scanning row only, each
// floor key the node holds but cannot apply, with the closed reason the
// family's evaluator gave (securityscanning.Evaluate): a part not in this
// build or not selected, a managed-only key on an individual node, a key
// with no node setting yet, or the whole module inactive. Keys and closed
// reasons only; never a value. A gen7 server 400s the field
// (DisallowUnknownFields), which the node's generation ladder probes for and
// strips (cmd/observer/policystate_wire.go).

// FamilyKeyNotApplicable is one floor key the node did not apply and why.
type FamilyKeyNotApplicable struct {
	Key    string `json:"key"`
	Reason string `json:"reason"`
}

// FamilyNotApplicableReasons is the closed reason vocabulary (the
// security.scanning family's not_applicable reasons).
var FamilyNotApplicableReasons = []string{"component_absent", "individual_node", "not_built", "module_inactive"}

// MaxFamilyNotApplicable bounds the list on one row.
const MaxFamilyNotApplicable = 64

// familyNotApplicableKeyRe is a floor body key ("require.commit_gate",
// "components:security.deps", "sections.scan.osv").
var familyNotApplicableKeyRe = regexp.MustCompile(`^[a-z][a-z0-9_.:-]{0,95}$`)

// ValidateFamilyNotApplicable checks the list: at most
// MaxFamilyNotApplicable entries, each key in the floor key shape, each
// reason in the closed vocabulary, no key twice.
func ValidateFamilyNotApplicable(list []FamilyKeyNotApplicable) error {
	if len(list) > MaxFamilyNotApplicable {
		return fmt.Errorf("family_not_applicable has %d entries, max %d", len(list), MaxFamilyNotApplicable)
	}
	seen := map[string]bool{}
	for _, k := range list {
		if !familyNotApplicableKeyRe.MatchString(k.Key) || !slices.Contains(FamilyNotApplicableReasons, k.Reason) || seen[k.Key] {
			return fmt.Errorf("family_not_applicable entry %q/%q is not a floor key with a closed reason (or names a key twice)", k.Key, k.Reason)
		}
		seen[k.Key] = true
	}
	return nil
}

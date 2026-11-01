//go:build !sbo_omit_security

package main

import (
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policyfam/securityscanning"
)

// security_scanning_na.go reads the not_applicable detail of the
// security.scanning floor this node holds for the policy-state row (gen8,
// SECP-10, lane LEFT-SHARED). It reads the existing node state
// (secScanning's held body and facts, the same inputs `observer security
// status` reports from) and evaluates it with the family's own evaluator; it
// changes nothing on the node. A key the evaluator reports not_applicable
// travels as its key and closed reason only.

// securityNotApplicableKeys is the held floor's not_applicable keys, nil
// when no floor is held or every key applied.
func securityNotApplicableKeys() []orgcontract.FamilyKeyNotApplicable {
	h := secScanning.heldCopy()
	if h == nil {
		return nil
	}
	return securityNotApplicableFrom(securityscanning.Evaluate(h.Spec, secScanning.facts()))
}

// securityNotApplicableFrom keeps the not_applicable key states (pure): a
// reason outside the wire's closed vocabulary or a key outside its shape is
// left out rather than sent, and the list is capped.
func securityNotApplicableFrom(states []securityscanning.KeyState) []orgcontract.FamilyKeyNotApplicable {
	var out []orgcontract.FamilyKeyNotApplicable
	seen := map[string]bool{}
	for _, k := range states {
		if k.State != securityscanning.StateNotApplicable || seen[k.Key] || len(out) == orgcontract.MaxFamilyNotApplicable {
			continue
		}
		one := []orgcontract.FamilyKeyNotApplicable{{Key: k.Key, Reason: k.Reason}}
		if orgcontract.ValidateFamilyNotApplicable(one) != nil {
			continue
		}
		seen[k.Key] = true
		out = append(out, one[0])
	}
	return out
}

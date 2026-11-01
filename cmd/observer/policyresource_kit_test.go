package main

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/policyfam"
)

// TestPolicyResourceKitWiring pins the F0-8/F0-9 node bindings: the posture
// gate is bound, the linked families' live tokens are advertised, and this
// build registers no family twice.
func TestPolicyResourceKitWiring(t *testing.T) {
	opts := policyResourceOptionsFor(config.Default(), nil)
	if opts.CheckPosture == nil {
		t.Fatal("CheckPosture must be bound from the linked families' evaluators")
	}
	for _, f := range policyfam.SupportedFamilies {
		axis, err := opts.CheckPosture(f, nil)
		if !policyfam.IsFamilyLinked(f) && (axis != "" || err != nil) {
			t.Errorf("an unlinked family %s must pass the posture gate", f)
		}
		if f == policyfam.FamilySecurityScanning && policyfam.IsFamilyLinked(f) && err == nil {
			t.Errorf("a linked %s must refuse a spec it cannot read", f)
		}
	}
	caps := nodeLiveCapabilities(nil)
	for _, want := range policyfam.LinkedLiveCapabilities() {
		found := false
		for _, c := range caps {
			found = found || c == want
		}
		if !found {
			t.Errorf("linked live capability %q not advertised", want)
		}
	}
	if c := logLinkedFamilyConflicts(nil); len(c) != 0 {
		t.Fatalf("linked family conflicts in this build: %v", c)
	}
}

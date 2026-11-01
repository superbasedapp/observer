package main

import (
	"errors"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policyfam"
	"github.com/marmutapp/superbased-observer/internal/policyfam/nodegov"
)

// TestCheckPolicyPostureComposition: the accept gate judges a
// node.governance body by the module posture providers of the pins it
// carries (N3), and every other family by its own linked evaluator.
func TestCheckPolicyPostureComposition(t *testing.T) {
	// An injected registry: every real owner is removed for the test, so the
	// stub below is the only owner of mask_paths and the real sandbox
	// evaluator (which reads the node's own config) never runs.
	for _, owner := range nodegov.PinPostureOwners() {
		restoreOwner := nodegov.SwapPinPostureForTest(owner, nil, nil)
		defer restoreOwner()
	}
	restore := nodegov.SwapPinPostureForTest("test.posture", []string{"terminal.sandbox.mask_paths"},
		func(pins map[string]any) (string, error) { return "masks", errors.New("weaker") })
	defer restore()

	cases := []struct {
		name     string
		family   string
		spec     any
		wantAxis string
	}{
		{
			"governance body pinning a module key", policyfam.FamilyNodeGovernance,
			nodegov.PolicySpec{Pinned: map[string]any{"terminal.sandbox.mask_paths": []string{"/x"}}},
			"masks",
		},
		{
			"governance body pinning nothing the module owns", policyfam.FamilyNodeGovernance,
			nodegov.PolicySpec{Pinned: map[string]any{"guard.enabled": true}},
			"",
		},
		{"a family with no evaluator", policyfam.FamilyNodeFeatures, nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			axis, err := checkPolicyPosture(tc.family, tc.spec)
			if axis != tc.wantAxis || (tc.wantAxis != "") != (err != nil) {
				t.Fatalf("axis %q err %v, want axis %q", axis, err, tc.wantAxis)
			}
		})
	}
}

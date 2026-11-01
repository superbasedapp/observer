//go:build !sbo_omit_security

package main

import (
	"slices"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
)

// TestOptInChildrenStayOutOfTheLegacyPackSet: a config with no [components]
// block resolves every compiled module active, but the signed pack set (and
// so every rule of those packs) leaves out the opt-in children of
// security_optin.go until a block selects them (plans decision log P-020,
// P-021).
func TestOptInChildrenStayOutOfTheLegacyPackSet(t *testing.T) {
	legacy := securityActivePacks(componentstate.Legacy())
	if securityInertByDefault() {
		// The managed edition leaves the module inert with no block.
		if len(legacy) != 0 {
			t.Fatalf("pack set %v with no block in an edition that leaves the module inert", legacy)
		}
	} else if !slices.Contains(legacy, "security") {
		t.Fatalf("legacy pack set %v lost the module root", legacy)
	}
	offered := components.Compiled(components.BinaryNode)
	for id := range securityOptIn {
		if slices.Contains(legacy, id) {
			t.Errorf("legacy pack set %v carries opt-in child %s", legacy, id)
		}
		// A block can select only what this build offers: a published
		// edition without the child (the developer one has no actionlint)
		// keeps it out of the pack set even when a block names it.
		want := slices.Contains(offered, id)
		chosen := securityActivePacks(componentstate.Resolve(config.ComponentsConfig{Add: []string{id}}, nil))
		if slices.Contains(chosen, id) != want {
			t.Errorf("pack set %v with a [components] block adding %s: carries it %v, want %v (offered by this build %v)", chosen, id, !want, want, want)
		}
	}
}

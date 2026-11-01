//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
)

// sandbox_gates_optin.go is the opt-in rule of the sandbox FEATURE
// children lane GATES-SBX added (operator ruling P-129, each off by
// default): re-adoption and checkpoints of local container runs, and the
// credential injection of sandboxed runs. Like the drivers
// (sandboxDriverSelected), each runs only when a [components] block selects
// it, so an install with no block, which resolves every compiled module
// active (componentstate.Legacy), gains none of them. The driver rows of
// the same lane (mxc-appcontainer, wslc, hcs) are drivers and follow
// sandboxDriverOptIn through registerSandboxDriver.

// The feature children's component ids.
const (
	readoptComponent     = "terminals.sandbox.oci.readopt"
	credentialsComponent = "terminals.sandbox.credentials"
)

// sandboxFeatureComponents are the feature children this rule governs.
var sandboxFeatureComponents = []string{readoptComponent, credentialsComponent}

func init() {
	componentOptInRules = append(componentOptInRules, sandboxFeatureOptIn)
}

// sandboxFeatureOptIn governs the feature children's components.
func sandboxFeatureOptIn(snap componentstate.Snapshot, id string) (governs, active bool) {
	for _, c := range sandboxFeatureComponents {
		if c == id {
			return true, sandboxFeatureSelected(snap, id)
		}
	}
	return false, false
}

// sandboxFeatureSelected is the feature children's rule: a [components]
// block selects the child, and the sandbox module is active.
func sandboxFeatureSelected(snap componentstate.Snapshot, id string) bool {
	return snap.BlockSelects(id) && sandboxModuleActive(snap) && snap.ModuleActive(id)
}

// sandboxFeatureActive loads the config at cfgPath (the daemon's, "" for
// the default) and reports whether the feature child id is selected. A
// variable so tests set it.
var sandboxFeatureActive = func(_ context.Context, cfgPath, id string) bool {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		return false
	}
	return sandboxFeatureSelected(componentSnapshotForConfig(cfg), id)
}

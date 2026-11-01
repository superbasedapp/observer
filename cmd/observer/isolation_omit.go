//go:build sbo_omit_isolation

package main

import (
	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/extrun"
)

// isolation_omit.go stands in for isolation_wire.go and isolation_host.go
// in a build without the isolation component (-tags sbo_omit_isolation):
// internal/sandbox and internal/isolation are not linked, and a consumer is
// handed no isolation factory, exactly as when the component is inactive.
// terminals.sandbox Requires isolation, so its files are compiled out by
// the same tag (terminal_sandbox_omit.go stands in for them).
func init() { components.MarkOmitted(isolationComponent) }

// isolationComponent is the node catalog id of the isolation engine.
const isolationComponent = "isolation"

// isolationFactoryFor returns nil: nothing can be isolated in this build.
func isolationFactoryFor(componentstate.Snapshot, string, []string) extrun.IsolationFactory {
	return nil
}

// isolationAvailable reports false: no isolation provider in this build.
func isolationAvailable() bool { return false }

// isolationMissingOnHost is never reached in this build (no factory).
func isolationMissingOnHost(error) bool { return true }

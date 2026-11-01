//go:build !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
)

// N2 (lane SBX-P3B): where the container sandbox is active, the repository
// trust check also reads .devcontainer/devcontainer.json for every field
// the driver ignores (agentconfig TrustCondOCISandbox). Active means the
// sandbox is on, the terminals.sandbox.oci component is selected and an
// oci-* row is among the enabled backends.
//
// The initializeCommand row that holds wherever the trust check runs (the
// N2 ruling P-108, TrustCondDevcontainerHost) is not this driver's: its
// hook lives in the always-built trust_conditions.go, so a build without
// this driver has it too. Both read the file through the one shared reader
// (internal/devcontainer), which this driver's planner adopts from as well.
func init() {
	repoTrustConditionHooks = append(repoTrustConditionHooks, ociTrustCondition)
}

// ociTrustCondition reports whether the container sandbox is active.
func ociTrustCondition(cfg config.Config, snap componentstate.Snapshot) (repoTrustCondition, bool) {
	sb := cfg.Terminal.Sandbox
	on := sb.Enabled && sandboxDriverSelected(snap, ociComponent) && ociAnyListed(sb)
	return repoTrustCondition{cond: agentconfig.TrustCondOCISandbox}, on
}

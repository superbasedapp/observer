//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/agentlaunch"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// TestOpenShellRowsAreNotLoopbackExposed pins the registry side of fold
// audit L2 (lane FX5): the two OpenShell rows offer no host tier and their
// relay does not ride host loopback, so a live run on either, resolved
// through boxRun as the caller check resolves it, is not exposed to the
// daemon's loopback control plane on any tier the row offers. A row change
// that adds either capability fails here, and LAUNCH-1 must then be read
// again for that row.
func TestOpenShellRowsAreNotLoopbackExposed(t *testing.T) {
	for _, id := range []string{sandboxbackend.BackendOpenShell, sandboxbackend.BackendOpenShellOrg} {
		row, ok := sandboxbackend.Get(id)
		if !ok {
			t.Fatalf("%s: no row", id)
		}
		if len(row.Net.Egress) == 0 {
			t.Fatalf("%s: offers no egress tier", id)
		}
		for _, tier := range row.Net.Egress {
			if tier == vocab.TierHost {
				t.Fatalf("%s offers the host tier", id)
			}
			run := boxRun("r", string(row.Iso.Class), id, string(tier))
			if run.HostLoopbackRelay {
				t.Fatalf("%s: its relay rides host loopback", id)
			}
			if e, exposed := agentlaunch.LoopbackExposure([]agentlaunch.BoxRun{run}); exposed {
				t.Fatalf("%s on %s is exposed by %s", id, tier, e.Rule)
			}
		}
	}
}

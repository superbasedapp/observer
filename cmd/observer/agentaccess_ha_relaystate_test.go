package main

// Lane HA - doc3 §18 gate 3 / §12.8 (node effective-state on a refused
// config), regression for Lane HA defect D3: a node relay that REFUSES policy
// v9 keeps table v3 live (TestMCPRelay_ApplyBadSpecKeepsPreviousTable), and
// its effective-state facts must keep reporting v3 - before the fix
// recordApplyErr's state.Version = 9 leaked into RunningVersion /
// EffectiveHash, so the node claimed to RUN the version it refused (a false
// ACK of a NACKed config).

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgclient"
)

func TestAgentAccessHARelayRefusedVersionNotReportedRunning(t *testing.T) {
	h := appliedHandle(t, mcpRelayTestCfg(t, true), "enforce", false)
	before, ok := h.Facts()
	if !ok || before.RunningVersion != 3 {
		t.Fatalf("precondition: running v3, got %+v ok=%v", before, ok)
	}
	h.Apply(orgclient.PolicyResourceResult{Status: orgclient.PRApplied, Version: 9, Spec: "not a spec"})
	if h.Table() == nil || h.Table().Meta.Version != 3 {
		t.Fatal("precondition: the refused v9 must leave table v3 live")
	}
	after, _ := h.Facts()
	t.Logf("after refusing v9: running=%d cached=%d hash %s -> %s", after.RunningVersion, after.CachedAcceptedVersion, before.EffectiveHash, after.EffectiveHash)
	if after.RunningVersion != 3 {
		t.Errorf("effective-state claims running v%d while table v3 is live (refused v9 reported as running)", after.RunningVersion)
	}
	if after.EffectiveHash != before.EffectiveHash {
		t.Errorf("effective hash changed although the live table did not (%s -> %s)", before.EffectiveHash, after.EffectiveHash)
	}
}

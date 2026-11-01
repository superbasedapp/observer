package main

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// TestLiveGatedHookNeverAutoRegisters: a hook writer that waits on a live
// check (DEC-12) fails the `observer start` gate even when its mechanism is
// grandfathered and every binding is live; clearing the gate restores the
// mechanism's own answer.
func TestLiveGatedHookNeverAutoRegisters(t *testing.T) {
	live := integration.Grounding{Kind: integration.GroundingLive, Source: "test", Date: "2026-10-28"}
	c := integration.Capability{Hook: integration.HookSpec{
		Mechanism: integration.HookClaudeSettings, AutoWired: true, LiveGate: "LC18",
		Bindings: []integration.HookBinding{{Cap: integration.HookCapToolGate, Phase: integration.HookPhasePre, NativeEvent: "PreToolUse", Grounding: live, Wired: true, Registered: true}},
	}}
	if autoRegisterLiveGate(c) {
		t.Fatal("a live-gated hook writer passed the auto-register gate")
	}
	c.Hook.LiveGate = ""
	if !autoRegisterLiveGate(c) {
		t.Fatal("the ungated twin did not pass the auto-register gate")
	}
	for _, w := range integration.LiveGatedWriters() {
		if w.Kind != "hooks" {
			continue
		}
		rc, _ := integration.For(w.Tool)
		if autoRegisterLiveGate(rc) {
			t.Errorf("%s: gated hook writer passes the auto-register gate", w.Tool)
		}
	}
}

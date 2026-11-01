package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// TestEveryWiredBindingHasAReceiver generalizes
// TestPromptLaneHookRowsHaveAReceiver (kept) from the prompt lane to every
// capability: a binding the registry says a feature ACTS on must reach a
// real receiver. A wired binding with no hookReceivers entry would fall to
// the binding fallback, which only allows, so the registry's claim would be
// false. The two transports served elsewhere (the cline-cli tailer, the
// browser extension) are named by HookBinding.ServedElsewhere.
func TestEveryWiredBindingHasAReceiver(t *testing.T) {
	for _, c := range integration.Capabilities() {
		if adapterCompiledOut(c.Tool) {
			continue // no receiver by design (hook_<pkg>_omit.go answers its gates)
		}
		for _, b := range c.Hook.Bindings {
			if !b.Wired {
				continue
			}
			if b.ServedElsewhere() != "" {
				continue
			}
			if _, ok := standaloneToolGate(c.Tool, b.NativeEvent); ok {
				// A served tool gate on a mechanism with no receiver of
				// its own: the binding-driven route (hook_toolgate.go)
				// is its real receiver.
				continue
			}
			// A lifecycle-dialect binding is served by the one lifecycle
			// handler for every tool (runHookInvocation, before the
			// hookReceivers lookup), and Grok's through the claude-code
			// receiver's replay dispatch (hook-parity Lane C1/C3).
			if _, ok := lifecycleBinding(c.Tool, b.NativeEvent); ok {
				continue
			}
			if _, ok := bindingDialectReceivers[b.Dialect]; ok {
				continue // served by its dialect's handler (hook_pluginshim.go)
			}
			if _, ok := hookReceivers[c.Tool]; !ok {
				t.Errorf("%s/%s (%s) is Wired but %s has no hookReceivers entry", c.Tool, b.NativeEvent, b.Cap, c.Tool)
			}
		}
	}
	elsewhere := 0
	for _, c := range integration.Capabilities() {
		for _, b := range c.Hook.Bindings {
			if b.Wired && b.ServedElsewhere() != "" && b.Cap == integration.HookCapTurnLifecycle {
				elsewhere++
			}
		}
	}
	if elsewhere == 0 {
		t.Error("no wired turn-lifecycle binding is served elsewhere: the tailer / browser transports lost their rows")
	}
}

// TestBindingFallbackRepliesLikeHandleApprove: for a tool with bindings and
// no receiver, the fallback's stdout is byte-identical to the HandleApprove
// default it replaces, gate binding or not.
func TestBindingFallbackRepliesLikeHandleApprove(t *testing.T) {
	for _, tc := range []struct{ tool, event string }{
		// kiro-cli (gfiD) and copilot-cli (userPromptSubmitted, guard-fix lane
		// B) have receivers since 2026-10-15; kiro-crew is still vendor-only.
		{"kiro-crew", "PreToolUse"},
		{"kiro-crew", "SessionStart"},
	} {
		if _, ok := hookReceivers[tc.tool]; ok {
			t.Fatalf("%s has a receiver; pick a fallback tool", tc.tool)
		}
		b, ok := resolveHookBinding(tc.tool, tc.event)
		if !ok {
			t.Fatalf("%s/%s: no binding", tc.tool, tc.event)
		}
		label := tc.tool + ":" + tc.event
		var got, want, errBuf bytes.Buffer
		handleBindingFallback(tc.tool, label, b, strings.NewReader("{}"), &got, &errBuf)
		hook.HandleApprove(label, strings.NewReader("{}"), &want, &bytes.Buffer{})
		if got.String() != want.String() {
			t.Errorf("%s/%s fallback reply %q, HandleApprove %q", tc.tool, tc.event, got.String(), want.String())
		}
		if !strings.Contains(errBuf.String(), string(b.Cap)) {
			t.Errorf("fallback stderr does not name the capability: %q", errBuf.String())
		}
	}
	if _, ok := resolveHookBinding("kimi-code", "NoSuchEvent"); ok {
		t.Error("an undeclared event resolved a binding")
	}
	if _, ok := resolveHookBinding("no-such-tool", "PreToolUse"); ok {
		t.Error("an unknown tool resolved a binding")
	}
}

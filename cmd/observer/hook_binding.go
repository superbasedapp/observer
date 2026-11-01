package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/hookevent"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// resolveHookBinding returns the registry binding for `observer hook <tool>
// <event>`: the tool's row, then the binding whose NativeEvent is event.
// ok=false for an unknown tool or an event the row does not declare.
func resolveHookBinding(tool, event string) (integration.HookBinding, bool) {
	c, ok := integration.For(tool)
	if !ok {
		return integration.HookBinding{}, false
	}
	return c.Hook.Binding(event)
}

// handleBindingFallback is the ONE binding-driven receiver (hook-parity Lane
// 0 step 8) for a tool that declares hook bindings but has no hookReceivers
// entry. It resolves the invocation into a normalized hookevent.Event and
// answers with the dialect's documented allow, recording nothing new: every
// such binding today is vendor-only (Observer writes no config that invokes
// it), so the reply is byte-identical to the HandleApprove default this
// path replaces (pinned by the hook-parity receiver_replies golden). A later
// lane gives a capability its handler here; until then an unhandled gate
// is an allow, because unknown is never a violation.
func handleBindingFallback(tool, label string, b integration.HookBinding, stdin io.Reader, stdout, stderr io.Writer) {
	ev := hookevent.FromBinding(tool, b)
	out := hookevent.Allow()
	fmt.Fprintf(stderr, "observer-hook: %s binding cap=%s phase=%q event=%s has no receiver; %s\n",
		label, ev.Cap, ev.Phase, ev.NativeEvent, out.Decision)
	hook.HandleApprove(label, stdin, stdout, stderr)
}

// dispatchBindingReceiver runs the capability receiver for a binding of a
// tool that has no hookReceivers entry (hook-parity Lanes B and E). The
// binding's Dialect names the wire shape: a dialect with a row in the
// prompt dialect table gets the shared prompt-only receiver, which
// evaluates a prompt_gate event and answers every other event with that
// dialect's own allow before recording an observe-family payload
// (compaction, task) through hook_observe.go. Returns false when no
// receiver applies (the caller's binding fallback then answers allow).
func dispatchBindingReceiver(ctx context.Context, tool, event, configPath string, b integration.HookBinding) bool {
	// A post-tool event registered for the security feedback (lane sec-h):
	// the dialect's allow with the feedback lines (security_feedback.go).
	if handlePostFeedbackHook(ctx, tool, event, tool+":"+event, configPath, os.Stdin, hookStdout, os.Stderr) {
		markHookReplied()
		return true
	}
	if !hook.KnownPromptDialect(b.Dialect) {
		return false
	}
	promptEvent := ""
	if b.Cap == integration.HookCapPromptGate {
		promptEvent = event
	}
	handlePromptSubmitOnlyHook(tool, tool, b.Dialect, promptEvent, event, configPath)
	return true
}

// A wired binding whose dialect is served by a receiver other than
// `observer hook <tool> <event>` (the cline-cli hooks.jsonl tailer, the
// browser extension's `observer browser hook`) names it through
// integration.HookBinding.ServedElsewhere: keyed on the dialect, so a row
// can mix those bindings with per-event registrations (T-342).

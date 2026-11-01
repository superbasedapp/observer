package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guardposture"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// Tool-gate receivers (hook-parity Lane A). Every wired tool_gate binding
// whose dialect is a row of hook's tool-gate table is answered by ONE path,
// runToolGate: config, failure plan, guard, hook.HandleToolGate, the
// dialect's allow. A mechanism whose receiver does more on the same event
// (Claude Code's shell rewrite, Cursor's capture, Codex's account evidence)
// calls runToolGate itself; every other mechanism reaches it through the
// binding-driven route in runHookInvocation, so a new vendor needs a
// binding row, not a receiver.

// toolGateOwnReceiver names the mechanisms whose hookReceivers entry serves
// its tool gate itself, with what it does on the event besides the gate.
// Keyed on the mechanism (capability shape), never a tool.
var toolGateOwnReceiver = map[integration.HookMechanism]string{
	integration.HookClaudeSettings: "PreToolUse also rewrites shell commands through `observer run` and captures effort",
	integration.HookCursor:         "preToolUse also captures the long-tail tool rows the per-tool before* events do not",
	integration.HookCodexConfig:    "PreToolUse also records tool-account evidence after the reply",
}

// toolGateServed reports whether b is a wired tool gate whose dialect the
// tool-gate table speaks.
func toolGateServed(b integration.HookBinding) bool {
	return b.Cap == integration.HookCapToolGate && b.Wired && hook.IsToolGateDialect(b.Dialect)
}

// standaloneToolGate resolves an invocation to a tool gate the
// binding-driven route serves: a served tool gate on a mechanism that has
// no receiver of its own for it.
func standaloneToolGate(tool, event string) (integration.HookBinding, bool) {
	b, ok := resolveHookInvocationBinding(tool, event)
	if !ok || !toolGateServed(b) {
		return integration.HookBinding{}, false
	}
	c, ok := integration.For(tool)
	if !ok {
		return integration.HookBinding{}, false
	}
	if _, own := toolGateOwnReceiver[c.Hook.Mechanism]; own {
		return integration.HookBinding{}, false
	}
	return b, true
}

// handleToolGateHook is the binding-driven tool-gate receiver: read the
// payload once, answer through runToolGate.
func handleToolGateHook(tool, label string, b integration.HookBinding, stdin io.Reader, configPath string) {
	// An exit-code-only dialect has no stdout channel: a recovered panic
	// must not invent a JSON reply its host never parses.
	setHookExpectsStdoutReply(hook.ToolGateAllowWritesStdout(b.Dialect))
	body, truncated := readHookBodyDetectTruncation(stdin, promptSubmitBodyLimit)
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
	// Another surface that runs this tool's registration (the Antigravity
	// App and IDE on the agy hooks.json) is served as its own call
	// (hook_surface.go, surface-gap W-2c).
	if surface, sb, ok := hookSurfaceBinding(tool, b, body); ok {
		tool, b, label = surface, sb, surface+":"+sb.NativeEvent
	}
	runToolGate(tool, label, b, body, truncated, configPath, hookStdout, os.Stderr)
}

// runToolGate answers one tool-gate event: it ALWAYS replies (the block,
// the dialect's allow, or a fail-closed block under enforcement) and marks
// the reply. Before the reply it loads the config and builds the guard and
// nothing else: no DB open on the allow path (the approval lookup opens
// the DB lazily, only for a verdict that would block).
//
// Failure semantics (audit section 5.7) follow the invocation's plan: an
// unreadable config, an unparseable payload or a guard that cannot be
// built blocks under enforcement and allows otherwise; a truncated payload
// is held (ask where the host asks, else deny) under enforcement.
func runToolGate(tool, label string, b integration.HookBinding, body []byte, truncated bool, configPath string, stdout, stderr io.Writer) {
	// A host that shows the hook's stderr as the block reason gets the
	// reason and nothing else there (T-048): Observer's diagnostics go
	// nowhere on such a dialect.
	diag := stderr
	if hook.ToolGateDialectStderrReason(b.Dialect) || hook.ToolGateDialectQuietStderr(b.Dialect) {
		diag = io.Discard
	}
	// A host that reads its reason from stdout and may turn stderr text into
	// a hook error (Copilot, WINNODE2 item 10) gets no stderr at all, the
	// block's diagnostic line included.
	gateStderr := stderr
	if hook.ToolGateDialectQuietStderr(b.Dialect) {
		gateStderr = io.Discard
	}
	fmt.Fprintf(diag, "observer-hook: event=%s received bytes=%d truncated=%v at=%s\n",
		label, len(body), truncated, time.Now().UTC().Format(time.RFC3339))
	noteHookPayload(body)
	cfg, stop, cfgErr := loadGateConfig(configPath, body, diag)
	if stop {
		return
	}
	req := hook.ToolGateRequest{
		Tool: tool, Dialect: b.Dialect, NativeEvent: b.NativeEvent, Label: label,
		Body: body, Truncated: truncated,
		Enforcing: hookPlanFailsClosed() || (cfgErr == nil && cfg.Guard.Enabled && cfg.Guard.Mode == "enforce"),
		// The block's verdict is marked decided before persist runs (review
		// M2-11), and a call the gate cannot classify is recorded after the
		// reply, rate-limited (review M2-12).
		Decided: markHookDecided,
		Unclassified: func(native string) {
			recordUnclassifiedToolGate(currentHookPlan(), native, hookPayloadSessionID(body), diag)
		},
		// The security pillar's facts and the dirty-marker raise, per
		// event, through the hook context seam (hook_security.go).
		Enrich: securityToolGateEnrich(configPath, tool, b.NativeEvent, hookSecurityAliases(cfg, cfgErr)),
	}
	if !truncated && hookPayloadUnparseable(body) && hookFailClosed(guardposture.KindUnparseable, body) {
		return
	}
	var res hook.ToolGateResult
	if cfgErr == nil && cfg.Guard.Enabled && cfg.Guard.Mode != "off" {
		if g := buildHookGuard(cfg, diag); g != nil {
			// A sibling dialect's firing of the same action (Devin Desktop:
			// PreToolUse and pre_run_command) is recorded once (FU-127).
			persist := recordSiblingGateOnce(tool, b, currentHookPlan().SpoolPath, makeGuardPersist(cfg, g, label, diag))
			res = hook.HandleToolGate(req, g, persist, stdout, gateStderr)
		} else if hookFailClosed(guardposture.KindGuardInit, body) {
			return
		}
	}
	// JSON whose fields the gate reads do not decode was not judged: under
	// enforcement it fails closed, never the dialect's allow (FU-161).
	if res.Undecodable && hookFailClosed(guardposture.KindUnparseable, body) {
		return
	}
	if res.Replied {
		// A dialect that blocks by exit code (Cascade, Kiro): the code is
		// decided with the reply (req.Decided already marked it before
		// persist; marking again is idempotent), then delivered.
		markHookDecided(res.ExitCode)
		if res.ExitCode != 0 {
			hookExit(res.ExitCode)
		}
		return
	}
	// The allow path: an allowed agent commit's trailer marker (audit
	// finding F3; a no-op unless the enrich step held one).
	provenanceAgentCommitAllowed()
	// A record-worthy flag rides the allow's developer notice field where
	// the binding declares one (integration.HookBinding.WarnField).
	hook.WriteToolGateAllowWarn(b.Dialect, res.WarnField, res.Warn, stdout)
	markHookReplied()
	if res.RecordAfterReply != nil {
		res.RecordAfterReply()
	}
}

// unclassifiedToolGateWindow is how often one (tool, event, native tool)
// unclassified record may be spooled: once per window across hook
// processes, so a host that keeps calling an unknown tool is visible without
// flooding guard_events.
const unclassifiedToolGateWindow = time.Hour

// recordUnclassifiedToolGate spools, rate-limited, a wired tool-gate call
// the gate could not classify (review M2-12): it went through unjudged,
// which must be visible (guard_events, the org push) rather than silent. It
// is not a hook failure (guardposture.KindUnclassified is outside
// FailureKinds) and never blocks.
func recordUnclassifiedToolGate(plan hookFailurePlan, native, sessionID string, stderr io.Writer) {
	if plan.SpoolPath == "" || !plan.Gated {
		return
	}
	key := plan.Tool + "\x00" + plan.Event + "\x00" + native
	if !guardposture.AllowOnce(guardposture.RateLimitDir(plan.SpoolPath), key, unclassifiedToolGateWindow, time.Now()) {
		return
	}
	if err := guardposture.Append(plan.SpoolPath, guardposture.Record{
		Tool: plan.Tool, Event: plan.Event, Cap: string(plan.Cap), SessionID: sessionID,
		Kind: guardposture.KindUnclassified, Outcome: guardposture.OutcomeFailOpen, Native: native,
	}); err != nil {
		fmt.Fprintf(stderr, "observer-hook: hook failure spool: %v\n", err)
	}
}

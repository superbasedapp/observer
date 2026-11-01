package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// Tool-gate probe (hook-parity Lane G, `observer doctor --probe-hook`): the
// tool-gate counterpart of the prompt probe in probehook.go. For every WIRED
// tool_gate binding it fires a synthetic tool call through the REGISTERED
// hook command exactly as the host would (`<binary> hook <tool> <event>`),
// and reports what came back. The call is a WRITE to a fake credential path
// under ~/.ssh (a name no real key ever has), which the built-in R-152 rule
// denies under enforcement and flags in observe mode. NOTHING IS EXECUTED:
// the probe hands the payload to the hook receiver directly, the receiver
// only evaluates it, and no host exists to run the tool. Each probe records
// one guard verdict under a recognisable "observer-doctor-probe-..." session
// id (the evidence that the gate evaluated), like the prompt probe.
//
// Payload and reply shapes are DATA keyed by the binding's reply dialect,
// never by tool: a dialect this table does not know gets the generic
// superset payload (Claude-shaped fields plus the camelCase and flat
// spellings) and the generic reply classifier, so a tool-gate dialect added
// by another lane is probed without an edit here.

// toolGateProbeFakeName is the fake file the probe "writes". It never exists
// and is never created.
const toolGateProbeFakeName = "observer-doctor-probe-fake-key-NEVER-WRITTEN"

// toolGateProbeContent is the fake body of the probe write.
const toolGateProbeContent = "observer doctor tool-gate probe: never written"

// toolGateProbePath is the fake credential path the probe targets.
func toolGateProbePath(home string) string {
	return filepath.Join(home, ".ssh", toolGateProbeFakeName)
}

// toolGateProbeInput is everything a payload builder may use.
type toolGateProbeInput struct {
	Event, SessionID, FakePath, Cwd string
}

// toolGateProbeShapes maps a tool-gate reply dialect to its payload builder.
// A builder returning nil means the event's operand cannot be probed with a
// synthetic path (an MCP call needs a pinned server, for example).
var toolGateProbeShapes = map[string]func(toolGateProbeInput) []byte{
	// Claude Code PreToolUse: a Write tool call.
	"claude-code-pretool": func(in toolGateProbeInput) []byte {
		return mustJSON(map[string]any{
			"session_id": in.SessionID, "cwd": in.Cwd, "hook_event_name": in.Event,
			"tool_name":  "Write",
			"tool_input": map[string]string{"file_path": in.FakePath, "content": toolGateProbeContent},
		})
	},
	// Cursor's permission channels: one payload shape per event.
	"cursor-permission": func(in toolGateProbeInput) []byte {
		base := map[string]any{"conversation_id": in.SessionID, "hook_event_name": in.Event, "workspace_roots": []string{in.Cwd}}
		switch in.Event {
		case "beforeShellExecution":
			base["command"] = "echo observer-doctor-probe > " + in.FakePath
			base["cwd"] = in.Cwd
		case "beforeReadFile":
			base["file_path"] = in.FakePath
			base["content"] = ""
		default:
			return nil
		}
		return mustJSON(base)
	},
	// The 2026-10-21 wave: dialects whose payload carries the tool under a
	// field the generic superset does not spell, or names it natively.
	// Dirac: the call sits under preToolUse.{toolName, parameters}.
	"dirac-pretool": func(in toolGateProbeInput) []byte {
		return mustJSON(map[string]any{
			"hookName": in.Event, "taskId": in.SessionID, "workspaceRoots": []string{in.Cwd},
			"preToolUse": map[string]any{"toolName": "write_to_file", "parameters": map[string]string{"path": in.FakePath, "content": toolGateProbeContent}},
		})
	},
	// Autohand pre-tool: native tool names, no session id.
	"autohand-pretool": func(in toolGateProbeInput) []byte {
		return mustJSON(map[string]any{
			"cwd": in.Cwd, "hook_event_name": in.Event, "tool_name": "write_file",
			"tool_input": map[string]string{"path": in.FakePath, "content": toolGateProbeContent},
		})
	},
	// Kimchi's bash pre-gate: the bash tool only, no session id.
	"kimchi-bash-pretool": func(in toolGateProbeInput) []byte {
		return mustJSON(map[string]any{
			"tool_name": "bash", "cwd": in.Cwd,
			"input": map[string]string{"command": "echo observer-doctor-probe > " + in.FakePath},
		})
	},
}

// genericToolGateProbe is the superset payload for a dialect the table does
// not know: the Claude-shaped fields plus camelCase and flat spellings of
// the session, tool and operand, so any JSON tool-gate dialect finds a write
// to the fake path in a field it reads.
func genericToolGateProbe(in toolGateProbeInput) []byte {
	input := map[string]string{"file_path": in.FakePath, "path": in.FakePath, "filePath": in.FakePath, "content": toolGateProbeContent}
	return mustJSON(map[string]any{
		"session_id": in.SessionID, "sessionId": in.SessionID, "conversation_id": in.SessionID,
		"cwd": in.Cwd, "hook_event_name": in.Event, "hookEventName": in.Event,
		"tool_name": "Write", "toolName": "Write", "tool": "write",
		"tool_input": input, "toolInput": input, "args": input, "input": input,
		"file_path": in.FakePath,
	})
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// toolGateProbePayload builds the payload for a binding.
func toolGateProbePayload(dialect string, in toolGateProbeInput) []byte {
	if f, ok := toolGateProbeShapes[dialect]; ok {
		return f(in)
	}
	return genericToolGateProbe(in)
}

// toolGateReplyRules is the ordered table the reply classifier walks: the
// first rule whose JSON path holds one of the blocking values wins. Generic
// across dialects (each vendor spells deny / ask in one of these fields).
var toolGateReplyRules = []struct {
	path   []string
	values []any
}{
	{[]string{"hookSpecificOutput", "permissionDecision"}, []any{"deny", "ask"}},
	{[]string{"hook_specific_output", "permission_decision"}, []any{"deny", "ask"}},
	{[]string{"permissionDecision"}, []any{"deny", "ask"}},
	{[]string{"permission_decision"}, []any{"deny", "ask"}},
	{[]string{"permission"}, []any{"deny", "ask"}},
	{[]string{"decision"}, []any{"deny", "block", "ask"}},
	{[]string{"action"}, []any{"deny", "block"}},
	{[]string{"cancel"}, []any{true}},
	{[]string{"continue"}, []any{false}},
}

// classifyToolGateReply reports whether a hook reply blocked (or asked about)
// the call: a non-zero exit (the exit-code dialects' block), or a JSON reply
// whose blocking field carries a deny / ask value.
func classifyToolGateReply(stdout []byte, exitCode int) (blocked bool, detail string) {
	if exitCode != 0 {
		return true, fmt.Sprintf("exit code %d", exitCode)
	}
	trimmed := bytes.TrimSpace(stdout)
	if len(trimmed) == 0 {
		return false, "empty reply"
	}
	var reply map[string]any
	if err := json.Unmarshal(trimmed, &reply); err != nil {
		return false, fmt.Sprintf("reply is not JSON (%q)", string(trimmed))
	}
	for _, r := range toolGateReplyRules {
		v, ok := jsonPath(reply, r.path)
		if !ok {
			continue
		}
		for _, want := range r.values {
			if v == want {
				return true, fmt.Sprintf("%s=%v", strings.Join(r.path, "."), v)
			}
		}
	}
	return false, "allow reply " + string(trimmed)
}

func jsonPath(m map[string]any, path []string) (any, bool) {
	var cur any = m
	for _, p := range path {
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = obj[p]; !ok {
			return nil, false
		}
	}
	return cur, true
}

// guardEventLookup reports the guard verdicts the probe's session recorded
// (rule ids), the evidence that the gate evaluated the call.
type guardEventLookup func(ctx context.Context, sessionID string) ([]string, error)

// toolGateProbeOutcome is the ordered decision table for one probe result.
var toolGateProbeOutcomes = []struct {
	match   func(blocked, evaluated, enforced bool) bool
	status  diag.Status
	message string // fmt: tool, event, detail
}{
	{
		func(b, _, _ bool) bool { return b }, diag.StatusOK,
		"%s %s: BLOCKED a synthetic write to a fake credential path (%s); the tool gate is live",
	},
	{
		func(b, e, enf bool) bool { return !b && e && !enf }, diag.StatusWarn,
		"%s %s: EVALUATED and allowed (%s): the gate recorded the call but tool-call enforcement is off, so an allow is expected",
	},
	{
		func(b, e, enf bool) bool { return !b && e && enf }, diag.StatusFail,
		"%s %s: evaluated but ALLOWED under enforcement (%s): an approval or policy override may cover the rule",
	},
	{
		func(b, e, _ bool) bool { return !b && !e }, diag.StatusFail,
		"%s %s: ALLOWED and nothing was recorded (%s): the receiver did not evaluate this event",
	},
}

// wiredToolGateBindings returns tool's wired tool_gate bindings, one per
// native event.
func wiredToolGateBindings(c integration.Capability) []integration.HookBinding {
	var out []integration.HookBinding
	seen := map[string]bool{}
	for _, b := range c.Hook.Bindings {
		if b.Cap != integration.HookCapToolGate || !b.Wired || seen[b.NativeEvent] {
			continue
		}
		seen[b.NativeEvent] = true
		out = append(out, b)
	}
	return out
}

// toolGateProbeCandidates is every registry tool with a wired tool_gate
// binding, sorted.
func toolGateProbeCandidates() []string {
	var out []string
	for _, c := range integration.Capabilities() {
		if len(wiredToolGateBindings(c)) > 0 {
			out = append(out, c.Tool)
		}
	}
	sort.Strings(out)
	return out
}

// hookArgvFor is the argv event `observer hook <tool> <argv>` a registered
// config invokes for native (the mechanism's spelling, hookArgvSpelling).
func hookArgvFor(m integration.HookMechanism, native string) string {
	if f, ok := hookArgvSpelling[m]; ok {
		return f(native)
	}
	return native
}

// toolGateEnforced reports whether tool-call enforcement is in force on this
// node, the same answer the hook's failure plan uses (posture when fresh,
// else the config and the signed bundle).
func toolGateEnforced(configPath string) bool {
	resolved, err := config.ResolveGlobalPath(configPath)
	if err != nil {
		return false
	}
	return hookPostureFailsClosedFn(resolved, configPath, integration.HookCapToolGate).FailsClosed
}

// probeHookHome resolves the home the probe's fake path sits under (the
// registration seam's pinned home in tests).
func probeHookHome(binary, configPath string) string {
	if h := hookRegistrationOptions(binary, configPath).HomeDir; h != "" {
		return h
	}
	h, _ := os.UserHomeDir()
	return h
}

// runToolGateProbes fires the synthetic call through each wired tool_gate
// binding of tool: one check per binding.
func runToolGateProbes(ctx context.Context, binary, configPath, tool string, lookup guardEventLookup) []diag.Check {
	c, ok := integration.For(tool)
	if !ok {
		return []diag.Check{{Name: "guard.tool.probe:" + tool, Status: diag.StatusWarn, Message: fmt.Sprintf("%q is not a registry adapter", tool)}}
	}
	bindings := wiredToolGateBindings(c)
	if len(bindings) == 0 {
		return []diag.Check{{
			Name: "guard.tool.probe:" + tool, Status: diag.StatusWarn,
			Message: fmt.Sprintf("%s: no wired tool-gate hook to probe (see `observer adapters --hooks`)", tool),
		}}
	}
	if cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath}); err == nil && (!cfg.Guard.Enabled || cfg.Guard.Mode == "off") {
		return []diag.Check{{
			Name: "guard.tool.probe:" + tool, Status: diag.StatusWarn,
			Message: fmt.Sprintf("%s: the guard is off ([guard] enabled=false or mode=\"off\"), so no tool gate evaluates; nothing to probe", tool),
		}}
	}
	enforced := toolGateEnforced(configPath)
	out := make([]diag.Check, 0, len(bindings))
	for _, b := range bindings {
		out = append(out, runToolGateProbe(ctx, binary, configPath, c, b, enforced, lookup))
	}
	return out
}

// runToolGateProbe probes one binding.
func runToolGateProbe(ctx context.Context, binary, configPath string, c integration.Capability, b integration.HookBinding, enforced bool, lookup guardEventLookup) diag.Check {
	tool := c.Tool
	name := "guard.tool.probe:" + tool + ":" + b.NativeEvent
	if !c.Hook.AutoWired {
		return diag.Check{
			Name: name, Status: diag.StatusWarn,
			Message: fmt.Sprintf("%s %s: documented, not auto-wired: no registration writer exists to check a live install against", tool, b.NativeEvent),
		}
	}
	if c.Hook.Mechanism.PerEventConfig() {
		homes := checkHookRegistrationHomes(binary, configPath, tool, b.NativeEvent)
		winner := hookHomeOverallState(homes)
		switch {
		case winner.err != nil:
			return diag.Check{Name: name, Status: diag.StatusFail, Message: fmt.Sprintf("%s %s: could not determine hook registration: %v", tool, b.NativeEvent, winner.err)}
		case winner.state == hookRegNotRegistered:
			return diag.Check{
				Name: name, Status: diag.StatusFail,
				Message: fmt.Sprintf("%s %s: NOT REGISTERED, so the tool gate never sees this tool's calls (%s)", tool, b.NativeEvent, hookHomesSummary(homes)),
				Details: []string{"remedy: " + autoRegisterRemediation(tool)},
			}
		case winner.state == hookRegConflict:
			return diag.Check{
				Name: name, Status: diag.StatusFail,
				Message: fmt.Sprintf("%s %s: NOT REGISTERED, a non-observer hook occupies the event (%s)", tool, b.NativeEvent, hookHomesSummary(homes)),
			}
		}
	}
	sessionID := probeHookSessionID()
	cwd, _ := os.Getwd()
	payload := toolGateProbePayload(b.Dialect, toolGateProbeInput{
		Event: b.NativeEvent, SessionID: sessionID, FakePath: toolGateProbePath(probeHookHome(binary, configPath)), Cwd: cwd,
	})
	if payload == nil {
		return diag.Check{
			Name: name, Status: diag.StatusWarn,
			Message: fmt.Sprintf("%s %s: no synthetic probe for this event's operand (it needs a real target, e.g. a pinned MCP server); registration is fine", tool, b.NativeEvent),
		}
	}
	argv := hookArgvFor(c.Hook.Mechanism, b.NativeEvent)
	args := []string{"hook", tool, argv}
	if configPath != "" {
		args = append(args, "--config", configPath)
	}
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(probeCtx, binary, args...) //nolint:gosec // G204: binary is this process's own path; args are the registered hook argv for a registry binding
	cmd.Stdin = bytes.NewReader(payload)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	runErr := cmd.Run()
	if probeCtx.Err() != nil {
		return diag.Check{Name: name, Status: diag.StatusFail, Message: fmt.Sprintf("probe timed out invoking `%s %s`: the hook receiver may be hung", binary, strings.Join(args, " "))}
	}
	exitCode := 0
	var exitErr *exec.ExitError
	switch {
	case runErr == nil:
	case errors.As(runErr, &exitErr):
		exitCode = exitErr.ExitCode()
	default:
		return diag.Check{
			Name: name, Status: diag.StatusFail, Message: fmt.Sprintf("probe failed to invoke `%s %s`: %v", binary, strings.Join(args, " "), runErr),
			Details: []string{"stderr: " + stderr.String()},
		}
	}
	blocked, detail := classifyToolGateReply(stdout.Bytes(), exitCode)
	var rules []string
	if lookup != nil {
		rules, _ = lookup(ctx, sessionID)
	}
	evaluated := len(rules) > 0
	if evaluated {
		detail += "; recorded " + strings.Join(rules, ", ")
	}
	for _, o := range toolGateProbeOutcomes {
		if o.match(blocked, evaluated, enforced) {
			ck := diag.Check{Name: name, Status: o.status, Message: fmt.Sprintf(o.message, tool, b.NativeEvent, detail)}
			if o.status != diag.StatusOK {
				ck.Details = []string{"session: " + sessionID, "stderr: " + strings.TrimSpace(stderr.String())}
			}
			return ck
		}
	}
	return diag.Check{Name: name, Status: diag.StatusFail, Message: tool + " " + b.NativeEvent + ": unclassified probe result"}
}

package hook

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// HandleGuarded is the guarded counterpart of HandleApprove for Claude
// Code's PreToolUse (guard spec §3.2 seam 1, §6.1): the Claude Code row of
// the tool-gate dialect table, served by the one generalized handler
// (HandleToolGate). HandleApprove remains the path for [guard]
// enabled=false.
//
// Reply-ownership contract: HandleGuarded writes to stdout ONLY when
// it blocks (deny/ask emission) — it then returns blocked=true and
// has already run the persist callback (the reply went out first,
// spec §6.4). On the allow/flag path it writes NOTHING (the caller
// owns the approve/rewrite reply) and returns a non-nil
// recordAfterReply when a record-worthy verdict needs persisting —
// the caller invokes it AFTER encoding its own reply, preserving the
// reply-before-persist ordering on every path.
//
// persist is nil-tolerant and must never panic; it is invoked at most
// once. The cmd layer implements it as a lazy DB open + one
// store.PersistGuardVerdicts call so the SQLite/migration cost never
// lands before a reply (spec §6.4 latency budget).
func HandleGuarded(
	event string,
	body []byte,
	ev guard.Evaluator,
	persist func(guard.ActionVerdict),
	stdout, stderr io.Writer,
) (blocked bool, recordAfterReply func()) {
	return HandleGuardedDecided(event, body, ev, persist, nil, stdout, stderr)
}

// HandleGuardedDecided is HandleGuarded with ToolGateRequest.Decided: on a
// block, decided runs right after the reply is written and before persist,
// so the cmd layer marks the reply sent before any work that could panic or
// outlive the watchdog (review M2-11). A nil decided is HandleGuarded.
func HandleGuardedDecided(
	event string,
	body []byte,
	ev guard.Evaluator,
	persist func(guard.ActionVerdict),
	decided func(exitCode int),
	stdout, stderr io.Writer,
) (blocked bool, recordAfterReply func()) {
	res := HandleGuardedResult(event, body, ev, persist, decided, stdout, stderr)
	return res.Replied, res.RecordAfterReply
}

// HandleGuardedResult is HandleGuardedDecided returning the whole
// ToolGateResult, so the caller can add a flag's developer notice
// (Warn / WarnField, via WithWarnField) to its own approve or rewrite
// reply.
func HandleGuardedResult(
	event string,
	body []byte,
	ev guard.Evaluator,
	persist func(guard.ActionVerdict),
	decided func(exitCode int),
	stdout, stderr io.Writer,
) ToolGateResult {
	return HandleGuardedEnriched(event, body, ev, persist, decided, nil, stdout, stderr)
}

// HandleGuardedEnriched is HandleGuardedResult with ToolGateRequest.Enrich:
// the cmd layer fills the security pillar's facts on each event before it
// is evaluated, as every other tool gate does (lane sec-gate2: Claude
// Code's PreToolUse ran no enrich, so the commit gate and S-721 never
// fired there). A nil enrich is HandleGuardedResult.
func HandleGuardedEnriched(
	event string,
	body []byte,
	ev guard.Evaluator,
	persist func(guard.ActionVerdict),
	decided func(exitCode int),
	enrich func(*policy.Event),
	stdout, stderr io.Writer,
) ToolGateResult {
	return HandleToolGate(ToolGateRequest{
		Tool: models.ToolClaudeCode, Dialect: ToolGateDialectClaudeCode,
		NativeEvent: "PreToolUse", Label: event, Body: body, Decided: decided, Enrich: enrich,
	}, ev, persist, stdout, stderr)
}

// HandleTruncatedPreTool is the fail-closed branch for a Claude Code
// PreToolUse payload the caller could NOT read in full (security review
// 2026-09-27, SR27-D2). A truncated body fails json.Unmarshal, and
// HandleGuarded treats "not an evaluable shape" as approve - so before
// this branch a Write/Edit whose content pushed the payload past the read
// bound (e.g. an Edit of ~/.claude/settings.json or ~/.bashrc) was
// approved WITHOUT evaluation even when an enforce-mode deny rule covered
// its target. When the guard is enforcing, the call is held for the human
// (ask) rather than approved; when it is not enforcing (observe / off),
// nothing is written and the caller keeps its normal approve path. The
// generalized form is HandleToolGate's Truncated request field.
//
// Returns true when it wrote the ask reply (the caller must not write
// another).
func HandleTruncatedPreTool(event string, enforcing bool, stdout, stderr io.Writer) bool {
	return handleTruncatedToolGate(ToolGateRequest{
		Tool: models.ToolClaudeCode, Dialect: ToolGateDialectClaudeCode,
		NativeEvent: "PreToolUse", Label: event, Truncated: true, Enforcing: enforcing,
	}, stdout, stderr).Replied
}

// claudeCodeBlockReply is the §6.2 Claude Code decision shape: the
// modern hookSpecificOutput.permissionDecision contract plus the
// legacy top-level decision/reason fields, emitted TOGETHER in one
// object for a DENY (documented compatible: new clients prefer the modern
// field, old clients only read the legacy one). An ASK carries the modern
// field alone: the legacy protocol has no ask, and the live audit
// (2026-10-15) found that the legacy decision:"block" sent beside
// permissionDecision:"ask" turned the native ask into a block, so the
// developer was never asked.
type claudeCodeBlockReply struct {
	Decision           string                  `json:"decision,omitempty"`
	Reason             string                  `json:"reason,omitempty"`
	HookSpecificOutput claudeCodePermissionOut `json:"hookSpecificOutput"`
}

// claudeCodePermissionOut is the modern PreToolUse decision envelope.
type claudeCodePermissionOut struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason"`
}

// buildClaudeCodeBlockReply assembles the reply for a blocking emission:
// the dual shape for a deny, the modern permissionDecision alone for an
// ask (the native ask prompt).
func buildClaudeCodeBlockReply(em guard.Emission) claudeCodeBlockReply {
	r := claudeCodeBlockReply{
		HookSpecificOutput: claudeCodePermissionOut{
			HookEventName:            "PreToolUse",
			PermissionDecision:       em.Permission,
			PermissionDecisionReason: em.Reason,
		},
	}
	if em.Permission != "ask" {
		r.Decision, r.Reason = "block", em.Reason
	}
	return r
}

// guardedPreToolPayload is the subset of the Claude Code PreToolUse
// payload the guard event needs.
type guardedPreToolPayload struct {
	SessionID string `json:"session_id"`
	Cwd       string `json:"cwd"`
	ToolName  string `json:"tool_name"`
	ToolInput struct {
		Command      string `json:"command"`
		FilePath     string `json:"file_path"`
		NotebookPath string `json:"notebook_path"`
		Path         string `json:"path"`
		URL          string `json:"url"`
		Query        string `json:"query"`
	} `json:"tool_input"`
}

// claudeCodePreToolCaps are the Claude Code PreToolUse channel
// capabilities: pre-execution, full block + native ask support. Data
// resolved at this boundary (spec §3.3); the G6 conformance matrix
// centralizes the per-client values.
var claudeCodePreToolCaps = policy.Capabilities{
	PreExecution: true,
	CanBlock:     true,
	CanAsk:       true,
}

// claudeToolShape maps a Claude Code tool name onto the policy event
// vocabulary. Table-driven (Module rule 5); the target selector keys
// off which tool_input field carries the operand.
//
// Every Claude Code tool that runs a shell command or returns file content
// needs a row here: a tool with no row is approved WITHOUT evaluation, so a
// missing row is a guard bypass (security review 2026-09-27, SR27-D1 -
// Monitor and PowerShell run a command, Grep returns file content).
var claudeToolShape = map[string]struct {
	kind       policy.EventKind
	actionType string
	target     func(*guardedPreToolPayload) string
	dialect    policy.Dialect // "" = posix
}{
	"Bash": {
		kind: policy.KindShellExec, actionType: models.ActionRunCommand,
		target: func(p *guardedPreToolPayload) string { return p.ToolInput.Command },
	},
	// Monitor runs its `command` as a background shell script whose stdout
	// streams back as events - the same exec surface as Bash.
	"Monitor": {
		kind: policy.KindShellExec, actionType: models.ActionRunCommand,
		target: func(p *guardedPreToolPayload) string { return p.ToolInput.Command },
	},
	// The Windows-native PowerShell tool (and its lower-case aliases, the
	// same spellings internal/tooltax classifies as run_command).
	"PowerShell": {
		kind: policy.KindShellExec, actionType: models.ActionRunCommand,
		target:  func(p *guardedPreToolPayload) string { return p.ToolInput.Command },
		dialect: policy.DialectPowerShell,
	},
	"powershell": {
		kind: policy.KindShellExec, actionType: models.ActionRunCommand,
		target:  func(p *guardedPreToolPayload) string { return p.ToolInput.Command },
		dialect: policy.DialectPowerShell,
	},
	"pwsh": {
		kind: policy.KindShellExec, actionType: models.ActionRunCommand,
		target:  func(p *guardedPreToolPayload) string { return p.ToolInput.Command },
		dialect: policy.DialectPowerShell,
	},
	// Grep with output_mode "content" returns file bytes, so its path is a
	// read for the sensitive-path rules. A Grep with no path searches cwd
	// (empty target -> not evaluated, as before).
	"Grep": {
		kind: policy.KindFileAccess, actionType: models.ActionReadFile,
		target: func(p *guardedPreToolPayload) string { return p.ToolInput.Path },
	},
	"Write": {
		kind: policy.KindFileAccess, actionType: models.ActionWriteFile,
		target: func(p *guardedPreToolPayload) string { return p.ToolInput.FilePath },
	},
	"Edit": {
		kind: policy.KindFileAccess, actionType: models.ActionEditFile,
		target: func(p *guardedPreToolPayload) string { return p.ToolInput.FilePath },
	},
	"MultiEdit": {
		kind: policy.KindFileAccess, actionType: models.ActionEditFile,
		target: func(p *guardedPreToolPayload) string { return p.ToolInput.FilePath },
	},
	// Claude Code's NotebookEdit names its operand notebook_path (file_path
	// kept as a fallback for older payloads).
	"NotebookEdit": {
		kind: policy.KindFileAccess, actionType: models.ActionEditFile,
		target: func(p *guardedPreToolPayload) string {
			if p.ToolInput.NotebookPath != "" {
				return p.ToolInput.NotebookPath
			}
			return p.ToolInput.FilePath
		},
	},
	"Read": {
		kind: policy.KindFileAccess, actionType: models.ActionReadFile,
		target: func(p *guardedPreToolPayload) string { return p.ToolInput.FilePath },
	},
	"WebFetch": {
		kind: policy.KindToolCall, actionType: models.ActionWebFetch,
		target: func(p *guardedPreToolPayload) string { return p.ToolInput.URL },
	},
	"WebSearch": {
		kind: policy.KindToolCall, actionType: models.ActionWebSearch,
		target: func(p *guardedPreToolPayload) string { return p.ToolInput.Query },
	},
}

// BuildClaudeCodeEvent extracts a policy.Event from a Claude Code
// PreToolUse payload. ok=false means the payload isn't an evaluable
// tool shape (unknown tool, missing operand, unparsable JSON) — the
// caller approves as before; unknown is never a violation.
//
// Boundary notes (documented approximations):
//   - ProjectRoot stays EMPTY on the hook path: the payload carries
//     only cwd, and treating cwd as the project root would
//     false-positive R-150 whenever the agent works from a subdir.
//     Outside-project / cross-project / taint-write rules are
//     therefore inert pre-execution; the watcher evaluates the same
//     action post-hoc seconds later with the real root. Cwd IS set,
//     so relative targets still resolve for the home-anchored rules
//     (sensitive paths, persistence vectors).
//   - Dialect stays posix for Bash/Monitor: Claude Code's Bash tool runs
//     a POSIX shell on every platform (Git-Bash on Windows); nested
//     powershell/cmd payloads are detected mid-parse regardless. The
//     Windows-native PowerShell tool rows set DialectPowerShell.
//   - mcp__<server>__<tool> names classify as mcp_call with the full
//     name as Target (MCPServerFromTarget parses the server out).
//   - A leading UTF-8 BOM (a .NET / PowerShell stdin writer's) is stripped
//     here too, so no caller's untrimmed copy reads as unparseable (FU-161).
func BuildClaudeCodeEvent(body []byte) (policy.Event, bool) {
	ev, ok, _ := buildClaudeCodeEvent(body)
	return ev, ok
}

// buildClaudeCodeEvent is BuildClaudeCodeEvent that also says whether a
// not-ok payload is undecodable (FU-161): JSON that is not an object, a
// session / cwd / tool name of the wrong type, or, for a tool the gate
// judges, a tool_input that is not an object or whose operand fields have
// the wrong type. An MCP tool's input is never decoded here (its target is
// its name), so an MCP server's own argument types never read as
// undecodable. undecodable is false for an unknown tool or a missing
// operand: those pass, as before.
func buildClaudeCodeEvent(body []byte) (ev policy.Event, ok, undecodable bool) {
	body = bytes.TrimPrefix(body, utf8BOM)
	var top struct {
		SessionID string          `json:"session_id"`
		Cwd       string          `json:"cwd"`
		ToolName  string          `json:"tool_name"`
		ToolInput json.RawMessage `json:"tool_input"`
	}
	if err := json.Unmarshal(body, &top); err != nil {
		return policy.Event{}, false, true
	}
	if top.ToolName == "" {
		return policy.Event{}, false, false
	}
	p := guardedPreToolPayload{SessionID: top.SessionID, Cwd: top.Cwd, ToolName: top.ToolName}
	if _, judged := claudeToolShape[p.ToolName]; judged {
		if rawNotObject(top.ToolInput) {
			return policy.Event{}, false, true
		}
		if t := bytes.TrimSpace(top.ToolInput); len(t) > 0 && !bytes.Equal(t, []byte("null")) {
			if err := json.Unmarshal(t, &p.ToolInput); err != nil {
				return policy.Event{}, false, true
			}
		}
	}
	ev, ok = claudeCodeEventFrom(&p, body)
	return ev, ok, false
}

// claudeCodeEventFrom builds the policy event from a decoded payload.
func claudeCodeEventFrom(p *guardedPreToolPayload, body []byte) (policy.Event, bool) {
	ev := policy.Event{
		Tool:      models.ToolClaudeCode,
		SessionID: p.SessionID,
		Cwd:       p.Cwd,
		Caps:      claudeCodePreToolCaps,
		Now:       time.Now().UTC(),
	}
	ev.Caps.Sandboxed = sandboxedChild()
	if shape, ok := claudeToolShape[p.ToolName]; ok {
		ev.Kind = shape.kind
		ev.ActionType = shape.actionType
		ev.Target = shape.target(p)
		ev.Dialect = shape.dialect
		if ev.Target == "" {
			return policy.Event{}, false
		}
		if isWriteAction(ev.ActionType) {
			ev.Edits = proposedEditsIn(toolInputMap(body))
		}
		return ev, true
	}
	if strings.HasPrefix(p.ToolName, "mcp__") {
		ev.Kind = policy.KindMCPCall
		ev.ActionType = models.ActionMCPCall
		ev.Target = p.ToolName
		return ev, true
	}
	return policy.Event{}, false
}

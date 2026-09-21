package hook

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// HandleGuarded is the guarded counterpart of HandleApprove for
// pre-execution hook channels (guard spec §3.2 seam 1, §6.1): parse
// the payload into a policy.Event, evaluate, and — when the verdict
// requires blocking or asking — write the client's decision JSON.
// HandleApprove remains the path for [guard] enabled=false.
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
	pe, ok := BuildClaudeCodeEvent(body)
	if !ok {
		// Not an evaluable tool shape: nothing to judge, caller
		// proceeds with its normal approve path.
		return false, nil
	}
	verdict, recordWorthy := ev.EvaluateHook(pe)
	em := guard.ResolveEmission(verdict.Verdict, pe.Caps)
	// Human first, agent second (org guardrail control wave, Track B):
	// under an org bundle a blocking reason leads with one plain
	// sentence naming the override command (or saying the rule is
	// locked). A no-op on an individual node, so the wire reply stays
	// byte-identical there.
	em = guard.HumanizeEmission(em, verdict, pe.SessionID)
	verdict.Enforced = em.Enforced
	if em.DegradedFrom != "" {
		// Don't clobber a marker EvaluateHook already set (the §6.3
		// "approved" exception marker) with the empty no-degradation
		// case.
		verdict.DegradedFrom = em.DegradedFrom
	}

	doPersist := func() {
		if persist != nil {
			persist(verdict)
		}
	}
	logForensics := func(action string) {
		appendHookEventLog(hookEvent{
			Event:        event,
			Bytes:        len(body),
			SessionID:    pe.SessionID,
			Tool:         payloadFieldString(body, "tool_name"),
			Action:       action,
			RuleID:       verdict.Verdict.RuleID,
			Decision:     verdict.Verdict.Decision.String(),
			Severity:     verdict.Verdict.Severity.String(),
			DegradedFrom: em.DegradedFrom,
		})
	}

	if em.Permission == "ask" || em.Permission == "deny" {
		// Reply FIRST (machine-parsable reason — agents read it and
		// self-correct), then forensics + DB.
		_ = json.NewEncoder(stdout).Encode(buildClaudeCodeBlockReply(em))
		fmt.Fprintf(stderr, "observer-hook: %s guard %s (%s: %s)\n",
			event, em.Permission, verdict.Verdict.RuleID, verdict.Verdict.Reason)
		logForensics("guard:" + em.Permission)
		doPersist()
		return true, nil
	}

	if !recordWorthy {
		return false, nil
	}
	// Flag-class (or degraded) verdict on the allow path: record it,
	// but only after the caller's reply.
	logForensics("approve+flag")
	return false, doPersist
}

// claudeCodeBlockReply is the §6.2 Claude Code decision shape: the
// modern hookSpecificOutput.permissionDecision contract plus the
// legacy top-level decision/reason fields, emitted TOGETHER in one
// object (documented compatible — new clients prefer the modern
// field, old clients only read the legacy one; an ask maps to legacy
// "block" since the legacy protocol has no ask).
type claudeCodeBlockReply struct {
	Decision           string                  `json:"decision"`
	Reason             string                  `json:"reason"`
	HookSpecificOutput claudeCodePermissionOut `json:"hookSpecificOutput"`
}

// claudeCodePermissionOut is the modern PreToolUse decision envelope.
type claudeCodePermissionOut struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason"`
}

// buildClaudeCodeBlockReply assembles the dual-shape reply for a
// blocking emission.
func buildClaudeCodeBlockReply(em guard.Emission) claudeCodeBlockReply {
	return claudeCodeBlockReply{
		Decision: "block",
		Reason:   em.Reason,
		HookSpecificOutput: claudeCodePermissionOut{
			HookEventName:            "PreToolUse",
			PermissionDecision:       em.Permission,
			PermissionDecisionReason: em.Reason,
		},
	}
}

// guardedPreToolPayload is the subset of the Claude Code PreToolUse
// payload the guard event needs.
type guardedPreToolPayload struct {
	SessionID string `json:"session_id"`
	Cwd       string `json:"cwd"`
	ToolName  string `json:"tool_name"`
	ToolInput struct {
		Command  string `json:"command"`
		FilePath string `json:"file_path"`
		URL      string `json:"url"`
		Query    string `json:"query"`
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
var claudeToolShape = map[string]struct {
	kind       policy.EventKind
	actionType string
	target     func(*guardedPreToolPayload) string
}{
	"Bash": {
		policy.KindShellExec, models.ActionRunCommand,
		func(p *guardedPreToolPayload) string { return p.ToolInput.Command },
	},
	"Write": {
		policy.KindFileAccess, models.ActionWriteFile,
		func(p *guardedPreToolPayload) string { return p.ToolInput.FilePath },
	},
	"Edit": {
		policy.KindFileAccess, models.ActionEditFile,
		func(p *guardedPreToolPayload) string { return p.ToolInput.FilePath },
	},
	"MultiEdit": {
		policy.KindFileAccess, models.ActionEditFile,
		func(p *guardedPreToolPayload) string { return p.ToolInput.FilePath },
	},
	"NotebookEdit": {
		policy.KindFileAccess, models.ActionEditFile,
		func(p *guardedPreToolPayload) string { return p.ToolInput.FilePath },
	},
	"Read": {
		policy.KindFileAccess, models.ActionReadFile,
		func(p *guardedPreToolPayload) string { return p.ToolInput.FilePath },
	},
	"WebFetch": {
		policy.KindToolCall, models.ActionWebFetch,
		func(p *guardedPreToolPayload) string { return p.ToolInput.URL },
	},
	"WebSearch": {
		policy.KindToolCall, models.ActionWebSearch,
		func(p *guardedPreToolPayload) string { return p.ToolInput.Query },
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
//   - Dialect stays posix: Claude Code's Bash tool runs a POSIX shell
//     on every platform (Git-Bash on Windows); nested
//     powershell/cmd payloads are detected mid-parse regardless.
//   - mcp__<server>__<tool> names classify as mcp_call with the full
//     name as Target (MCPServerFromTarget parses the server out).
func BuildClaudeCodeEvent(body []byte) (policy.Event, bool) {
	var p guardedPreToolPayload
	if err := json.Unmarshal(body, &p); err != nil || p.ToolName == "" {
		return policy.Event{}, false
	}
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
		ev.Target = shape.target(&p)
		if ev.Target == "" {
			return policy.Event{}, false
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

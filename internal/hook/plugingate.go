package hook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/tooltax"
)

// Plugin-host dialects (hook-parity audit 2026-10-02, Lane D). Every
// in-process plugin host (the internal/hook/pluginshim TypeScript shim and
// the Hermes Python plugin) speaks ONE wire shape to `observer hook <tool>
// <event>`: a normalized JSON envelope on stdin, a {"decision": ...} reply
// on stdout, exit 0. The plugin maps the reply onto its host's own contract
// (throw, a returned block object, a replaced message), so the dialect is a
// property of the transport, not of any vendor.
const (
	// PluginDialectToolGate is the plugin hosts' tool-gate dialect.
	PluginDialectToolGate = "plugin-shim"
	// PromptDialectPluginShim is the plugin hosts' prompt-gate dialect for
	// a seam that can stop the prompt and show a notice but has no native
	// confirm (OpenCode / Kilo CLI chat.message: the shim throws, so the
	// model is never called, and toasts the reason).
	PromptDialectPluginShim = "plugin-shim-prompt"
	// PromptDialectPluginShimConfirm is the plugin hosts' prompt-gate
	// dialect for a seam that can also open a native confirm dialog and
	// rewrite the prompt (pi `input`: {action:"handled"} stops it,
	// ctx.ui.confirm asks, {action:"transform"} rewrites). Where the host
	// has no UI the shim answers a confirm as a stop the developer resends
	// to confirm, the same reconsider-once flow re-enter uses.
	PromptDialectPluginShimConfirm = "plugin-shim-prompt-confirm"
)

// PluginReply is the plugin dialect's reply. Decision is allow, deny, ask
// or modify; Message, on an allow or a modify, is a notice the shim shows
// the developer (a guard warning or flag) without stopping anything;
// Enforced tells the plugin whether guard enforcement was in force for this
// capability, so a later failure to reach observer at all can fail closed
// (or open) the same way observer would have.
type PluginReply struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason,omitempty"`
	Prompt   string `json:"prompt,omitempty"`
	Message  string `json:"message,omitempty"`
	// Enforced is nil when the replying dialect does not know (the prompt
	// replies); the plugin then falls back to the posture file.
	Enforced *bool `json:"enforced,omitempty"`
}

// EnforcedHint returns v as a PluginReply.Enforced value.
func EnforcedHint(v bool) *bool { return &v }

// WritePluginReply writes r as one JSON line.
func WritePluginReply(w io.Writer, r PluginReply) {
	_ = json.NewEncoder(w).Encode(r)
}

// pluginEnvelope is the normalized payload every plugin sends.
type pluginEnvelope struct {
	Host      string          `json:"host"`
	Event     string          `json:"event"`
	SessionID string          `json:"session_id"`
	Cwd       string          `json:"cwd"`
	PID       int             `json:"pid"`
	ToolName  string          `json:"tool_name"`
	ToolInput json.RawMessage `json:"tool_input"`
	CallID    string          `json:"call_id"`
	Prompt    *string         `json:"prompt"`
}

// pluginOperandKeys maps each tooltax operand selector to the input field
// spellings the plugin hosts use for it, first match wins. Hosts pass the
// tool's own argument object through untouched (OpenCode `filePath`, pi
// `path`, Hermes `path`, OpenClaw `command`), so the selector, not the
// host, decides which keys are tried. Data, one row per operand.
var pluginOperandKeys = map[string][]string{
	tooltax.OperandCommand:      {"command", "cmd"},
	tooltax.OperandFilePath:     {"file_path", "filePath", "path", "file", "filename", "target_file"},
	tooltax.OperandNotebookPath: {"notebook_path", "notebookPath"},
	tooltax.OperandPath:         {"path", "dir", "directory"},
	tooltax.OperandURL:          {"url", "uri"},
	tooltax.OperandQuery:        {"query", "q"},
}

// pluginShellDialects marks the native shell tool names that run
// PowerShell rather than a POSIX shell (internal/tooltax spells them the
// same way for every host).
var pluginShellDialects = map[string]policy.Dialect{
	"powershell": policy.DialectPowerShell,
	"pwsh":       policy.DialectPowerShell,
}

// BuildPluginToolEvent extracts a policy.Event from a plugin envelope. The
// native tool name is classified through internal/tooltax for this tool id
// (action type + operand selector); the operand value comes from the tool
// input by pluginOperandKeys. ok=false: not an evaluable shape (unknown
// tool, no operand, not JSON); the caller allows, as unknown is never a
// violation.
//
// This is the narrow seam onto Lane A's generalized tool-gate builder
// (hook.HandleToolGate + its dialect table): when that lands, the
// integration step may route this extraction through it.
func BuildPluginToolEvent(tool string, body []byte, caps policy.Capabilities) (policy.Event, bool) {
	var env pluginEnvelope
	if err := json.Unmarshal(bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF}), &env); err != nil || env.ToolName == "" {
		return policy.Event{}, false
	}
	ev := policy.Event{
		Tool:      tool,
		SessionID: env.SessionID,
		Cwd:       env.Cwd,
		Caps:      caps,
		Now:       time.Now().UTC(),
	}
	ev.Caps.Sandboxed = sandboxedChild()
	if tooltax.IsMCPToolName(env.ToolName) {
		ev.Kind, ev.ActionType, ev.Target = policy.KindMCPCall, models.ActionMCPCall, env.ToolName
		return ev, true
	}
	row, ok := tooltax.Resolve(tool, env.ToolName)
	if !ok || row.Operand == tooltax.OperandNone {
		return policy.Event{}, false
	}
	kind, ok := guard.ClassifyActionType(row.ActionType)
	if !ok {
		return policy.Event{}, false
	}
	ev.Kind, ev.ActionType = kind, row.ActionType
	if row.Operand == tooltax.OperandMCPName {
		ev.Target = env.ToolName
	} else {
		ev.Target = pluginOperand(env.ToolInput, row.Operand)
	}
	if ev.Target == "" {
		return policy.Event{}, false
	}
	if isWriteAction(ev.ActionType) {
		// The proposed content, so the in-hook secret scan (S-721) reads
		// what the write would add, as on the Claude Code gate.
		ev.Edits = proposedEditsIn(toolInputMap(body))
	}
	ev.Dialect = pluginShellDialects[strings.ToLower(env.ToolName)]
	ev.AltDialect = unstatedShellAltDialect(ev.Kind, ev.Dialect, ev.Cwd)
	return ev, true
}

// pluginOperand reads the first non-empty string field for operand.
func pluginOperand(input json.RawMessage, operand string) string {
	if len(input) == 0 {
		return ""
	}
	var m map[string]any
	if json.Unmarshal(input, &m) != nil {
		return ""
	}
	for _, k := range pluginOperandKeys[operand] {
		if s, ok := m[k].(string); ok && strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

// HandlePluginToolGate is the plugin dialect's tool gate: build the event,
// evaluate, resolve the emission against caps, and write the plugin reply
// (deny / ask, or allow). It ALWAYS writes exactly one reply. persist runs
// before returning on a block (the reply went out first); on the allow path
// a record-worthy verdict is returned as recordAfterReply for the caller.
// enforced is carried in the reply as the plugin's hint (see PluginReply).
func HandlePluginToolGate(
	tool, event string,
	body []byte,
	caps policy.Capabilities,
	enforced bool,
	ev guard.Evaluator,
	persist func(guard.ActionVerdict),
	stdout, stderr io.Writer,
) (blocked bool, recordAfterReply func()) {
	return HandlePluginToolGateEnriched(tool, event, body, caps, enforced, ev, persist, nil, stdout, stderr)
}

// HandlePluginToolGateEnriched is HandlePluginToolGate with an enrich step
// (ToolGateRequest.Enrich's contract): the cmd layer fills the security
// pillar's facts on the event before it is evaluated (lane sec-gate2). A
// nil enrich is HandlePluginToolGate.
func HandlePluginToolGateEnriched(
	tool, event string,
	body []byte,
	caps policy.Capabilities,
	enforced bool,
	ev guard.Evaluator,
	persist func(guard.ActionVerdict),
	enrich func(*policy.Event),
	stdout, stderr io.Writer,
) (blocked bool, recordAfterReply func()) {
	return HandlePluginToolGateAllow(tool, event, body, caps, enforced, ev, persist, enrich, nil, stdout, stderr)
}

// HandlePluginToolGateAllow is HandlePluginToolGateEnriched with an allow
// seam (lane SEC-F2B, decision log P-078 ruling 4): onAllow runs once
// guard allowed the call, after the decision and BEFORE the allow reply is
// written, so whatever it records exists when the plugin reads the reply
// (the shim's earlier call after the reply left a small race). It never
// runs for an ask, a deny or an event that could not be built. A nil
// onAllow is HandlePluginToolGateEnriched.
func HandlePluginToolGateAllow(
	tool, event string,
	body []byte,
	caps policy.Capabilities,
	enforced bool,
	ev guard.Evaluator,
	persist func(guard.ActionVerdict),
	enrich func(*policy.Event),
	onAllow func(),
	stdout, stderr io.Writer,
) (blocked bool, recordAfterReply func()) {
	pe, ok := BuildPluginToolEvent(tool, body, caps)
	if !ok {
		WritePluginReply(stdout, PluginReply{Decision: "allow", Enforced: EnforcedHint(enforced)})
		return false, nil
	}
	if enrich != nil {
		enrich(&pe)
	}
	verdict, recordWorthy := ev.EvaluateHook(pe)
	em := guard.ResolveEmission(verdict.Verdict, pe.Caps)
	em = guard.HumanizeEmission(em, verdict, pe.SessionID)
	verdict.Enforced = em.Enforced
	if em.DegradedFrom != "" {
		verdict.DegradedFrom = em.DegradedFrom
	}
	doPersist := func() {
		if persist != nil {
			persist(verdict)
		}
	}
	logForensics := func(action string) {
		appendHookEventLog(hookEvent{
			Event: event, Bytes: len(body), SessionID: pe.SessionID, Tool: tool, Action: action,
			RuleID: verdict.Verdict.RuleID, Decision: verdict.Verdict.Decision.String(),
			Severity: verdict.Verdict.Severity.String(), DegradedFrom: em.DegradedFrom,
		})
	}
	if em.Permission == "ask" || em.Permission == "deny" {
		WritePluginReply(stdout, PluginReply{Decision: em.Permission, Reason: em.Reason, Enforced: EnforcedHint(enforced)})
		fmt.Fprintf(stderr, "observer-hook: %s:%s guard %s (%s: %s)\n", tool, event, em.Permission, verdict.Verdict.RuleID, verdict.Verdict.Reason)
		logForensics("guard:" + em.Permission)
		doPersist()
		return true, nil
	}
	if onAllow != nil {
		onAllow()
	}
	allow := PluginReply{Decision: "allow", Enforced: EnforcedHint(enforced)}
	if recordWorthy {
		allow.Message = pluginFlagMessage(verdict.Verdict.Decision, em.Reason)
	}
	WritePluginReply(stdout, allow)
	if !recordWorthy {
		return false, nil
	}
	logForensics("approve+flag")
	return false, doPersist
}

// pluginFlagMessage is the notice a plugin tool gate carries on an allow
// whose verdict is still worth recording (a flag): the shim shows it to the
// developer (a TUI toast, a pi notify) so a flagged call is not silent. ""
// for anything below a flag or without a reason.
func pluginFlagMessage(d policy.Decision, reason string) string {
	reason = strings.TrimSpace(reason)
	if d < policy.DecisionFlag || reason == "" {
		return ""
	}
	return "observer: flagged, not blocked: " + reason
}

// PluginToolGateCaps are a plugin tool gate's channel capabilities:
// pre-execution and blocking always (every plugin host can refuse the
// call), native ask only where the plugin maps ask onto the host's own
// approval prompt.
func PluginToolGateCaps(canAsk bool) policy.Capabilities {
	return policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: canAsk}
}

// buildPluginFailClosedReply is the plugin tool gate's fail-closed block.
func buildPluginFailClosedReply(reason string) FailClosedReply {
	var buf bytes.Buffer
	WritePluginReply(&buf, PluginReply{Decision: "deny", Reason: reason, Enforced: EnforcedHint(true)})
	return FailClosedReply{Stdout: buf.Bytes()}
}

// --- prompt dialect: plugin hosts' prompt gate ------------------------------

func extractPluginPrompt(body []byte) (prompt, sessionID string, ok, fieldMissing bool) {
	var env pluginEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return "", "", false, false
	}
	if env.Prompt == nil {
		return "", env.SessionID, true, true
	}
	return *env.Prompt, env.SessionID, true, false
}

// buildPluginPromptReply is both plugin prompt dialects' reply: a stop the
// developer can confirm (re-enter, or the native confirm) is "ask", any
// other stop "deny", a warning an allow carrying the notice as message, and
// anything else a bare allow. The shim maps each onto its host (pluginshim
// observer-shim.ts); the dialect row's caps decide which of these a verdict
// can reach.
func buildPluginPromptReply(out promptReplyOutcome) any {
	switch {
	case out.Blocking && out.Confirmable:
		return PluginReply{Decision: "ask", Reason: out.Reason}
	case out.Blocking:
		return PluginReply{Decision: "deny", Reason: out.Reason}
	case out.Warn:
		return PluginReply{Decision: "allow", Message: out.Reason}
	}
	return PluginReply{Decision: "allow"}
}

// buildPluginPromptRedactReply is the plugin prompt dialects' MODIFY reply:
// the shim sends out.Masked to the model in place of what the developer
// typed (pi {action:"transform"}) and shows the reason as a notice.
func buildPluginPromptRedactReply(out promptReplyOutcome) any {
	return PluginReply{Decision: "modify", Prompt: out.Masked, Message: out.Reason}
}

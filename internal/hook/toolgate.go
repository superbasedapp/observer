package hook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/jsonv1compat"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/tooltax"
)

// Tool gate (hook-parity audit 2026-10-02, Lane A): ONE handler for every
// pre-tool hook channel, table-driven on the reply DIALECT (never on the
// tool name). A dialect row says how to read a payload into policy events
// (extract) and how to write the vendor's documented block and allow
// replies. A new vendor whose pre-tool event speaks an existing wire shape
// is one registry binding (internal/integration) naming the dialect; a new
// wire shape is one row below. The channel's capabilities (can it block,
// can it ask) come from the guard conformance matrix, which is generated
// from the same bindings, so ask degrades to deny on a deny-only host
// through guard.ResolveEmission without any branch here.

// Tool-gate dialect ids: the internal/integration HookBinding.Dialect
// values of the tool_gate bindings this table serves.
const (
	// ToolGateDialectClaudeCode is Claude Code's PreToolUse: the dual-shape
	// (permissionDecision plus legacy decision/reason) block; the receiver
	// owns the allow reply because it may rewrite the input.
	ToolGateDialectClaudeCode = "claude-code-pretool"
	// ToolGateDialectClaudeJSON is the Claude-shaped JSON family on
	// hosts other than Claude Code (Codex, Qwen Code, Factory Droid,
	// Qoder): the modern hookSpecificOutput.permissionDecision block, and
	// an empty object as the allow. The empty object matters: these hosts
	// read a legacy decision:"approve" as an EXPLICIT allow that skips the
	// host's own permission prompt (Codex rejects it outright), so the tool
	// gate never sends it.
	ToolGateDialectClaudeJSON = "claude-json-pretool"
	// ToolGateDialectGemini is Gemini CLI's BeforeTool: a top-level
	// decision:"deny" with the reason (sent to the agent as the tool
	// error) and a systemMessage (shown to the developer). Deny only.
	ToolGateDialectGemini = "gemini-beforetool"
	// ToolGateDialectCursor is Cursor's universal preToolUse: permission
	// allow|deny plus user_message / agent_message. Cursor's per-tool
	// before* events (shell, MCP, read) gate those action classes
	// already, so this dialect skips them (no double verdict).
	ToolGateDialectCursor = "cursor-pretool"
	// ToolGateDialectCursorReplay is the same preToolUse reaching Observer's
	// Claude Code hooks (Cursor runs ~/.claude/settings.json too, FU-122)
	// while Observer's own cursor hooks are absent. cursor-agent replays no
	// before* event there, so the replay is the only gate Observer has on
	// the call and judges every class, the shell, MCP and read ones
	// included. Same wire as ToolGateDialectCursor.
	ToolGateDialectCursorReplay = "cursor-pretool-replay"
	// ToolGateDialectAntigravity is Antigravity's PreToolUse (agy CLI and
	// the desktop app share ~/.gemini/config/hooks.json): camelCase
	// toolCall.{name,args}, a REQUIRED top-level decision. deny blocks;
	// force_ask prompts even past a cached "always allow".
	ToolGateDialectAntigravity = "antigravity-pretool"
	// ToolGateDialectGrok is Grok Build's PreToolUse: camelCase payload,
	// top-level decision deny|ask, and an allow that only means "not
	// blocked" (it never auto-approves).
	ToolGateDialectGrok = "grok-pretool"
	// ToolGateDialectCopilotCLI is Copilot CLI's preToolUse: camelCase
	// payload whose toolArgs may be a JSON-encoded string, top-level
	// permissionDecision deny|ask.
	ToolGateDialectCopilotCLI = "copilot-cli-pretool"
	// ToolGateDialectVibe is Mistral vibe's pre_tool: JSON decision only
	// (exit 2 is a hook failure, not a block).
	ToolGateDialectVibe = "vibe-pretool"
	// ToolGateDialectGoose is Goose's Open Plugins PreToolUse: the cwd is
	// working_dir, a block is decision:"block"; the allow is silence.
	ToolGateDialectGoose = "goose-pretool"
	// ToolGateDialectCline is the Cline SDK hook runtime's file-per-event
	// PreToolUse: cancel stops the run (no per-call deny exists); exit codes
	// are ignored, so the allow is silence.
	ToolGateDialectCline = "cline-pretool"
	// ToolGateDialectPoolside is Poolside's snake_case PreToolUse block.
	ToolGateDialectPoolside = "poolside-pretool"
	// ToolGateDialectJunie is Junie CLI's PreToolUse: top-level decision
	// deny|ask.
	ToolGateDialectJunie = "junie-pretool"
	// ToolGateDialectCrush is Crush's PreToolUse: top-level decision deny;
	// an explicit allow would skip the permission prompt, so the allow is an
	// empty object (decision null falls through).
	ToolGateDialectCrush = "crush-pretool"
	// ToolGateDialectCascade is Windsurf / Devin Desktop Cascade's per-action
	// pre hooks: no tool name (the event names the action), the input under
	// tool_info, and a block that is exit code 2 with the reason on stderr
	// (shown to the developer).
	ToolGateDialectCascade = "cascade-pretool"
	// ToolGateDialectKiro is Kiro CLI's preToolUse: exit code 2 blocks and
	// stderr goes back to the agent; stdout on exit 0 joins the agent's
	// context, so the allow is silence.
	ToolGateDialectKiro = "kiro-pretool"
	// ToolGateDialectKimi is Kimi Code's PreToolUse (T-378): snake_case
	// Claude-shaped payload (tool_name, tool_input); exit code 2 blocks and
	// stderr is the reason written back to the model; stdout on exit 0 is
	// added to the model context, so the allow is silence.
	ToolGateDialectKimi = "kimi-pretool"
	// ToolGateDialectClaudeWire is the Claude-shaped JSON tool gate of a host
	// that names some or all tools with Claude Code's WIRE spellings (Bash,
	// Read, Write, Edit) instead of its own (Deep Agents Code, Kimchi, Cortex
	// Code): the host's vocabulary is tried first, then Claude Code's.
	ToolGateDialectClaudeWire = "claude-wire-pretool"
	// ToolGateDialectVTCode is VT Code's PreToolUse: the Claude JSON
	// permissionDecision (deny and a native ask), but the allow is an EMPTY
	// stdout because VT Code echoes any hook stdout into its TUI.
	ToolGateDialectVTCode = "vtcode-pretool"
	// ToolGateDialectDirac is Dirac's legacy-Cline file hook: the tool and its
	// stringified parameters under preToolUse, {cancel, errorMessage} cancels
	// the whole task; the allow is silence.
	ToolGateDialectDirac = "dirac-pretool"
	// ToolGateDialectAutohand is Autohand's pre-tool: top-level decision deny
	// with a reason; the allow is {} (an explicit decision allow would skip
	// Autohand's own permission prompt). The payload carries no session id.
	ToolGateDialectAutohand = "autohand-pretool"
	// ToolGateDialectKimchiBash is Kimchi's user-level bash pre-gate script:
	// {tool_name: "bash", input: {command}, cwd}; exit 2 with the stderr
	// reason blocks, the allow is silence (non-JSON stdout would REPLACE the
	// command).
	ToolGateDialectKimchiBash = "kimchi-bash-pretool"
)

// ToolGateRequest is one tool-gate invocation.
type ToolGateRequest struct {
	// Tool is the registry tool id (models.Tool*): the policy event's tool
	// and the conformance-matrix row the channel capabilities come from.
	Tool string
	// Dialect is the binding's tool-gate dialect id.
	Dialect string
	// NativeEvent is the vendor's event name (the conformance channel is
	// "hook:"+NativeEvent, and the reply's hookEventName).
	NativeEvent string
	// Label names the invocation in forensics and stderr ("codex:PreToolUse").
	Label string
	// Body is the raw payload (UTF-8 BOM already stripped or not: the
	// extractor strips it).
	Body []byte
	// Truncated is true when the caller's read hit its bound: the body is
	// not the whole payload and cannot be evaluated.
	Truncated bool
	// contextOnly asks a shaped extractor for the payload's session,
	// working directory and project root alone, as one event, without
	// classifying the tool (ToolGatePayloadContext).
	contextOnly bool
	// Enforcing is true when guard enforcement is in force; together with
	// Truncated it holds the call (ask where the host can ask, else deny)
	// instead of approving it unexamined (SR27-D2, generalized).
	Enforcing bool
	// Decided, when non-nil, is called with the block's exit code right
	// after a block (deny / ask) reply is written and BEFORE anything else
	// runs on that path (forensics, persist). The cmd layer marks the
	// verdict decided there (markHookDecided), so a panic or a watchdog
	// fire during persist delivers the block and never a second (allow)
	// reply or an exit 0 on an exit-code dialect (review M2-11).
	Decided func(exitCode int)
	// Unclassified, when non-nil, is called AFTER the caller's reply
	// (through ToolGateResult.RecordAfterReply) for a wired gate call the
	// gate could not classify: a tool name the shared taxonomy does not
	// know, or a known judged tool whose operand is missing. Such a call
	// passes unjudged; the callback records that (rate-limited by the cmd
	// layer) instead of letting it pass silently (review M2-12). nativeTool
	// is "" when the payload names no tool at all.
	Unclassified func(nativeTool string)
	// Enrich, when non-nil, is called once per extracted event before it
	// is evaluated: the cmd layer fills the security pillar's facts
	// (Event.Security) and raises the project's dirty marker there,
	// through the hook context seam (security pillar plan section 4.7 item
	// 2). Nil leaves every event as the extractor built it.
	Enrich func(*policy.Event)
}

// ToolGateResult is what HandleToolGate decided.
type ToolGateResult struct {
	// Replied is true when HandleToolGate wrote the block (deny / ask)
	// reply; the caller must not write another. On the allow path nothing
	// is written and the caller owns the reply (WriteToolGateAllow, or its
	// own rewrite / approve).
	Replied bool
	// ExitCode is the process exit code that carries the reply (0 for
	// every JSON dialect in the table today).
	ExitCode int
	// Evaluated is true when the payload yielded at least one evaluable
	// tool event (false: unknown tool or no operand, an allow).
	Evaluated bool
	// Undecodable is true when nothing was replied because the payload is
	// JSON whose fields the gate reads do not decode (a tool_input that is
	// not an object, a tool name or operand of the wrong type): the call
	// cannot be judged. Under guard enforcement the caller must fail closed
	// (cmd/observer hookFailClosed with KindUnparseable), never reach its
	// allow (FU-161); otherwise it keeps its allow, as before.
	Undecodable bool
	// RecordAfterReply, when non-nil, persists a record-worthy verdict on
	// the allow path; the caller runs it AFTER writing its own reply.
	RecordAfterReply func()
	// Warn / WarnField: on the allow path of a record-worthy flag, the
	// humanized notice and the allow-reply field the host shows the
	// developer (integration.HookBinding.WarnField). Both empty when the
	// binding declares no such field: the flag is then only recorded.
	// The caller adds the field to its allow (WriteToolGateAllowWarn,
	// WithWarnField).
	Warn      string
	WarnField string
}

// toolGateDialect is one row of the dialect table.
type toolGateDialect struct {
	// extract reads the payload into the policy events to judge (one per
	// target: an apply_patch touching three files is three events) and
	// the native tool name for forensics. ok=false means "not an evaluable
	// tool shape" (allow; unknown is never a violation), unless undecodable
	// is also true: the payload is JSON but a field the gate reads has the
	// wrong type (a tool_input that is not an object, a tool name or an
	// operand that is not a string), so the gate cannot tell what the call
	// does (FU-161). The caller fails closed on that under enforcement
	// (ToolGateResult.Undecodable).
	extract func(req ToolGateRequest) (events []policy.Event, nativeTool string, ok, undecodable bool)
	// block renders a blocking emission (Permission "deny" or "ask") as the
	// stdout reply; nil (or a nil result) writes nothing on stdout (an
	// exit-code-only dialect).
	block func(em guard.Emission, nativeEvent string) any
	// allow is the dialect's neutral allow reply; nil means the receiver
	// owns the allow (Claude Code's approve / rewrite), or, with
	// silentAllow, that an allow writes nothing at all.
	allow any
	// blockExitCode is the process exit code that carries a block (0: the
	// stdout reply carries it).
	blockExitCode int
	// stderrReason is true when the host shows the hook's stderr as the
	// block reason: on a block the reason, after the StderrBlockHeader on
	// one line (DEC-1) and with nothing else, goes to stderr (the T-048
	// rule the prompt dialects follow).
	stderrReason bool
	// silentAllow is true when the host's allow is an empty stdout (an
	// exit-code-only host, or one whose only documented allow is silence:
	// an explicit allow value there would skip the host's own permission
	// prompt or is undocumented).
	silentAllow bool
	// quietStderr is true when the host reads the reason from stdout and
	// any stderr text risks turning the reply into a hook error: Copilot
	// (the CLI and VS Code Copilot Chat's local agent, which is the same
	// runtime) reports a non-zero exit as "Denied by preToolUse hook (hook
	// errored)" and drops the reason, and on Windows it runs the handler's
	// powershell command, where a native program's stderr becomes an error
	// record (WINNODE2 item 10). Observer's diagnostic line then goes to the
	// forensics log only, never to stderr.
	quietStderr bool
	// mcpArgs are the dotted payload paths an MCP call's arguments sit at
	// on this host, tried in order (audit SEC-P4 F5): the same paths the
	// row's extractor reads its tool input from. nil is mcpToolInputFields,
	// the top-level spellings of the Claude-shaped hosts.
	mcpArgs []string
}

// topDecisionReply is the top-level {decision, reason} block several hosts
// read on their pre-tool event (Antigravity, Grok Build, Junie CLI, Crush,
// Mistral vibe, Goose; the decision word is the dialect's).
type topDecisionReply struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason,omitempty"`
}

// topDecision returns a block builder speaking a top-level decision: the
// emission's permission mapped through words ("deny" / "ask" to the
// host's spelling).
func topDecision(words map[string]string) func(guard.Emission, string) any {
	return func(em guard.Emission, _ string) any {
		w, ok := words[em.Permission]
		if !ok {
			w = words["deny"]
		}
		return topDecisionReply{Decision: w, Reason: em.Reason}
	}
}

// poolsideToolReply is Poolside's snake_case PreToolUse block.
type poolsideToolReply struct {
	HookSpecificOutput struct {
		PermissionDecision       string `json:"permission_decision"`
		PermissionDecisionReason string `json:"permission_decision_reason"`
	} `json:"hook_specific_output"`
}

// copilotToolReply is Copilot CLI's preToolUse block (top-level, camelCase).
type copilotToolReply struct {
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason"`
}

// clineToolReply is the Cline SDK hook runtime's PreToolUse cancel.
type clineToolReply struct {
	Cancel       bool   `json:"cancel"`
	ErrorMessage string `json:"errorMessage"`
}

// claudeJSONPermissionOut is the modern Claude-shaped PreToolUse envelope
// (no legacy decision field).
type claudeJSONPermissionReply struct {
	HookSpecificOutput claudeCodePermissionOut `json:"hookSpecificOutput"`
}

// geminiToolReply is Gemini CLI's BeforeTool block.
type geminiToolReply struct {
	Decision      string `json:"decision"`
	Reason        string `json:"reason"`
	SystemMessage string `json:"systemMessage"`
}

// cursorToolReply is Cursor's preToolUse reply.
type cursorToolReply struct {
	Permission   string `json:"permission"`
	Continue     bool   `json:"continue"`
	UserMessage  string `json:"user_message,omitempty"`
	AgentMessage string `json:"agent_message,omitempty"`
}

// toolGateDialects is THE tool-gate dialect table.
var toolGateDialects = map[string]toolGateDialect{
	ToolGateDialectClaudeCode: {
		extract: func(req ToolGateRequest) ([]policy.Event, string, bool, bool) {
			ev, ok, undecodable := buildClaudeCodeEvent(req.Body)
			if !ok {
				return nil, "", false, undecodable
			}
			return []policy.Event{ev}, payloadFieldString(bytes.TrimPrefix(req.Body, utf8BOM), "tool_name"), true, false
		},
		block: func(em guard.Emission, _ string) any { return buildClaudeCodeBlockReply(em) },
	},
	ToolGateDialectClaudeJSON: {
		extract: genericToolExtractor(nil),
		block: func(em guard.Emission, nativeEvent string) any {
			return claudeJSONPermissionReply{HookSpecificOutput: claudeCodePermissionOut{
				HookEventName: nativeEvent, PermissionDecision: em.Permission, PermissionDecisionReason: em.Reason,
			}}
		},
		allow: struct{}{},
	},
	ToolGateDialectGemini: {
		extract: genericToolExtractor(nil),
		block: func(em guard.Emission, _ string) any {
			// Deny-only unless a terminal is attached (D-791, JSP-6 live
			// half): the binding can ask, but the ask host row withdraws it
			// unless the per-call probe finds the gemini process with a
			// terminal, because a headless ask hangs the run. So an ask
			// reaches this writer only for an interactive gemini.
			if em.Permission == "ask" {
				return geminiToolReply{Decision: "ask", Reason: em.Reason, SystemMessage: em.Reason}
			}
			return geminiToolReply{Decision: "deny", Reason: em.Reason, SystemMessage: em.Reason}
		},
		allow: struct{}{},
	},
	ToolGateDialectCursor: {
		// beforeShellExecution / beforeMCPExecution / beforeReadFile gate
		// these canonical classes with the native ask; judging them again
		// here would double every verdict row. A content search (Grep) is
		// NOT among them, although the gate judges it as a read.
		extract: genericToolExtractor(map[string]bool{
			models.ActionRunCommand: true, models.ActionMCPCall: true, models.ActionReadFile: true,
		}),
		block: func(em guard.Emission, _ string) any {
			return cursorToolReply{Permission: "deny", Continue: true, UserMessage: em.Reason, AgentMessage: em.Reason}
		},
		allow: cursorReply{Permission: "allow", Continue: true},
	},
	ToolGateDialectCursorReplay: {
		extract: genericToolExtractor(nil),
		block: func(em guard.Emission, _ string) any {
			return cursorToolReply{Permission: "deny", Continue: true, UserMessage: em.Reason, AgentMessage: em.Reason}
		},
		allow: cursorReply{Permission: "allow", Continue: true},
	},
	ToolGateDialectAntigravity: {
		extract: shapedToolExtractor(toolPayloadShape{
			session: []string{"conversationId"}, root: []string{"workspacePaths"},
			tool: []string{"toolCall.name"}, input: []string{"toolCall.args"},
		}, nil),
		mcpArgs: []string{"toolCall.args"},
		// deny blocks; an ask is force_ask, agy's NATIVE prompt with a
		// "Reason:" line (live, agy 1.3.5: shown even for an in-workspace
		// read). force_ask auto-denies headless and RUNS the tool under
		// --dangerously-skip-permissions, so the channel's ask capability is
		// probed per call (toolGateAskProbes): without an interactive agy
		// ancestor ResolveEmission has already turned the ask into a deny
		// that says how to confirm. Plain "ask" is never sent (it respects
		// the default grants, weaker) nor "auto_approve" (skips the
		// developer's prompt).
		block: topDecision(map[string]string{"deny": "deny", "ask": "force_ask"}),
		// Live: an empty object {} DENIES the call (decision is required)
		// and decision:allow defers to agy's policy (auto_approve would
		// skip the developer's own prompt); an empty stdout leaves the call
		// to agy's own permission flow.
		silentAllow: true,
	},
	ToolGateDialectGrok: {
		extract: genericToolExtractor(nil),
		// Deny only: live (grok 1.0.46) an ask under --always-approve ran
		// the command, so the binding lists no ask.
		block: topDecision(map[string]string{"deny": "deny"}),
		// allow "means only not blocked" (vendor doc; live, ls ran): it
		// never skips the permission prompt.
		allow: topDecisionReply{Decision: "allow"},
	},
	ToolGateDialectCopilotCLI: {
		extract: shapedToolExtractor(toolPayloadShape{
			session: []string{"sessionId", "session_id"}, cwd: []string{"cwd"},
			tool: []string{"toolName", "tool_name"}, input: []string{"toolArgs", "tool_input"},
		}, nil),
		mcpArgs: []string{"toolArgs", "tool_input"},
		// Exit 0 with the top-level decision and its reason on stdout: the
		// GitHub hooks reference (docs.github.com/en/copilot/reference/
		// copilot-cli-reference/cli-hooks-reference) shows the reason to
		// the agent; exit 2 denies without it and any other non-zero exit
		// is "Denied by preToolUse hook (hook errored)".
		block: func(em guard.Emission, _ string) any {
			return copilotToolReply{PermissionDecision: em.Permission, PermissionDecisionReason: em.Reason}
		},
		// "allow" skips the normal prompting (vendor doc); an empty object
		// is no decision.
		allow:       struct{}{},
		quietStderr: true,
	},
	ToolGateDialectVibe: {
		extract: genericToolExtractor(nil),
		block:   topDecision(map[string]string{"deny": "deny"}),
		allow:   struct{}{},
	},
	ToolGateDialectGoose: {
		extract: shapedToolExtractor(toolPayloadShape{
			session: []string{"session_id"}, cwd: []string{"working_dir", "cwd"},
			tool: []string{"tool_name"}, input: []string{"tool_input"},
			// goose 1.53 resolves a model-mangled name before the hook,
			// but other extensions and older builds still send the
			// prefixed spellings (gfiD research, goose source).
			nameStrip: []string{"functions.", "functions:", "developer__", "developer."},
			mcpAlias:  tooltax.MCPNameFromExtension,
			flatten:   []string{"input"},
		}, nil),
		block:       topDecision(map[string]string{"deny": "block"}),
		silentAllow: true,
	},
	ToolGateDialectCline: {
		extract: shapedToolExtractor(toolPayloadShape{
			session: []string{"taskId", "sessionContext.sessionId", "sessionContext.rootSessionId"}, root: []string{"workspaceRoots"},
			tool: []string{"tool_call.name", "preToolUse.toolName"}, input: []string{"tool_call.input"},
			// The SDK hook runtime the extension and the CLI share names
			// tools in the CLI vocabulary (run_commands, read_files,
			// editor, apply_patch): live, cline 3.0.68 on demo node 1,
			// 2026-10-04. The gate is registered for cline-cli (T-342), so
			// that is the host's own vocabulary; the extension's
			// (execute_command, read_file) is the fallback, for a payload
			// the shared runtime names in the extension's words.
			vocab: []string{models.ToolCline},
		}, nil),
		mcpArgs: []string{"tool_call.input"},
		block: func(em guard.Emission, _ string) any {
			return clineToolReply{Cancel: true, ErrorMessage: em.Reason}
		},
		silentAllow: true,
	},
	ToolGateDialectPoolside: {
		extract: genericToolExtractor(nil),
		block: func(em guard.Emission, _ string) any {
			var r poolsideToolReply
			r.HookSpecificOutput.PermissionDecision = "deny"
			r.HookSpecificOutput.PermissionDecisionReason = em.Reason
			return r
		},
		// The documented allow is an empty stdout ("observe only").
		silentAllow: true,
	},
	ToolGateDialectJunie: {
		// Junie CLI and the Junie IDE plugin send cwd = the directory the
		// hook was registered from (~/.junie) and the project in
		// project_path (Mac round 4 rows 19 and 30, FU-155), so the
		// project is read first.
		extract: genericToolExtractorCwd(nil, "project_path"),
		block:   topDecision(map[string]string{"deny": "deny", "ask": "ask"}),
		allow:   struct{}{},
	},
	ToolGateDialectCrush: {
		// MCP tools arrive as mcp_<server>_<tool> (one underscore).
		extract: shapedToolExtractor(claudeShapedPayload.withMCPAlias(tooltax.MCPNameFromSingleUnderscore), nil),
		block:   topDecision(map[string]string{"deny": "deny"}),
		allow:   struct{}{},
	},
	ToolGateDialectCascade: {
		extract: shapedToolExtractor(toolPayloadShape{
			session: []string{"trajectory_id"}, cwd: []string{"tool_info.cwd"},
			input: []string{"tool_info"},
			eventTools: map[string]string{
				"pre_run_command": "run_command", "pre_write_code": "edit_file", "pre_read_code": "read_file",
			},
			mcpServer: []string{"tool_info.mcp_server_name"}, mcpTool: []string{"tool_info.mcp_tool_name"},
		}, nil),
		blockExitCode: 2, stderrReason: true, silentAllow: true,
	},
	ToolGateDialectKiro: {
		// 2.x agent hooks and the V3 standalone hooks share the payload
		// {hook_event_name, cwd, session_id, tool_name, tool_input}; V3
		// names an MCP tool mcp_<server>_<tool>. A read carries its paths
		// as operations[].path (operandListFields).
		extract:       shapedToolExtractor(claudeShapedPayload.withMCPAlias(tooltax.MCPNameFromSingleUnderscore), nil),
		blockExitCode: 2, stderrReason: true, silentAllow: true,
	},
	ToolGateDialectKimi: {
		extract:       genericToolExtractor(nil),
		blockExitCode: 2, stderrReason: true, silentAllow: true,
	},
	// The Cline CLI plugin's beforeTool (toolgate_clineplugin.go).
	ToolGateDialectClinePlugin: clinePluginToolGate,
	// 2026-10-21 wave (docs/guard.md "Live grounding: 2026-10-21 wave").
	ToolGateDialectClaudeWire: {
		extract: shapedToolExtractor(claudeShapedPayload.withVocab(models.ToolClaudeCode), nil),
		block:   claudeJSONBlock,
		allow:   struct{}{},
	},
	ToolGateDialectVTCode: {
		extract:     genericToolExtractor(nil),
		block:       claudeJSONBlock,
		silentAllow: true,
	},
	ToolGateDialectDirac: {
		extract: shapedToolExtractor(toolPayloadShape{
			session: []string{"taskId"}, root: []string{"workspaceRoots"},
			tool: []string{"preToolUse.toolName"}, input: []string{"preToolUse.parameters"},
		}, nil),
		block: func(em guard.Emission, _ string) any {
			return clineToolReply{Cancel: true, ErrorMessage: em.Reason}
		},
		// Dirac echoes hook stderr into its transcript: the bare reason there
		// is the only place a developer can read why the task was cancelled
		// (the model never sees it), and Observer's diagnostics stay off it.
		stderrReason: true, silentAllow: true,
	},
	ToolGateDialectAutohand: {
		extract: genericToolExtractor(nil),
		block:   topDecision(map[string]string{"deny": "deny"}),
		allow:   struct{}{},
	},
	ToolGateDialectKimchiBash: {
		extract: shapedToolExtractor(toolPayloadShape{
			session: []string{"session_id"}, cwd: []string{"cwd"},
			tool: []string{"tool_name"}, input: []string{"input", "tool_input"},
		}, nil),
		blockExitCode: 2, stderrReason: true, silentAllow: true,
	},
}

// claudeJSONBlock renders the modern Claude-shaped PreToolUse block
// (hookSpecificOutput.permissionDecision deny|ask with the reason).
func claudeJSONBlock(em guard.Emission, nativeEvent string) any {
	return claudeJSONPermissionReply{HookSpecificOutput: claudeCodePermissionOut{
		HookEventName: nativeEvent, PermissionDecision: em.Permission, PermissionDecisionReason: em.Reason,
	}}
}

// ToolGateDialectQuietStderr reports whether the dialect's host must see
// nothing on stderr (toolGateDialect.quietStderr): Observer's diagnostics go
// to the forensics log only.
func ToolGateDialectQuietStderr(dialect string) bool {
	d, ok := toolGateDialects[dialect]
	return ok && d.quietStderr
}

// IsToolGateDialect reports whether d is a row of the tool-gate table.
func IsToolGateDialect(d string) bool {
	_, ok := toolGateDialects[d]
	return ok
}

// ToolGateDialects returns the tool-gate dialect ids, sorted.
func ToolGateDialects() []string {
	out := make([]string, 0, len(toolGateDialects))
	for d := range toolGateDialects {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// ToolGateAllowReply returns the dialect's neutral allow reply as bytes
// (nil when the dialect has none: the receiver owns its allow).
func ToolGateAllowReply(dialect string) []byte {
	d, ok := toolGateDialects[dialect]
	if !ok || d.allow == nil {
		return nil
	}
	return encodeReply(d.allow)
}

// WriteToolGateAllow writes the dialect's neutral allow reply (nothing for
// a dialect whose receiver owns the allow).
func WriteToolGateAllow(dialect string, stdout io.Writer) {
	if b := ToolGateAllowReply(dialect); b != nil {
		_, _ = stdout.Write(b)
	}
}

// HandleDialectAllow writes the "nothing to say" reply of ANY reply
// dialect (with HandleApprove's forensics): a tool-gate dialect's neutral
// allow, else the prompt dialect's allow (HandlePromptAllow, which falls
// back to the generic approve). The recovered-panic path uses it so a
// fail-open crash on a tool-gate host answers with that host's own allow,
// never the legacy decision:"approve" (which some Claude-shaped hosts read
// as an explicit allow that skips their own permission prompt).
func HandleDialectAllow(dialect, event string, stdin io.Reader, stdout, stderr io.Writer) {
	if d, ok := toolGateDialects[dialect]; ok {
		switch {
		case d.silentAllow:
			// An exit-code-only host parses no stdout: an allow is silence.
			_, _ = io.Copy(io.Discard, io.LimitReader(stdin, 2*1024*1024))
			return
		case d.allow != nil:
			handleAllow(event, stdin, stdout, stderr, d.allow)
			return
		}
	}
	HandlePromptAllow(dialect, event, stdin, stdout, stderr)
}

// ToolGateAllowWritesStdout reports whether dialect answers on stdout at all
// (false for an exit-code-only tool-gate dialect; true for every other
// dialect, tool gate or not).
func ToolGateAllowWritesStdout(dialect string) bool {
	d, ok := toolGateDialects[dialect]
	return !ok || !d.silentAllow
}

// ToolGateDialectStderrReason reports whether dialect's host shows the
// hook's stderr as the block reason (so a receiver writes no diagnostics
// there).
func ToolGateDialectStderrReason(dialect string) bool {
	d, ok := toolGateDialects[dialect]
	return ok && d.stderrReason
}

// toolGateBlock is a dialect's rendered block: the stdout bytes (nil =
// nothing on stdout), the exit code that carries it, and whether stderr is
// the host's reason channel.
type toolGateBlock struct {
	stdout       []byte
	exitCode     int
	stderrReason bool
}

// toolGateBlockFor renders the dialect's block for em ("deny" or "ask").
func toolGateBlockFor(dialect, nativeEvent string, em guard.Emission) (toolGateBlock, bool) {
	d, ok := toolGateDialects[dialect]
	if !ok || (d.block == nil && d.blockExitCode == 0) {
		return toolGateBlock{}, false
	}
	out := toolGateBlock{exitCode: d.blockExitCode, stderrReason: d.stderrReason}
	if d.block != nil {
		if r := d.block(em, nativeEvent); r != nil {
			out.stdout = encodeReply(r)
		}
	}
	return out, true
}

// writeToolGateBlock writes a rendered block: the stdout reply, then
// either the reason on stderr after the StderrBlockHeader (a host that
// shows stderr as the reason) or Observer's diagnostic line. It returns the
// exit code that carries the block.
func writeToolGateBlock(b toolGateBlock, reason, diagnostic string, stdout, stderr io.Writer) int {
	if len(b.stdout) > 0 {
		_, _ = stdout.Write(b.stdout)
	}
	if b.stderrReason {
		WriteStderrBlockReason(stderr, reason)
	} else {
		fmt.Fprintln(stderr, diagnostic)
	}
	return b.exitCode
}

// truncatedPreToolReason is the agent/human-facing reason for the
// fail-closed hold HandleToolGate emits for a truncated payload.
const truncatedPreToolReason = "Observer guard could not evaluate this tool call: its hook payload exceeded the size the guard reads, so the call is held for your approval instead of being approved unexamined."

// HandleToolGate is the ONE tool-gate handler (generalized from
// HandleGuarded): read the payload through the dialect's extractor,
// evaluate each event, resolve the emission against the channel's
// capabilities, and, when the verdict blocks or asks, write the dialect's
// reply FIRST and persist after it (spec §6.4).
//
// Reply-ownership contract (unchanged from HandleGuarded): it writes to
// stdout ONLY when it blocks or asks (Replied=true, persist already ran).
// On the allow path it writes nothing and returns RecordAfterReply for a
// record-worthy verdict, which the caller runs after its own reply.
//
// A payload naming several targets (a patch over several files) yields one
// event per target; the most severe emission wins and is the one verdict
// persisted (persist runs at most once).
func HandleToolGate(req ToolGateRequest, ev guard.Evaluator, persist func(guard.ActionVerdict), stdout, stderr io.Writer) ToolGateResult {
	d, ok := toolGateDialects[req.Dialect]
	if !ok || ev == nil {
		return ToolGateResult{}
	}
	if req.Truncated {
		return handleTruncatedToolGate(req, stdout, stderr)
	}
	events, nativeTool, ok, undecodable := d.extract(req)

	var (
		best      guard.ActionVerdict
		bestEm    guard.Emission
		bestEv    policy.Event
		bestWorth bool
		found     bool
	)
	if !ok || len(events) == 0 {
		// An exhausted managed budget stops the call whatever it is (T-519):
		// a call the policy extractor cannot classify, or one this event
		// leaves to a sibling, still spends against the cap. The budget is
		// the only verdict an unclassified call can get.
		if pe, av, stopped := toolGateBudgetStop(req, ev); stopped {
			best, bestEm, bestEv, bestWorth, found = av, guard.ResolveEmission(av.Verdict, pe.Caps), pe, true, true
			events = nil
		} else if !ok {
			// Not classifiable (an extractor's ok=false): the call passes, and a
			// caller that asked is told after its own reply (review M2-12). A
			// payload whose fields the gate reads do not decode is marked
			// Undecodable: under enforcement the caller fails closed on it
			// instead of passing it (FU-161).
			res := ToolGateResult{Undecodable: undecodable}
			if req.Unclassified != nil {
				native := nativeTool
				res.RecordAfterReply = func() { req.Unclassified(native) }
			}
			return res
		}
	}
	if req.Enrich != nil {
		for i := range events {
			if events[i].Kind == policy.KindMCPCall && len(events[i].Raw) == 0 {
				// The commit gate's MCP placement column reads the call's
				// arguments (repo_path, file contents) from Raw (lane SEC-P4
				// decision 2); in memory only, never persisted.
				events[i].Raw = mcpToolInputRaw(req.Body, d.mcpArgs)
			}
			req.Enrich(&events[i])
		}
	}
	for _, pe := range events {
		pe.Caps = withHostAsk(req.Tool, pe.Caps)
		verdict, recordWorthy := ev.EvaluateHook(pe)
		em := guard.ResolveEmission(verdict.Verdict, pe.Caps)
		if !found || emissionRank(em, recordWorthy) > emissionRank(bestEm, bestWorth) {
			best, bestEm, bestEv, bestWorth, found = verdict, em, pe, recordWorthy, true
		}
	}
	if !found {
		return ToolGateResult{}
	}
	verdict, em := best, bestEm
	// Human first, agent second (org guardrail control wave, Track B), then
	// the deny-only ask explanation (audit section 5.7 decision table): both
	// are no-ops on an individual node's ask-capable channel, so the wire
	// reply stays byte-identical there.
	em = guard.HumanizeEmission(em, verdict, bestEv.SessionID)
	em = guard.ExplainDegradedAsk(em, verdict, bestEv.SessionID)
	verdict.Enforced = em.Enforced
	if em.DegradedFrom != "" {
		// Don't clobber a marker EvaluateHook already set (the §6.3
		// "approved" exception marker) with the empty no-degradation case.
		verdict.DegradedFrom = em.DegradedFrom
	}

	doPersist := func() {
		if persist != nil {
			persist(verdict)
		}
	}
	logForensics := func(action string) {
		appendHookEventLog(hookEvent{
			Event:        req.Label,
			Bytes:        len(req.Body),
			SessionID:    bestEv.SessionID,
			Tool:         nativeTool,
			Action:       action,
			RuleID:       verdict.Verdict.RuleID,
			Decision:     verdict.Verdict.Decision.String(),
			Severity:     verdict.Verdict.Severity.String(),
			DegradedFrom: em.DegradedFrom,
		})
	}

	if em.Permission == "ask" || em.Permission == "deny" {
		b, _ := toolGateBlockFor(req.Dialect, req.NativeEvent, em)
		code := writeToolGateBlock(b, em.Reason, fmt.Sprintf("observer-hook: %s guard %s (%s: %s)",
			req.Label, em.Permission, verdict.Verdict.RuleID, verdict.Verdict.Reason), stdout, stderr)
		if req.Decided != nil {
			req.Decided(code)
		}
		logForensics("guard:" + em.Permission)
		doPersist()
		return ToolGateResult{Replied: true, Evaluated: true, ExitCode: code}
	}
	if !bestWorth {
		return ToolGateResult{Evaluated: true}
	}
	// Flag-class (or degraded) verdict on the allow path: record it, but
	// only after the caller's reply, and tell the developer through the
	// allow's notice field where the binding declares one.
	logForensics("approve+flag")
	res := ToolGateResult{Evaluated: true, RecordAfterReply: doPersist}
	if f := toolGateWarnField(req.Tool, req.NativeEvent); f != "" && verdict.Verdict.RuleID != "" && !verdict.GuardError {
		res.WarnField, res.Warn = f, toolGateWarnText(verdict.Verdict.RuleID, em.Reason)
	}
	return res
}

// toolGateWarnField is the developer-visible notice field of tool's
// tool-gate binding on nativeEvent ("" when it declares none). Read from the
// registry row (capability data), never keyed by the tool name here.
func toolGateWarnField(tool, nativeEvent string) string {
	c, ok := integration.For(tool)
	if !ok {
		return ""
	}
	for _, b := range c.Hook.Bindings {
		if b.Cap == integration.HookCapToolGate && b.NativeEvent == nativeEvent {
			return b.WarnField
		}
	}
	return ""
}

// toolGateWarnText is the developer-facing notice for a flagged tool call.
func toolGateWarnText(ruleID, reason string) string {
	return "SuperBased Observer flagged this tool call (" + ruleID + "): " + reason
}

// WithWarnField returns reply with field set to warn, as a JSON object
// (reply must encode to one). It returns reply unchanged when field or warn
// is empty or reply is not an object.
func WithWarnField(reply any, field, warn string) any {
	if field == "" || warn == "" {
		return reply
	}
	b, err := json.Marshal(reply)
	if err != nil {
		return reply
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil || m == nil {
		return reply
	}
	m[field] = warn
	return m
}

// WriteToolGateAllowWarn writes the dialect's neutral allow reply with the
// flag notice added under field (WriteToolGateAllow when there is no
// notice). A dialect whose allow is silence writes nothing either way.
func WriteToolGateAllowWarn(dialect, field, warn string, stdout io.Writer) {
	d, ok := toolGateDialects[dialect]
	if !ok || d.allow == nil || field == "" || warn == "" {
		WriteToolGateAllow(dialect, stdout)
		return
	}
	_, _ = stdout.Write(encodeReply(WithWarnField(d.allow, field, warn)))
}

// handleTruncatedToolGate holds a call whose payload the caller could not
// read in full (SR27-D2): a truncated body cannot be parsed, so without
// this an enforce-mode deny rule over its target would be approved
// unexamined. Under enforcement it asks where the channel can ask and
// denies where it cannot; otherwise nothing is written (the caller keeps
// its normal allow path).
func handleTruncatedToolGate(req ToolGateRequest, stdout, stderr io.Writer) ToolGateResult {
	if !req.Enforcing {
		return ToolGateResult{}
	}
	caps := toolGateChannelCaps(req)
	em := guard.Emission{Permission: "deny", Enforced: true, Reason: truncatedPreToolReason}
	if caps.CanAsk {
		em.Permission = "ask"
	}
	b, ok := toolGateBlockFor(req.Dialect, req.NativeEvent, em)
	if !ok {
		return ToolGateResult{}
	}
	code := writeToolGateBlock(b, em.Reason,
		fmt.Sprintf("observer-hook: %s guard %s (payload truncated, not evaluable)", req.Label, em.Permission), stdout, stderr)
	if req.Decided != nil {
		req.Decided(code)
	}
	appendHookEventLog(hookEvent{Event: req.Label, Action: "guard:" + em.Permission + ":truncated"})
	return ToolGateResult{Replied: true, ExitCode: code}
}

// emissionRank orders emissions for the multi-target pick: deny over ask
// over allow; on a tie a record-worthy verdict wins.
func emissionRank(em guard.Emission, recordWorthy bool) int {
	r := 0
	switch em.Permission {
	case "deny":
		r = 4
	case "ask":
		r = 2
	}
	if recordWorthy {
		r++
	}
	return r
}

// toolGateChannelCaps is the channel's capability row from the conformance
// matrix (generated from the registry bindings). Claude Code's dialect
// pins its own constants (claudeCodePreToolCaps, conformance-tested).
func toolGateChannelCaps(req ToolGateRequest) policy.Capabilities {
	if req.Dialect == ToolGateDialectClaudeCode {
		return withHostAsk(req.Tool, claudeCodePreToolCaps)
	}
	caps, _ := guard.CapabilitiesFor(req.Tool, "hook:"+req.NativeEvent)
	if probe, ok := toolGateAskProbes[req.Dialect]; ok && caps.CanAsk && !probe() {
		caps.CanAsk = false
	}
	return withHostAsk(req.Tool, caps)
}

// withHostAsk withdraws CanAsk when the tool's ask host row says THIS
// invocation cannot show a native ask (a headless run, or a terminal-gated
// host without a terminal: integration.AskHost, D-791 Q27). The channel's
// capability is otherwise unchanged; a tool without a row is untouched.
func withHostAsk(tool string, caps policy.Capabilities) policy.Capabilities {
	if !caps.CanAsk {
		return caps
	}
	if can, ok := askHostProbeFn(tool); ok && !can {
		caps.CanAsk = false
	}
	return caps
}

// askHostProbeFn is the per-call ask host probe (a test replaces it).
var askHostProbeFn = askHostProbe

// toolGateAskProbes lists the dialects whose native ask reaches a developer
// only in some host modes: the probe reports whether THIS invocation's host
// can ask, and a false answer withdraws CanAsk so ResolveEmission degrades
// the ask to a deny that says how to confirm. Kept beside (not inside) the
// dialect table so the table's initializer does not depend on this lookup.
var toolGateAskProbes = map[string]func() bool{
	// Antigravity: force_ask only under an interactive agy without
	// --dangerously-skip-permissions or headless -p (agyhost.go).
	ToolGateDialectAntigravity: agyAskProbe,
}

// ToolGateAskProbed reports whether dialect's native ask is offered only
// when the running host proves it can show it (toolGateAskProbes): elsewhere
// an ask is a deny that says how to confirm. Coverage surfaces read it
// (controlcoverage.RuleCoverage).
func ToolGateAskProbed(dialect string) bool {
	if _, ok := toolGateAskProbes[dialect]; ok {
		return true
	}
	// A terminal-gated ask host (integration.AskHost.AskNeedsTerminal) is
	// offered its ask only when the per-call probe sees a terminal.
	for _, tool := range integration.AskHostTools() {
		h, _ := integration.AskHostFor(tool)
		if !h.AskNeedsTerminal {
			continue
		}
		if c, ok := integration.For(tool); ok {
			for _, b := range c.Hook.Bindings {
				if b.Cap == integration.HookCapToolGate && b.Dialect == dialect {
					return true
				}
			}
		}
	}
	return false
}

// genericToolPayload is the Claude-shaped pre-tool payload the generic
// extractor reads; every spelling a dialect of the family uses is listed
// (snake_case and camelCase; Cursor's conversation_id).
type genericToolPayload struct {
	SessionID      string          `json:"session_id"`
	SessionIDCamel string          `json:"sessionId"`
	ConversationID string          `json:"conversation_id"`
	Cwd            string          `json:"cwd"`
	ToolName       string          `json:"tool_name"`
	ToolNameCamel  string          `json:"toolName"`
	ToolInput      json.RawMessage `json:"tool_input"`
	ToolInputCamel json.RawMessage `json:"toolInput"`
	WorkspaceRoots json.RawMessage `json:"workspace_roots"`
	// WorkspaceRoot is Grok Build's camelCase single root.
	WorkspaceRoot string `json:"workspaceRoot"`
}

// genericToolExtractor returns the Claude-shaped extractor; skip names the
// CANONICAL (tooltax) action types the channel leaves to a sibling event of
// the same host.
func genericToolExtractor(skip map[string]bool) func(ToolGateRequest) ([]policy.Event, string, bool, bool) {
	return func(req ToolGateRequest) ([]policy.Event, string, bool, bool) {
		return extractGenericToolEvents(req, skip)
	}
}

// genericToolExtractorCwd is genericToolExtractor for a host whose payload
// names the working directory under another key ahead of cwd: the first
// non-empty string among cwdFirst (dotted paths) wins, then cwd. Only the
// dialect row that passes cwdFirst reads those keys; every other row keeps
// reading cwd alone.
func genericToolExtractorCwd(skip map[string]bool, cwdFirst ...string) func(ToolGateRequest) ([]policy.Event, string, bool, bool) {
	return func(req ToolGateRequest) ([]policy.Event, string, bool, bool) {
		return extractGenericToolEventsCwd(req, skip, cwdFirst)
	}
}

// utf8BOM is the UTF-8 byte order mark a .NET / PowerShell stdin writer on a
// UTF-8 console prepends to a hook payload; every decoder strips it first.
var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// rawNotObject reports whether a present tool-input value is not a JSON
// object (null and absent count as an empty input, not a wrong type).
func rawNotObject(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	if len(t) == 0 || bytes.Equal(t, []byte("null")) {
		return false
	}
	var m map[string]any
	return jsonv1compat.UnmarshalObject(t, &m) != nil
}

// extractGenericToolEvents reads a Claude-shaped pre-tool payload into
// policy events: the native tool name resolves through internal/tooltax
// (action type + operand), the operand's value comes from the tool input
// under any of its field spellings, and an edit whose input is a patch
// envelope fans out into one event per file the patch touches.
func extractGenericToolEvents(req ToolGateRequest, skip map[string]bool) ([]policy.Event, string, bool, bool) {
	return extractGenericToolEventsCwd(req, skip, nil)
}

// extractGenericToolEventsCwd is extractGenericToolEvents with cwdFirst, the
// payload keys read for the working directory before cwd
// (genericToolExtractorCwd); nil reads cwd alone.
func extractGenericToolEventsCwd(req ToolGateRequest, skip map[string]bool, cwdFirst []string) ([]policy.Event, string, bool, bool) {
	body := bytes.TrimPrefix(req.Body, utf8BOM)
	var p genericToolPayload
	if err := json.Unmarshal(body, &p); err != nil {
		// Not an object, or a field the gate reads (session, cwd, tool name)
		// of the wrong type: the call cannot be judged (FU-161).
		return nil, "", false, true
	}
	cwd := p.Cwd
	if len(cwdFirst) > 0 {
		var m map[string]any
		if json.Unmarshal(body, &m) == nil {
			if s := firstPathString(m, cwdFirst); s != "" {
				cwd = s
			}
		}
	}
	native := firstNonEmpty(p.ToolName, p.ToolNameCamel)
	if native == "" {
		return nil, "", false, false
	}
	input := map[string]any{}
	raw := p.ToolInput
	if len(raw) == 0 {
		raw = p.ToolInputCamel
	}
	// Go 1.26 result for an out-of-range number (internal/jsonv1compat).
	_ = jsonv1compat.UnmarshalObject(raw, &input)
	return buildToolGateEvents(req, skip, native, input, toolGateEventContext{
		session:  firstNonEmpty(p.SessionID, p.SessionIDCamel, p.ConversationID),
		cwd:      cwd,
		root:     firstNonEmpty(firstWorkspaceRoot(p.WorkspaceRoots), p.WorkspaceRoot),
		inputBad: rawNotObject(raw),
	})
}

// toolGateEventContext is the per-payload context every judged event
// carries.
type toolGateEventContext struct {
	session, cwd, root string
	// vocab is toolPayloadShape.vocab.
	vocab []string
	// inputBad: the tool input is present but not an object (nor a string
	// holding one), so a judged tool's operand cannot be read (FU-161).
	inputBad bool
}

// buildToolGateEvents judges one native tool call: it resolves the native
// name through internal/tooltax, reads the operand from the tool input, and
// returns one event per target (a patch envelope fans out per file).
//
// ok is the classification answer (review M2-12): false means the call
// could not be classified (a tool name no vocabulary knows, or a judged
// tool whose operand is missing), true with no events means there is
// legitimately nothing to judge here (a known tool the guard does not
// evaluate, an action a sibling event of the host judges, a channel that is
// not a grounded pre-execution gate). undecodable (FU-161) is true with
// ok=false when the judged tool's input is not an object, or its operand
// field is present with the wrong type: the call does something the gate
// cannot read, which is not the same as an input that names no operand.
func buildToolGateEvents(req ToolGateRequest, skip map[string]bool, native string, input map[string]any, ctx toolGateEventContext) ([]policy.Event, string, bool, bool) {
	shape, ok := resolveGateShapeIn(req.Tool, ctx.vocab, native)
	if !ok {
		return nil, native, nativeKnownIn(req.Tool, ctx.vocab, native), false
	}
	if skip[shape.canonical] {
		return nil, native, true, false
	}
	caps := toolGateChannelCaps(req)
	if !caps.PreExecution {
		// Not a wired pre-execution channel (no conformance row): judge
		// nothing; the binding has not been grounded as a gate.
		return nil, native, true, false
	}
	if ctx.inputBad && shape.operand != tooltax.OperandMCPName {
		return nil, native, false, true
	}
	var targets []string
	switch shape.operand {
	case tooltax.OperandMCPName:
		targets = []string{native}
	default:
		// Every operand the input carries is judged: a single-operand field
		// never shadows a batch field beside it (`command` next to
		// `commands`, review M2-12).
		targets = unionOperands(operandValue(shape.operand, input), operandList(shape.operand, input))
	}
	if len(targets) == 0 && (shape.actionType == models.ActionEditFile || shape.actionType == models.ActionWriteFile) {
		targets = patchTargetsIn(input)
	}
	if len(targets) == 0 {
		return nil, native, false, operandWrongType(shape.operand, input)
	}
	caps.Sandboxed = sandboxedChild()
	base := policy.Event{
		Kind:        shape.kind,
		ActionType:  shape.actionType,
		Tool:        req.Tool,
		SessionID:   ctx.session,
		Cwd:         ctx.cwd,
		ProjectRoot: ctx.root,
		Caps:        caps,
		Dialect:     shape.dialect,
		AltDialect:  unstatedShellAltDialect(shape.kind, shape.dialect, ctx.cwd),
		Now:         time.Now().UTC(),
	}
	// The proposed content of a write or edit rides each event (T-910,
	// R-162); a patch envelope gives each file its own section.
	var edits []policy.ProposedEdit
	if isWriteAction(shape.actionType) {
		edits = proposedEditsIn(input)
	}
	events := make([]policy.Event, 0, len(targets))
	for _, t := range targets {
		e := base
		e.Target = t
		e.Edits = edits
		if edits == nil && isWriteAction(shape.actionType) {
			e.Edits = patchEditsFor(input, t)
		}
		events = append(events, e)
	}
	return events, native, true, false
}

// operandWrongType reports whether input carries operand's field (a single
// or a batch spelling, exact or without case and separators) with a value
// of a type the gate cannot read as one: neither a string nor, for a batch
// field, a list. Such a call names an operand the gate cannot judge
// (FU-161), which is not an input that names none.
func operandWrongType(operand string, input map[string]any) bool {
	matches := func(fields []string, k string) bool {
		for _, f := range fields {
			if k == f || normalizeNative(k) == normalizeNative(f) {
				return true
			}
		}
		return false
	}
	for k, v := range input {
		if v == nil {
			continue
		}
		_, isString := v.(string)
		_, isList := v.([]any)
		if matches(operandListFields[operand], k) {
			if !isString && !isList {
				return true
			}
			continue
		}
		if matches(operandFields[operand], k) && !isString {
			return true
		}
	}
	return false
}

// toolPayloadShape names where a vendor's pre-tool payload carries each
// field the gate reads, as dotted JSON paths tried in order (data: one value
// per wire shape; the Claude-shaped family reads genericToolPayload
// instead). A tool input found as a JSON-encoded STRING is decoded.
type toolPayloadShape struct {
	session, cwd, root, tool, input []string
	// eventTools maps a native EVENT to the native tool name it implies, for
	// a host whose per-action pre-tool events carry no tool name (Cascade's
	// pre_run_command / pre_write_code / pre_read_code).
	eventTools map[string]string
	// mcpServer / mcpTool are the paths of a payload that names an MCP call
	// in two fields; together they compose the canonical
	// mcp__<server>__<tool> name.
	mcpServer, mcpTool []string
	// vocab lists further tooltax vocabularies (tool ids) the payload's tool
	// names may come from, tried in order after the host's own: a hook
	// runtime shared by several products names tools in one product's
	// vocabulary whichever host runs it.
	vocab []string
	// nameStrip lists name prefixes a host's model may wrap a tool name in
	// (Goose: `developer__shell`, `developer.shell`, `functions.shell`); a
	// prefix is stripped only when the rest is a tool name the taxonomy
	// knows, so an unrelated name is never mangled.
	nameStrip []string
	// mcpAlias, when non-nil, canonicalizes the host's own MCP tool-name
	// form into `mcp__<server>__<tool>` (tooltax.MCPNameFromSingleUnderscore
	// for crush and Kiro, tooltax.MCPNameFromExtension for Goose), so an MCP
	// rule (server pins, taint origins) sees the server the call names. It
	// runs only for a name no literal taxonomy row claims.
	mcpAlias func(string) (string, bool)
	// flatten lists tool-input keys whose OBJECT value carries the operand
	// one level down (Goose Code Mode's execute_typescript {input: {code}}):
	// the nested keys are merged into the input, outer keys winning.
	flatten []string
}

// canonicalNative is the native tool name the gate judges for a payload
// that names native: the name itself when a literal taxonomy row (host or
// extra vocabulary) claims it EXACTLY, else the name with a nameStrip prefix
// removed when that rest is known, else the host's MCP alias, else the
// name unchanged (which then classifies, or not, as before).
//
// The literal check is exact, never the taxonomy's normalized match
// (case, `_`, `-` and `.` folded): with the folded match a Goose extension
// "web" exposing "fetch" (`web__fetch`) folded onto the built-in
// `web_fetch` row and skipped the MCP alias, so MCP pin, deny and taint
// rules never saw it (integration security review, 2026-10-15).
func (s toolPayloadShape) canonicalNative(tool, native string) string {
	if literalNativeExact(tool, s.vocab, native) {
		return native
	}
	for _, p := range s.nameStrip {
		if rest, ok := strings.CutPrefix(native, p); ok && rest != "" && nativeKnownIn(tool, s.vocab, rest) {
			return rest
		}
	}
	if s.mcpAlias != nil {
		if m, ok := s.mcpAlias(native); ok {
			return m
		}
	}
	return native
}

// literalNativeExact reports whether a LITERAL (non-glob) taxonomy row of
// the host's vocabulary or an extra one names native byte for byte.
func literalNativeExact(tool string, vocab []string, native string) bool {
	for _, v := range append([]string{tool}, vocab...) {
		if _, ok := tooltax.For(v)[native]; ok {
			return true
		}
	}
	return false
}

// flattenInput merges the object value of each key in keys into input
// (outer keys win) and returns input.
func flattenInput(input map[string]any, keys []string) map[string]any {
	for _, k := range keys {
		inner, ok := input[k].(map[string]any)
		if !ok {
			continue
		}
		for ik, iv := range inner {
			if _, taken := input[ik]; !taken {
				input[ik] = iv
			}
		}
	}
	return input
}

// claudeShapedPayload is the snake_case Claude-shaped pre-tool payload a
// toolPayloadShape reads when a host also needs a shape-only option
// (crush, Kiro CLI): session_id, cwd, tool_name, tool_input.
var claudeShapedPayload = toolPayloadShape{
	session: []string{"session_id", "sessionId"}, cwd: []string{"cwd"},
	tool: []string{"tool_name", "toolName"}, input: []string{"tool_input", "toolInput"},
}

// withVocab returns s with further tool vocabularies to try after the host's
// own (toolPayloadShape.vocab).
func (s toolPayloadShape) withVocab(v ...string) toolPayloadShape {
	s.vocab = append(append([]string{}, s.vocab...), v...)
	return s
}

// withMCPAlias returns s with its MCP alias set.
func (s toolPayloadShape) withMCPAlias(f func(string) (string, bool)) toolPayloadShape {
	s.mcpAlias = f
	return s
}

// shapedToolExtractor returns the extractor for a toolPayloadShape; skip is
// as for genericToolExtractor.
func shapedToolExtractor(shape toolPayloadShape, skip map[string]bool) func(ToolGateRequest) ([]policy.Event, string, bool, bool) {
	return func(req ToolGateRequest) ([]policy.Event, string, bool, bool) {
		var m map[string]any
		if err := json.Unmarshal(bytes.TrimPrefix(req.Body, utf8BOM), &m); err != nil {
			// Valid JSON that is not an object decodes to no map either
			// (json.Unmarshal fails): nothing the gate reads is there.
			return nil, "", false, true
		}
		if req.contextOnly {
			return []policy.Event{{
				SessionID: firstPathString(m, shape.session), Cwd: firstPathString(m, shape.cwd), ProjectRoot: firstPathString(m, shape.root),
			}}, "", true, false
		}
		native := firstPathString(m, shape.tool)
		if server, tool := firstPathString(m, shape.mcpServer), firstPathString(m, shape.mcpTool); server != "" && tool != "" {
			native = "mcp__" + server + "__" + tool
		}
		if native == "" && pathPresentNotString(m, shape.tool) {
			// The payload names its tool, as something other than a name.
			return nil, "", false, true
		}
		if native == "" {
			native = shape.eventTools[req.NativeEvent]
		}
		if native == "" {
			return nil, "", false, false
		}
		native = shape.canonicalNative(req.Tool, native)
		input := flattenInput(firstPathObject(m, shape.input), shape.flatten)
		return buildToolGateEvents(req, skip, native, input, toolGateEventContext{
			session:  firstPathString(m, shape.session),
			cwd:      firstPathString(m, shape.cwd),
			root:     firstPathString(m, shape.root),
			vocab:    shape.vocab,
			inputBad: pathObjectBad(m, shape.input),
		})
	}
}

// pathPresentNotString reports whether one of paths is present with a
// non-null value that is neither a string nor a list starting with one
// (what firstPathString reads).
func pathPresentNotString(m map[string]any, paths []string) bool {
	for _, p := range paths {
		v, ok := pathValue(m, p)
		if !ok || v == nil {
			continue
		}
		if list, ok := v.([]any); ok && len(list) > 0 {
			v = list[0]
		}
		if _, ok := v.(string); !ok {
			return true
		}
	}
	return false
}

// pathObjectBad reports whether a tool input is present under one of paths
// but none of them holds what firstPathObject reads (an object, or a string
// that decodes to one); null counts as absent.
func pathObjectBad(m map[string]any, paths []string) bool {
	present := false
	for _, p := range paths {
		v, ok := pathValue(m, p)
		if !ok || v == nil {
			continue
		}
		present = true
		switch t := v.(type) {
		case map[string]any:
			return false
		case string:
			var obj map[string]any
			if json.Unmarshal([]byte(t), &obj) == nil && obj != nil {
				return false
			}
		}
	}
	return present
}

// pathValue walks a dotted path through decoded JSON objects.
func pathValue(m map[string]any, path string) (any, bool) {
	var cur any = m
	for _, k := range strings.Split(path, ".") {
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = obj[k]; !ok {
			return nil, false
		}
	}
	return cur, true
}

// firstPathString returns the first non-empty string value among paths; a
// list of strings (Antigravity's workspacePaths) yields its first entry.
func firstPathString(m map[string]any, paths []string) string {
	for _, p := range paths {
		v, ok := pathValue(m, p)
		if !ok {
			continue
		}
		if list, ok := v.([]any); ok && len(list) > 0 {
			v = list[0]
		}
		if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

// firstPathObject returns the first object value among paths; a string
// value that decodes to a JSON object counts (Copilot CLI's toolArgs). An
// empty map when none does.
func firstPathObject(m map[string]any, paths []string) map[string]any {
	for _, p := range paths {
		v, ok := pathValue(m, p)
		if !ok {
			continue
		}
		switch t := v.(type) {
		case map[string]any:
			return t
		case string:
			var obj map[string]any
			if json.Unmarshal([]byte(t), &obj) == nil && obj != nil {
				return obj
			}
		}
	}
	return map[string]any{}
}

// gateShape is what the gate judges for one native tool.
type gateShape struct {
	// canonical is the tooltax action type before any gate override.
	canonical  string
	kind       policy.EventKind
	actionType string
	operand    string
	dialect    policy.Dialect
}

// gateActionOverrides re-reads a canonical action the guard does not
// classify as a gateable one where the call still exposes what a rule
// judges: a content search returns file bytes, so it is judged as a read
// of its search root (the claude-code Grep precedent, claudeToolShape).
var gateActionOverrides = map[string]struct{ actionType, operand string }{
	models.ActionSearchText: {models.ActionReadFile, tooltax.OperandPath},
}

// gateUnclassifiedNatives covers native tools internal/tooltax leaves
// unclassified (no delete action type exists): deleting a file is a write
// to it for the sensitive-path and persistence rules. Keys are
// normalized (lower case, no separators).
var gateUnclassifiedNatives = map[string]struct{ actionType, operand string }{
	"delete":     {models.ActionWriteFile, tooltax.OperandFilePath},
	"deletefile": {models.ActionWriteFile, tooltax.OperandFilePath},
	"removefile": {models.ActionWriteFile, tooltax.OperandFilePath},
}

// powerShellNatives are native shell tools whose command is PowerShell.
var powerShellNatives = map[string]bool{"powershell": true, "pwsh": true}

// unstatedShellAltDialect is the second reading a shell event gets when its
// host does not state which shell runs the command; the rule lives in
// policy.UnstatedShellAltDialect (one owner, shared with `observer guard
// test`). Claude Code's Bash tool is Git-Bash on Windows and is built by
// BuildClaudeCodeEvent, which does not ask for this reading.
func unstatedShellAltDialect(kind policy.EventKind, dialect policy.Dialect, cwd string) policy.Dialect {
	return policy.UnstatedShellAltDialect(kind, dialect, cwd)
}

// unionOperands is single followed by every list operand not equal to an
// earlier one, in order ("" contributes nothing).
func unionOperands(single string, list []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, v := range append([]string{single}, list...) {
		if strings.TrimSpace(v) == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// nativeKnownIn reports whether native is a tool name the shared taxonomy
// knows under the host's vocabulary or an extra one (or an MCP tool name):
// a known tool the guard does not judge is not an unclassified call.
func nativeKnownIn(tool string, vocab []string, native string) bool {
	if native == "" {
		return false
	}
	if tooltax.IsMCPToolName(native) {
		return true
	}
	for _, v := range append([]string{tool}, vocab...) {
		if _, ok := tooltax.Resolve(v, native); ok {
			return true
		}
	}
	return false
}

// resolveGateShapeIn is resolveGateShape over the host's own vocabulary
// first, then each extra vocabulary in order (toolPayloadShape.vocab).
func resolveGateShapeIn(tool string, vocab []string, native string) (gateShape, bool) {
	if g, ok := resolveGateShape(tool, native); ok {
		return g, true
	}
	for _, v := range vocab {
		if g, ok := resolveGateShape(v, native); ok {
			return g, true
		}
	}
	return gateShape{}, false
}

// resolveGateShape maps (tool, native) onto the gate's event vocabulary.
func resolveGateShape(tool, native string) (gateShape, bool) {
	actionType, operand := "", ""
	if e, ok := tooltax.Resolve(tool, native); ok {
		actionType, operand = e.ActionType, e.Operand
	} else if tooltax.IsMCPToolName(native) {
		actionType, operand = models.ActionMCPCall, tooltax.OperandMCPName
	}
	canonical := actionType
	if o, ok := gateActionOverrides[actionType]; ok {
		actionType, operand = o.actionType, o.operand
	}
	key := normalizeNative(native)
	if operand == tooltax.OperandNone {
		if o, ok := gateUnclassifiedNatives[key]; ok {
			actionType, operand = o.actionType, o.operand
		}
	}
	kind, evaluable := guard.ClassifyActionType(actionType)
	if !evaluable || operand == tooltax.OperandNone {
		return gateShape{}, false
	}
	s := gateShape{canonical: canonical, kind: kind, actionType: actionType, operand: operand}
	if powerShellNatives[key] {
		s.dialect = policy.DialectPowerShell
	}
	return s, true
}

// operandFields lists, per tooltax operand, the tool-input field spellings
// the vendors use, tried in order.
var operandFields = map[string][]string{
	tooltax.OperandCommand:      {"command", "cmd", "commandLine", "script", "code"},
	tooltax.OperandFilePath:     {"file_path", "filePath", "absolute_path", "target_file", "path", "notebook_path", "filename"},
	tooltax.OperandNotebookPath: {"notebook_path", "file_path"},
	tooltax.OperandPath:         {"path", "dir_path", "directory", "absolute_path", "file_path", "directory_path", "search_path"},
	tooltax.OperandURL:          {"url", "uri"},
	tooltax.OperandQuery:        {"query", "q"},
}

// operandListFields lists, per tooltax operand, the BATCH field spellings a
// tool input may carry instead of one operand: a list of strings, or of
// objects that each carry the operand (Cline CLI's run_commands
// {commands:[...]} and read_files {files:[{path}]}; Kiro CLI's read
// {operations:[{path}]}). Every element is judged.
var operandListFields = map[string][]string{
	tooltax.OperandCommand:  {"commands"},
	tooltax.OperandFilePath: {"files", "file_paths", "paths", "operations"},
	tooltax.OperandPath:     {"paths", "files", "operations"},
}

// operandList returns every operand of the first non-empty batch field for
// operand (exact spelling first, then compared without case or separators),
// or nil. A JSON-encoded list string is decoded.
func operandList(operand string, input map[string]any) []string {
	if len(input) == 0 {
		return nil
	}
	keys := make([]string, 0, len(input))
	for k := range input {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, f := range operandListFields[operand] {
		want := normalizeNative(f)
		for _, k := range keys {
			if k != f && normalizeNative(k) != want {
				continue
			}
			if out := operandListValues(operand, input[k]); len(out) > 0 {
				return out
			}
		}
	}
	return nil
}

// operandListValues reads one batch value: strings are operands as-is, an
// object yields its operand field. A batch field may also hold ONE bare
// operand string (Cline CLI 3.0.68 sent {"commands":"rm -rf ~/x"} live on
// demo node 1 for some models), which is that single operand.
func operandListValues(operand string, v any) []string {
	if s, ok := v.(string); ok {
		var decoded []any
		if json.Unmarshal([]byte(s), &decoded) != nil {
			if strings.TrimSpace(s) == "" {
				return nil
			}
			return []string{s}
		}
		v = decoded
	}
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, el := range list {
		switch t := el.(type) {
		case string:
			if strings.TrimSpace(t) != "" {
				out = append(out, t)
			}
		case map[string]any:
			if s := operandValue(operand, t); s != "" {
				out = append(out, s)
			}
		case []any:
			// An argv element (a command as a list of words): judged as the
			// line those words make, so `["git","commit","-m","x"]`
			// classifies like `git commit -m x` (security plan section 4.7
			// item 4, Cline arrays element by element).
			if operand == tooltax.OperandCommand {
				if s := argvLine(t); s != "" {
					out = append(out, s)
				}
			}
		}
	}
	return out
}

// argvLine joins an argv element's words into one POSIX command line,
// quoting each word that needs it; "" when an element is not a string.
func argvLine(words []any) string {
	parts := make([]string, 0, len(words))
	for _, w := range words {
		s, ok := w.(string)
		if !ok {
			return ""
		}
		parts = append(parts, shellQuoteIfNeeded(s))
	}
	return strings.Join(parts, " ")
}

// operandValue returns the first non-empty string input field for operand:
// an exact spelling first, then the same spellings compared without case or
// separators (Antigravity's PascalCase CommandLine / TargetFile /
// AbsolutePath, Cascade's command_line), so one field list serves every
// vendor's casing.
func operandValue(operand string, input map[string]any) string {
	for _, f := range operandFields[operand] {
		if s, ok := input[f].(string); ok && strings.TrimSpace(s) != "" {
			return s
		}
	}
	if len(input) == 0 {
		return ""
	}
	keys := make([]string, 0, len(input))
	for k := range input {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, f := range operandFields[operand] {
		want := normalizeNative(f)
		for _, k := range keys {
			if normalizeNative(k) != want {
				continue
			}
			if s, ok := input[k].(string); ok && strings.TrimSpace(s) != "" {
				return s
			}
		}
	}
	return ""
}

// patchFileHeaders are the file headers of the apply_patch envelope (Codex
// and its rebadges): each names one path the patch touches.
var patchFileHeaders = []string{"Add File:", "Update File:", "Delete File:", "Move File:", "Move to:"}

// patchTargetsIn finds a patch envelope in any string input field and
// returns every path it touches, in order, de-duplicated. Content-shaped
// (the envelope's own markers), never keyed on a tool name.
func patchTargetsIn(input map[string]any) []string {
	keys := make([]string, 0, len(input))
	for k := range input {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []string
	seen := map[string]bool{}
	for _, k := range keys {
		s, ok := input[k].(string)
		if !ok || !strings.Contains(s, "*** Begin Patch") {
			continue
		}
		for _, line := range strings.Split(s, "\n") {
			line = strings.TrimSpace(line)
			rest, ok := strings.CutPrefix(line, "*** ")
			if !ok {
				continue
			}
			for _, h := range patchFileHeaders {
				if p, ok := strings.CutPrefix(rest, h); ok {
					if p = strings.TrimSpace(p); p != "" && !seen[p] {
						seen[p] = true
						out = append(out, p)
					}
				}
			}
		}
	}
	return out
}

// firstWorkspaceRoot returns the first workspace root a payload declares
// as a plain string list ("" for any other shape: boundary rules then see
// no project root, as on Claude Code's PreToolUse).
func firstWorkspaceRoot(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var roots []string
	if json.Unmarshal(raw, &roots) != nil {
		return ""
	}
	for _, r := range roots {
		if r = strings.TrimSpace(r); r != "" {
			return r
		}
	}
	return ""
}

func normalizeNative(name string) string {
	key := strings.ToLower(strings.TrimSpace(name))
	for _, sep := range []string{"_", "-", ".", " "} {
		key = strings.ReplaceAll(key, sep, "")
	}
	return key
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// mcpToolInputFields are the top-level payload members a Claude-shaped
// host carries an MCP call's arguments in, tried in order: tool_input and
// toolInput (genericToolPayload: Claude Code, Gemini CLI, Kimi, Grok,
// Vibe, Poolside, Junie; claudeShapedPayload: Crush, Kiro, Goose), toolArgs
// (Copilot CLI), arguments, and input (Cursor's beforeMCPExecution,
// internal/adapter/cursor's payload struct). A host whose payload nests
// them lists its own paths (toolGateDialect.mcpArgs).
var mcpToolInputFields = []string{"tool_input", "toolInput", "toolArgs", "arguments", "input"}

// mcpToolInputRaw returns an MCP call's arguments from the hook payload as
// raw JSON (nil when there are none), from the first of paths (dotted;
// nil is mcpToolInputFields) that holds a value. The policy side bounds and
// decodes it (policy.MaxMCPToolInput); a JSON string holding an object
// (Copilot CLI's toolArgs) is decoded there.
func mcpToolInputRaw(body []byte, paths []string) []byte {
	if paths == nil {
		paths = mcpToolInputFields
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF}), &m); err != nil {
		return nil
	}
	for _, p := range paths {
		if v, ok := rawPath(m, p); ok && len(v) > 0 && string(v) != "null" {
			return []byte(v)
		}
	}
	return nil
}

// rawPath walks a dotted path through raw JSON objects.
func rawPath(m map[string]json.RawMessage, path string) (json.RawMessage, bool) {
	keys := strings.Split(path, ".")
	cur := m
	for i, k := range keys {
		v, ok := cur[k]
		if !ok {
			return nil, false
		}
		if i == len(keys)-1 {
			return v, true
		}
		var next map[string]json.RawMessage
		if json.Unmarshal(v, &next) != nil {
			return nil, false
		}
		cur = next
	}
	return nil, false
}

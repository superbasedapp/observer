package kimicode

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// wireLine is one JSONL line of an agent's wire-protocol trace
// (`agents/<name>/wire.jsonl`). The wire format is a flat event stream
// discriminated by `type`; a single struct decodes every shape because
// the per-type bodies are optional/raw. Only the fields the adapter
// consumes are declared — the rest of each event (systemPrompt bodies,
// tool snapshots, permission modes) is intentionally ignored.
type wireLine struct {
	Type string `json:"type"`

	// metadata
	ProtocolVersion string `json:"protocol_version"`
	CreatedAt       int64  `json:"created_at"`

	// turn.prompt
	Input  []wirePart  `json:"input"`
	Origin *wireOrigin `json:"origin"`

	// context.append_loop_event
	Event json.RawMessage `json:"event"`

	// llm.request + usage.record
	Model      string     `json:"model"`
	ModelAlias string     `json:"modelAlias"`
	Provider   string     `json:"provider"`
	Usage      *wireUsage `json:"usage"`
	UsageScope string     `json:"usageScope"`

	Time int64 `json:"time"`
}

// wirePart is a content part carried by turn.prompt.input and by a
// content.part loop event. Non-text parts (images, media) carry an empty
// Text and are skipped.
type wirePart struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// wireOrigin discriminates the source of a turn.prompt / message: a real
// user prompt (`kind:"user"`) vs an injected system reminder
// (`kind:"injection"`).
type wireOrigin struct {
	Kind    string `json:"kind"`
	Variant string `json:"variant"`
}

// wireUsage is the per-API-call token envelope carried by usage.record
// (and, identically, by a step.end loop event). inputOther is the NET
// non-cached input: it EXCLUDES inputCacheRead (verified 2026-07-09 — a
// step whose cache read was 18816 reported inputOther 55, so inputOther
// cannot include the cached portion). No subtraction is required to reach
// the cost engine's NET-input contract. No reasoning/thoughts field is
// emitted by the wire format.
type wireUsage struct {
	InputOther         int64 `json:"inputOther"`
	Output             int64 `json:"output"`
	InputCacheRead     int64 `json:"inputCacheRead"`
	InputCacheCreation int64 `json:"inputCacheCreation"`
}

// loopEvent is the `event` body of a context.append_loop_event line,
// discriminated by its own `type` (step.begin / tool.call / tool.result /
// content.part / step.end). Fields are a superset; unused ones stay zero.
type loopEvent struct {
	Type       string          `json:"type"`
	UUID       string          `json:"uuid"`
	ToolCallID string          `json:"toolCallId"`
	ParentUUID string          `json:"parentUuid"`
	TurnID     string          `json:"turnId"`
	Step       int             `json:"step"`
	StepUUID   string          `json:"stepUuid"`
	Name       string          `json:"name"`
	Args       json.RawMessage `json:"args"`
	Display    *loopDisplay    `json:"display"`
	Result     *loopResult     `json:"result"`
	Part       *wirePart       `json:"part"`

	// step.end
	Usage        *wireUsage `json:"usage"`
	MessageID    string     `json:"messageId"`
	FinishReason string     `json:"finishReason"`
}

// loopDisplay is a tool.call's UI display hint; the adapter reads only its
// working-directory hint (`cwd`), used as a project-root fallback when the
// sibling state.json is unavailable.
type loopDisplay struct {
	Kind    string `json:"kind"`
	Command string `json:"command"`
	Cwd     string `json:"cwd"`
	Path    string `json:"path"`
}

// loopResult is a tool.result's outcome. A non-empty Error, or IsError
// true, marks the paired tool call failed.
type loopResult struct {
	Output  string `json:"output"`
	Error   string `json:"error"`
	IsError *bool  `json:"isError"`
}

// stateFile is the session-root `state.json` sibling of the wire trace.
// WorkDir is the authoritative session cwd (the project-root seam).
type stateFile struct {
	WorkDir    string `json:"workDir"`
	Title      string `json:"title"`
	CreatedAt  string `json:"createdAt"`
	LastPrompt string `json:"lastPrompt"`
}

// mapKimiTool collapses kimi-code's tool vocabulary onto the normalized
// action set. Matching is case-insensitive with `_`/`-` stripped so a
// future rename in either case survives. The raw name is preserved on
// ToolEvent.RawToolName; an unrecognised built-in maps to ActionUnknown,
// and any `mcp__*` (or `__`-containing) name maps to ActionMCPCall.
func mapKimiTool(name string) string {
	if strings.HasPrefix(name, "mcp") || strings.Contains(name, "__") {
		return models.ActionMCPCall
	}
	key := strings.ToLower(strings.TrimSpace(name))
	key = strings.ReplaceAll(key, "_", "")
	key = strings.ReplaceAll(key, "-", "")
	switch key {
	case "read", "readfile", "readmediafile", "view":
		return models.ActionReadFile
	case "write", "writefile", "createfile":
		return models.ActionWriteFile
	case "edit", "editfile", "applypatch", "patch", "replace":
		return models.ActionEditFile
	case "bash", "shell", "exec", "runcommand", "run", "terminal":
		return models.ActionRunCommand
	case "grep", "searchtext", "ripgrep", "findtext":
		return models.ActionSearchText
	case "glob", "findfiles", "listfiles", "ls", "listdirectory":
		return models.ActionSearchFiles
	case "websearch", "search":
		return models.ActionWebSearch
	case "fetchurl", "webfetch", "fetch", "fetchwebpage":
		return models.ActionWebFetch
	case "agent", "agentswarm", "subagent", "spawnagent", "delegate":
		return models.ActionSpawnSubagent
	case "todolist", "todowrite", "todo":
		return models.ActionTodoUpdate
	// kimi-code 2.1.1 built-ins, grounded 2026-09-28 in the shipped
	// bundle (@moonshot-ai/kimi-code 2.1.1 dist/main.mjs, each tool
	// class's `name = "..."`) and the public source
	// (github.com/MoonshotAI/kimi-code packages/agent-core-v2/src/
	// {agent/tools,features/*/tools}).
	case "askuserquestion":
		return models.ActionAskUser
	case "enterplanmode", "exitplanmode":
		// Plan-mode toggles (ExitPlanModeTool drives the permission-mode
		// service) — Claude Code's EnterPlanMode/ExitPlanMode bucket.
		return models.ActionPermissionMode
	case "skill":
		return models.ActionSkillInvoke
	case "croncreate", "cronlist", "crondelete":
		// Schedule / list / cancel a future prompt — claude-code Cron*.
		return models.ActionSchedule
	case "tasklist", "taskoutput", "taskstop":
		// BACKGROUND-task control (a background Bash, Agent or
		// AskUserQuestion), NOT a todo list: enumerate / snapshot /
		// stop the running pool — deepseek job_list/job_output/job_kill
		// precedent. Deliberately not todo_update (the claude-code
		// TaskList/TaskOutput/TaskStop mis-bucket that
		// internal/taskflow/decode.go documents).
		return models.ActionAgentControl
	case "waitfor":
		// Blocks the turn on running background tasks — codex `wait`.
		return models.ActionSubagentWait
	case "notifyuser":
		return models.ActionNotification
	case "creategoal", "getgoal", "setgoalbudget", "updategoal":
		// The runtime's own goal state (objective / budget / status) —
		// deepseek create_goal/get_goal/update_goal precedent.
		return models.ActionHarnessCall
	// Tower: the multi-agent "control tower" feature
	// (features/tower/tools, TOWER_TOOL_NAMES).
	case "towerspawn":
		// Spawns a worker/reviewer as a background subagent.
		return models.ActionSpawnSubagent
	case "towersend", "towerfinding", "towerreview":
		// Hand a message / finding / review verdict to the tower or
		// another roster agent — an inter-agent message.
		return models.ActionAgentMessage
	case "towerinbox", "towerstatus":
		// Read the inbox / the roster+missions dashboard — inspecting
		// the agent pool (codex read_thread / list_agents precedent).
		return models.ActionAgentControl
	case "towerplan", "towermission":
		// Split the goal into missions with verifiable task checklists
		// / read or tick a mission's checklist — structured plan
		// tracking.
		return models.ActionTodoUpdate
	case "towerteardown":
		// Removes the mission git worktrees — claude-code ExitWorktree.
		return models.ActionWorktreeRemove
	case "towerinit", "towermerge":
		// Create the .tower/ workspace / merge a reviewed mission branch:
		// harness-owned operations, neither a shell command nor file
		// work the model authored.
		return models.ActionHarnessCall
	default:
		return models.ActionUnknown
	}
}

// normalizeModel strips a leading provider prefix (`openai/gpt-4o` →
// `gpt-4o`) so the emitted model id matches the cost engine's pricing
// keys, and trims any trailing OpenRouter-style `:suffix` tail. A bare id
// (no `/`) is returned unchanged.
func normalizeModel(raw string) string {
	m := strings.TrimSpace(raw)
	if i := strings.LastIndex(m, "/"); i >= 0 && i+1 < len(m) {
		m = m[i+1:]
	}
	if i := strings.IndexByte(m, ':'); i >= 0 {
		m = m[:i]
	}
	return m
}

// targetFromArgs picks a representative target string from a tool call's
// raw args JSON, trying common path/command/query keys before falling
// back to the tool name.
func targetFromArgs(args json.RawMessage, fallback string) string {
	if len(args) == 0 {
		return fallback
	}
	var m map[string]any
	if err := json.Unmarshal(args, &m); err != nil {
		return fallback
	}
	for _, key := range []string{
		"path", "file_path", "filePath", "absolute_path", "file",
		"command", "query", "url", "pattern", "prompt", "directory",
	} {
		if v, ok := m[key].(string); ok && strings.TrimSpace(v) != "" {
			return v
		}
	}
	return fallback
}

// authoredContentBytes returns the byte length of code the model authored
// in a write/edit call — the `content` / `new_string` arg — for the
// Output-Composition surface. Zero when the args carry no authored body.
func authoredContentBytes(args json.RawMessage) int64 {
	if len(args) == 0 {
		return 0
	}
	var m map[string]any
	if err := json.Unmarshal(args, &m); err != nil {
		return 0
	}
	for _, key := range []string{"content", "new_string", "newString", "text"} {
		if v, ok := m[key].(string); ok && v != "" {
			return int64(len(v))
		}
	}
	return 0
}

// resultOutcome extracts the plain-text output, success flag, and error
// message from a tool.result. Success is false when Error is non-empty or
// IsError is explicitly true.
func resultOutcome(r *loopResult) (output string, success bool, errMsg string) {
	if r == nil {
		return "", true, ""
	}
	success = true
	if strings.TrimSpace(r.Error) != "" {
		success = false
		errMsg = r.Error
	}
	if r.IsError != nil && *r.IsError {
		success = false
	}
	output = r.Output
	if output == "" {
		output = r.Error
	}
	return output, success, errMsg
}

// hashID returns a deterministic 16-hex-char digest of raw, used to
// synthesize a stable SourceEventID for events the wire format gives no
// native id (turn.prompt, usage.record). The digest is byte-stable across
// re-parses and unique per event (each raw line carries a `time` field).
func hashID(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])[:16]
}

// unixMillis converts a wire millisecond timestamp to UTC time. Returns
// the zero time for a non-positive value.
func unixMillis(ms int64) time.Time {
	if ms <= 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms).UTC()
}

// promptText joins the text parts of a turn.prompt input, trimmed.
func promptText(parts []wirePart) string {
	var b strings.Builder
	for _, p := range parts {
		if p.Text == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(p.Text)
	}
	return strings.TrimSpace(b.String())
}

// truncate caps a preview string to n bytes.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

package tooltax

// Canonical tool ids. Values are identical to the internal/models Tool*
// constants; re-declared because tooltax imports nothing project-internal
// (see doc.go). TestToolIDValuesMatchModels pins the equality.
const (
	toolAider           = "aider"
	toolAntigravity     = "antigravity"
	toolAntigravityCLI  = "antigravity-cli"
	toolClaudeCode      = "claude-code"
	toolCline           = "cline"
	toolClineCLI        = "cline-cli"
	toolCodex           = "codex"
	toolCommandCode     = "command-code"
	toolCopilot         = "copilot"
	toolCopilotCLI      = "copilot-cli"
	toolCowork          = "cowork"
	toolCrush           = "crush"
	toolCursor          = "cursor"
	toolDeepSeek        = "deepseek"
	toolDevin           = "devin"
	toolDroid           = "droid"
	toolFreebuff        = "freebuff"
	toolGeminiCLI       = "gemini-cli"
	toolGoose           = "goose"
	toolGrok            = "grok"
	toolHermes          = "hermes"
	toolJunie           = "junie"
	toolKiloCode        = "kilo-code"
	toolKiloCodeCLI     = "kilo-code-cli"
	toolKimiCode        = "kimi-code"
	toolKiroCLI         = "kiro-cli"
	toolKiroCrew        = "kiro-crew"
	toolMistralCode     = "mistral-code"
	toolMuse            = "muse"
	toolOpenClaw        = "openclaw"
	toolOpenCode        = "opencode"
	toolOpenInterpreter = "open-interpreter"
	toolPi              = "pi"
	toolPoolside        = "poolside"
	toolPrimeAgent      = "prime-agent"
	toolQoder           = "qoder"
	toolQwenCode        = "qwen-code"
	toolRooCode         = "roo-code"
	toolZcode           = "zcode"
	toolZed             = "zed"
	toolZooCode         = "zoo-code"
)

// table is THE canonical taxonomy table: ordered, walked top-down by
// Resolve. Assembled by buildTable in the precedence order the plan
// requires — specific (tool, native) literals, then tool-specific globs,
// then vocabulary aliases, then tool-less fallbacks, then the global
// `mcp__*` glob last.
var table = buildTable()

// toolAlias records a tool whose native vocabulary is a REBADGE of
// another tool's — same binary lineage, same tool names, different
// install path and `tool` column. The alias's rows are generated from
// the source's so the two can never drift.
type toolAlias struct {
	alias  string
	source string
	why    string
}

var toolAliases = []toolAlias{
	{
		alias: toolOpenInterpreter, source: toolCodex,
		why: "open-interpreter is a rebadge of the OpenAI Codex CLI Rust " +
			"build; codex.NewOpenInterpreter() retags the SAME parser " +
			"(internal/adapter/codex, models.go:325-333).",
	},
	{
		alias: toolAntigravityCLI, source: toolAntigravity,
		why: "the antigravity CLI (`agy`) and the desktop app share one " +
			"mapToolName (internal/adapter/antigravity/classify.go:426).",
	},
	{
		alias: toolRooCode, source: toolCline,
		why: "roo-code is parsed by the Cline adapter — its actionMap " +
			"comment is literally \"Cline/Roo tool names\" " +
			"(internal/adapter/cline/adapter.go:112).",
	},
	{
		alias: toolZooCode, source: toolCline,
		why: "zoo-code (ZooCode, ZooCodeOrganization.zoo-code) is the " +
			"community continuation of Roo Code and carries Roo's task " +
			"layout, so it is parsed through the SAME cline adapter " +
			"table as roo-code (internal/adapter/cline/roots.go " +
			"clineExtensions), added 2026-09-03 (uncaptured-surfaces " +
			"wiring plan, ticket U1).",
	},
	{
		alias: toolKiloCode, source: toolCline,
		why: "kilocode.LegacyAdapter wraps internal/adapter/cline.Adapter " +
			"and re-tags rows Tool=\"kilo-code\".",
	},
}

func buildTable() []Entry {
	out := make([]Entry, 0, len(specificRows)+len(toolGlobRows)+len(fallbackRows)+len(globalGlobRows)+256)
	out = append(out, specificRows...)
	out = append(out, toolGlobRows...)
	for _, a := range toolAliases {
		for _, e := range specificRows {
			if e.Tool == a.source {
				out = append(out, entry(a.alias, e.Native, e.ActionType, e.Surface))
			}
		}
		for _, e := range toolGlobRows {
			if e.Tool == a.source {
				out = append(out, entry(a.alias, e.Native, e.ActionType, e.Surface))
			}
		}
	}
	out = append(out, fallbackRows...)
	out = append(out, globalGlobRows...)
	return out
}

// rows is a small builder that stamps one (tool, surface, actionType)
// onto a run of native names, keeping the data table readable at ~500
// rows without repeating four fields per line.
func rows(tool string, surface Surface, actionType string, natives ...string) []Entry {
	out := make([]Entry, 0, len(natives))
	for _, n := range natives {
		out = append(out, entry(tool, n, actionType, surface))
	}
	return out
}

func concat(groups ...[]Entry) []Entry {
	n := 0
	for _, g := range groups {
		n += len(g)
	}
	out := make([]Entry, 0, n)
	for _, g := range groups {
		out = append(out, g...)
	}
	return out
}

// specificRows holds every LITERAL (tool, native) row, grouped by tool.
//
// Provenance of each group is noted inline: "code" = the adapter's own
// private map/switch (which WINS on any disagreement, per the plan's
// mining rule); "corpus" = a native name measured in the live 321,675-row
// action corpus on 2026-07-31 that the code does not map (these are the
// rows that currently land in `unknown`).
var specificRows = concat(
	claudeCodeRows,
	codexRows,
	coworkRows,
	cursorRows,
	openCodeRows,
	clineRows,
	clineCLIRows,
	copilotRows,
	copilotCLIRows,
	antigravityRows,
	geminiCLIRows,
	grokRows,
	gooseRows,
	devinRows,
	crushRows,
	droidRows,
	hermesRows,
	kiloCodeCLIRows,
	kimiCodeRows,
	kiroCLIRows,
	kiroCrewRows,
	openClawRows,
	piRows,
	poolsideRows,
	primeAgentRows,
	qoderRows,
	qwenCodeRows,
	commandCodeRows,
	aiderRows,
	museRows,
	deepSeekRows,
	zcodeRows,
	mistralCodeRows,
	freebuffRows,
	junieRows,
	zedRows,
)

// --- claude-code -----------------------------------------------------
// code: internal/adapter/claudecode/adapter.go:137-195 (actionMap).
// corpus: the ToolSearch/Monitor/SendMessage/Skill/ScheduleWakeup/
// StructuredOutput family — ~1,100 rows currently `unknown`, exactly the
// gap plan §0 measured and migration 024 deferred.
var claudeCodeRows = concat(
	rows(toolClaudeCode, SurfaceBuiltin, ActionReadFile, "Read"),
	rows(toolClaudeCode, SurfaceBuiltin, ActionWriteFile, "Write"),
	rows(toolClaudeCode, SurfaceBuiltin, ActionEditFile, "Edit", "MultiEdit", "NotebookEdit"),
	// Shell variants: Bash is canonical on Linux/macOS/WSL; the rest
	// surface on Windows-side Claude Code and operator shell wrappers
	// (adapter.go:130-136). PowerShell alone is 1,789 corpus rows.
	rows(toolClaudeCode, SurfaceBuiltin, ActionRunCommand,
		"Bash", "PowerShell", "powershell", "pwsh", "cmd", "cmd.exe", "sh"),
	rows(toolClaudeCode, SurfaceBuiltin, ActionSearchText, "Grep"),
	rows(toolClaudeCode, SurfaceBuiltin, ActionSearchFiles, "Glob"),
	rows(toolClaudeCode, SurfaceBuiltin, ActionWebSearch, "WebSearch"),
	rows(toolClaudeCode, SurfaceBuiltin, ActionWebFetch, "WebFetch"),
	rows(toolClaudeCode, SurfaceOrchestration, ActionSpawnSubagent, "Agent"),
	rows(toolClaudeCode, SurfaceBuiltin, ActionTodoUpdate,
		"TaskCreate", "TaskUpdate", "TaskList", "TaskGet", "TaskOutput",
		"TaskStop", "TodoWrite"),
	rows(toolClaudeCode, SurfaceBuiltin, ActionAskUser, "AskUserQuestion"),
	rows(toolClaudeCode, SurfaceMeta, ActionPermissionMode, "EnterPlanMode", "ExitPlanMode"),
	// corpus — orchestration family.
	rows(toolClaudeCode, SurfaceOrchestration, ActionAgentMessage, "SendMessage"),
	// Monitor starts a background watcher whose events re-enter the agent
	// loop; it is not a one-shot shell exec, so it is agent_control, not
	// run_command.
	rows(toolClaudeCode, SurfaceOrchestration, ActionAgentControl, "Monitor"),
	// corpus — skill / harness family.
	rows(toolClaudeCode, SurfaceBuiltin, ActionSkillInvoke, "Skill"),
	rows(toolClaudeCode, SurfaceMeta, ActionToolSearch, "ToolSearch"),
	rows(toolClaudeCode, SurfaceMeta, ActionSchedule,
		"ScheduleWakeup", "CronCreate", "CronDelete", "CronList"),
	rows(toolClaudeCode, SurfaceMeta, ActionNotification, "PushNotification"),
	rows(toolClaudeCode, SurfaceMeta, ActionWorktreeCreate, "EnterWorktree"),
	rows(toolClaudeCode, SurfaceMeta, ActionWorktreeRemove, "ExitWorktree"),
	rows(toolClaudeCode, SurfaceMeta, ActionHarnessCall,
		"StructuredOutput", "SendUserFile", "Artifact", "Workflow"),
)

// --- codex -----------------------------------------------------------
// code: internal/adapter/codex/adapter.go:148-207 (actionMap).
// corpus: the wait/wait_agent/spawn_agent/send_message/write_stdin
// orchestration family (~1,900 rows `unknown`), plus the *_end event
// names codex writes into raw_tool_name, plus a capitalised `Bash`
// (24 rows) the map lacks.
var codexRows = concat(
	rows(toolCodex, SurfaceBuiltin, ActionRunCommand,
		"shell", "exec", "execute", "command", "shell_command",
		"exec_command", "powershell", "pwsh", "cmd.exe",
		"Bash"), // corpus, 24 rows — absent from actionMap.
	rows(toolCodex, SurfaceBuiltin, ActionEditFile,
		"apply_patch", "patch", "replace", "edit_file",
		"patch_apply_end"), // corpus, 2,274 rows.
	rows(toolCodex, SurfaceBuiltin, ActionReadFile,
		"file_read", "read_file", "open_file", "view_image"),
	rows(toolCodex, SurfaceBuiltin, ActionWriteFile,
		"file_write", "write_file", "create_file"),
	rows(toolCodex, SurfaceBuiltin, ActionSearchText,
		"search", "grep", "find_text", "find_in_files"),
	rows(toolCodex, SurfaceBuiltin, ActionSearchFiles,
		"file_search", "find", "glob", "list_files", "list_directory"),
	rows(toolCodex, SurfaceBuiltin, ActionWebSearch,
		"web_search",
		"web_search_end"), // corpus, 148 rows.
	rows(toolCodex, SurfaceBuiltin, ActionWebFetch, "web_fetch", "fetch_url"),
	rows(toolCodex, SurfaceBuiltin, ActionTodoUpdate, "update_plan"),
	rows(toolCodex, SurfaceBuiltin, ActionAskUser, "request_user_input"),
	rows(toolCodex, SurfaceMeta, ActionHarnessCall, "imagegen"),
	// Codex strips the `mcp__` namespace before writing raw_tool_name,
	// so its MCP calls arrive as BARE tool names. Only names actually
	// observed in the corpus or already pinned in the adapter's map are
	// listed — no speculative MCP surface (honesty rule).
	rows(toolCodex, SurfaceMCP, ActionMCPCall,
		"mcp_tool_call_end", // corpus, 151 rows.
		"js",                // corpus, 47 rows (node_repl:js).
		"list_mcp_resources", "list_mcp_resource_templates",
		"search_past_outputs", "get_session_summary", "get_project_patterns",
		"get_last_test_result", "get_session_recovery_context",
		"get_cost_summary", "check_command_freshness", "get_failure_context",
		"load_workspace_dependencies",
		"get_file", "get_action_details", "list_actions_around"), // corpus.
	// Orchestration family — the plan's headline unknown bucket.
	rows(toolCodex, SurfaceOrchestration, ActionSubagentWait, "wait", "wait_agent"),
	rows(toolCodex, SurfaceOrchestration, ActionSpawnSubagent, "spawn_agent"),
	// followup_task hands more work to an EXISTING agent thread, so it is
	// agent_message rather than a fresh spawn.
	rows(toolCodex, SurfaceOrchestration, ActionAgentMessage, "send_message", "followup_task"),
	rows(toolCodex, SurfaceOrchestration, ActionAgentControl,
		"list_agents", "interrupt_agent", "read_thread",
		"read_thread_terminal", "list_threads"),
	rows(toolCodex, SurfaceOrchestration, ActionStdinWrite, "write_stdin"),
)

// --- cowork ----------------------------------------------------------
// code: internal/adapter/cowork/adapter.go:136-179 (actionMap).
// NOTE the two deliberate cowork-vs-claude-code divergences: cowork maps
// Skill and ToolSearch to mcp_call, where claude-code (above) uses the
// new skill_invoke / tool_search types. Code wins per the mining rule;
// WP-T3 is where the two are reconciled.
var coworkRows = concat(
	rows(toolCowork, SurfaceBuiltin, ActionReadFile, "Read"),
	rows(toolCowork, SurfaceBuiltin, ActionWriteFile, "Write"),
	rows(toolCowork, SurfaceBuiltin, ActionEditFile, "Edit", "NotebookEdit"),
	rows(toolCowork, SurfaceBuiltin, ActionRunCommand,
		"Bash", "PowerShell", "powershell", "pwsh", "cmd", "cmd.exe", "sh"),
	rows(toolCowork, SurfaceBuiltin, ActionSearchText, "Grep"),
	rows(toolCowork, SurfaceBuiltin, ActionSearchFiles, "Glob"),
	rows(toolCowork, SurfaceBuiltin, ActionWebSearch, "WebSearch"),
	rows(toolCowork, SurfaceBuiltin, ActionWebFetch, "WebFetch"),
	rows(toolCowork, SurfaceOrchestration, ActionSpawnSubagent, "Agent", "Task"),
	rows(toolCowork, SurfaceBuiltin, ActionTodoUpdate,
		"TaskCreate", "TaskUpdate", "TaskList", "TaskGet", "TaskOutput",
		"TaskStop", "TodoWrite"),
	rows(toolCowork, SurfaceBuiltin, ActionAskUser, "AskUserQuestion"),
	rows(toolCowork, SurfaceBuiltin, ActionMCPCall, "Skill", "ToolSearch"),
	// Workspace MCP twins of the built-ins: Surface mcp, Category cmd/web.
	rows(toolCowork, SurfaceMCP, ActionRunCommand, "mcp__workspace__bash"),
	rows(toolCowork, SurfaceMCP, ActionWebFetch, "mcp__workspace__web_fetch"),
	rows(toolCowork, SurfaceMCP, ActionMCPCall,
		"mcp__cowork__request_cowork_directory",
		"mcp__cowork__present_files",
		"mcp__cowork__allow_cowork_file_delete",
		"mcp__cowork__send_user_message", // corpus, 2 rows.
		"mcp__visualize__show_widget",
		"mcp__visualize__read_me"),
)

// --- cursor ----------------------------------------------------------
// code: internal/adapter/cursor/adapter.go:980-1015 (transcript switch)
// + :547-560 / :957-975 (live-hook switches). The code lower-cases the
// name before switching, so the corpus's capitalised spellings (Read,
// Grep, Glob, Shell, SemanticSearch) resolve through Resolve's
// normalized pass.
// corpus: `Write` (4 rows) and `Delete` (2 rows) land `unknown` today —
// the transcript switch has writefile/createfile but no bare `write`,
// and no delete branch at all.
var cursorRows = concat(
	rows(toolCursor, SurfaceBuiltin, ActionTodoUpdate, "TodoWrite"),
	rows(toolCursor, SurfaceBuiltin, ActionReadFile,
		"read", "readfile", "cat", "readlints", "beforeReadFile"),
	rows(toolCursor, SurfaceBuiltin, ActionWriteFile,
		"writefile", "createfile",
		"Write"), // corpus gap fix.
	rows(toolCursor, SurfaceBuiltin, ActionEditFile,
		"applypatch", "editfile", "strreplace", "edit", "afterFileEdit",
		// No canonical delete action type exists; edit_file is the
		// established precedent (copilot `deletefile`, grok `deletefile`
		// / `removefile`). WP-T4 candidate for a real delete type.
		"Delete"),
	rows(toolCursor, SurfaceBuiltin, ActionRunCommand,
		"shell", "bash", "command", "powershell", "pwsh", "cmd", "cmdexe",
		"beforeShellExecution"),
	rows(toolCursor, SurfaceBuiltin, ActionSearchText,
		"grep", "search", "searchfiles", "semanticsearch"),
	rows(toolCursor, SurfaceBuiltin, ActionSearchFiles, "glob", "findfiles"),
	rows(toolCursor, SurfaceOrchestration, ActionSpawnSubagent, "subagent", "agent"),
	rows(toolCursor, SurfaceMCP, ActionMCPCall, "call_mcp_tool", "mcp", "mcptool"),
	// `await` is a control-flow primitive with no file/command target;
	// the adapter keeps it deliberately unclassified rather than
	// mis-categorising it (adapter.go:1009-1014). Preserved as an
	// EXPLICIT unknown row — a known tool we chose not to bucket, which
	// is different information from "never seen".
	rows(toolCursor, SurfaceBuiltin, ActionUnknown, "await"),
)

// --- opencode --------------------------------------------------------
// code: internal/adapter/opencode/adapter.go:1030-1085 (mapTool).
// corpus: `opencode.step_finish` (52 rows `unknown`) is a turn marker,
// not a tool.
var openCodeRows = concat(
	rows(toolOpenCode, SurfaceBuiltin, ActionRunCommand,
		"bash", "shell", "command", "powershell", "pwsh", "cmd", "cmd.exe"),
	rows(toolOpenCode, SurfaceBuiltin, ActionReadFile, "read", "cat", "view"),
	rows(toolOpenCode, SurfaceBuiltin, ActionWriteFile, "write", "create"),
	rows(toolOpenCode, SurfaceBuiltin, ActionEditFile,
		"edit", "patch", "replace", "multiedit", "applypatch", "apply_patch"),
	rows(toolOpenCode, SurfaceBuiltin, ActionSearchText, "grep", "search", "rg"),
	rows(toolOpenCode, SurfaceBuiltin, ActionSearchFiles, "glob", "find", "ls"),
	rows(toolOpenCode, SurfaceBuiltin, ActionWebFetch, "webfetch", "fetch", "http"),
	rows(toolOpenCode, SurfaceBuiltin, ActionWebSearch, "websearch"),
	rows(toolOpenCode, SurfaceOrchestration, ActionSpawnSubagent, "task", "agent", "subagent"),
	rows(toolOpenCode, SurfaceBuiltin, ActionTodoUpdate, "todoread", "todowrite", "todo"),
	rows(toolOpenCode, SurfaceMeta, ActionHarnessCall, "opencode.step_finish"),
)

// --- cline (+ roo-code, kilo-code aliases) ---------------------------
// code: internal/adapter/cline/adapter.go:113-131 (actionMap).
// NOTE cline is the one adapter where `search_files` means TEXT search
// (regex over file bodies) and `list_files` means file discovery — the
// inverse of clinecli/command-code. Tool-specific rows are exactly why
// Resolve keys on (tool, native).
var clineRows = concat(
	rows(toolCline, SurfaceBuiltin, ActionRunCommand,
		"execute_command", "powershell", "pwsh", "cmd", "cmd.exe", "bash", "sh"),
	rows(toolCline, SurfaceBuiltin, ActionReadFile, "read_file"),
	rows(toolCline, SurfaceBuiltin, ActionWriteFile, "write_to_file"),
	rows(toolCline, SurfaceBuiltin, ActionEditFile, "replace_in_file"),
	rows(toolCline, SurfaceBuiltin, ActionSearchText, "search_files"),
	rows(toolCline, SurfaceBuiltin, ActionSearchFiles, "list_files"),
	rows(toolCline, SurfaceBuiltin, ActionBrowserAction, "browser_action"),
	rows(toolCline, SurfaceMeta, ActionTaskComplete, "attempt_completion"),
	rows(toolCline, SurfaceMCP, ActionMCPCall, "use_mcp_tool", "access_mcp_resource"),
	rows(toolCline, SurfaceBuiltin, ActionAskUser, "ask_followup_question"),
)

// --- cline-cli -------------------------------------------------------
// code: internal/adapter/clinecli/normalize.go:36-130 (normalizeToolName).
// The 17 team_* fleet primitives are Surface orchestration but Category
// mcp — the adapter routes them all through mcp_call and the plan's
// mining rule keeps that.
var clineCLIRows = concat(
	rows(toolClineCLI, SurfaceBuiltin, ActionReadFile, "read_files"),
	rows(toolClineCLI, SurfaceBuiltin, ActionRunCommand, "run_commands"),
	rows(toolClineCLI, SurfaceBuiltin, ActionEditFile, "apply_patch", "editor"),
	rows(toolClineCLI, SurfaceBuiltin, ActionSearchFiles, "search_codebase"),
	rows(toolClineCLI, SurfaceBuiltin, ActionWebFetch, "fetch_web_content"),
	rows(toolClineCLI, SurfaceBuiltin, ActionAskUser, "ask_question"),
	rows(toolClineCLI, SurfaceBuiltin, ActionMCPCall, "skills"),
	rows(toolClineCLI, SurfaceMeta, ActionTaskComplete, "submit_and_exit"),
	rows(toolClineCLI, SurfaceOrchestration, ActionSpawnSubagent,
		"spawn_agent", "team_spawn_teammate"),
	rows(toolClineCLI, SurfaceOrchestration, ActionMCPCall,
		"team_attach_outcome_fragment", "team_await_runs", "team_broadcast",
		"team_cancel_run", "team_cleanup", "team_create_outcome",
		"team_finalize_outcome", "team_list_outcomes", "team_list_runs",
		"team_mission_log", "team_read_mailbox",
		"team_review_outcome_fragment", "team_run_task", "team_send_message",
		"team_shutdown_teammate", "team_status", "team_task"),
)

// --- copilot (VS Code extension) -------------------------------------
// code: internal/adapter/copilot/adapter.go:278-305 (mapToolName; the
// switch keys are lower-cased with `_` stripped, so the corpus's
// `read_file` / `view_image` / `list_dir` / `grep_search` / `create_file`
// resolve through Resolve's normalized pass).
var copilotRows = concat(
	rows(toolCopilot, SurfaceBuiltin, ActionReadFile,
		"readfile", "openfile", "readsemantic", "searchbyname", "viewimage"),
	rows(toolCopilot, SurfaceBuiltin, ActionWriteFile, "createfile", "writefile"),
	rows(toolCopilot, SurfaceBuiltin, ActionEditFile,
		"replacestringinfile", "replacelinesinfile", "applypatch",
		"deletefile", "editfiles"),
	rows(toolCopilot, SurfaceBuiltin, ActionRunCommand,
		"runinterminal", "executecommand", "shell", "powershell", "pwsh",
		"cmd", "cmdexe", "bash"),
	rows(toolCopilot, SurfaceBuiltin, ActionSearchText,
		"findtextinfiles", "grep", "grepsearch"),
	rows(toolCopilot, SurfaceBuiltin, ActionSearchFiles,
		"filesearch", "findfiles", "listdir"),
	rows(toolCopilot, SurfaceBuiltin, ActionWebFetch, "fetchwebpage", "webfetch"),
	rows(toolCopilot, SurfaceBuiltin, ActionWebSearch, "websearch"),
	rows(toolCopilot, SurfaceBuiltin, ActionTodoUpdate, "managetodolist"),
	rows(toolCopilot, SurfaceOrchestration, ActionSpawnSubagent, "runsubagent"),
)

// --- copilot-cli -----------------------------------------------------
// code: internal/adapter/copilotcli/events.go:1178-1205 (mapToolName).
// `report_intent` is an EXPLICIT ActionUnknown in the adapter ("Copilot's
// mid-turn intent announcement", events.go:1199-1200); the mining rule
// keeps that decision rather than inventing a bucket for it.
// corpus: `write` / `shell` (permission_request rows) and `ask_user`
// (1 row `unknown`) are absent from the switch;
// `fetch_copilot_cli_documentation` (2 rows `unknown`) is the CLI's own
// local docs lookup, not a web fetch.
var copilotCLIRows = concat(
	rows(toolCopilotCLI, SurfaceBuiltin, ActionReadFile, "view", "read"),
	rows(toolCopilotCLI, SurfaceBuiltin, ActionWriteFile,
		"create",
		"write"), // corpus.
	rows(toolCopilotCLI, SurfaceBuiltin, ActionEditFile, "edit", "str_replace_editor"),
	rows(toolCopilotCLI, SurfaceBuiltin, ActionSearchFiles, "glob"),
	rows(toolCopilotCLI, SurfaceBuiltin, ActionSearchText, "grep"),
	rows(toolCopilotCLI, SurfaceBuiltin, ActionRunCommand,
		"bash", "powershell", "pwsh", "cmd", "cmd.exe", "sh",
		"shell"), // corpus.
	rows(toolCopilotCLI, SurfaceBuiltin, ActionWebFetch, "web_fetch"),
	rows(toolCopilotCLI, SurfaceBuiltin, ActionWebSearch, "web_search"),
	rows(toolCopilotCLI, SurfaceOrchestration, ActionSpawnSubagent, "task"),
	rows(toolCopilotCLI, SurfaceBuiltin, ActionAskUser, "ask_user"), // corpus.
	rows(toolCopilotCLI, SurfaceBuiltin, ActionUnknown, "report_intent"),
	rows(toolCopilotCLI, SurfaceMeta, ActionHarnessCall,
		"fetch_copilot_cli_documentation"), // corpus.
)

// --- antigravity (+ antigravity-cli alias) ---------------------------
// code: internal/adapter/antigravity/classify.go (mapToolName; keys are
// lower-cased with `_`/`-` stripped).
// corpus: the `structured.*` synthetic names the structured-record
// parser writes into raw_tool_name, plus the desktop IDE's native
// tool_calls[].name spellings (`list_dir`, `view_file`, `run_command`,
// `write_to_file`, `replace_file_content`, `find_by_name`) that
// transcript.go writes verbatim into raw_tool_name — live-grounded
// 2026-09-03 from brain/<uuid>/.system_generated/logs/transcript.jsonl.
// The `transcript.*` synthetic names are the orphan-result fallback
// (a typed result step with no preceding tool_calls entry).
var antigravityRows = concat(
	rows(toolAntigravity, SurfaceBuiltin, ActionReadFile,
		"readfile", "read", "viewfile", "view", "cat", "structured.file_view",
		"transcript.view_file"),
	rows(toolAntigravity, SurfaceBuiltin, ActionWriteFile,
		"writefile", "write", "createfile", "create", "writetofile"),
	rows(toolAntigravity, SurfaceBuiltin, ActionEditFile,
		"replace", "edit", "editfile", "applypatch", "patch",
		"replacefilecontent", "structured.artifact_write",
		"transcript.code_action"),
	rows(toolAntigravity, SurfaceBuiltin, ActionRunCommand,
		"runshellcommand", "shell", "bash", "exec", "execute", "runcommand",
		"run", "powershell", "pwsh", "cmd", "cmdexe", "structured.run_command",
		"transcript.run_command"),
	rows(toolAntigravity, SurfaceBuiltin, ActionWebSearch,
		"googlewebsearch", "websearch", "search"),
	rows(toolAntigravity, SurfaceBuiltin, ActionWebFetch,
		"webfetch", "fetch", "fetchurl", "fetchwebpage"),
	rows(toolAntigravity, SurfaceBuiltin, ActionSearchText, "grep", "searchtext", "findtext",
		"transcript.grep_search"),
	rows(toolAntigravity, SurfaceBuiltin, ActionSearchFiles,
		"glob", "findfiles", "filesearch", "ls", "listfiles", "listdir", "findbyname",
		"transcript.list_directory"),
)

// --- gemini-cli ------------------------------------------------------
// code: internal/adapter/gemini/parser.go:604-632.
var geminiCLIRows = concat(
	rows(toolGeminiCLI, SurfaceBuiltin, ActionReadFile, "readfile", "read", "viewfile", "view"),
	rows(toolGeminiCLI, SurfaceBuiltin, ActionWriteFile, "writefile", "write", "createfile", "create"),
	rows(toolGeminiCLI, SurfaceBuiltin, ActionEditFile,
		"replace", "edit", "editfile", "applypatch", "patch"),
	rows(toolGeminiCLI, SurfaceBuiltin, ActionRunCommand,
		"runshellcommand", "shell", "bash", "exec", "execute", "runcommand",
		"powershell", "pwsh", "cmd", "cmdexe"),
	rows(toolGeminiCLI, SurfaceBuiltin, ActionWebSearch, "googlewebsearch", "websearch", "search"),
	rows(toolGeminiCLI, SurfaceBuiltin, ActionWebFetch,
		"webfetch", "fetch", "fetchurl", "fetchwebpage"),
	rows(toolGeminiCLI, SurfaceBuiltin, ActionSearchText, "grep", "searchtext", "findtext", "grepsearch"),
	rows(toolGeminiCLI, SurfaceBuiltin, ActionSearchFiles,
		"glob", "findfiles", "filesearch", "ls", "listfiles", "listdirectory"),
	// invokeagent: live corpus (2026-07-31, WP-T6 G1 follow-up) shows
	// args {agent_name, prompt} — hands work to a sub-agent, same family
	// as claude-code Agent / grok+qwen-code spawnagent.
	rows(toolGeminiCLI, SurfaceOrchestration, ActionSpawnSubagent, "invokeagent"),
	// savememory/memorize: "closest existing semantic; defer dedicated
	// type" (parser.go:623-624). Kept as code has it.
	rows(toolGeminiCLI, SurfaceBuiltin, ActionMCPCall, "savememory", "memorize"),
	// write_todos: gemini-cli's real, shipped todo/plan tool (PR #8761,
	// merged 2025-09-20, first release v0.8.0) — RETRACTED from a
	// wrongly-recorded "no task tool" during the 2026-09-07 task-
	// tracking capture audit round 2. Without this row every write_todos
	// call normalized to `writetodos` and fell through to ActionUnknown
	// for ~10 months. Schema: {todos:[{description,status}]}, 5-value
	// status vocabulary (pending/in_progress/completed/cancelled/
	// blocked), no item id — a Snapshot rewrite (internal/taskflow
	// decodes it). Gated at the vendor to the Gemini-2 family since
	// v0.21.1 (docs/audits/task-tracking-capture-audit-2026-09-07.md §2.6).
	rows(toolGeminiCLI, SurfaceBuiltin, ActionTodoUpdate, "write_todos"),
	// complete_task: sibling constant in the same vendor source block as
	// write_todos (ENTER_PLAN_MODE_TOOL_NAME / EXIT_PLAN_MODE_TOOL_NAME /
	// COMPLETE_TASK_TOOL_NAME) — an unmapped turn-terminus signal, the
	// same family as cline's attempt_completion / codex's terminal
	// event. Never observed live; added defensively alongside the
	// write_todos fix per the audit's round-2 recommendation (§R2.8).
	rows(toolGeminiCLI, SurfaceBuiltin, ActionTaskComplete, "complete_task"),
	// updatetopic: DELIBERATE unknown, not a corpus gap the code failed
	// to notice. Live args (2026-07-31, WP-T6 G1 follow-up) are
	// {title, summary, strategic_intent} — a running conversation-topic
	// LABEL, not a structured todo-list/plan (no items, no per-item
	// status). ActionTodoUpdate's contract requires that shape (codex
	// update_plan, TodoWrite, etc. all carry discrete items); forcing
	// update_topic in would conflate topic-narration with plan-tracking.
	// See mapToolName's "updatetopic" case + this file's
	// tooltax_conformance_test.go unclassifiedDomain entry.
	rows(toolGeminiCLI, SurfaceBuiltin, ActionUnknown, "updatetopic"),
)

// --- grok ------------------------------------------------------------
// code: internal/adapter/grok/records.go:258-293.
var grokRows = concat(
	rows(toolGrok, SurfaceBuiltin, ActionReadFile, "readfile", "read", "view", "viewfile", "cat"),
	rows(toolGrok, SurfaceBuiltin, ActionWriteFile,
		"writefile", "write", "createfile", "create", "newfile"),
	rows(toolGrok, SurfaceBuiltin, ActionEditFile,
		"editfile", "edit", "replace", "applypatch", "patch", "strreplace",
		"searchreplace", "multiedit", "deletefile", "removefile"),
	rows(toolGrok, SurfaceBuiltin, ActionRunCommand,
		"runterminalcommand", "runcommand", "terminal", "bash", "shell",
		"exec", "execute", "cmd", "powershell", "pwsh"),
	rows(toolGrok, SurfaceBuiltin, ActionSearchText,
		"grep", "searchtext", "ripgrep", "codesearch", "findtext", "search"),
	rows(toolGrok, SurfaceBuiltin, ActionSearchFiles,
		"listdir", "listdirectory", "glob", "findfiles", "filesearch", "ls", "readfolder"),
	rows(toolGrok, SurfaceBuiltin, ActionWebSearch, "websearch", "search_web", "browsersearch"),
	rows(toolGrok, SurfaceBuiltin, ActionWebFetch,
		"webfetch", "fetch", "fetchurl", "readurl", "browse", "openurl"),
	rows(toolGrok, SurfaceOrchestration, ActionSpawnSubagent,
		"task", "subagent", "spawnagent", "dispatchagent", "delegate", "agent"),
	rows(toolGrok, SurfaceBuiltin, ActionTodoUpdate,
		"todowrite", "todo", "todoupdate", "updateplan", "planupdate"),
)

// --- goose -----------------------------------------------------------
// code: internal/adapter/goose/parse.go:330-352.
var gooseRows = concat(
	rows(toolGoose, SurfaceBuiltin, ActionRunCommand,
		"shell", "bash", "run_command", "command", "terminal"),
	rows(toolGoose, SurfaceBuiltin, ActionReadFile, "read", "view", "cat", "read_file"),
	rows(toolGoose, SurfaceBuiltin, ActionWriteFile,
		"write", "write_file", "create", "create_file"),
	rows(toolGoose, SurfaceBuiltin, ActionEditFile,
		"text_editor", "str_replace", "edit", "edit_file", "apply_patch", "replace"),
	rows(toolGoose, SurfaceBuiltin, ActionSearchFiles, "glob", "list", "list_dir", "ls", "find"),
	rows(toolGoose, SurfaceBuiltin, ActionSearchText, "grep", "search", "rg", "ripgrep"),
	rows(toolGoose, SurfaceBuiltin, ActionWebFetch, "fetch", "web_fetch", "read_url", "download"),
	rows(toolGoose, SurfaceBuiltin, ActionWebSearch, "web_search", "websearch", "search_web"),
)

// --- deepseek ----------------------------------------------------------
// code: internal/adapter/deepseek/records.go (actionMap).
//
// GROUNDED against the confirmed 24-name live inventory (a request/header
// event embeds the full JSON-schema tool-definition set) — literal names
// only, no defensive synonyms, since DeepSeek Harness's tool names are
// already a single stable snake_case spelling.
var deepSeekRows = concat(
	rows(toolDeepSeek, SurfaceBuiltin, ActionAskUser, "ask_user_question"),
	rows(toolDeepSeek, SurfaceBuiltin, ActionRunCommand, "bash", "pwsh"),
	// create_goal / get_goal / update_goal are DSH's own goal-tracking
	// trio — they record state back INTO the harness, not workspace
	// state.
	rows(toolDeepSeek, SurfaceBuiltin, ActionHarnessCall,
		"create_goal", "get_goal", "update_goal", "exit_plan_mode"),
	rows(toolDeepSeek, SurfaceBuiltin, ActionEditFile, "edit"),
	rows(toolDeepSeek, SurfaceBuiltin, ActionSearchFiles, "glob"),
	rows(toolDeepSeek, SurfaceBuiltin, ActionSearchText, "grep"),
	// interrupt_agent / job_kill / job_list / job_output / list_agents /
	// send_message are multi-agent orchestration control-plane calls —
	// they don't spawn a NEW agent themselves.
	rows(toolDeepSeek, SurfaceOrchestration, ActionAgentControl,
		"interrupt_agent", "job_kill", "job_list", "job_output", "list_agents"),
	rows(toolDeepSeek, SurfaceOrchestration, ActionAgentMessage, "send_message"),
	// ralph / subagent / subagent_fork / workflow all launch a NEW agent
	// run.
	rows(toolDeepSeek, SurfaceOrchestration, ActionSpawnSubagent,
		"ralph", "subagent", "subagent_fork", "workflow"),
	rows(toolDeepSeek, SurfaceBuiltin, ActionReadFile, "read", "read_image"),
	rows(toolDeepSeek, SurfaceBuiltin, ActionSkillInvoke, "skill"),
	rows(toolDeepSeek, SurfaceBuiltin, ActionTodoUpdate, "todo_write"),
	rows(toolDeepSeek, SurfaceBuiltin, ActionWebSearch, "web_search"),
	rows(toolDeepSeek, SurfaceBuiltin, ActionWriteFile, "write"),
)

// --- devin -----------------------------------------------------------
// code: internal/adapter/devin/adapter.go:392-420.
var devinRows = concat(
	rows(toolDevin, SurfaceBuiltin, ActionRunCommand,
		"exec", "bash", "shell", "command", "run_command", "run_terminal_cmd"),
	rows(toolDevin, SurfaceBuiltin, ActionReadFile, "read", "view", "cat", "read_file", "open"),
	rows(toolDevin, SurfaceBuiltin, ActionWriteFile,
		"write", "create", "create_file", "write_file"),
	rows(toolDevin, SurfaceBuiltin, ActionEditFile,
		"str_replace", "edit", "multiedit", "replace", "edit_file",
		"apply_patch", "str_replace_editor"),
	rows(toolDevin, SurfaceBuiltin, ActionSearchFiles,
		"ls", "glob", "find", "list_dir", "list_files"),
	rows(toolDevin, SurfaceBuiltin, ActionSearchText, "grep", "rg", "search", "codebase_search"),
	rows(toolDevin, SurfaceBuiltin, ActionWebFetch,
		"fetch", "download", "http", "web_fetch", "read_url"),
	rows(toolDevin, SurfaceBuiltin, ActionWebSearch, "web_search", "websearch", "search_web"),
	rows(toolDevin, SurfaceOrchestration, ActionSpawnSubagent,
		"run_subagent", "subagent", "task", "agent", "spawn_subagent"),
	rows(toolDevin, SurfaceMeta, ActionPermissionRequest, "request_scope", "request_permission"),
	rows(toolDevin, SurfaceBuiltin, ActionAskUser, "ask_user", "ask_question", "request_input"),
)

// --- crush -----------------------------------------------------------
// code: internal/adapter/crush/adapter.go:510-534.
var crushRows = concat(
	rows(toolCrush, SurfaceBuiltin, ActionRunCommand, "bash", "shell", "cmd", "powershell", "pwsh"),
	rows(toolCrush, SurfaceBuiltin, ActionReadFile, "view", "read", "cat"),
	rows(toolCrush, SurfaceBuiltin, ActionWriteFile, "write", "create"),
	rows(toolCrush, SurfaceBuiltin, ActionEditFile, "edit", "multiedit", "patch", "replace"),
	rows(toolCrush, SurfaceBuiltin, ActionSearchFiles, "ls", "glob", "find"),
	rows(toolCrush, SurfaceBuiltin, ActionSearchText, "grep", "rg", "search"),
	rows(toolCrush, SurfaceBuiltin, ActionWebFetch, "fetch", "download", "http"),
	rows(toolCrush, SurfaceBuiltin, ActionWebSearch, "sourcegraph", "websearch"),
	rows(toolCrush, SurfaceOrchestration, ActionSpawnSubagent, "agent", "task", "subagent"),
)

// --- droid -----------------------------------------------------------
// code: internal/adapter/droid/records.go:174-214 (actionMap).
// DISCREPANCY WORTH NAMING: droid maps its Cron*/Automation* family to
// config_change ("the closest honest bucket", records.go:202-204) while
// claude-code's equivalents get the new `schedule` type. Code wins here;
// WP-T4 should decide whether droid moves to `schedule`.
var droidRows = concat(
	rows(toolDroid, SurfaceBuiltin, ActionReadFile, "Read", "ReadFile"),
	rows(toolDroid, SurfaceBuiltin, ActionWriteFile, "Create", "Write", "GenerateDroid"),
	rows(toolDroid, SurfaceBuiltin, ActionEditFile, "Edit", "MultiEdit", "ApplyPatch"),
	rows(toolDroid, SurfaceBuiltin, ActionRunCommand, "Execute", "Bash"),
	rows(toolDroid, SurfaceBuiltin, ActionSearchText, "Grep"),
	rows(toolDroid, SurfaceBuiltin, ActionSearchFiles, "Glob", "LS"),
	rows(toolDroid, SurfaceBuiltin, ActionWebSearch, "WebSearch"),
	rows(toolDroid, SurfaceBuiltin, ActionWebFetch, "FetchUrl", "WebFetch"),
	rows(toolDroid, SurfaceBuiltin, ActionTodoUpdate, "TodoWrite"),
	rows(toolDroid, SurfaceBuiltin, ActionAskUser, "AskUser"),
	rows(toolDroid, SurfaceMeta, ActionPermissionMode, "ExitSpecMode"),
	rows(toolDroid, SurfaceOrchestration, ActionSpawnSubagent, "Task", "TaskOutput", "TaskStop"),
	rows(toolDroid, SurfaceMeta, ActionConfigChange,
		"CronCreate", "CronList", "CronDelete", "CreateAutomation",
		"ListAutomations", "ReadAutomation", "EditAutomation",
		"DeleteAutomation", "ListAutomationRun"),
)

// --- hermes ----------------------------------------------------------
// code: internal/adapter/hermes/normalize.go:36-130.
// DISCREPANCY WORTH NAMING: hermes maps `send_message` to mcp_call (an
// outbound Telegram/Discord/Slack gateway bridge) where codex's
// `send_message` is inter-agent (agent_message). Same name, genuinely
// different tool — the clearest argument for keying on (tool, native).
var hermesRows = concat(
	rows(toolHermes, SurfaceBuiltin, ActionReadFile, "read_file"),
	rows(toolHermes, SurfaceBuiltin, ActionWriteFile, "write_file"),
	rows(toolHermes, SurfaceBuiltin, ActionEditFile, "patch", "apply_diff"),
	rows(toolHermes, SurfaceBuiltin, ActionSearchFiles, "search_files"),
	rows(toolHermes, SurfaceBuiltin, ActionRunCommand, "terminal", "process", "execute_code"),
	rows(toolHermes, SurfaceBuiltin, ActionWebSearch, "web_search"),
	rows(toolHermes, SurfaceBuiltin, ActionWebFetch, "web_extract"),
	rows(toolHermes, SurfaceBuiltin, ActionBrowserAction, "computer_use"),
	rows(toolHermes, SurfaceOrchestration, ActionSpawnSubagent,
		"delegate_task", "mixture_of_agents"),
	rows(toolHermes, SurfaceBuiltin, ActionTodoUpdate, "todo"),
	rows(toolHermes, SurfaceBuiltin, ActionAskUser, "clarify"),
	rows(toolHermes, SurfaceBuiltin, ActionMCPCall,
		"memory", "session_search",
		"vision_analyze", "image_generate", "text_to_speech",
		"video_generate", "video_analyze",
		"send_message",
		"skill_view", "skill_manage", "skills_list",
		"cronjob"),
)

// --- kilo-code-cli ---------------------------------------------------
// code: internal/adapter/kilocode/adapter.go:1288-1340 (structural
// transposition of opencode's mapTool).
// corpus: `kilo-code-cli.step_finish` (68 rows `unknown`) — turn marker.
var kiloCodeCLIRows = concat(
	rows(toolKiloCodeCLI, SurfaceBuiltin, ActionRunCommand,
		"bash", "shell", "command", "powershell", "pwsh", "cmd", "cmd.exe"),
	rows(toolKiloCodeCLI, SurfaceBuiltin, ActionReadFile, "read", "cat", "view"),
	rows(toolKiloCodeCLI, SurfaceBuiltin, ActionWriteFile, "write", "create"),
	rows(toolKiloCodeCLI, SurfaceBuiltin, ActionEditFile,
		"edit", "patch", "replace", "multiedit", "applypatch", "apply_patch"),
	rows(toolKiloCodeCLI, SurfaceBuiltin, ActionSearchText, "grep", "search", "rg"),
	rows(toolKiloCodeCLI, SurfaceBuiltin, ActionSearchFiles, "glob", "find", "ls", "list"),
	rows(toolKiloCodeCLI, SurfaceBuiltin, ActionWebFetch, "webfetch", "fetch", "http"),
	rows(toolKiloCodeCLI, SurfaceBuiltin, ActionWebSearch, "websearch"),
	rows(toolKiloCodeCLI, SurfaceOrchestration, ActionSpawnSubagent, "task", "agent", "subagent"),
	rows(toolKiloCodeCLI, SurfaceBuiltin, ActionTodoUpdate, "todoread", "todowrite", "todo"),
	rows(toolKiloCodeCLI, SurfaceMeta, ActionHarnessCall, "kilo-code-cli.step_finish"),
)

// --- kimi-code -------------------------------------------------------
// code: internal/adapter/kimicode/records.go:128-160.
var kimiCodeRows = concat(
	rows(toolKimiCode, SurfaceBuiltin, ActionReadFile, "read", "readfile", "readmediafile", "view"),
	rows(toolKimiCode, SurfaceBuiltin, ActionWriteFile, "write", "writefile", "createfile"),
	rows(toolKimiCode, SurfaceBuiltin, ActionEditFile,
		"edit", "editfile", "applypatch", "patch", "replace"),
	rows(toolKimiCode, SurfaceBuiltin, ActionRunCommand,
		"bash", "shell", "exec", "runcommand", "run", "terminal"),
	rows(toolKimiCode, SurfaceBuiltin, ActionSearchText, "grep", "searchtext", "ripgrep", "findtext"),
	rows(toolKimiCode, SurfaceBuiltin, ActionSearchFiles,
		"glob", "findfiles", "listfiles", "ls", "listdirectory"),
	rows(toolKimiCode, SurfaceBuiltin, ActionWebSearch, "websearch", "search"),
	rows(toolKimiCode, SurfaceBuiltin, ActionWebFetch,
		"fetchurl", "webfetch", "fetch", "fetchwebpage"),
	rows(toolKimiCode, SurfaceOrchestration, ActionSpawnSubagent,
		"agent", "agentswarm", "subagent", "spawnagent", "delegate"),
	rows(toolKimiCode, SurfaceBuiltin, ActionTodoUpdate, "todolist", "todowrite", "todo"),
)

// --- kiro-cli --------------------------------------------------------
// code: internal/adapter/kirocli/normalize.go (normalizeTool). ONE
// classifier serves all three Kiro layouts, so this block carries BOTH
// vocabularies: the CLI's (`fs_*`, `execute_bash`) and the Kiro IDE's
// (`read_file`, `str_replace`, `execute_pwsh`, `delete_file`,
// `list_directory`, `todo_list`), grounded on the operator's live Kiro
// IDE 1.0.411 run 2026-09-03.
//
// `fs_write` dispatches on the sub-arg: command="str_replace" →
// edit_file, else write_file. The table records the DEFAULT
// (write_file); the adapter keeps the sub-arg branch (a shape tooltax
// deliberately does not model).
//
// `delete_file` → edit_file follows the established precedent — no
// canonical delete action type exists (see the cowork block's note),
// and copilot `deletefile` / grok `deletefile` land the same way.
//
// corpus: `execute_cmd` (1 row `unknown`) is absent from the switch.
var kiroCLIRows = concat(
	rows(toolKiroCLI, SurfaceBuiltin, ActionReadFile,
		"fs_read",
		"read_file", // Kiro IDE.
		"read"),     // interactive flat stream (2026-09-03).
	rows(toolKiroCLI, SurfaceBuiltin, ActionWriteFile,
		"fs_write",
		"write"), // interactive flat stream (2026-09-03).
	rows(toolKiroCLI, SurfaceBuiltin, ActionEditFile,
		"str_replace",  // Kiro IDE.
		"delete_file"), // Kiro IDE; no canonical delete type.
	rows(toolKiroCLI, SurfaceBuiltin, ActionRunCommand,
		"execute_bash",
		"execute_pwsh", // Kiro IDE (shellType=powershell).
		"execute_cmd",  // corpus.
		"shell"),       // interactive flat stream (2026-09-03).
	rows(toolKiroCLI, SurfaceBuiltin, ActionSearchFiles, "list_directory"), // Kiro IDE.
	rows(toolKiroCLI, SurfaceBuiltin, ActionTodoUpdate, "todo_list"),       // Kiro IDE.
	rows(toolKiroCLI, SurfaceBuiltin, ActionUnknown, "introspect"),
)

// --- kiro-crew -------------------------------------------------------
// code: internal/adapter/kirocrew/parse.go (kindActions + resolveTool).
//
// Kiro Crew logs a tool call under its OWN normalized vocabulary in
// `meta.kind`, not under the kiro-cli tool name it actually drove. The
// vocabulary is deliberately tiny — three tokens, all grounded on the
// live 2026-09-03 capture (9 tool calls: 1 read, 2 edit, 6 execute):
//
//	read     -> read_file    (kiro-cli `read`)
//	edit     -> edit_file    (kiro-cli `write`, BOTH sub-modes)
//	execute  -> run_command  (kiro-cli `shell`)
//
// `edit` is LOSSY: Crew labels a file CREATE and a str-replace with the
// same token. The table records the default (edit_file) and the adapter
// keeps the `command == "create"` sub-arg branch that recovers write_file
// — exactly the split kiro-cli's own `fs_write` row documents above.
//
// No corpus rows: kiro-crew has never appeared in an action corpus (it is
// registered by this commit). Nothing is listed that was not observed.
var kiroCrewRows = concat(
	rows(toolKiroCrew, SurfaceBuiltin, ActionReadFile, "read"),
	rows(toolKiroCrew, SurfaceBuiltin, ActionEditFile, "edit"),
	rows(toolKiroCrew, SurfaceBuiltin, ActionRunCommand, "execute"),
)

// --- openclaw --------------------------------------------------------
// code: internal/adapter/openclaw/adapter.go:905-945.
var openClawRows = concat(
	rows(toolOpenClaw, SurfaceBuiltin, ActionReadFile, "read", "cat", "view"),
	rows(toolOpenClaw, SurfaceBuiltin, ActionWriteFile, "write", "create"),
	rows(toolOpenClaw, SurfaceBuiltin, ActionEditFile, "edit", "patch", "replace"),
	rows(toolOpenClaw, SurfaceBuiltin, ActionRunCommand,
		"exec", "bash", "shell", "command", "powershell", "pwsh", "cmd",
		"cmd.exe", "process"),
	rows(toolOpenClaw, SurfaceBuiltin, ActionWebFetch, "web_fetch"),
	rows(toolOpenClaw, SurfaceBuiltin, ActionBrowserAction, "browser"),
	rows(toolOpenClaw, SurfaceBuiltin, ActionSearchText, "memory_search"),
	rows(toolOpenClaw, SurfaceOrchestration, ActionSpawnSubagent, "sessions_spawn"),
	rows(toolOpenClaw, SurfaceBuiltin, ActionMCPCall,
		"canvas", "cron", "gateway", "memory_get", "message", "nodes",
		"session_status", "sessions_history", "sessions_list",
		"sessions_send", "sessions_yield", "subagents", "tts", "agents_list"),
)

// --- pi --------------------------------------------------------------
// code: internal/adapter/pi/adapter.go:425-452.
var piRows = concat(
	rows(toolPi, SurfaceBuiltin, ActionReadFile, "read", "cat", "view", "read_file", "open_file"),
	rows(toolPi, SurfaceBuiltin, ActionWriteFile, "write", "create", "write_file", "create_file"),
	rows(toolPi, SurfaceBuiltin, ActionEditFile,
		"edit", "patch", "replace", "apply_patch", "edit_file"),
	rows(toolPi, SurfaceBuiltin, ActionRunCommand,
		"bash", "shell", "command", "exec", "execute", "run",
		"powershell", "pwsh", "cmd", "cmd.exe"),
	rows(toolPi, SurfaceBuiltin, ActionSearchText, "grep", "search", "find_text", "find_in_files"),
	rows(toolPi, SurfaceBuiltin, ActionSearchFiles, "find", "ls", "glob", "list_files", "file_search"),
	rows(toolPi, SurfaceBuiltin, ActionWebSearch, "web_search"),
	rows(toolPi, SurfaceBuiltin, ActionWebFetch, "web_fetch", "fetch", "fetch_url"),
)

// --- poolside ----------------------------------------------------------
// code: internal/adapter/poolside/records.go (actionMap).
//
// Every row is GROUNDED — the complete tool surface observed in a live
// 2026-09-05 JetBrains ACP capture (22 calls, one prompt): read, write,
// edit, shell, list_directory_tree, todo_action, and the harness-
// injected synthetic completion tool `exit`. Unlike most adapters this
// table carries NO defensive rows: the ACP session/new response's own
// configOptions never enumerated a larger tool surface than what was
// actually called, so there is no evidence to guess a longer vocabulary
// from.
var poolsideRows = concat(
	rows(toolPoolside, SurfaceBuiltin, ActionReadFile, "read"),
	rows(toolPoolside, SurfaceBuiltin, ActionWriteFile, "write"),
	rows(toolPoolside, SurfaceBuiltin, ActionEditFile, "edit"),
	rows(toolPoolside, SurfaceBuiltin, ActionRunCommand, "shell"),
	rows(toolPoolside, SurfaceBuiltin, ActionSearchFiles, "list_directory_tree"),
	rows(toolPoolside, SurfaceBuiltin, ActionTodoUpdate, "todo_action"),
	// exit is the harness-injected, IsSynthetic completion signal (the
	// model calls it on purpose, same family as cline's
	// attempt_completion / cline-cli's submit_and_exit).
	rows(toolPoolside, SurfaceMeta, ActionTaskComplete, "exit"),
)

// --- prime-agent -----------------------------------------------------
// code: internal/adapter/primeagent/adapter.go (mapToolName).
//
// Prime Agent is deliberately a ONE-TOOL agent: "Available built-in
// tools: `ipython`" (README) — the model drives a persistent Python
// kernel to read files, edit code and run commands, so `ipython` is a
// run_command, not a bespoke action type. `bash` and `edit` are the other
// two built-in names docs/extensions.md says an extension may override.
// Those three are the grounded vocabulary; everything else is the
// conventional defensive set for a custom extension tool.
//
// prime-agent is NOT a toolAliases entry off pi: it is a hard fork whose
// surface diverged to a single tool, so generating pi's ~30 names for it
// would fabricate a vocabulary it does not have.
var primeAgentRows = concat(
	// grounded (live capture + README): the sole built-in tool.
	rows(toolPrimeAgent, SurfaceBuiltin, ActionRunCommand,
		"ipython", "bash", "shell", "command", "exec", "execute", "run"),
	// grounded (docs/extensions.md "Overriding Built-in Tools").
	rows(toolPrimeAgent, SurfaceBuiltin, ActionEditFile,
		"edit", "patch", "apply_patch", "edit_file"),
	rows(toolPrimeAgent, SurfaceBuiltin, ActionReadFile, "read", "cat", "view", "read_file"),
	rows(toolPrimeAgent, SurfaceBuiltin, ActionWriteFile,
		"write", "create", "write_file", "create_file"),
	rows(toolPrimeAgent, SurfaceBuiltin, ActionSearchText, "grep", "search", "search_text"),
	rows(toolPrimeAgent, SurfaceBuiltin, ActionSearchFiles, "glob", "find", "ls", "list_files"),
	rows(toolPrimeAgent, SurfaceBuiltin, ActionWebSearch, "web_search", "websearch"),
	rows(toolPrimeAgent, SurfaceBuiltin, ActionWebFetch, "web_fetch", "fetch", "fetch_url"),
)

// --- qoder -----------------------------------------------------------
// code: internal/adapter/qoder/records.go:95-120 (actionMap).
var qoderRows = concat(
	rows(toolQoder, SurfaceBuiltin, ActionReadFile, "Read"),
	rows(toolQoder, SurfaceBuiltin, ActionWriteFile, "Write"),
	// SearchReplace: the Qoder IDE's own edit tool (grounded live 2026-09-03
	// in projects/<slug>/transcript/*.session.execution.jsonl:
	// {file_path, replacements[{original_text, new_text, replace_all}]}).
	// The IDE's DeleteFile has no normalized delete action type and stays
	// rowless (ActionUnknown with the raw name) rather than mislabelled.
	rows(toolQoder, SurfaceBuiltin, ActionEditFile, "Edit", "MultiEdit", "NotebookEdit", "SearchReplace"),
	rows(toolQoder, SurfaceBuiltin, ActionRunCommand,
		"Bash", "PowerShell", "powershell", "pwsh", "cmd", "cmd.exe", "sh"),
	rows(toolQoder, SurfaceBuiltin, ActionSearchText, "Grep"),
	rows(toolQoder, SurfaceBuiltin, ActionSearchFiles, "Glob", "LS"),
	rows(toolQoder, SurfaceBuiltin, ActionWebSearch, "WebSearch"),
	rows(toolQoder, SurfaceBuiltin, ActionWebFetch, "WebFetch", "Fetch"),
	rows(toolQoder, SurfaceOrchestration, ActionSpawnSubagent, "Agent", "Task"),
	rows(toolQoder, SurfaceBuiltin, ActionTodoUpdate, "TodoWrite", "TaskCreate", "TaskUpdate"),
	rows(toolQoder, SurfaceBuiltin, ActionAskUser, "AskUserQuestion"),
)

// --- qwen-code -------------------------------------------------------
// code: internal/adapter/qwencode/records.go:171-201.
// corpus: `qwen-code.slash_command` (8 rows `unknown`) is a user slash
// command, which the canonical taxonomy already has a type for.
var qwenCodeRows = concat(
	rows(toolQwenCode, SurfaceBuiltin, ActionReadFile,
		"readfile", "read", "readmanyfiles", "viewfile", "view"),
	rows(toolQwenCode, SurfaceBuiltin, ActionWriteFile, "writefile", "write", "createfile", "create"),
	rows(toolQwenCode, SurfaceBuiltin, ActionEditFile,
		"replace", "edit", "editfile", "applypatch", "patch", "smartedit"),
	rows(toolQwenCode, SurfaceBuiltin, ActionRunCommand,
		"runshellcommand", "shell", "bash", "exec", "execute", "runcommand",
		"powershell", "pwsh", "cmd", "cmdexe"),
	rows(toolQwenCode, SurfaceBuiltin, ActionSearchText,
		"searchfilecontent", "grep", "searchtext", "findtext", "ripgrep"),
	rows(toolQwenCode, SurfaceBuiltin, ActionSearchFiles,
		"glob", "findfiles", "filesearch", "ls", "listfiles", "listdirectory", "readfolder"),
	rows(toolQwenCode, SurfaceBuiltin, ActionWebSearch, "googlewebsearch", "websearch", "search"),
	rows(toolQwenCode, SurfaceBuiltin, ActionWebFetch,
		"webfetch", "fetch", "fetchurl", "fetchwebpage"),
	rows(toolQwenCode, SurfaceOrchestration, ActionSpawnSubagent,
		"task", "subagent", "spawnagent", "delegate"),
	rows(toolQwenCode, SurfaceBuiltin, ActionTodoUpdate, "todowrite", "todo", "updateplan"),
	// The memory tools are BUILT-IN (no `mcp__` prefix, no MCP server
	// behind them) but the adapter buckets them as mcp_call — "closest
	// existing semantic; no dedicated type", records.go:196. Same shape
	// and same precedent as cowork's `Skill`/`ToolSearch`: Surface
	// builtin, Category mcp. Found missing by
	// internal/adapter/qwencode/tooltax_conformance_test.go's
	// classifier-domain direction.
	rows(toolQwenCode, SurfaceBuiltin, ActionMCPCall, "savememory", "memorize"),
	rows(toolQwenCode, SurfaceMeta, ActionUserPromptExpansion, "qwen-code.slash_command"),
)

// --- command-code ----------------------------------------------------
// code: internal/adapter/commandcode/records.go:186-245 (actionMap; keys
// are already normalized by normalizeToolKey, records.go:250).
var commandCodeRows = concat(
	rows(toolCommandCode, SurfaceBuiltin, ActionReadFile,
		"readfile", "read", "viewfile", "view", "readmanyfiles"),
	rows(toolCommandCode, SurfaceBuiltin, ActionSearchFiles,
		"readdirectory", "listdirectory", "listfiles", "listdir", "ls",
		"glob", "findfiles", "searchfiles"),
	rows(toolCommandCode, SurfaceBuiltin, ActionWriteFile, "writefile", "write", "createfile"),
	rows(toolCommandCode, SurfaceBuiltin, ActionEditFile,
		"editfile", "edit", "multiedit", "applypatch", "patch", "replace"),
	rows(toolCommandCode, SurfaceBuiltin, ActionRunCommand,
		"runcommand", "runshellcommand", "shellcommand", "shell", "bash",
		"exec", "execute", "terminal", "powershell", "pwsh"),
	rows(toolCommandCode, SurfaceBuiltin, ActionSearchText,
		"grep", "searchtext", "searchfilecontent", "ripgrep", "codesearch"),
	rows(toolCommandCode, SurfaceBuiltin, ActionWebSearch, "websearch"),
	rows(toolCommandCode, SurfaceBuiltin, ActionWebFetch,
		"webfetch", "fetch", "fetchurl", "readurl"),
	rows(toolCommandCode, SurfaceOrchestration, ActionSpawnSubagent,
		"task", "agent", "spawnagent", "subagent", "delegate"),
	rows(toolCommandCode, SurfaceBuiltin, ActionTodoUpdate,
		"todowrite", "todo", "updateplan", "updatetodos"),
	rows(toolCommandCode, SurfaceBuiltin, ActionAskUser,
		"askuser", "askuserquestion", "askfollowupquestion"),
)

// --- aider -----------------------------------------------------------
// code: internal/adapter/aider/parse.go:146,151. Aider's transcript is
// prose Markdown, so the adapter SYNTHESISES the raw tool names; only
// the two tool-shaped ones belong in the taxonomy (aider.user_prompt /
// aider.assistant_text are message rows, already correctly typed).
var aiderRows = concat(
	rows(toolAider, SurfaceBuiltin, ActionEditFile, "aider.apply_edit"),
	rows(toolAider, SurfaceBuiltin, ActionRunCommand, "aider.run_command"),
)

// --- muse -------------------------------------------------------------
// code: internal/adapter/muse/records.go (actionMap; keys are already
// normalized by normalizeToolKey in the same file).
//
// GROUNDED from the live 2026-08-06 Phase-0 capture: bash, read_file,
// write_file, edit_file. GROUNDED from the shipped 0.1.0-R708.1 binary's
// own string table: web_search, web_fetch, read_skill (next to "Read one
// available SKILL.md body as a tool result.") and `search` (from "child
// tools may only include read_file, search, bash, or web_search"). `search`
// is TOOL-SPECIFIC here rather than a fallback row precisely because the
// name disagrees across adapters (see the fallbackRows note); Muse's own
// guardrail string pairs it against web_search, so it is the code/text
// search, not the web one. Everything else is the conventional agent
// vocabulary the adapter maps defensively.
var museRows = concat(
	rows(toolMuse, SurfaceBuiltin, ActionReadFile,
		"readfile", "read", "viewfile", "view", "readmanyfiles"),
	rows(toolMuse, SurfaceBuiltin, ActionSearchFiles,
		"listdirectory", "listdir", "listfiles", "glob", "findfiles", "searchfiles"),
	rows(toolMuse, SurfaceBuiltin, ActionWriteFile, "writefile", "write", "createfile"),
	rows(toolMuse, SurfaceBuiltin, ActionEditFile,
		"editfile", "edit", "multiedit", "applypatch", "patch", "replace"),
	rows(toolMuse, SurfaceBuiltin, ActionRunCommand,
		"bash", "shell", "runcommand", "execcommand", "exec", "execute", "terminal"),
	rows(toolMuse, SurfaceBuiltin, ActionSearchText,
		"search", "grep", "searchtext", "ripgrep", "codesearch"),
	rows(toolMuse, SurfaceBuiltin, ActionWebSearch, "websearch"),
	rows(toolMuse, SurfaceBuiltin, ActionWebFetch,
		"webfetch", "fetch", "fetchurl", "readurl"),
	rows(toolMuse, SurfaceBuiltin, ActionSkillInvoke, "readskill", "skill", "useskill"),
	rows(toolMuse, SurfaceOrchestration, ActionSpawnSubagent,
		"task", "agent", "subagent", "spawnagent", "delegate"),
	// grounded (live, sub-agent side): the reminder observer's verdict
	// submission — writes a decision back into the harness, touches no
	// workspace state.
	rows(toolMuse, SurfaceMeta, ActionHarnessCall, "submitreminderdecision"),
	rows(toolMuse, SurfaceBuiltin, ActionTodoUpdate,
		"todowrite", "todo", "updateplan", "updatetodos"),
	rows(toolMuse, SurfaceBuiltin, ActionAskUser, "askuser", "askuserquestion"),
)

// --- zcode ---------------------------------------------------------
// code: internal/adapter/zcode/adapter.go:1105-1156 (mapTool). zcode is
// Z.AI's OpenCode fork; its own tool-name switch is an OpenCode-derived
// vocabulary (short-name aliases like "read"/"cat"/"view" rather than
// OpenCode's own "readfile"/"viewfile" spellings). The default case's
// `strings.Contains(part.Tool, "mcp")` heuristic stays adapter-private
// (the same precedent as opencode/droid/qoder/etc — a guess, not an
// identity, per the globalGlobRows note below).
//
// code: internal/adapter/zcode/adapter.go:824-831 — a `step-finish` part
// (turn-boundary marker, same OpenCode-derived shape as opencode's own
// step_finish) is emitted as RawToolName "zcode.step_finish", WP-T4
// harness_call family (see the opencode/kilo-code-cli precedent below).
var zcodeRows = concat(
	rows(toolZcode, SurfaceBuiltin, ActionRunCommand,
		"bash", "shell", "command", "powershell", "pwsh", "cmd", "cmd.exe"),
	rows(toolZcode, SurfaceBuiltin, ActionReadFile, "read", "cat", "view"),
	rows(toolZcode, SurfaceBuiltin, ActionWriteFile, "write", "create"),
	rows(toolZcode, SurfaceBuiltin, ActionEditFile,
		"edit", "patch", "replace", "multiedit", "applypatch", "apply_patch"),
	rows(toolZcode, SurfaceBuiltin, ActionSearchText, "grep", "search", "rg"),
	rows(toolZcode, SurfaceBuiltin, ActionSearchFiles, "glob", "find", "ls"),
	rows(toolZcode, SurfaceBuiltin, ActionWebFetch, "webfetch", "fetch", "http"),
	rows(toolZcode, SurfaceBuiltin, ActionWebSearch, "websearch"),
	rows(toolZcode, SurfaceOrchestration, ActionSpawnSubagent, "task", "agent", "subagent"),
	rows(toolZcode, SurfaceBuiltin, ActionTodoUpdate, "todoread", "todowrite", "todo"),
	rows(toolZcode, SurfaceMeta, ActionHarnessCall, "zcode.step_finish"),
)

// --- mistral-code (vibe) ---------------------------------------------
// code: internal/adapter/mistralcode/adapter.go:350-378 (mapVibeTool).
// Mistral Code's own function-name vocabulary — snake_case, distinct
// from both Claude Code's and OpenCode's spellings.
var mistralCodeRows = concat(
	rows(toolMistralCode, SurfaceBuiltin, ActionRunCommand,
		"bash", "bash_output", "bash_stdin", "bash_sessions", "bash_log_file"),
	rows(toolMistralCode, SurfaceBuiltin, ActionReadFile, "read_file"),
	rows(toolMistralCode, SurfaceBuiltin, ActionWriteFile, "write_file"),
	rows(toolMistralCode, SurfaceBuiltin, ActionEditFile, "edit"),
	rows(toolMistralCode, SurfaceBuiltin, ActionSearchText, "grep"),
	rows(toolMistralCode, SurfaceOrchestration, ActionSpawnSubagent, "task"),
	rows(toolMistralCode, SurfaceBuiltin, ActionWebFetch, "web_fetch"),
	rows(toolMistralCode, SurfaceBuiltin, ActionWebSearch, "web_search"),
	rows(toolMistralCode, SurfaceBuiltin, ActionTodoUpdate, "todo"),
	rows(toolMistralCode, SurfaceBuiltin, ActionAskUser, "ask_user_question"),
	rows(toolMistralCode, SurfaceBuiltin, ActionSkillInvoke, "skill"),
)

// --- freebuff ----------------------------------------------------------
// code: internal/adapter/freebuff/adapter.go:231-249 (mapFreebuffTool).
// Freebuff (the Manicode -> Codebuff -> Freebuff lineage) has its own
// snake_case tool-name vocabulary with several Claude-Code-style aliases
// (read_file/write_file/edit_file accepted alongside its own
// read_files/create_file/str_replace spellings). The distinct message
// block kind "agent" (adapter.go's block-type switch, separate from
// mapFreebuffTool) is a structural block DISCRIMINATOR, not a
// model-chosen tool name — like Junie's typed block kinds — so it is
// deliberately NOT given a row here; only real tool names appear below.
var freebuffRows = concat(
	rows(toolFreebuff, SurfaceBuiltin, ActionReadFile, "read_files", "read_file"),
	rows(toolFreebuff, SurfaceBuiltin, ActionWriteFile, "write_file", "create_file"),
	rows(toolFreebuff, SurfaceBuiltin, ActionEditFile, "str_replace", "edit_file"),
	rows(toolFreebuff, SurfaceBuiltin, ActionRunCommand,
		"run_terminal_command", "run_command", "bash"),
	rows(toolFreebuff, SurfaceBuiltin, ActionSearchText, "code_search", "grep"),
	// list_directory + glob: grounded live in the Freebuff DESKTOP store
	// (desktop-v2.db parts_json, 2026-09-03); the remaining names below
	// come from the CLI adapter's mapFreebuffTool table, which had drifted
	// ahead of this registry. suggest_prompts / suggest_followups stay
	// deliberately rowless (ActionUnknown — not a tool the model acts with).
	rows(toolFreebuff, SurfaceBuiltin, ActionSearchFiles, "find_files", "glob", "list_directory"),
	rows(toolFreebuff, SurfaceBuiltin, ActionWebSearch, "web_search"),
	rows(toolFreebuff, SurfaceBuiltin, ActionWebFetch, "read_url", "web_fetch"),
	rows(toolFreebuff, SurfaceOrchestration, ActionSpawnSubagent, "spawn_agents", "spawn_agent"),
	rows(toolFreebuff, SurfaceBuiltin, ActionTodoUpdate, "write_todos"),
	rows(toolFreebuff, SurfaceBuiltin, ActionAskUser, "ask_user"),
	rows(toolFreebuff, SurfaceBuiltin, ActionSkillInvoke, "skill"),
	rows(toolFreebuff, SurfaceBuiltin, ActionBrowserAction, "browser_use"),
	rows(toolFreebuff, SurfaceBuiltin, ActionTaskComplete, "set_output"),
)

// --- junie -----------------------------------------------------------
// code: internal/adapter/junie/mcpblocks.go (mcpToolRules).
// Junie's own typed block kinds (Terminal / FileChanges / ViewFiles /
// Result) are structural discriminators, not tool names, and stay
// rowless. The rows here are the JetBrains AI Assistant's built-in
// `idea` MCP server tools, which a Junie run hosted inside the IDE calls
// through McpBlockUpdatedEvent (grounded live 2026-09-03: 4 of the
// server's ~40 tools were exercised by the five-turn prompt kit; the
// rest fall through to mcp_call with the verbatim name). Note that
// tooltax.MCPIdentityFromTarget drops the `<server>/<tool>` form, so
// these targets never parse as MCP identities in the guard layer — a
// pre-existing, documented choice.
var junieRows = concat(
	rows(toolJunie, SurfaceMCP, ActionSearchFiles, "idea/list_directory_tree"),
	rows(toolJunie, SurfaceMCP, ActionWriteFile, "idea/create_new_file"),
	rows(toolJunie, SurfaceMCP, ActionRunCommand, "idea/execute_terminal_command"),
	rows(toolJunie, SurfaceMCP, ActionEditFile, "idea/apply_patch"),
)

// --- zed ---------------------------------------------------------------
// code: internal/adapter/zed/thread.go (mapZedTool). 7 grounded native
// tool names — the COMPLETE surface a live multi-call session exercised
// (list_directory / find_path / read_file / write_file / terminal /
// edit_file / delete_path); no defensive rows.
var zedRows = concat(
	rows(toolZed, SurfaceBuiltin, ActionReadFile, "read_file"),
	rows(toolZed, SurfaceBuiltin, ActionWriteFile, "write_file"),
	rows(toolZed, SurfaceBuiltin, ActionEditFile, "edit_file",
		// No canonical delete action type exists; edit_file is the
		// established precedent (cursor `Delete`, copilot/grok
		// `deletefile`/`removefile`).
		"delete_path"),
	rows(toolZed, SurfaceBuiltin, ActionRunCommand, "terminal"),
	rows(toolZed, SurfaceBuiltin, ActionSearchFiles, "list_directory", "find_path"),
)

// toolGlobRows are the tool-specific PREFIX globs. They sort after every
// literal row so a literal always wins, and before the tool-less rows.
//
// NOTE the copilot-cli adapter also has a CONTAINS pattern
// (`-mcp-server-`, events.go:1202) which a prefix glob cannot express;
// that branch stays in the adapter for now.
var toolGlobRows = concat(
	// clinecli's prefix rule (normalize.go:40-42) — runs before its
	// literal switch, but no cline-cli literal starts with `mcp_`, so
	// literal-first ordering is behaviour-preserving.
	rows(toolClineCLI, SurfaceMCP, ActionMCPCall, "mcp_*"),
	// hermes prefix rules (normalize.go:40-45).
	rows(toolHermes, SurfaceMCP, ActionMCPCall, "mcp_*"),
	rows(toolHermes, SurfaceBuiltin, ActionBrowserAction, "browser_*"),
	// copilot-cli's GitHub MCP server naming (events.go:1202).
	rows(toolCopilotCLI, SurfaceMCP, ActionMCPCall, "github-mcp-server-*"),
	// opencode writes todo rows as "todo.<status>" (adapter.go:1024).
	rows(toolOpenCode, SurfaceBuiltin, ActionTodoUpdate, "todo.*"),
)

// fallbackRows apply to ANY tool. Deliberately small and UNAMBIGUOUS:
// only names that mean the same thing in every adapter that has them.
// Notably absent are `search`, `search_files` and `list_files`, which
// genuinely disagree across adapters (grok `search` = text search vs
// gemini `search` = web search; cline `search_files` = text search vs
// command-code `searchfiles` = file discovery) — those stay
// tool-specific on purpose.
var fallbackRows = concat(
	rows("", SurfaceBuiltin, ActionReadFile, "read_file"),
	rows("", SurfaceBuiltin, ActionWriteFile, "write_file"),
	rows("", SurfaceBuiltin, ActionEditFile, "edit_file", "apply_patch"),
	rows("", SurfaceBuiltin, ActionRunCommand,
		"run_command", "bash", "sh", "shell", "exec",
		"powershell", "pwsh", "cmd", "cmd.exe"),
	rows("", SurfaceBuiltin, ActionSearchText, "grep"),
	rows("", SurfaceBuiltin, ActionSearchFiles, "glob"),
	rows("", SurfaceBuiltin, ActionWebSearch, "web_search"),
	rows("", SurfaceBuiltin, ActionWebFetch, "web_fetch"),
)

// globalGlobRows is the last resort, and the single highest-value row in
// the table: `mcp__*` for every tool.
//
// Plan §0 measured the loss it repairs — action_type='mcp_call' covers
// 1,168 rows while raw_tool_name LIKE 'mcp\_\_%' covers 2,758, and 264
// of the difference were simply unresolved. Re-measured 2026-07-31 that
// is exactly 264 rows sitting in `unknown` with an unmistakable
// `mcp__server__tool` name — 261 claude-code plus 3 codex (codex has no
// `mcp__` branch at all).
//
// NOT covered here, deliberately: the looser MCP HEURISTICS several
// adapters carry as a default branch — HasPrefix(lower, "mcp") and
// Contains(name, "__") (droid, qoder, kimicode, grok, antigravity,
// gemini, qwencode, command-code), Contains(lower, "mcp") (crush, devin,
// goose, opencode, kilocode) and Contains(name, "___") (kiro-cli). Those
// are guesses, not identities; folding them into the canonical table
// would launder a heuristic into a fact. They stay in their adapters,
// and WP-T3 decides per adapter whether each survives conversion.
var globalGlobRows = rows("", SurfaceMCP, ActionMCPCall, "mcp__*")

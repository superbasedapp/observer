package cortexcode

import (
	"encoding/json"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// actionMap maps Cortex Code's native tool names (lower snake_case) to the
// normalized action vocabulary. Grounding per row:
//
//   - live (2026-10-21, both OSes): bash, read, write, edit.
//   - the v1.2.18 bundle's own hook-name table (native -> Claude Code
//     name, used to build PreToolUse payloads): glob, grep, web_search,
//     web_fetch, task, ask_user_question, enter_plan_mode, exit_plan_mode,
//     notebook_edit, bash_output, kill_shell; and its permission-label
//     table: notebook_execute.
//   - the harness's own system reminder in the live transcript ("Cron
//     Tools: cron_create ..., cron_delete ..., cron_list"; "invoke the
//     skill tool with input { "skill": "<skill-name>" }"): the cron
//     trio and skill.
//   - the v1.2.18 bundle's tool definitions (`name:"<tool>",description:..,
//     inputSchema:..`), read 2026-10-21 for the parity wave: skill_*,
//     curator, the todo/task family, the team and agent family,
//     apply_patch, tool_search, tgrep, monitor, the Python REPL family
//     and the Snowflake data tools. None of these was observed in a live
//     transcript yet.
//
// Mappings follow the Claude Code rows those names translate to
// (Read/Write/Edit/Glob/Grep/WebSearch/WebFetch/AskUserQuestion,
// Enter/ExitPlanMode -> permission_mode, NotebookEdit -> edit_file,
// CronCreate/Delete/List -> schedule, Skill -> skill_invoke,
// TaskCreate/TaskUpdate/... -> todo_update, SendMessage -> agent_message,
// Monitor -> agent_control). The background-shell helpers follow the
// shell-family precedent (mistralcode bash_output); the Python REPL and
// sql_execute run code against a live kernel / database, so they are
// commands; the Snowflake catalog and docs lookups are text searches;
// skill and program management, Curator and connection switching are
// harness calls.
var actionMap = map[string]string{
	// Shell, notebooks, REPL, SQL.
	"bash":                      models.ActionRunCommand,
	"bash_output":               models.ActionRunCommand,
	"kill_shell":                models.ActionRunCommand,
	"notebook_execute":          models.ActionRunCommand,
	"notebook_actions":          models.ActionRunCommand,
	"python_repl":               models.ActionRunCommand,
	"programmatic_tool_calling": models.ActionRunCommand,
	"repl_program_run":          models.ActionRunCommand,
	"sql_execute":               models.ActionRunCommand,
	"data_diff":                 models.ActionRunCommand,
	"fdbt":                      models.ActionRunCommand,
	// Files.
	"read":          models.ActionReadFile,
	"write":         models.ActionWriteFile,
	"edit":          models.ActionEditFile,
	"notebook_edit": models.ActionEditFile,
	"apply_patch":   models.ActionEditFile,
	// Search.
	"glob":                    models.ActionSearchFiles,
	"grep":                    models.ActionSearchText,
	"tgrep":                   models.ActionSearchText,
	"snowflake_object_search": models.ActionSearchText,
	"snowflake_table_lookup":  models.ActionSearchText,
	"semantic_view_search":    models.ActionSearchText,
	"cortex_agent_search":     models.ActionSearchText,
	"snowscope_search":        models.ActionSearchText,
	"web_search":              models.ActionWebSearch,
	"snowflake_product_docs":  models.ActionWebSearch,
	"web_fetch":               models.ActionWebFetch,
	// Sub-agents and teams.
	"task":           models.ActionSpawnSubagent,
	"spawn_teammate": models.ActionSpawnSubagent,
	"send_message":   models.ActionAgentMessage,
	"agent_output":   models.ActionSubagentWait,
	"kill_agent":     models.ActionAgentControl,
	"team_create":    models.ActionAgentControl,
	"team_delete":    models.ActionAgentControl,
	"list_teammates": models.ActionAgentControl,
	"monitor":        models.ActionAgentControl,
	// Todo list (snapshot) and task registry (deltas and reads).
	"system_todo_write": models.ActionTodoUpdate,
	"task_create":       models.ActionTodoUpdate,
	"task_update":       models.ActionTodoUpdate,
	"task_list":         models.ActionTodoUpdate,
	"task_get":          models.ActionTodoUpdate,
	"task_stats":        models.ActionTodoUpdate,
	"task_claim":        models.ActionTodoUpdate,
	"task_next":         models.ActionTodoUpdate,
	"task_complete":     models.ActionTodoUpdate,
	"task_fail":         models.ActionTodoUpdate,
	"task_heartbeat":    models.ActionTodoUpdate,
	// Skills and harness meta.
	"skill":                            models.ActionSkillInvoke,
	"skill_view":                       models.ActionHarnessCall,
	"skills_list":                      models.ActionHarnessCall,
	"skill_manage":                     models.ActionHarnessCall,
	"curator":                          models.ActionHarnessCall,
	"repl_program_manage":              models.ActionHarnessCall,
	"repl_program_list":                models.ActionHarnessCall,
	"repl_program_view":                models.ActionHarnessCall,
	"snowflake_connections_list":       models.ActionHarnessCall,
	"snowflake_connections_set_active": models.ActionHarnessCall,
	"tool_search":                      models.ActionToolSearch,
	"ask_user_question":                models.ActionAskUser,
	"enter_plan_mode":                  models.ActionPermissionMode,
	"exit_plan_mode":                   models.ActionPermissionMode,
	"cron_create":                      models.ActionSchedule,
	"cron_delete":                      models.ActionSchedule,
	"cron_list":                        models.ActionSchedule,
}

// normalizeToolKey lower-cases a native tool name for the actionMap lookup.
func normalizeToolKey(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// mapTool returns the normalized action for a native tool name and whether
// the name is recognised.
func mapTool(name string) (string, bool) {
	if a, ok := actionMap[normalizeToolKey(name)]; ok {
		return a, true
	}
	return models.ActionUnknown, false
}

// targetKeys is the ordered list of input keys targetFromInput tries. The
// tail covers the bundle-grounded families: skill (`skill`; `command` on
// the REM path), task registry (`subject`, `task_id`), team messaging
// (`recipient`), sql_execute (`sql`) and skill / program management
// (`name`).
var targetKeys = []string{
	"command", "file_path", "path", "notebook_path", "url", "query", "sql",
	"pattern", "skill", "subject", "task_id", "recipient", "name",
	"description", "prompt",
}

// pathTargetKeys are the targetKeys whose value is a filesystem path. Only
// these are relativized against the project root (relativeTarget).
var pathTargetKeys = map[string]bool{
	"file_path":     true,
	"path":          true,
	"notebook_path": true,
}

// targetFromInput pulls the most human-meaningful field out of a tool's
// input object, and the input key it came from.
func targetFromInput(input json.RawMessage) (value, key string) {
	if len(input) == 0 {
		return "", ""
	}
	var m map[string]any
	if err := json.Unmarshal(input, &m); err != nil {
		return "", ""
	}
	for _, k := range targetKeys {
		if v, ok := m[k].(string); ok && strings.TrimSpace(v) != "" {
			return v, k
		}
	}
	return "", ""
}

// relativeTarget rewrites an ABSOLUTE path target relative to the project
// root, the convention the Claude Code, Codex, Cline and Dirac adapters
// share (a path outside the root becomes "[external]/<abs>"). The target
// is translated to this host's path flavor first, exactly like the root:
// a Windows session read by a WSL observer writes `C:\Users\...` file
// paths while its root is `/mnt/c/Users/...`, and an untranslated target
// never lies under its own root (live 2026-10-22: the guard's
// cross-project rule R-151 flagged both writes of a Windows session as
// landing in a different project). Non-path keys, relative paths and the
// placeholder root are left alone; a relative path handed to
// git.RelativePath would resolve against the observer's own cwd.
func relativeTarget(target, key, root string) string {
	if !pathTargetKeys[key] || root == "" || root == placeholderRoot || !isAbsAnyOS(target) {
		return target
	}
	return git.RelativePath(root, crossmount.TranslateForeignPath(target))
}

// isAbsAnyOS reports whether p is absolute in EITHER path flavor: POSIX
// `/...`, UNC `\\...`, or a Windows drive path `C:\...` / `C:/...`.
// filepath.IsAbs answers only for the running OS.
func isAbsAnyOS(p string) bool {
	if p == "" {
		return false
	}
	if p[0] == '/' || strings.HasPrefix(p, `\\`) {
		return true
	}
	if len(p) < 3 || p[1] != ':' || (p[2] != '\\' && p[2] != '/') {
		return false
	}
	c := p[0]
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// authoredBytes returns the byte length of the code the model authored in
// a write (content) or edit (new_string / new_source) call; zero for every
// other action (§8.5).
func authoredBytes(action string, input json.RawMessage) int64 {
	if len(input) == 0 {
		return 0
	}
	var in struct {
		Content   string `json:"content"`
		NewString string `json:"new_string"`
		NewSource string `json:"new_source"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
		return 0
	}
	switch action {
	case models.ActionWriteFile:
		return int64(len(in.Content))
	case models.ActionEditFile:
		return int64(len(in.NewString) + len(in.NewSource))
	}
	return 0
}

package integration

import "sort"

// StatusLineKind names the SHAPE of a tool's configurable status-line
// command: where the command is declared and in what format. A consumer
// that writes or doctors a status line dispatches on this, never on the
// tool name (CLAUDE.md rule 3).
type StatusLineKind string

// Status-line shapes. The zero value is the honest floor: no grounded
// status-line command.
const (
	// StatusLineNone: no status-line command grounded for the tool (the
	// zero value). A row may still record the audit in its Note.
	StatusLineNone StatusLineKind = ""
	// StatusLineSettingsJSON: a top-level "statusLine" object with a
	// "command" string in a JSON settings file; the tool runs the command
	// and pipes a JSON session payload on stdin (Claude Code's
	// {"type":"command","command":...} and its look-alikes).
	StatusLineSettingsJSON StatusLineKind = "settings_json_command"
	// StatusLineVTCodeTOML: [ui.status_line] mode = "command" plus
	// command = <script path> in VT Code's vtcode.toml.
	StatusLineVTCodeTOML StatusLineKind = "vtcode_toml_command"
)

// StatusLineExec names how a tool runs the configured command. A writer
// dispatches on it: a shell command can carry arguments, a script path
// cannot, so Observer writes a wrapper script for it.
type StatusLineExec string

// Status-line exec shapes. The zero value is a none row's.
const (
	// StatusLineExecShell: the command string runs through a shell, so it
	// can be `<observer> statusline` with arguments (Claude Code, CodeBuddy).
	StatusLineExecShell StatusLineExec = "shell"
	// StatusLineExecScriptPath: the command is ONE executable path, spawned
	// with no arguments and no shell (Kimchi's spawn(path, [])) or required
	// to be a regular, non-symlink file (VT Code). Observer writes a
	// marker-owned wrapper script under ~/.observer/statusline/ and points
	// the command at it. Not written on Windows (no grounded way for these
	// hosts to run a script there).
	StatusLineExecScriptPath StatusLineExec = "script_path"
)

// StatusLineSpec is the registry column for a tool's own status-line
// command: whether the tool can run a user-supplied command in its TUI
// status bar, which is how `observer statusline` reaches a tool
// (docs/observer-statusline.md). It is the CAPABILITY declaration; the
// writer lives in internal/hook (register_statusline.go).
type StatusLineSpec struct {
	Kind StatusLineKind
	// File is the config file the command is declared in, relative to the
	// user's home, slash-separated.
	File string
	// ClaudePayload reports that the stdin JSON uses Claude Code's
	// top-level keys (session_id, transcript_path, cwd, model, workspace,
	// cost), the shape internal/statusline.Input decodes, so `observer
	// statusline` could render it unchanged.
	ClaudePayload bool
	// Exec is how the tool runs the command (shell string or script path).
	Exec StatusLineExec
	// PlanRateLimits reports that the payload carries Claude Code's plan
	// rate_limits, which `observer statusline` forwards to Plans & limits as
	// Claude readings. Only a host declaring it ever forwards, so a
	// look-alike payload (CodeBuddy) is never read as Claude's plan meter.
	PlanRateLimits bool
	// Writer reports that Observer writes this status line today. False on
	// a grounded shape means the writer is not built.
	Writer bool
	// InitFlag is the `observer init` flag that writes it: "--statusline"
	// (the Claude Code writer, register_statusline.go) or
	// "--statusline-tools" (the capability-driven writer,
	// register_statusline_tools.go). Set exactly when Writer is.
	InitFlag string
	// Grounding names the evidence: "live", "doc", "source" or a
	// combination, with the version read.
	Grounding string
	// Note records a caveat, or, on a StatusLineNone row, what the audit
	// found instead of a command.
	Note string
}

// The `observer init` flags that write a status line (StatusLineSpec.InitFlag).
const (
	StatusLineInitClaude = "--statusline"
	StatusLineInitTools  = "--statusline-tools"
)

// statusLines is the ONE owner of the status-line column, keyed by registry
// tool. Only the claude-code row and the 2026-10-21 capture wave (audited
// 2026-10-22, writers AP-133 2026-10-23) are declared. A tool absent
// here was not audited; a StatusLineNone row was audited and has no
// command.
var statusLines = map[string]StatusLineSpec{
	"claude-code": {
		Kind: StatusLineSettingsJSON, File: ".claude/settings.json", ClaudePayload: true, Exec: StatusLineExecShell,
		PlanRateLimits: true, Writer: true, InitFlag: StatusLineInitClaude,
		Grounding: "doc (code.claude.com/docs/en/statusline) + live",
		Note:      "opt-in: `observer init --statusline`, native OS only (no WSL bridge per render)",
	},
	"codebuddy": {
		Kind: StatusLineSettingsJSON, File: ".codebuddy/settings.json", ClaudePayload: true, Exec: StatusLineExecShell,
		Writer: true, InitFlag: StatusLineInitTools,
		Grounding: "doc (codebuddy.cn/docs/cli/statusline) + source (codebuddy-code 2.171.0 bundle: executeStatusLine reads settings statusLine.command, spawn(command, [], {shell: true}); collectStatusLineData)",
		Note:      "Claude-compatible payload plus context_window; session_id is \"unknown\" with no session (read as absent). Not live-run (no login, AP-127). The same settings.json can carry CODEBUDDY_API_KEY in its env block: the writer splices only the statusLine member",
	},
	"kimchi": {
		Kind: StatusLineSettingsJSON, File: ".config/kimchi/harness/settings.json", Exec: StatusLineExecScriptPath,
		Writer: true, InitFlag: StatusLineInitTools,
		Grounding: "source (kimchi 1.17.0 bundle: readStatusLineCommand / buildScriptPayload / runScript spawn(path, []) with no shell, 1 s timeout)",
		Note:      "only statusLine.command is read, from the fixed ~/.config/kimchi/harness/settings.json (KIMCHI_CODING_AGENT_DIR is not consulted for it); the payload nests the session id and transcript path under session{}, names the model model.name and adds credits / budget display strings (not read)",
	},
	"vtcode": {
		Kind: StatusLineVTCodeTOML, File: ".config/vtcode/vtcode.toml", Exec: StatusLineExecScriptPath,
		Writer: true, InitFlag: StatusLineInitTools,
		Grounding: "doc (vtcode CONFIG_FIELD_REFERENCE) + source (vtcode 0.180.2 binary: status_line_command.rs)",
		Note:      "the command must be a regular-file script path (symlinks refused), refreshed every refresh_interval_ms with a 200 ms default command_timeout_ms (Observer's table sets 1000 unless one is already set); the payload (StatusLineCommandPayload: hook_event_name Status, cwd, workspace, model, runtime, git, context) has no session id or cost. File is the Linux user layer the hook writer uses; on Windows it is %APPDATA%\\vinhnx\\vtcode\\config\\vtcode.toml",
	},
	"autohand": {
		Grounding: "doc + source (autohand-cli 0.9.8)",
		Note:      "ui.statusLine holds display toggles only; extensions add segments in process (setStatusLine), no shell command",
	},
	"ibm-bob": {
		Grounding: "doc + source (bobshell 2.0.6)",
		Note:      "fixed footer (mode, context, Bobcoin cost); no status-line setting in the 2.0 schema",
	},
	"cortex-code": {
		Grounding: "doc + source (cortex 1.2.18)",
		Note:      "footer toggles only (showModelInFooter, alwaysShowContextUsage); no status-line command",
	},
	"deepagents-code": {
		Grounding: "doc + source (deepagents-code 0.1.87)",
		Note:      "Textual TUI status bar with no command hook",
	},
	"dimcode": {
		Grounding: "source (dimcode 0.5.21 binary)",
		Note:      "built-in status chips (goal, approvals, model); no command",
	},
	"dirac": {
		Grounding: "doc + source (dirac-cli 0.5.22)",
		Note:      "no status-line setting",
	},
	"stakpak": {
		Grounding: "doc + source (stakpak 0.3.88 binary)",
		Note:      "no status-line setting",
	},
}

// init folds the status-line column into the registry rows. A key with no
// registry row is a table error caught by TestStatusLinesAreRegistryRows.
func init() {
	for tool, s := range statusLines {
		if c, ok := registry[tool]; ok {
			c.StatusLine = s
			registry[tool] = c
		}
	}
}

// StatusLineFor returns tool's status-line column (zero value when the tool
// has no registry row or was not audited).
func StatusLineFor(tool string) StatusLineSpec {
	if c, ok := registry[tool]; ok {
		return c.StatusLine
	}
	return StatusLineSpec{}
}

// StatusLineWriterTools returns, sorted, every tool whose status line the
// given `observer init` flag writes (StatusLineInitClaude or
// StatusLineInitTools).
func StatusLineWriterTools(initFlag string) []string {
	var out []string
	for t, s := range statusLines {
		if s.Writer && s.InitFlag == initFlag {
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}

// StatusLineTools returns every tool with a grounded status-line command
// (Kind != StatusLineNone), unsorted.
func StatusLineTools() []string {
	out := make([]string, 0, len(statusLines))
	for t, s := range statusLines {
		if s.Kind != StatusLineNone {
			out = append(out, t)
		}
	}
	return out
}

package remedy

import (
	"net/url"
	"sort"
	"strings"
)

// Action is a closed remediation id. A new id is one row in the table below.
type Action string

const (
	// Init is `observer init` for every detected tool.
	Init Action = "init"
	// InitTool is `observer init --<tool>` (the Connected tools wizard).
	InitTool Action = "init_tool"
	// InitToolForce is `observer init --<tool> --force`.
	InitToolForce Action = "init_tool_force"
	// InitToolRoute re-adds a tool's proxy route only.
	InitToolRoute Action = "init_tool_route"
	// InitMCP rewrites only the MCP entries (hooks and routes untouched):
	// `observer init [--<tool>] --skip-hooks --skip-proxy-route`.
	InitMCP Action = "init_mcp"
	// InitMCPForce is InitMCP with --force, for an entry init would refuse.
	InitMCPForce Action = "init_mcp_force"
	// UninstallTool is `observer uninstall --<tool>` (the wizard's Remove panel).
	UninstallTool Action = "uninstall_tool"
	// InitWindowsHome is `observer init --windows-<x>-home <path>`; Tool is
	// the cross-OS target ("claude-code-windows").
	InitWindowsHome Action = "init_windows_home"
	// InitWindowsRoute is `observer init` writing a detected Windows-side
	// home's route; Tool is the cross-OS target.
	InitWindowsRoute Action = "init_windows_route"
	// CodexTrust is trusting Observer's hooks inside Codex (/hooks): a step
	// Observer never takes for the user, so it has no command.
	CodexTrust Action = "codex_trust"
	// OrgEnroll is `observer enroll --link <url>`.
	OrgEnroll Action = "org_enroll"
	// OrgUnenroll is `observer unenroll`.
	OrgUnenroll Action = "org_unenroll"
	// OrgClientEnable is setting [org_client] enabled = true (no command).
	OrgClientEnable Action = "org_client_enable"
	// RestartDaemon restarts the daemon (no single command: it depends on
	// how the daemon runs).
	RestartDaemon Action = "restart_daemon"
	// DoctorTool is `observer doctor <tool>` (a per-adapter check run).
	DoctorTool Action = "doctor_tool"
	// DoctorDBIntegrity is `observer doctor db` (the forced whole-database
	// integrity check).
	DoctorDBIntegrity Action = "doctor_db_integrity"
	// OpenSettings opens one Settings section; Tool is the section id (the
	// dashboard's ?section= value, e.g. "proxy"). It has no command: the
	// section's form (or its More settings editor) is the control, and the
	// finding's text names the config key for a reader of the file.
	OpenSettings Action = "open_settings"
	// BrowserHostSetup is `observer init --browser`: the browser-capture
	// native-messaging host and per-browser manifests. The dashboard control
	// lives in Settings > Browser capture.
	BrowserHostSetup Action = "browser_host_setup"
	// OpenScanners opens Code security > Scanners, where each scanner
	// component has its switch. No command: the finding's text names the
	// [components] key for a reader of the file.
	OpenScanners Action = "open_scanners"
)

// Remediation is one structured fix for a finding. Tool is the action's one
// parameter: a tool id ("cursor"), a cross-OS target ("codex-windows"), a
// Settings section id (OpenSettings), or empty where the action takes none
// (or leaves the choice to the operator).
type Remediation struct {
	Action Action `json:"action"`
	Tool   string `json:"tool,omitempty"`
}

// Control is a remediation as the dashboard renders it: a button label and
// the in-app link to the control that performs it (a Settings section for
// most actions; Code security > Scanners for OpenScanners).
type Control struct {
	Label string `json:"label"`
	Href  string `json:"href"`
}

// toolFlags is the CLI's per-tool selector vocabulary (`observer init
// --claude-code`, ...). A tool without a selector is reached through --all.
var toolFlags = map[string]string{
	"claude-code": "--claude-code",
	"codex":       "--codex",
	"cursor":      "--cursor",
	"cline":       "--cline",
}

// windowsHomeFlags is the CLI's cross-OS home override vocabulary, keyed by
// the cross-OS target.
var windowsHomeFlags = map[string]string{
	"claude-code-windows": "--windows-claude-home",
	"codex-windows":       "--windows-codex-home",
	"cursor-windows":      "--windows-cursor-home",
}

// WindowsHomeFlag returns the `observer init` flag that pins target's
// Windows-side home.
func WindowsHomeFlag(target string) (string, bool) {
	f, ok := windowsHomeFlags[target]
	return f, ok
}

// WindowsHomeTargets lists the cross-OS targets with a home override flag,
// sorted.
func WindowsHomeTargets() []string {
	out := make([]string, 0, len(windowsHomeFlags))
	for t := range windowsHomeFlags {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func toolSelector(tool string) string {
	if f, ok := toolFlags[tool]; ok {
		return f
	}
	return "--all"
}

// settingsSections is the dashboard's Settings section vocabulary (the
// ?section= ids and the labels the rail shows), for OpenSettings. A section
// missing here still links; it only renders a generic label.
var settingsSections = map[string]string{
	"advisor":       "Advisor",
	"antigravity":   "Antigravity",
	"backfill":      "Backfill",
	"browser":       "Browser capture",
	"cachetrack":    "Cache tracking",
	"cloud":         "Cloud Intelligence",
	"compression":   "Compression",
	"dashboard":     "Dashboard",
	"enrolment":     "Enrolment",
	"guard":         "Guard",
	"health":        "Health",
	"hooks":         "Hooks",
	"intelligence":  "Intelligence",
	"mcp":           "MCP tools",
	"observability": "Observability",
	"observer":      "Observer",
	"org":           "Org sharing",
	"process":       "Process capture",
	"proxy":         "Proxy",
	"retention":     "Retention",
	"routing":       "Routing",
	"storage":       "Storage",
	"terminal":      "Session attach",
	"tools":         "Connected tools",
	"watcher":       "Watcher",
}

// SettingsSectionLabel returns the rail label of a Settings section id, and
// false when the id is not in the vocabulary.
func SettingsSectionLabel(id string) (string, bool) {
	l, ok := settingsSections[id]
	return l, ok
}

func settingsHref(section string) string {
	q := url.Values{}
	q.Set("section", section)
	return "/settings?" + q.Encode()
}

func openSettingsLabel(section string) string {
	if l, ok := settingsSections[section]; ok {
		return "Open Settings > " + l
	}
	return "Open Settings"
}

// row is one action: its CLI command, its dashboard label and its link.
type row struct {
	command func(tool string) string
	label   func(tool string) string
	href    func(tool string) string
}

func toolsHref(tool, open string) string {
	q := url.Values{}
	q.Set("section", "tools")
	if tool != "" {
		q.Set("tool", tool)
	}
	if open != "" {
		q.Set("open", open)
	}
	return "/settings?" + q.Encode()
}

func windowsHref(target string) string {
	q := url.Values{}
	q.Set("section", "tools")
	q.Set("open", "windows-home")
	if target != "" {
		q.Set("target", target)
	}
	return "/settings?" + q.Encode()
}

// optSelector is toolSelector plus a trailing space, or nothing when tool
// is empty (every detected tool).
func optSelector(tool string) string {
	if tool == "" {
		return ""
	}
	return toolSelector(tool) + " "
}

func orTool(tool, fallback string) string {
	if tool == "" {
		return fallback
	}
	return tool
}

var table = map[Action]row{
	Init: {
		command: func(string) string { return "observer init" },
		label:   func(string) string { return "Open Connected tools" },
		href:    func(string) string { return toolsHref("", "") },
	},
	InitTool: {
		command: func(t string) string { return "observer init " + toolSelector(t) },
		label:   func(t string) string { return "Set up " + orTool(t, "the tool") },
		href:    func(t string) string { return toolsHref(t, "setup") },
	},
	InitToolForce: {
		command: func(t string) string { return "observer init " + toolSelector(t) + " --force" },
		label:   func(t string) string { return "Set up " + orTool(t, "the tool") + " (force)" },
		href:    func(t string) string { return toolsHref(t, "setup") },
	},
	InitToolRoute: {
		command: func(t string) string { return "observer init " + toolSelector(t) + " --skip-hooks --skip-mcp" },
		label:   func(t string) string { return "Route " + orTool(t, "the tool") + " through the proxy" },
		href:    func(t string) string { return toolsHref(t, "setup") },
	},
	InitMCP: {
		command: func(t string) string { return "observer init " + optSelector(t) + "--skip-hooks --skip-proxy-route" },
		label:   func(t string) string { return "Refresh the MCP entry for " + orTool(t, "your tools") },
		href:    func(t string) string { return toolsHref(t, "setup") },
	},
	InitMCPForce: {
		command: func(t string) string {
			return "observer init " + optSelector(t) + "--skip-hooks --skip-proxy-route --force"
		},
		label: func(t string) string { return "Replace the MCP entry for " + orTool(t, "your tools") + " (force)" },
		href:  func(t string) string { return toolsHref(t, "setup") },
	},
	UninstallTool: {
		// A tool with no CLI selector has no one-tool uninstall command:
		// `--all` would remove every tool's wiring and the keychain entries,
		// so the dashboard's Remove panel is the only one-step form.
		command: func(t string) string {
			if f, ok := toolFlags[t]; ok {
				return "observer uninstall " + f
			}
			return ""
		},
		label: func(t string) string { return "Remove Observer's wiring from " + orTool(t, "the tool") },
		href:  func(t string) string { return toolsHref(t, "remove") },
	},
	InitWindowsHome: {
		command: func(t string) string {
			if f, ok := windowsHomeFlags[t]; ok {
				return "observer init " + f + " <path>"
			}
			return "observer init"
		},
		label: func(string) string { return "Choose the Windows home" },
		href:  windowsHref,
	},
	InitWindowsRoute: {
		command: func(string) string { return "observer init" },
		label:   func(string) string { return "Wire the Windows side" },
		href:    windowsHref,
	},
	CodexTrust: {
		command: func(string) string { return "" },
		label:   func(string) string { return "See the Codex trust steps" },
		href:    func(string) string { return toolsHref("codex", "setup") },
	},
	OrgEnroll: {
		command: func(string) string { return "observer enroll --link <url>" },
		label:   func(string) string { return "Enrol this machine" },
		href:    func(string) string { return "/settings?section=enrolment" },
	},
	OrgUnenroll: {
		command: func(string) string { return "observer unenroll" },
		label:   func(string) string { return "Open organization enrolment" },
		href:    func(string) string { return "/settings?section=enrolment" },
	},
	OrgClientEnable: {
		command: func(string) string { return "" },
		label:   func(string) string { return "Open organization client settings" },
		href:    func(string) string { return "/settings?section=org" },
	},
	RestartDaemon: {
		command: func(string) string { return "" },
		label:   func(string) string { return "Restart the daemon" },
		href:    func(string) string { return "/settings?section=health#daemon" },
	},
	DoctorTool: {
		command: func(t string) string { return "observer doctor " + orTool(t, "<tool>") },
		label:   func(t string) string { return "Run checks for " + orTool(t, "a tool") },
		href:    func(t string) string { return toolsHref(t, "doctor") },
	},
	DoctorDBIntegrity: {
		command: func(string) string { return "observer doctor db" },
		label:   func(string) string { return "Run the integrity check" },
		href:    func(string) string { return "/settings?section=health#integrity" },
	},
	OpenSettings: {
		command: func(string) string { return "" },
		label:   openSettingsLabel,
		href:    settingsHref,
	},
	BrowserHostSetup: {
		command: func(string) string { return "observer init --browser" },
		label:   func(string) string { return "Set up browser capture" },
		href:    func(string) string { return settingsHref("browser") },
	},
	OpenScanners: {
		command: func(string) string { return "" },
		label:   func(string) string { return "Open Code security > Scanners" },
		href:    func(string) string { return "/code-security?tab=scanners" },
	},
}

// Known reports whether a is a remediation id this build knows.
func Known(a Action) bool {
	_, ok := table[a]
	return ok
}

// Actions lists every known action id, sorted (the closed set).
func Actions() []Action {
	out := make([]Action, 0, len(table))
	for a := range table {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Command is the CLI spelling of r: the command a terminal user runs, or ""
// when the fix has no single command (the dashboard control is the only
// one-step form).
func Command(r Remediation) string {
	row, ok := table[r.Action]
	if !ok {
		return ""
	}
	return row.command(r.Tool)
}

// ControlFor is the dashboard spelling of r: a label and the in-app link to
// the control that does what Command does.
func ControlFor(r Remediation) (Control, bool) {
	row, ok := table[r.Action]
	if !ok {
		return Control{}, false
	}
	return Control{Label: row.label(r.Tool), Href: row.href(r.Tool)}, true
}

// Quote wraps r's command in backticks for prose (`observer init`), the form
// every finding embeds it in.
func Quote(r Remediation) string {
	c := Command(r)
	if c == "" {
		return ""
	}
	return "`" + c + "`"
}

// Of is a convenience constructor.
func Of(a Action, tool string) Remediation { return Remediation{Action: a, Tool: tool} }

// Mentions reports whether text spells r's command (or r has none): the
// consistency rule every finding keeps, so the CLI text and the structured
// remediation can never drift apart.
func Mentions(text string, r Remediation) bool {
	c := Command(r)
	return c == "" || strings.Contains(text, c)
}

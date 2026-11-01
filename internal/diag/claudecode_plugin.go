package diag

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/claudeplugin"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/mcp/locate"
	"github.com/marmutapp/superbased-observer/internal/mcpregister"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/remedy"
)

// checkClaudeCodePlugin reports whether observer is wired into Claude
// Code through BOTH available surfaces at once.
//
// Claude Code merges hook configuration from every source it loads, and
// namespaces a plugin's MCP server (`plugin:<plugin>:<server>`)
// separately from a user-config one (`<server>`). So a user who
// installed the SuperBased Observer plugin AND ran `observer init
// --claude-code` before the init-side skip existed has each hook event
// firing twice and the observer MCP tool schema loaded twice per turn.
//
// The probe covers BOTH installs a host can carry: the native `.claude`
// under $HOME, and — on a WSL daemon serving a Windows Claude Code — the
// Windows-side `.claude` the claude-code-windows registration target
// writes into. Each side is judged independently and reported by name,
// because they hold independent plugin state.
//
// Duplicate hook fires do NOT corrupt the action history — every
// claude-code hook builder derives a deterministic SourceEventID and the
// actions table is UNIQUE(source_file, source_event_id), so the second
// fire upserts (pinned by cmd/observer's
// TestClaudeCodeHookDoubleFireIsIdempotent). The costs are real but
// bounded: a wasted process spawn plus a DB open per event, a doubled
// MCP tool schema in every turn's context, duplicate rows in the
// append-only guard_events ledger when [guard] is enabled, and one
// duplicate compaction_events row per /compact — that table has no
// natural key and the PreCompact payload carries no compaction id, so
// the duplicate is documented residue rather than something we dedupe.
//
// Hence StatusWarn, never StatusFail: the install works, it just does
// everything twice.
//
// Named with the "claude-code" substring so `observer doctor
// claude-code` scopes to it (Report.Filter matches on Name).
func checkClaudeCodePlugin(homeDir, homeOverride string) Check {
	const name = "claude-code.plugin"

	sides := []pluginSide{nativePluginSide(homeDir)}
	var details []string
	// Cross-OS side: honour the caller's HomeDir sandbox. A doctor run with
	// DoctorOptions.HomeDir set must not reach outside it — the probe used to
	// call the zero-argument resolver, so a sandboxed run still READ the
	// operator's real /mnt/c/.claude (read-only, but it broke the sandbox and
	// made results machine-dependent). Same one owner as the writers:
	// crossmount.AutoDetectSuppressed. Reported honestly rather than silently
	// dropped.
	switch winDir := windowsClaudeDir(homeOverride); {
	case winDir != "":
		sides = append(sides, windowsPluginSide(winDir))
	case crossmount.AutoDetectSuppressed(homeOverride, ""):
		details = append(details,
			"windows: not inspected - this doctor run pinned HomeDir, so cross-OS auto-detection is suppressed (incident 2026-07-31)")
	}

	var (
		doubled []pluginSide
		plugin  []pluginSide
	)
	for _, s := range sides {
		if s.Unnamed != "" {
			details = append(details, fmt.Sprintf("%s: %s", s.Label, s.Unnamed))
		}
		switch {
		case s.Detection.Uncertain:
			details = append(details, fmt.Sprintf("%s: %s", s.Label, s.Detection.Warning()))
		case !s.Detection.Active:
			continue
		case len(s.InitWiring) > 0:
			doubled = append(doubled, s)
		default:
			plugin = append(plugin, s)
		}
	}

	if len(doubled) > 0 {
		for _, s := range doubled {
			details = append(
				details,
				fmt.Sprintf("%s: %s", s.Label, s.Detection.Reason()),
				fmt.Sprintf("%s: `observer init` also wrote %s", s.Label, strings.Join(s.InitWiring, "; ")),
			)
		}
		details = append(
			details,
			"Each source fires independently, so every event fires twice.",
			"Remove ONE of them:",
			"  keep the plugin  → "+remedy.Quote(remedy.Of(remedy.UninstallTool, "claude-code"))+" (removes init's copy;"+
				" re-add the proxy route with "+remedy.Quote(remedy.Of(remedy.InitToolRoute, "claude-code"))+")",
			fmt.Sprintf("  keep init wiring → `/plugin uninstall %s` inside Claude Code (removes the plugin's copy)",
				claudeplugin.Name),
			"Cost while both are wired: action rows do NOT duplicate (deterministic source_event_id +"+
				" UNIQUE upsert), but each event costs a second process spawn and DB open, the observer"+
				" MCP tool schema loads twice per turn, and compaction_events gains one duplicate row"+
				" per /compact (no natural key exists to dedupe on).",
		)
		return Check{
			Name: name, Status: StatusWarn,
			Message: fmt.Sprintf("observer is wired into Claude Code TWICE - by the %s plugin AND by `observer init` (%s)",
				claudeplugin.Name, sideLabels(doubled)),
			Details: details,
		}
	}

	if len(plugin) > 0 {
		for _, s := range plugin {
			details = append(details, fmt.Sprintf("%s: %s", s.Label, s.Detection.Reason()))
		}
		return Check{
			Name: name, Status: StatusOK,
			Message: fmt.Sprintf("wired through the %s Claude Code plugin only (%s)",
				claudeplugin.Name, sideLabels(plugin)),
			Details: details,
		}
	}

	return Check{
		Name: name, Status: StatusOK,
		Message: "no Claude Code plugin installed; `observer init` wiring is the only source",
		Details: details,
	}
}

// windowsClaudeDir resolves the Windows-side .claude the
// claude-code-windows registration target writes into, or "" when there
// is none. It delegates to internal/hook so the probe inspects exactly
// the directory that registrar would write to instead of re-deriving
// crossmount + ownership rules and drifting from them (one owner).
//
// It is a package var because it is ALSO the containment seam: without
// an override, a test running on a WSL host with a real Windows-side
// .claude would read the operator's own config. Tests must replace it
// (restore in a defer).
//
// homeOverride is the RAW DoctorOptions.HomeDir — "" on every production run
// (Run then resolves the real $HOME for the native side), non-empty only when
// a caller sandboxed the doctor. In the sandboxed case the cross-OS side is
// NOT auto-detected: reading /mnt/c from a run that declared a sandbox is the
// read-side of the 2026-07-31 incident, and it made results
// machine-dependent. Same one owner as the writers — no second predicate.
var windowsClaudeDir = func(homeOverride string) string {
	if crossmount.AutoDetectSuppressed(homeOverride, "") {
		return ""
	}
	return hook.WindowsClaudeDir("")
}

// pluginSide is one Claude Code install this host can carry: the native
// one under $HOME, or the Windows-side one a WSL daemon bridges into.
type pluginSide struct {
	// Label names the side in user-facing output.
	Label     string
	Detection claudeplugin.Detection
	// InitWiring describes the observer-written entries `observer init`
	// put in THIS side's config. Empty when init wrote nothing here.
	InitWiring []string
	// Unnamed says why a config this side would hold has no path (a
	// relocation variable with a relative value, FU-130), "" otherwise:
	// reported, never skipped silently.
	Unnamed string
}

func sideLabels(sides []pluginSide) string {
	out := make([]string, 0, len(sides))
	for _, s := range sides {
		out = append(out, s.Label)
	}
	return strings.Join(out, ", ")
}

// nativePluginSide inspects the same-OS ~/.claude plus the user-level
// MCP config `observer init --claude-code` writes.
func nativePluginSide(homeDir string) pluginSide {
	claudeDir := filepath.Join(homeDir, ".claude")
	s := pluginSide{Label: "native", Detection: claudeplugin.DetectInClaudeDir(claudeDir)}

	hooksPath := filepath.Join(claudeDir, "settings.json")
	if events := observerHookEventsInClaudeSettings(hooksPath); len(events) > 0 {
		s.InitWiring = append(s.InitWiring,
			fmt.Sprintf("%d hook event(s) in %s (%s)", len(events), hooksPath, strings.Join(events, ", ")))
	}
	mcpPath, unnamed := claudeCodeMCPConfigPath(homeDir)
	if mcpPath != "" && observerMCPEntryRegistered(mcpPath) {
		s.InitWiring = append(s.InitWiring,
			fmt.Sprintf("the %q MCP server in %s", mcpregister.ServerName, mcpPath))
	}
	s.Unnamed = unnamed
	return s
}

// windowsPluginSide inspects the Windows-side .claude a WSL daemon
// bridges into. Hooks only: the MCP registrar has no claude-code-windows
// target, so init never writes an MCP entry over there.
func windowsPluginSide(claudeDir string) pluginSide {
	s := pluginSide{Label: "windows (" + claudeDir + ")", Detection: claudeplugin.DetectInClaudeDir(claudeDir)}
	hooksPath := filepath.Join(claudeDir, "settings.json")
	if events := observerHookEventsInClaudeSettings(hooksPath); len(events) > 0 {
		s.InitWiring = append(s.InitWiring,
			fmt.Sprintf("%d hook event(s) in %s (%s)", len(events), hooksPath, strings.Join(events, ", ")))
	}
	return s
}

// observerHookEventsInClaudeSettings lists the Claude Code hook events
// whose settings.json entry is an observer-written command.
//
// Ownership is decided by hook.IsObserverClaudeCodeHookCommand — the
// STRICT tokenizing predicate, not the registrar's deliberately-loose
// substring heuristic. This is a reporting surface, so a false positive
// (warning a user about wiring observer never wrote) is the harm to
// avoid: `/opt/acme hook claude-code audit` must not count, while both
// our native and our wsl.exe-bridged shapes must. Best-effort: an
// unreadable or malformed file yields no events.
func observerHookEventsInClaudeSettings(path string) []string {
	raw, err := os.ReadFile(path) //nolint:gosec // G304: an operator-owned config path derived from $HOME, not user input.
	if err != nil {
		return nil
	}
	var doc struct {
		Hooks map[string][]struct {
			Hooks []struct {
				Command string `json:"command"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil
	}
	var events []string
	for event, groups := range doc.Hooks {
		observer := false
		for _, g := range groups {
			for _, h := range g.Hooks {
				if hook.IsObserverClaudeCodeHookCommand(h.Command) {
					observer = true
				}
			}
		}
		if observer {
			events = append(events, event)
		}
	}
	sort.Strings(events)
	return events
}

// observerMCPEntryRegistered reports whether an MCP config carries an
// "observer" server entry. Binary-path agnostic: this check is about the
// entry EXISTING alongside the plugin's own, which the mcp.registrations
// check (binary drift) does not answer.
func observerMCPEntryRegistered(path string) bool {
	raw, err := os.ReadFile(path) //nolint:gosec // G304: an operator-owned config path derived from $HOME, not user input.
	if err != nil {
		return false
	}
	var doc struct {
		MCPServers map[string]json.RawMessage `json:"mcpServers"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return false
	}
	_, ok := doc.MCPServers[mcpregister.ServerName]
	return ok
}

// claudeCodeMCPConfigPath resolves claude-code's user-level MCP config
// through the shared locate table (the one owner of those paths). With no
// path, reason says why (locate.Location.Reason: a relocation variable
// holding a relative value, FU-130), "" when there is simply no row.
func claudeCodeMCPConfigPath(homeDir string) (path, reason string) {
	if loc, ok := locate.ForClient("claude-code", homeDir); ok {
		return loc.Path, loc.Reason()
	}
	return "", ""
}

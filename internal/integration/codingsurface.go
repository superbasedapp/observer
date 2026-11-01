package integration

import (
	"regexp"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// codingsurface.go is the per-SURFACE coverage record of every coding surface
// in the vendor inventory that Observer does not cover in full (surface-gap
// arc Wave 8, findings S-1 to S-5, IDE-9, CLI-9; pending tracker FU-57;
// docs/audits/vendor-surface-inventory-2026-10-25.md section 6; operator
// decision DEC-13: full parity for every coding surface, grounded or not).
//
// A registry row answers per TOOL, and RouteSurfaces / HookSpec.Surfaces
// refine that per capture surface of a tool Observer already captures. This
// table covers what those two cannot: a surface named by product (Goose for
// VS Code, Copilot in Visual Studio, Claude Agent in Xcode), a surface whose
// product has no registry row yet (AiderDesk, Gemini Code Assist, the
// Cascade editor), and an ACP host itself (Zed, Neovim, Emacs). Each row says,
// for capture, hooks, route and MCP, whether Observer covers the surface
// today, and when that is not grounded, which live check decides and what a
// grounding run must capture. It is DATA: `observer doctor` renders it as
// "not covered" lines, and no writer, watcher or gate reads it.
//
// Honesty rules (pinned by codingsurface_test.go): a covered hook, route or
// MCP cell needs the registry writer that covers it; every probe_required or
// gated cell names a live check, and a row with one carries the grounding
// run; a surface proven to run no hooks is vendor_none with its live check,
// never wired.

// SurfaceCoverage is how far Observer covers one dimension of a coding
// surface. Closed; the zero value is invalid on a row.
type SurfaceCoverage string

const (
	// SurfaceCovered: grounded, Observer covers it today (an adapter reads
	// the surface's store, or a registry writer reaches its file).
	SurfaceCovered SurfaceCoverage = "covered"
	// SurfaceCoverageGated: a writer is built and switched off until its
	// live check passes (DEC-12).
	SurfaceCoverageGated SurfaceCoverage = "gated"
	// SurfaceProbeRequired: not grounded; the named live check decides.
	SurfaceProbeRequired SurfaceCoverage = "probe_required"
	// SurfaceNotCovered: grounded, nothing Observer has reaches it today (a
	// reader or a writer is owed, or Observer itself breaks it).
	SurfaceNotCovered SurfaceCoverage = "not_covered"
	// SurfaceVendorNone: grounded, the surface has no such mechanism or
	// ignores the one Observer writes (no hooks run, no base-URL knob, a
	// context bridge that is not an agent). Not an Observer gap.
	SurfaceVendorNone SurfaceCoverage = "vendor_none"
)

// surfaceCoverages is the closed SurfaceCoverage set.
var surfaceCoverages = map[SurfaceCoverage]bool{
	SurfaceCovered: true, SurfaceCoverageGated: true, SurfaceProbeRequired: true,
	SurfaceNotCovered: true, SurfaceVendorNone: true,
}

// Known reports whether c is one of the declared SurfaceCoverage values.
func (c SurfaceCoverage) Known() bool { return surfaceCoverages[c] }

// SurfaceCell is one dimension of a coding surface.
type SurfaceCell struct {
	State SurfaceCoverage
	// LiveCheck names the live check that grounds or would ground the cell
	// (pending tracker id: LC<n>, LC<n><letter>, LCR-<n>, LCX-<n>, MAC-<n>).
	// Required for probe_required and gated.
	LiveCheck string
	// Note is one plain sentence for people.
	Note string
}

// CodingSurface is one coding surface's coverage row.
type CodingSurface struct {
	// ID is unique across the table, a lowercase token.
	ID string
	// Label is the product name people use ("Goose for VS Code").
	Label string
	// Kind is a models.Surface* kind; Host the surface-host token its
	// sessions carry or would carry ("" when there is none).
	Kind string
	Host string
	// Tool is the registry row the surface rides on today ("" when none).
	Tool string
	// NewTool is the registry id the surface would get as its own capture
	// row ("aider-desk", "gemini-code-assist", "windsurf-cascade"), "" when
	// it belongs to Tool. Never an existing registry tool.
	NewTool string
	// HostRow marks a row about an ACP host itself (Zed, JetBrains, Neovim,
	// Emacs) rather than one agent: Tool and NewTool may both be empty.
	HostRow bool
	// OS is the vendor's platforms: any of "W", "M", "L", space-separated,
	// or "unverified".
	OS string
	// Community marks a third-party surface for a vendor's product.
	Community bool
	// Detect lists the identifiers a detector would match: a VS Code
	// extension id, a JetBrains plugin id, an ACP registry id, an app
	// bundle. Data only; nothing scans for them yet.
	Detect []string
	// The four dimensions.
	Capture, Hooks, Route, MCP SurfaceCell
	// Grounding names the evidence ("doc: <url>", "live: <date> <what>",
	// "audit: <doc> <section>"). Required.
	Grounding string
	// FU57 lists the docs/audits/vendor-surface-inventory-2026-10-25.md
	// section 6 rows (FU-57) this row answers.
	FU57 []int
	// GroundingRun is what an operator grounding run must capture for the
	// cells this row leaves probe_required: the app and version, what to do,
	// and which files or directories to list. Required when any cell is
	// probe_required.
	GroundingRun string
	// DoctorHint, when non-empty, is one plain sentence `observer doctor`
	// prints after the row's line: what the developer does so the surface
	// runs what Observer wrote (a vendor condition Observer cannot meet for
	// them, such as trusting a workspace). Never an action Observer takes.
	DoctorHint string
}

// extensionIDPattern is a VS Code extension id (publisher.name), lowercase.
var extensionIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*\.[a-z0-9][a-z0-9.-]*$`)

// ExtensionIDs returns the VS Code extension ids among the row's Detect
// entries, lowercase: an entry whose first word is publisher.name (a note
// after it, such as "(unconfirmed)", is ignored). JetBrains plugin ids, ACP
// registry ids, app bundles and paths are not extension ids (FU-152).
func (s CodingSurface) ExtensionIDs() []string {
	var out []string
	for _, d := range s.Detect {
		f := strings.Fields(d)
		if len(f) == 0 {
			continue
		}
		if id := strings.ToLower(f[0]); extensionIDPattern.MatchString(id) {
			out = append(out, id)
		}
	}
	return out
}

// Group is the doctor grouping key: the registry tool, else the proposed
// new id, else the host.
func (s CodingSurface) Group() string {
	switch {
	case s.Tool != "":
		return s.Tool
	case s.NewTool != "":
		return s.NewTool
	default:
		return s.Host
	}
}

// Cells returns the four dimensions in reading order with their labels.
func (s CodingSurface) Cells() []struct {
	Name string
	Cell SurfaceCell
} {
	return []struct {
		Name string
		Cell SurfaceCell
	}{
		{"capture", s.Capture}, {"hooks", s.Hooks}, {"route", s.Route}, {"MCP", s.MCP},
	}
}

// FullyCovered reports whether every dimension is covered or vendor_none
// (nothing for Observer to do).
func (s CodingSurface) FullyCovered() bool {
	for _, c := range s.Cells() {
		if c.Cell.State != SurfaceCovered && c.Cell.State != SurfaceVendorNone {
			return false
		}
	}
	return true
}

// Line renders the row as one doctor line: "Goose for VS Code (ide/vscode):
// capture probe_required (LCR-62); hooks ...".
func (s CodingSurface) Line() string {
	where := s.Kind
	if s.Host != "" {
		where += "/" + s.Host
	}
	parts := make([]string, 0, 4)
	for _, c := range s.Cells() {
		p := c.Name + " " + string(c.Cell.State)
		if c.Cell.LiveCheck != "" {
			p += " (" + c.Cell.LiveCheck + ")"
		}
		parts = append(parts, p)
	}
	line := s.Label + " (" + where + "): " + strings.Join(parts, "; ")
	if s.NewTool != "" {
		line += "; would be registry id " + s.NewTool
	}
	if s.DoctorHint != "" {
		line += ". " + s.DoctorHint
	}
	return line
}

// CodingSurfaces returns the table sorted by Group then ID. Callers get a
// copy.
func CodingSurfaces() []CodingSurface {
	out := append([]CodingSurface(nil), codingSurfaces...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Group() != out[j].Group() {
			return out[i].Group() < out[j].Group()
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// CodingSurfacesFor returns the rows of one doctor group.
func CodingSurfacesFor(group string) []CodingSurface {
	var out []CodingSurface
	for _, s := range CodingSurfaces() {
		if s.Group() == group {
			out = append(out, s)
		}
	}
	return out
}

// macRound is the one id form a SurfaceCell accepts beyond IsLiveCheckID: a
// completed tracker ROUND (MAC-5, the 2026-10-27 macOS IDE hook round),
// cited as the grounding of a vendor_none cell. It never names a pending
// check, so a LiveGate never accepts it.
var macRound = regexp.MustCompile(`^MAC-[1-9][0-9]*$`)

// surfaceCheckRef reports whether s is a valid live-check reference in a
// SurfaceCell: a live-check id, or a completed round (macRound).
func surfaceCheckRef(s string) bool { return IsLiveCheckID(s) || macRound.MatchString(s) }

// LiveCheckRefs splits a cell's LiveCheck ("LC16, LC24") into ids.
func LiveCheckRefs(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// fu57Elsewhere names the FU-57 rows answered outside this table, with
// where; together with the rows' FU57 lists they cover rows 1 to 30.
var fu57Elsewhere = map[int]string{
	8:  "registry: kilo-code-cli Routability probe_required (CLI-9, LC24); also row kilo-cli",
	13: "internal/platform/jetbrainshost UnmappedACPAgents (one doctor line per agent, LCR-63)",
	30: "none by decision D10: chat desktop apps stay inventory (vendor inventory section 3.10)",
}

// newToolReasons says, per proposed registry id a row names as NewTool, why
// it is not a registry row yet (FU-147). A registry row needs a REGISTERED
// adapter (TestRegistryHasNoOrphanRows); none of these has one. Every
// NewTool id on a row needs an entry, and an entry whose id gets a
// registered adapter (or a registry row) fails TestNewToolIDsAreNotRegistered
// until the row is made and the NewTool moves to Tool.
var newToolReasons = map[string]string{
	"aider-desk":         "internal/adapter/aiderdesk is an unregistered skeleton: the task context.json shape is vendor-source only and its ParseSessionFile refuses to guess until live check LCR-60 supplies a fixture",
	"gemini-code-assist": "internal/adapter/geminicodeassist is an unregistered skeleton: the chat-mode memento shape is a static bundle read with no signed-in capture, so registration waits on live check LCR-64",
	"windsurf-cascade":   "no Cascade reader exists: windsurf is devin's lifecycle alias (the windsurf package is the deprecated alias, not this id), and the Cascade store in state.vscdb waits on the Cascade grounding run",
	"trae":               "decision D10 keeps Trae capture-only with no adapter yet: the macOS store is grounded (state.vscdb input history, ai-agent stdout logs) but no reader is built",
}

// NewToolReasons returns newToolReasons as a copy, for the pin test and the
// lane report.
func NewToolReasons() map[string]string {
	out := make(map[string]string, len(newToolReasons))
	for k, v := range newToolReasons {
		out[k] = v
	}
	return out
}

// FU57Elsewhere returns fu57Elsewhere as a copy, for the pin test and the
// lane report.
func FU57Elsewhere() map[int]string {
	out := make(map[int]string, len(fu57Elsewhere))
	for k, v := range fu57Elsewhere {
		out[k] = v
	}
	return out
}

// Cell constructors, to keep the table readable.
func covered(note string) SurfaceCell { return SurfaceCell{State: SurfaceCovered, Note: note} }

func probe(check, note string) SurfaceCell {
	return SurfaceCell{State: SurfaceProbeRequired, LiveCheck: check, Note: note}
}

func notCovered(note string) SurfaceCell { return SurfaceCell{State: SurfaceNotCovered, Note: note} }

func vendorNone(check, note string) SurfaceCell {
	return SurfaceCell{State: SurfaceVendorNone, LiveCheck: check, Note: note}
}

const (
	inv1025      = "audit: docs/audits/vendor-surface-inventory-2026-10-25.md "
	macRound1027 = "live: 2026-10-27 MAC-5 (docs/handovers/surface-gap-mac-ide-round-2026-10-27.md)"
)

// codingSurfaces is the table. Rows are grouped by the tool they ride on.
var codingSurfaces = []CodingSurface{
	// --- aider and AiderDesk (FU-57 rows 1, 2).
	{
		ID: "aider-desk", Label: "AiderDesk", Kind: models.SurfaceDesktop, NewTool: "aider-desk", OS: "W M L",
		Detect:  []string{"Electron userData aider-desk", "~/.aider-desk"},
		Capture: probe("LCR-60", "A task's conversation is <project>/.aider-desk/tasks/<task>/context.json (the vendor bundle's ContextManager; aider-desk.db under Electron userData holds only unfinished-run state); the unregistered skeleton internal/adapter/aiderdesk claims that file and refuses to guess its shape until LCR-60 supplies a fixture; whether its aider mode also writes .aider.chat.history.md is unknown."),
		Hooks:   probe("LCR-60", "No hook system found in the vendor sources read; extensions inject logic instead."),
		Route:   probe("LCR-60", "Its connector.py reads OPENAI_API_BASE and ANTHROPIC_BASE_URL from its environment; where the app stores provider base URLs is unknown, and the observer aider launcher never reaches its own venv."),
		MCP:     probe("LCR-60", "mcp-servers.json (key mcpServers) under ~/.aider-desk (AIDER_DESK_HOME_DIR) and <project>/.aider-desk; Observer's writer for the global file (mcpregister target aider-desk) is built and switched off until LCR-60."),
		Grounding: "doc: https://raw.githubusercontent.com/hotovo/aider-desk/main/README.md, src/main/constants.ts, src/main/paths.ts, electron-builder.yml (re-fetched 2026-10-25); " +
			inv1025 + "section 2.1",
		FU57: []int{1},
		GroundingRun: "Install AiderDesk 0.88 or later on Windows. In a scratch project run one aider-mode task and one agent-mode task. " +
			"List (names and sizes only) %APPDATA%\\aider-desk, %USERPROFILE%\\.aider-desk and <project>\\.aider-desk, and say whether <project>\\.aider.chat.history.md was written. " +
			"Set an OpenAI-compatible provider base URL to the Observer proxy in AiderDesk's provider settings, send one message, and record whether an api_turns row lands and which settings file changed.",
	},
	{
		ID: "aider-desk-connector", Label: "AiderDesk Connector (VS Code, JetBrains)", Kind: models.SurfaceIDE, NewTool: "aider-desk", OS: "W M L",
		Detect:    []string{"hotovo-sk.aider-desk-connector", "JetBrains plugin 26313"},
		Capture:   vendorNone("", "A context bridge: it syncs context files into AiderDesk and runs no agent of its own."),
		Hooks:     vendorNone("", "A context bridge with no agent, so no hooks."),
		Route:     vendorNone("", "A context bridge with no model traffic of its own."),
		MCP:       vendorNone("", "A context bridge with no MCP client."),
		Grounding: "doc: https://raw.githubusercontent.com/hotovo/aider-desk/main/README.md (re-fetched 2026-10-25); " + inv1025 + "section 2.1",
		FU57:      []int{2},
	},
	{
		ID: "aider-community-extensions", Label: "Community aider extensions (Aider Composer, VSCode Aider, Coding-Aider IntelliJ)", Kind: models.SurfaceIDE, Tool: "aider",
		OS: "unverified", Community: true,
		Detect:  []string{"lee88688.aider-composer", "Apertia.vscode-aider", "Coding-Aider (mimoccc)"},
		Capture: probe("LCR-61", "They run aider, which writes .aider.chat.history.md that the adapter reads, but whether they keep that file and what marks their sessions is unknown."),
		Hooks:   vendorNone("", "aider has no hook system."),
		Route:   probe("LCR-61", "They spawn aider themselves, so the observer aider launcher env never reaches them; a project .env OPENAI_API_BASE might."),
		MCP:     vendorNone("", "aider has no MCP client."),
		Grounding: "audit: docs/audits/surface-settings-location-matrix-2026-10-25.md Part 1 (carried, not re-fetched); " +
			inv1025 + "section 2.1",
		FU57: []int{2},
		GroundingRun: "Install one community aider extension (Aider Composer or VSCode Aider) in VS Code with aider on PATH. Run one edit task in a scratch repository. " +
			"List the repository root (does .aider.chat.history.md appear) and the extension's globalStorage directory, and note whether a launcher or project .env OPENAI_API_BASE reaches the Observer proxy (an api_turns row).",
	},

	// --- antigravity
	{
		ID: "antigravity-acp-zed", Label: "Antigravity ACP in Zed", Kind: models.SurfaceIDE, Host: "zed", Tool: "antigravity-cli", OS: "W M L",
		Detect:  []string{"acp registry antigravity-acp"},
		Capture: covered("antigravity-acp writes ~/.gemini/antigravity-acp, which the antigravity adapter reads; the Zed host is not stamped (no Zed enricher, FU-95)."),
		Hooks:   probe("LC27", "Whether the ACP server runs ~/.gemini/config/hooks.json is not grounded."),
		Route:   vendorNone("", "No base-URL knob: antigravity is native_exempt."),
		MCP:     probe("LC27", "Zed context_servers may be forwarded to ACP agents; Observer's Zed MCP writer (mcpregister target zed) is built and switched off until LC27."),
		Grounding: "doc: https://raw.githubusercontent.com/agentclientprotocol/registry/main/antigravity-acp/agent.json (re-fetched 2026-10-25); " +
			"repo: internal/platform/jetbrainshost acpAgents (antigravity-acp, live 2026-09-04)",
		FU57:         []int{14},
		GroundingRun: "In Zed, install Antigravity from the ACP registry, run one task with Observer's hooks registered, and list ~/.gemini/antigravity-acp and Zed's data dir external_agents/registry/antigravity-acp; note whether a PreToolUse hook fired.",
	},

	// --- claude-code
	{
		ID: "claude-agent-jetbrains", Label: "Claude Agent in JetBrains AI Assistant (ACP)", Kind: models.SurfaceIDE, Host: "jetbrains", Tool: "claude-code", OS: "W M L",
		Detect:  []string{"acp registry claude-acp"},
		Capture: covered("The agent writes the Claude Code store; the surface enricher stamps ide/jetbrains-<product> from the IDE's .agentsession pointer (live 2026-09-03)."),
		Hooks:   vendorNone("MAC-5", "It does not load ~/.claude/settings.json, so Observer's Claude Code hooks do not gate it (tracker FU-124)."),
		Route:   probe("LC28", "The settings route may not reach an agent the IDE spawns; the IDE's ~/.jetbrains/acp.json env could carry it (D8 writer, not built)."),
		MCP:     probe("LC28", "Whether it reads ~/.claude.json MCP or only acp.json default_mcp_settings is not grounded."),
		Grounding: macRound1027 + " batch 2, observed on IntelliJ IDEA CE only (AI Chat Claude Agent logged no hook call; other JetBrains products inferred); " +
			"repo: internal/platform/jetbrainshost acpAgents claude-acp (live 2026-09-03)",
		GroundingRun: "In IntelliJ IDEA 2026.2, add a test env var to ~/.jetbrains/acp.json agent_servers claude-acp env, run one Claude Agent task, and record whether the agent saw it (LC28); list the agent's ~/.claude/projects entry for the session.",
	},
	{
		ID: "claude-agent-zed", Label: "Claude Agent in Zed (ACP)", Kind: models.SurfaceIDE, Host: "zed", Tool: "claude-code", OS: "W M L",
		Detect:  []string{"acp registry claude-acp"},
		Capture: covered("The agent writes the Claude Code store, which the adapter reads; Zed is not stamped as the host (no Zed enricher, FU-95)."),
		Hooks:   probe("LC27", "Whether a Zed-spawned Claude Agent runs ~/.claude/settings.json hooks is not grounded."),
		Route:   probe("LC27", "Zed's agent_servers.<id>.env comes last in Zed's env order and could carry the route; the D8 writer (target zed-acp/claude-acp, ANTHROPIC_BASE_URL) is built and switched off until LC27."),
		MCP:     probe("LC27", "Zed context_servers may be forwarded; ~/.claude.json MCP may or may not load."),
		Grounding: "audit: docs/audits/surface-settings-precedence-gap-review-2026-10-25.md S-1 (Zed agent_server_store.rs env order); " +
			inv1025 + "section 3.1",
		FU57:         []int{14},
		GroundingRun: "In Zed, install Claude Agent from the ACP registry; set agent_servers.claude-acp.env to a test value and one context_servers entry; run one task with Observer's hooks registered. Record whether the env and the MCP server reached the agent and whether a PreToolUse hook fired; list ~/.claude/projects for the session.",
	},
	{
		ID: "claude-agent-xcode", Label: "Claude Agent in Xcode 26.3+", Kind: models.SurfaceIDE, Host: "xcode", Tool: "claude-code", OS: "M",
		Detect: []string{
			"~/Library/Developer/Xcode/CodingAssistant/ClaudeAgentConfig/",
			"~/Library/Developer/Xcode/CodingAssistant/Agents/claude/<version>/claude",
		},
		Capture: probe("MAC-7", "Xcode runs its own bundled Claude Code (Agents/claude/<version>) with CLAUDE_CONFIG_DIR = CodingAssistant/ClaudeAgentConfig, so its transcripts land in ClaudeAgentConfig/projects/<slug>/<uuid>.jsonl (seen live in round 5b, under the -Users-<user>-Library-Autosave-Information slug); the claude-code adapter watches that tree on macOS and stamps its sessions ide/xcode by place (FU-150). Live on MAC-6 (2026-10-30, observer start in the real home): the session landed stamped ide/xcode, but Xcode runs its agents with cwd ~/Library/Autosave Information, not the open project, so Observer files such a session under the explicit project \"Xcode (project unknown)\" (FU-193, internal/platform/xcodehost); where Xcode names the open project is owed on MAC-7."),
		Hooks: covered("It never reads ~/.claude, so Observer writes its Claude Code hooks into ClaudeAgentConfig/settings.json (target claude-code-xcode, FU-145), only where Xcode created that folder; live 2026-10-28 (LCR-89 passed): the hooks ran and blocked a deny-marker Bash call, and Xcode kept settings.json byte for byte. " +
			"Its callers follow the base tool (FU-145): observer start's auto-registration, observer init, the dashboard's install path and observer uninstall register or remove the target with its base tool on macOS where that folder exists, and the hook doctor reads the home; a live run of that caller path is owed on MAC-6."),
		Route: probe("LCR-89", "The ~/.claude/settings.json route never reaches it; whether an env route written to ClaudeAgentConfig/settings.json would, beside its policy-limits.json and remote-settings.json, is not checked."),
		MCP:   notCovered("Its MCP servers would live in ClaudeAgentConfig/.claude.json, which Xcode's Claude rewrites atomically; Observer's MCP writer targets ~/.claude.json only."),
		Grounding: "live: 2026-10-28 MAC-1 read (macOS 26.2, Xcode 26.6 17F113 beside 26.4.1 17E202): ClaudeAgentConfig/ holds .claude.json, policy-limits.json, remote-settings.json, projects/, sessions/, session-env/, shell-snapshots/, backups/, debug/ and NO settings.json; " +
			"the transcript of 2 Bash calls with no hook call; live: 2026-10-28 Mac round 5b (Xcode 26.6, LCR-89 passed with the claude-code-xcode writer's own settings.json: SessionStart, UserPromptSubmit, PreToolUse Bash blocked, Stop, SessionEnd; settings.json sha256 unchanged; docs/handovers/surface-gap-mac-ide-round-2026-10-27.md); doc: https://developer.apple.com/documentation/xcode/extending-and-customizing-agents",
		FU57: []int{16},
		GroundingRun: "LCR-89, on the macOS VM with Xcode 26.6: back up ~/Library/Developer/Xcode/CodingAssistant/ClaudeAgentConfig, write ClaudeAgentConfig/settings.json with only Observer's stand-in PreToolUse hook (the round 3 lc-hook.sh), restart Xcode, and have Claude Agent run a Bash call carrying mac-tool-deny. " +
			"Record whether the hook ran and the call was blocked, whether Xcode kept or rewrote settings.json, and list ClaudeAgentConfig (names only) after; then restore the backup. " +
			"MAC-7 (FU-193): with observer start running and a project open in Xcode, run one turn per Xcode agent and record where the open project is named (the first user message's Xcode context, ClaudeAgentConfig/.claude.json, codex/config.toml [projects], gemini/.gemini/projects.json; keys and paths only), so the session can be filed under it instead of \"Xcode (project unknown)\".",
	},

	// --- cline-cli
	{
		ID: "cline-jetbrains", Label: "Cline for JetBrains", Kind: models.SurfaceIDE, Host: "jetbrains", Tool: "cline-cli", OS: "W M L",
		Detect:    []string{"JetBrains plugin 28247"},
		Capture:   covered("It shares ~/.cline/data with the CLI, which the cline-cli adapter reads (the jetbrains surface is mapped)."),
		Hooks:     probe("LCR-85", "The VS Code extension loads Observer's ~/.cline/plugins shim (MAC-5, FU-126); whether the JetBrains plugin does is not grounded."),
		Route:     probe("LCR-85", "Whether the plugin reads the providers.json route observer cline-cli writes is not grounded."),
		MCP:       probe("LCR-85", "Cline for JetBrains reads the shared ~/.cline/data/settings/cline_mcp_settings.json, which Observer's existing cline MCP writer writes (S-6); not live-checked from the JetBrains plugin."),
		Grounding: "audit: docs/audits/surface-settings-location-matrix-2026-10-25.md Part 1 (carried); " + macRound1027 + " batch 2 (VS Code Cline loads the plugin shim)",
		GroundingRun: "Install Cline for JetBrains in IntelliJ IDEA with Observer's cline-cli hooks registered; run one task with a tool call. " +
			"Record whether ~/.cline/plugins/superbased-observer-guard.js fired (beforeTool), list ~/.cline/data/tasks for the task, and note whether an api_turns row lands after observer cline-cli wrote the route.",
	},

	// --- codebuddy
	{
		ID: "codebuddy-ide", Label: "CodeBuddy IDE (Craft Agent)", Kind: models.SurfaceIDE, Tool: "codebuddy", OS: "W M",
		Capture:   notCovered("The adapter reads the CodeBuddy Code CLI's store only; the IDE's own store has no reader."),
		Hooks:     probe("LCR-76", "Vendor docs say the IDE reads the same ~/.codebuddy/settings.json hooks; not live-checked."),
		Route:     probe("LCR-76", "Not grounded."),
		MCP:       probe("LCR-76", "~/.codebuddy/.mcp.json (mcpServers); Observer's MCP writer (mcpregister target codebuddy) is built and switched off until LCR-76."),
		Grounding: "audit: docs/audits/surface-settings-location-matrix-2026-10-25.md Part 7 (carried); " + inv1025 + "section 3.8",
		FU57:      []int{25},
		GroundingRun: "Install the CodeBuddy IDE on Windows; with Observer's codebuddy hooks registered run one agent task with a shell call. " +
			"Record whether the PreToolUse hook fired, and list %APPDATA%\\CodeBuddy (and %LOCALAPPDATA% equivalents) for where the IDE keeps conversations; also install the CodeBuddy VS Code plugin and say where it stores sessions.",
	},

	// --- codex
	{
		ID: "codex-xcode", Label: "Codex in Xcode 26.3+", Kind: models.SurfaceIDE, Host: "xcode", Tool: "codex", OS: "M",
		Detect: []string{
			"~/Library/Developer/Xcode/CodingAssistant/codex/",
			"~/Library/Developer/Xcode/CodingAssistant/Agents/XcodeVersions/<build>/codex",
		},
		Capture: probe("MAC-7", "CodingAssistant/codex is the CODEX_HOME of Xcode's bundled Codex: its rollouts land in codex/sessions/YYYY/MM/DD/rollout-*.jsonl (seen live in round 5b); the codex adapter watches that tree on macOS and stamps its sessions ide/xcode by place (FU-150). Live on MAC-6 (2026-10-30, observer start in the real home): the session landed stamped ide/xcode, but Xcode runs its agents with cwd ~/Library/Autosave Information, not the open project, so Observer files such a session under the explicit project \"Xcode (project unknown)\" (FU-193, internal/platform/xcodehost); where Xcode names the open project is owed on MAC-7."),
		Hooks: covered("It never reads ~/.codex, so Observer writes hooks.json, the config.toml [features] hooks switch and the trust records into CodingAssistant/codex (target codex-xcode, FU-145), only where Xcode created that folder; live 2026-10-28 (LCR-90 passed): the hooks ran and blocked the probe with no trust prompt, and Xcode, which rewrites config.toml at every session start, kept hooks = true and the trust records. " +
			"Its callers follow the base tool (FU-145): observer start's auto-registration, observer init, the dashboard's install path and observer uninstall register or remove the target with its base tool on macOS where that folder exists, and the hook doctor reads the home; a live run of that caller path is owed on MAC-6."),
		Route: probe("LCR-90", "The ~/.codex/config.toml route never reaches it; whether a model provider written to codex/config.toml would is not checked."),
		MCP:   notCovered("Its MCP servers would live in codex/config.toml; Observer's MCP writer targets ~/.codex/config.toml only."),
		Grounding: "live: 2026-10-28 MAC-1 read (macOS 26.2, Xcode 26.6 17F113): codex/ holds .personality_migration, installation_id, cache/, logs_2.sqlite, memories_1.sqlite, plugins/, rules/xcode.rules, sessions/2026/10/rollout-*.jsonl (4 sessions), shell_snapshots/, models_cache.json, .tmp/plugins/ and no config.toml or hooks.json; " +
			"no ~/.codex hook call during those sessions; live: 2026-10-28 Mac round 5b (Xcode 26.6, gpt-5.4-mini, LCR-90 passed with the codex-xcode writer's own hooks.json: SessionStart, UserPromptSubmit, PreToolUse Bash blocked, Stop; config.toml rewritten by Xcode with its own keys, [features] hooks = true and the nine [hooks.state] records kept; docs/handovers/surface-gap-mac-ide-round-2026-10-27.md)",
		FU57: []int{16},
		GroundingRun: "LCR-90, on the macOS VM with Xcode 26.6: back up CodingAssistant/codex, write codex/config.toml with only [features] hooks = true and codex/hooks.json with Observer's stand-in PreToolUse hook, restart Xcode, and have Codex run a shell call carrying mac-tool-deny. " +
			"Record whether the hook ran and the call was blocked (and whether Codex asked to trust the hooks), whether Xcode kept or rewrote config.toml, and list codex/ (names only) after; then restore the backup. " +
			"MAC-7 (FU-193): with observer start running and a project open in Xcode, run one turn per Xcode agent and record where the open project is named (the first user message's Xcode context, ClaudeAgentConfig/.claude.json, codex/config.toml [projects], gemini/.gemini/projects.json; keys and paths only), so the session can be filed under it instead of \"Xcode (project unknown)\".",
	},

	// --- command-code
	{
		ID: "command-code-vscode", Label: "Command Code for VS Code", Kind: models.SurfaceIDE, Host: "vscode", Tool: "command-code", OS: "W M L",
		Detect:    []string{"CommandCode.commandcode-vscode"},
		Capture:   covered("The bundled extension shares ~/.commandcode, which the adapter reads; its sessions carry no surface stamp."),
		Hooks:     probe("LCR-73", "Whether the extension loads Observer's ~/.commandcode/mods module is not grounded."),
		Route:     probe("LCR-73", "Not grounded (the CLI row itself is probe_required)."),
		MCP:       covered("The extension shares ~/.commandcode/mcp.json, which Observer's MCP writer covers."),
		Grounding: "doc: https://registry.npmjs.org/command-code (1.88.0, vsix/commandcode-vscode.vsix, re-fetched 2026-10-25); " + inv1025 + "X7",
		FU57:      []int{22},
		GroundingRun: "Install command-code 1.88+ and let it install CommandCode.commandcode-vscode; run one task from the extension with Observer's mod installed. " +
			"Record whether the mod fired, list ~/.commandcode/projects for the session, and note any field that tells the extension from the CLI.",
	},

	// --- copilot
	{
		ID: "copilot-visual-studio", Label: "GitHub Copilot in Visual Studio 2022 / 2026 (and SSMS 22)", Kind: models.SurfaceIDE, Host: "visual-studio", Tool: "copilot", OS: "W",
		Capture:   probe("LCR-68", "Where Visual Studio keeps Copilot chat history is not grounded; nothing reads it."),
		Hooks:     vendorNone("", "Copilot in Visual Studio has no hooks; only an ADMX Disable Agent Mode policy."),
		Route:     notCovered("A bring-your-own-model URL exists in 18.10 Insiders, held in the UI; no writer."),
		MCP:       probe("LCR-68", "It reads %USERPROFILE%\\.mcp.json first, then <SOLUTIONDIR>\\.mcp.json; Observer's writer for the user file (mcpregister target visual-studio, key servers) is built and switched off until LCR-68."),
		Grounding: "doc: https://learn.microsoft.com/en-us/visualstudio/ide/mcp-servers (fetched 2026-10-28: %USERPROFILE%\\.mcp.json and <SOLUTIONDIR>\\.mcp.json); " + inv1025 + "section 3.4",
		FU57:      []int{17},
		GroundingRun: "On Windows with Visual Studio 2022 17.14+ (or 2026), sign Copilot in and run one agent-mode chat in a scratch solution. " +
			"List %LOCALAPPDATA%\\Microsoft\\VisualStudio\\<ver>* and <solution>\\.vs (names only) for where chat history landed, and give the full path of devenv.exe so the visual-studio launch row can be grounded.",
	},
	{
		ID: "copilot-jetbrains", Label: "GitHub Copilot for JetBrains", Kind: models.SurfaceIDE, Host: "jetbrains", Tool: "copilot", OS: "W M L",
		Detect:    []string{"com.github.copilot"},
		Capture:   notCovered("Its sessions sit in H2 MVStore databases under the IDE system path; no reader."),
		Hooks:     vendorNone("", "No hooks."),
		Route:     notCovered("No writer for its settings."),
		MCP:       probe("LCR-78", "An mcp.json exists; its path is not grounded."),
		Grounding: "audit: docs/audits/vendor-surface-inventory-2026-09-03.md (jar read 2026-09-04) and docs/audits/surface-settings-location-matrix-2026-10-25.md Part 1",
		FU57:      []int{18},
		GroundingRun: "In IntelliJ IDEA with GitHub Copilot for JetBrains, add one MCP server in the Copilot settings UI and run one agent chat. " +
			"List the IDE config and system dirs (%APPDATA%\\JetBrains\\<Product><ver> and %LOCALAPPDATA%\\JetBrains\\<Product><ver>, names only) for the mcp.json it wrote and the session databases.",
	},
	{
		ID: "copilot-xcode", Label: "GitHub Copilot for Xcode", Kind: models.SurfaceIDE, Host: "xcode", Tool: "copilot", OS: "M",
		Capture:      probe("LCR-78", "Store not grounded; nothing reads it."),
		Hooks:        vendorNone("", "No hooks."),
		Route:        notCovered("BYOK is in preview, held in the UI; no writer."),
		MCP:          notCovered("UI-managed mcp.json, path not grounded; no writer."),
		Grounding:    "audit: docs/audits/surface-settings-location-matrix-2026-10-25.md Part 1 (carried); " + inv1025 + "section 3.4",
		FU57:         []int{18},
		GroundingRun: "On macOS, install GitHub Copilot for Xcode, run one agent chat and add one MCP server; list ~/Library/Application Support and ~/.config for the Copilot for Xcode directories (names only).",
	},
	{
		ID: "copilot-eclipse", Label: "GitHub Copilot for Eclipse", Kind: models.SurfaceIDE, Host: "eclipse", Tool: "copilot", OS: "W M L",
		Capture:      probe("LCR-78", "Store not grounded; nothing reads it."),
		Hooks:        vendorNone("", "No hooks."),
		Route:        notCovered("No writer."),
		MCP:          notCovered("MCP lives in Eclipse preferences (file not grounded); no writer."),
		Grounding:    "audit: docs/audits/surface-settings-location-matrix-2026-10-25.md Part 1 (carried); " + inv1025 + "section 3.4",
		FU57:         []int{18},
		GroundingRun: "Install GitHub Copilot for Eclipse, run one agent chat and add one MCP server; list the workspace .metadata/.plugins and ~/.eclipse directories (names only) for where it stored them.",
	},

	// --- copilot-cli
	{
		ID: "copilot-cli-acp", Label: "Copilot CLI via ACP (github-copilot-cli)", Kind: models.SurfaceIDE, Host: "jetbrains", Tool: "copilot-cli", OS: "W M L",
		Detect:       []string{"acp registry github-copilot-cli"},
		Capture:      covered("@github/copilot writes ~/.copilot/session-state, which the adapter reads; jetbrainshost maps the id as an alias of the proven package (S-1)."),
		Hooks:        probe("LCR-63", "Whether an ACP-run Copilot CLI runs ~/.copilot/hooks is not grounded."),
		Route:        probe("LC28", "The route is BYOK env only (COPILOT_PROVIDER_BASE_URL); only a host env writer could carry it."),
		MCP:          notCovered("No Observer MCP writer for copilot-cli."),
		Grounding:    "doc: https://raw.githubusercontent.com/agentclientprotocol/registry/main/github-copilot-cli/agent.json (re-fetched 2026-10-25); " + inv1025 + "X2",
		FU57:         []int{11},
		GroundingRun: "In IntelliJ IDEA 2026.2, install github-copilot-cli from the ACP registry, run one task, and give the .agentsession pointer text beside the ~/.copilot/session-state directory name it created (the sid round trip).",
	},
	{
		ID: "copilot-language-server-acp", Label: "Copilot via ACP (github-copilot, the language server)", Kind: models.SurfaceIDE, Host: "jetbrains", Tool: "copilot-cli", OS: "W M L",
		Detect:       []string{"acp registry github-copilot"},
		Capture:      probe("LCR-67", "The registry's github-copilot entry is now @github/copilot-language-server; whether it still writes ~/.copilot like the CLI did on 2026-09-03 is unknown."),
		Hooks:        probe("LCR-67", "Not grounded."),
		Route:        probe("LC28", "Only a host env writer could carry a route."),
		MCP:          notCovered("No Observer MCP writer for copilot-cli."),
		Grounding:    "doc: https://raw.githubusercontent.com/agentclientprotocol/registry/main/github-copilot/agent.json (re-fetched 2026-10-25); " + inv1025 + "X2",
		FU57:         []int{11},
		GroundingRun: "In IntelliJ IDEA 2026.2, install github-copilot from the ACP registry (the language-server package), run one task, and list ~/.copilot/session-state; give the .agentsession pointer text.",
	},
	{
		ID: "github-copilot-app", Label: "GitHub Copilot app (desktop)", Kind: models.SurfaceDesktop, Tool: "copilot-cli", OS: "W M L",
		Capture:   probe("LCR-69", "GA 2026-06-17; it needs the org Copilot CLI policy, but whether it writes ~/.copilot is unknown (else it needs its own id)."),
		Hooks:     probe("LCR-69", "Not grounded."),
		Route:     probe("LCR-69", "It offers BYOK; where that is stored is not grounded."),
		MCP:       probe("LCR-69", "It has MCP; where its config lives is not grounded."),
		Grounding: "doc: github.blog GitHub Copilot app GA posts (2026-06-17, 2026-07-06), via web search 2026-10-25; " + inv1025 + "X5",
		FU57:      []int{19},
		GroundingRun: "Install the GitHub Copilot app on Windows, run one session on a scratch repository branch, add one MCP server and set one BYOK provider. " +
			"List %USERPROFILE%\\.copilot and the app's %APPDATA% / %LOCALAPPDATA% directories (names only) and say whether ~/.copilot/session-state gained a session.",
	},

	// --- cortex-code
	{
		ID: "cortex-code-desktop", Label: "Cortex Code Desktop (IDE)", Kind: models.SurfaceDesktop, Tool: "cortex-code", OS: "W M L",
		Capture:      probe("LC18", "Whether it writes the ~/.snowflake/cortex store the adapter reads is not grounded."),
		Hooks:        vendorNone("LC18", "Its Agent tab ran neither ~/.snowflake/cortex/hooks.json nor Claude Code's ~/.claude/settings.json hooks (2026-10-26), so it is ungated (W-7, a vendor limit)."),
		Route:        notCovered("cortex-code is after_bridge: no route until a protocol bridge exists."),
		MCP:          probe("LC18", "Cortex Code's mcp.json (mcpServers); Observer's MCP writer (mcpregister target cortex-code) is built and switched off until LC18."),
		Grounding:    "live: 2026-10-26 LC18 (Cortex Code IDE Agent tab, no hook call from either file); audit: docs/audits/surface-settings-location-matrix-2026-10-25.md Part 7",
		FU57:         []int{24},
		GroundingRun: "With Cortex Code Desktop on Windows, run one Agent task and list ~/.snowflake/cortex (names only) for a new conversation; also give the desktop executable path for a GUI row.",
	},
	{
		ID: "cortex-code-vscode", Label: "Cortex Code for VS Code", Kind: models.SurfaceIDE, Host: "vscode", Tool: "cortex-code", OS: "W M L",
		Capture:      probe("LC18", "It talks ACP to Cortex; whether its sessions reach the store the adapter reads is not grounded."),
		Hooks:        probe("LC18", "The VS Code ACP path is still owed in LC18."),
		Route:        notCovered("cortex-code is after_bridge."),
		MCP:          probe("LC18", "Cortex Code's mcp.json (mcpServers); Observer's MCP writer (mcpregister target cortex-code) is built and switched off until LC18."),
		Grounding:    "audit: docs/audits/surface-settings-location-matrix-2026-10-25.md Parts 1 and 7; tracker LC18 (VS Code ACP path owed)",
		FU57:         []int{24},
		GroundingRun: "Install the Cortex Code VS Code extension, run one task with Observer's stand-in hooks in ~/.snowflake/cortex/hooks.json and ~/.claude/settings.json, record which fired, and list ~/.snowflake/cortex/conversations.",
	},

	// --- devin and the Cascade editor
	{
		ID: "windsurf-cascade", Label: "Devin Desktop Cascade editor (ex-Windsurf)", Kind: models.SurfaceIDE, Host: "windsurf", Tool: "devin", NewTool: "windsurf-cascade", OS: "W M L",
		Capture:      notCovered("Cascade conversations sit in %APPDATA%\\Windsurf\\User\\globalStorage\\state.vscdb and ~/.codeium/windsurf; no reader (a new capture id, since windsurf is the lifecycle alias of devin)."),
		Hooks:        covered("The devin row's Cascade writer registers ~/.codeium/windsurf/hooks.json; DEC-11 keeps it for the Cascade editor only (Devin Local uses the Devin CLI hooks)."),
		Route:        vendorNone("", "Vendor-hosted inference; devin is native_exempt."),
		MCP:          notCovered("Cascade's mcp_config.json has no Observer writer."),
		Grounding:    "live: 2026-10-26 LC29 (Devin Desktop fires the Cascade hooks with a trajectory_id); audit: docs/audits/vendor-surface-inventory-2026-09-03.md (new tool id) and " + inv1025 + "section 3.5",
		FU57:         []int{26},
		GroundingRun: "In Devin Desktop's Cascade editor (not Devin Local), run one Cascade task; list %APPDATA%\\Windsurf\\User\\globalStorage (names and sizes) and ~/.codeium/windsurf (names only), and give the trajectory_id the Cascade hook payload carried.",
	},
	{
		ID: "windsurf-plugins", Label: "Windsurf plugins for VS Code and JetBrains", Kind: models.SurfaceIDE, Tool: "devin", OS: "W M L",
		Capture:      probe("LCR-87", "Not documented; not grounded."),
		Hooks:        probe("LCR-87", "Not grounded."),
		Route:        vendorNone("", "Vendor-hosted inference."),
		MCP:          probe("LCR-87", "Not grounded."),
		Grounding:    "audit: docs/audits/vendor-surface-inventory-2026-09-03.md (carried); " + inv1025 + "section 3.5",
		GroundingRun: "Install the Windsurf plugin in VS Code and in IntelliJ IDEA, run one chat each, and list ~/.codeium (names only) and the extension's globalStorage directory.",
	},

	// --- dimcode
	{
		ID: "dimcode-desktop", Label: "DimCode Desktop", Kind: models.SurfaceDesktop, Tool: "dimcode", OS: "unverified",
		Capture:      probe("LCR-77", "Store and platforms not grounded."),
		Hooks:        probe("LCR-77", "Whether it runs ~/.dimcode/v2/hooks.json is not grounded."),
		Route:        probe("LCR-77", "Whether it honours the DIMCODE_*_BASE_URL env is not grounded."),
		MCP:          probe("LCR-77", "DimCode's v2 mcp.json (mcpServers); Observer's MCP writer (mcpregister target dimcode) is built and switched off until LCR-77."),
		Grounding:    "audit: docs/audits/surface-settings-location-matrix-2026-10-25.md Part 7 (DimCode Desktop 0.9.8); " + inv1025 + "section 3.8",
		FU57:         []int{25},
		GroundingRun: "Install DimCode Desktop (0.9.8 or later) on Windows; with Observer's dimcode hooks registered run one task with a shell call. Record whether the hook fired, list ~/.dimcode (names only), and give the executable path.",
	},

	// --- autohand
	{
		ID: "autohand-vscode", Label: "Autohand for VS Code", Kind: models.SurfaceIDE, Host: "vscode", Tool: "autohand", OS: "W M L",
		Detect:       []string{"AutohandAI.vscode-autohand"},
		Capture:      probe("LCR-71", "Whether it writes the ~/.autohand store the adapter reads is not grounded."),
		Hooks:        probe("LCR-71", "The vendor calls its hooks limited; whether it runs ~/.autohand/config.json hooks is not grounded."),
		Route:        probe("LCR-71", "It has its own autohand.* settings; whether a config.json provider baseUrl reaches it is not grounded."),
		MCP:          notCovered("No Observer MCP writer for autohand."),
		Grounding:    "doc: autohandai code-cli README (names the VS Code extension; re-fetched 2026-10-25); " + inv1025 + "section 3.8",
		FU57:         []int{22},
		GroundingRun: "Install AutohandAI.vscode-autohand with Observer's autohand hooks registered; run one task with a shell call. Record whether the hook fired, list ~/.autohand (names only, the config holds keys), and note what marks the session as the extension's.",
	},

	// --- dirac
	{
		ID: "dirac-vscode", Label: "Dirac for VS Code", Kind: models.SurfaceIDE, Host: "vscode", Tool: "dirac", OS: "W M L",
		Detect:       []string{"dirac-run.dirac"},
		Capture:      probe("LCR-72", "The adapter watches ~/.dirac only; where the extension stores tasks is not grounded."),
		Hooks:        probe("LCR-72", "Whether it runs ~/.dirac/Hooks is not grounded."),
		Route:        probe("LCR-72", "\"Provider configuration stays with Dirac across these interfaces\"; whether the CLI's store is that configuration is not grounded."),
		MCP:          notCovered("No Observer MCP writer for dirac."),
		Grounding:    "doc: dirac-run/dirac README (re-fetched 2026-10-25); " + inv1025 + "section 3.8",
		FU57:         []int{22},
		GroundingRun: "Install dirac-run.dirac with Observer's Dirac hooks in ~/.dirac/Hooks; run one task with a shell call. Record whether the hook fired and list ~/.dirac and the extension's globalStorage directory (names only).",
	},

	// --- gemini-cli and Gemini Code Assist
	{
		ID: "gemini-code-assist-vscode-agent", Label: "Gemini Code Assist agent mode (VS Code)", Kind: models.SurfaceIDE, Host: "vscode", Tool: "gemini-cli", OS: "W M L",
		Detect:       []string{"google.geminicodeassist"},
		Capture:      covered("Agent mode bundles gemini-cli-core and writes ~/.gemini/tmp/<project>/chats, which the gemini-cli adapter reads (unstamped)."),
		Hooks:        probe("LCR-64", "Whether agent mode runs ~/.gemini/settings.json hooks is not grounded."),
		Route:        vendorNone("", "No base-URL key: the launcher-only Gemini route never reaches it (Standard and Enterprise tiers; individual tier retired 2026-06-18)."),
		MCP:          probe("LCR-64", "It reads ~/.gemini/settings.json mcpServers; Observer's MCP writer (mcpregister target gemini-cli) is built and switched off until LCR-64."),
		Grounding:    "audit: " + "docs/audits/vendor-surface-inventory-2026-10-25.md section 2.3 (Google agent-mode pages via web search 2026-10-25) and the 2026-09-03 inventory",
		FU57:         []int{6},
		GroundingRun: "With a Gemini Code Assist Standard or Enterprise licence in VS Code, with Observer's gemini hooks registered, run one agent-mode task with a tool call. Record whether the BeforeAgent hook fired and list ~/.gemini/tmp for the chat.",
	},
	{
		ID: "gemini-code-assist-jetbrains", Label: "Gemini Code Assist for JetBrains (agent mode)", Kind: models.SurfaceIDE, Host: "jetbrains", NewTool: "gemini-code-assist", OS: "W M L",
		Capture:      probe("LCR-64", "Store not grounded; nothing reads it."),
		Hooks:        probe("LCR-64", "No built-in tool control on JetBrains; hooks not grounded."),
		Route:        vendorNone("", "No base-URL key."),
		MCP:          probe("LCR-64", "It reads mcp.json (key mcpServers) in the IDE configuration directory, not ~/.gemini (Google's docs); Observer's writer (mcpregister target gemini-code-assist-jetbrains, every JetBrains product configuration directory) is built and switched off until LCR-64, which also grounds which product directories carry the plugin."),
		Grounding:    "doc: https://docs.cloud.google.com/gemini/docs/codeassist/use-agentic-chat-pair-programmer and agent-mode (via web search 2026-10-25); " + inv1025 + "section 2.3 (C3)",
		FU57:         []int{5},
		GroundingRun: "With a Gemini Code Assist Standard or Enterprise licence on IntelliJ IDEA, add one MCP server and run one agent-mode task. List %APPDATA%\\JetBrains\\<Product><ver> (names only) for the mcp.json path and %LOCALAPPDATA%\\JetBrains\\<Product><ver> and ~/.gemini for where the session landed.",
	},
	{
		ID: "gemini-code-assist-chat", Label: "Gemini Code Assist chat mode (VS Code)", Kind: models.SurfaceIDE, Host: "vscode", NewTool: "gemini-code-assist", OS: "W M L",
		Detect:       []string{"google.geminicodeassist"},
		Capture:      notCovered("Chat threads sit in the state.vscdb memento geminiCodeAssist.chatThreads; internal/adapter/geminicodeassist is an unregistered skeleton."),
		Hooks:        probe("LCR-64", "Not grounded."),
		Route:        vendorNone("", "No base-URL key."),
		MCP:          probe("LCR-64", "Not grounded for chat mode."),
		Grounding:    "audit: docs/audits/vendor-surface-inventory-2026-09-03.md (memento key, metrics_to_send) and " + inv1025 + "section 3.3",
		FU57:         []int{5},
		GroundingRun: "Covered by the Gemini Code Assist run: also run one chat-mode exchange in VS Code and confirm the memento key and the metrics_to_send/*.json names (names only).",
	},
	{
		ID: "gemini-acp", Label: "Gemini CLI via ACP (JetBrains, Zed)", Kind: models.SurfaceIDE, Tool: "gemini-cli", OS: "W M L",
		Detect:       []string{"acp registry gemini"},
		Capture:      covered("The ACP-run Gemini CLI writes ~/.gemini/tmp, which the adapter reads; no host stamp (not in acpAgents, LCR-63)."),
		Hooks:        probe("LCR-63", "Whether an ACP-run Gemini runs settings.json hooks is not grounded."),
		Route:        probe("LC27, LC28", "The launcher env route never reaches a host-spawned Gemini; only a host env writer could."),
		MCP:          probe("LCR-64", "~/.gemini/settings.json mcpServers; Observer's MCP writer (mcpregister target gemini-cli) is built and switched off until LCR-64."),
		Grounding:    "doc: https://raw.githubusercontent.com/agentclientprotocol/registry/main/gemini/agent.json (re-fetched 2026-10-25); " + inv1025 + "section 3.3",
		FU57:         []int{13},
		GroundingRun: "Covered by the JetBrains ACP pointer runs (LCR-63): run gemini from the ACP registry in IntelliJ IDEA and give the .agentsession pointer beside the ~/.gemini/tmp chat file name.",
	},
	{
		ID: "gemini-xcode", Label: "Gemini in Xcode 26.3+", Kind: models.SurfaceIDE, Host: "xcode", Tool: "gemini-cli", OS: "M",
		Detect: []string{"~/Library/Developer/Xcode/CodingAssistant/gemini"},
		Capture: probe("MAC-7", "Xcode 26.6 runs its bundled Gemini CLI (Agents/gemini) with its home at CodingAssistant/gemini/.gemini, which holds the CLI's own tmp/ chat store (seen in round 5b); "+
			"the gemini-cli adapter watches that tmp/ on macOS and stamps its sessions ide/xcode by place (FU-160). Live on MAC-6 (2026-10-30, observer start in the real home): the session landed stamped ide/xcode, but Xcode runs its agents with cwd ~/Library/Autosave Information, not the open project, so Observer files such a session under the explicit project \"Xcode (project unknown)\" (FU-193, internal/platform/xcodehost); where Xcode names the open project is owed on MAC-7."),
		Hooks: vendorNone("LCR-91", "It never reads ~/.gemini (round 5b: a shell call ran with Observer's ~/.gemini registration in place and no hook reached it). "+
			"Its own home's settings.json hooks are kept by Xcode and BeforeAgent runs, but LCR-91 (MAC-6, 2026-10-30) found no BeforeTool for its run_shell_command, so a Gemini-in-Xcode tool call cannot be gated by a hook: the tool gate is not enforceable there. "+
			"Observer's writer for that settings.json (target gemini-cli-xcode, FU-160) stays switched off on that finding (FU-195); another seam (Xcode's own tool approval, an MCP route) is a follow-up."),
		Route: probe("LC34", "The launcher env route never reaches an Xcode-run Gemini."),
		MCP:   notCovered("No Observer MCP writer for the Xcode Gemini home."),
		Grounding: "doc: https://developer.apple.com/documentation/xcode/extending-and-customizing-agents (doc JSON re-fetched 2026-10-28); " +
			"live: 2026-10-28 Mac round 5b (Xcode 26.6): CodingAssistant/gemini/.gemini holds settings.json, GEMINI.md, projects.json, history/, tmp/; a shell call ran unblocked with Observer's ~/.gemini registration in place (docs/handovers/surface-gap-mac-ide-round-2026-10-27.md)",
		FU57: []int{16},
		GroundingRun: "LCR-91, on the macOS VM with Xcode 26.6: back up ~/Library/Developer/Xcode/CodingAssistant/gemini/.gemini (list names only; settings.json may hold credentials), switch gemini-cli-xcode on (a scratch build without its livegate.go row) and register it, or splice Observer's stand-in BeforeTool and BeforeAgent hooks into that settings.json by hand, restart Xcode, and have Gemini run a shell call carrying mac-tool-deny. " +
			"Record whether the hook ran and the call was blocked, whether Xcode kept or rewrote settings.json (sha256 before and after, and after a second session start), list .gemini (names only) after, and with observer start running whether a session landed stamped ide/xcode; then restore the backup. " +
			"MAC-7 (FU-193): with observer start running and a project open in Xcode, run one turn per Xcode agent and record where the open project is named (the first user message's Xcode context, ClaudeAgentConfig/.claude.json, codex/config.toml [projects], gemini/.gemini/projects.json; keys and paths only), so the session can be filed under it instead of \"Xcode (project unknown)\".",
	},

	// --- goose
	{
		ID: "goose-vscode", Label: "Goose for VS Code", Kind: models.SurfaceIDE, Host: "vscode", Tool: "goose", OS: "W M L",
		Detect:    []string{"block.vscode-goose"},
		Capture:   probe("LCR-62", "It talks ACP to a goose CLI it spawns; whether its sessions land in sessions.db, and with what marker, is unknown."),
		Hooks:     probe("LCR-62", "Whether an ACP-run goose loads Observer's ~/.agents/plugins hooks is not grounded (Goose itself blocked the MAC-5 deny probe)."),
		Route:     probe("LCR-62", "The observer goose launcher route never reaches it; only a provider host in config.yaml could."),
		MCP:       notCovered("No Observer MCP writer for goose."),
		Grounding: "doc: https://raw.githubusercontent.com/block/vscode-goose/main/package.json (0.2.3, experimental; re-fetched 2026-10-25); " + inv1025 + "section 2.2 (C2)",
		FU57:      []int{3},
		GroundingRun: "Install block.vscode-goose 0.2.3+ with goose CLI 1.16+ and Observer's goose plugin registered; run one task with a shell call. " +
			"Record whether the PreToolUse hook fired, query ~/.local/share/goose/sessions/sessions.db for the new session (id and any client or source column), and note whether OPENAI_HOST in the VS Code environment reached it.",
	},
	{
		ID: "goose-acp", Label: "Goose via ACP (JetBrains, Zed)", Kind: models.SurfaceIDE, Tool: "goose", OS: "W M L",
		Detect:       []string{"acp registry goose"},
		Capture:      probe("LCR-63", "Confirmed broken in the 2026-09-04 JetBrains run; not re-tested on goose 1.56."),
		Hooks:        probe("LCR-63", "Not grounded for an ACP-run goose."),
		Route:        probe("LC28", "The launcher route never reaches a host-spawned goose; only a host env writer or config.yaml could."),
		MCP:          notCovered("No Observer MCP writer for goose."),
		Grounding:    "doc: https://raw.githubusercontent.com/agentclientprotocol/registry/main/goose/agent.json (1.56.0, re-fetched 2026-10-25); repo: internal/platform/jetbrainshost (broken 2026-09-04)",
		FU57:         []int{4},
		GroundingRun: "Covered by the JetBrains ACP pointer runs (LCR-63): install goose from the ACP registry in IntelliJ IDEA, run one task and give the .agentsession pointer beside the sessions.db row id.",
	},

	// --- ibm-bob
	{
		ID: "bob-ide", Label: "IBM Bob IDE", Kind: models.SurfaceIDE, Tool: "ibm-bob", OS: "W M L",
		Capture:      probe("LCR-75", "The IDE shares ~/.bob; whether its conversations reach the store the adapter reads is not grounded."),
		Hooks:        covered("Bob IDE 2.2.3 runs the ~/.bob/settings/settings.json hooks and honours an exit-2 deny (LC17, 2026-10-25)."),
		Route:        probe("LCR-75", "Not grounded."),
		MCP:          probe("LCR-75", "Bob's settings mcp.json (mcpServers); Observer's MCP writer (mcpregister target ibm-bob) is built and switched off until LCR-75."),
		Grounding:    "live: 2026-10-25 LC17 (IBM Bob IDE 2.2.3, exit-2 deny blocks); audit: docs/audits/surface-settings-location-matrix-2026-10-25.md Part 7",
		FU57:         []int{25},
		GroundingRun: "In IBM Bob IDE on Windows run one agent task; list ~/.bob (names only) for the conversation and give the IDE executable path for a GUI row.",
	},

	// --- junie
	{
		ID: "junie-ide-plugin", Label: "Junie IDE plugin (JetBrains)", Kind: models.SurfaceIDE, Host: "jetbrains", Tool: "junie", OS: "W M L",
		Capture:      covered("It writes the ${JUNIE_HOME:-~/.junie} store the adapter reads; the enricher stamps ide/jetbrains-<product>."),
		Hooks:        vendorNone("MAC-5", "The Junie IDE plugin does not run the Junie CLI hooks (tracker FU-124)."),
		Route:        probe("LC20", "The JUNIE_LITELLM_URL route probe is still owed."),
		MCP:          probe("LCR-84", "Junie's mcp.json (mcpServers); whether the IDE plugin reads it is not grounded; Observer's MCP writer (mcpregister target junie) is built and switched off until LCR-84."),
		Grounding:    macRound1027 + " batch 2 (IntelliJ IDEA CE Junie plugin, no hook call); doc: https://junie.jetbrains.com/docs/junie-cli-hooks.html",
		GroundingRun: "Covered by LC20: point JUNIE_LITELLM_URL at the Observer proxy, run one Junie task in the IDE and record whether an api_turns row lands.",
	},
	{
		ID: "junie-jetbrains-air", Label: "JetBrains Air (runs Junie and other ACP agents)", Kind: models.SurfaceDesktop, Tool: "junie", OS: "M",
		Capture:      probe("LCR-84", "Air orchestrates Claude Code, Codex, Gemini CLI, Junie and Autohand over ACP; each writes its own store, but what marks a session as Air's is unknown."),
		Hooks:        probe("MAC-5", "Air runs the Junie CLI hooks (7 PreToolUse calls on 2026-10-27); whether it honoured the deny was not seen."),
		Route:        probe("LC20", "Not grounded."),
		MCP:          probe("LCR-84", "Junie's mcp.json (mcpServers); Observer's MCP writer (mcpregister target junie) is built and switched off until LCR-84."),
		Grounding:    macRound1027 + " batch 2 (JetBrains Air ran the ~/.junie registration)",
		GroundingRun: "On macOS, run one JetBrains Air task with a shell call carrying the deny marker; screenshot the result, and list ~/.junie/sessions plus any ~/Library/Application Support/JetBrains/Air* directory (names only) for a host marker.",
	},

	// --- kiro-cli
	{
		ID: "kiro-ide", Label: "Kiro IDE", Kind: models.SurfaceIDE, Host: "kiro", Tool: "kiro-cli", OS: "W M L",
		Capture: covered("Its sessions are read and stamped ide/kiro."),
		// FU-153: the earlier "ignores ~/.kiro/hooks" (LC15, MAC-5 batch 1)
		// was an untrusted workspace. Kiro IDE 1.4.51 runs ~/.kiro/hooks/*.json
		// only in a trusted workspace, decided at window load (kiro.log
		// hooks.v2.executionDisabledUntrustedWorkspace).
		Hooks: probe("LC15", "Kiro IDE 1.4.51 runs hook files in ~/.kiro/hooks and honoured a probe hook's deny (macOS round 4, Windows 2026-10-29), but only in a trusted workspace and only from window load; it ignores the Kiro CLI's agent hooks, and whether it runs Observer's own ~/.kiro/hooks file is not live-run yet."),
		Route: vendorNone("", "kiro-cli is native_exempt."),
		MCP:   notCovered("No Observer MCP writer for kiro-cli."),
		Grounding: "live: 2026-10-26 LC15 (Windows) and " + macRound1027 + " batch 1 (untrusted workspace, no hook); " +
			"round 4 rows 11 and 25 (macOS, trusted workspace, blocked) and the Windows rerun 2026-10-29 (trusted C:\\lc\\proj\\kiro-trusted after Developer: Reload Window, the ~\\.kiro\\hooks probe hook blocked)",
		GroundingRun: "On Kiro IDE 1.4.51 or later with Observer's kiro-cli hooks registered (observer init), open a folder, trust it, run Developer: Reload Window, and run one agent shell call with the deny marker; screenshot the result and copy the hooks lines of ~/.kiro/logs/<launch>/kiro.log.",
		DoctorHint:   "Kiro IDE runs ~/.kiro/hooks only in a trusted workspace and decides it when the window loads: trust the folder, then run Developer: Reload Window",
	},

	// --- kilo-code-cli
	{
		ID: "kilo-cli", Label: "Kilo CLI custom provider route", Kind: models.SurfaceCLI, Tool: "kilo-code-cli", OS: "W M L",
		Capture:      covered("kilo.db is read by the adapter."),
		Hooks:        covered("The plugin shim is auto-registered and live-tested."),
		Route:        probe("LC24", "Kilo documents provider.<id>.options.baseURL in kilo.jsonc; no writer, and no routed turn seen (CLI-9)."),
		MCP:          notCovered("No Observer MCP writer for kilo-code-cli."),
		Grounding:    "doc: https://raw.githubusercontent.com/Kilo-Org/kilocode/main/packages/kilo-docs/pages/ai-providers/openai-compatible.md (re-fetched 2026-10-25)",
		FU57:         []int{8},
		GroundingRun: "Add a custom OpenAI-compatible provider to ~/.config/kilo/kilo.jsonc with options.baseURL at the Observer proxy (/v1), select its model, run one turn and record whether an api_turns row lands.",
	},
	{
		ID: "kilo-vscode-7", Label: "Kilo Code 7.x for VS Code", Kind: models.SurfaceIDE, Host: "vscode", Tool: "kilo-code-cli", OS: "W M L",
		Capture:      probe("LC16", "It embeds the Kilo runtime and shares kilo.jsonc; whether its sessions land in kilo.db is grounded statically only (2026-09-04)."),
		Hooks:        probe("LC16", "Whether it loads the global plugin shim from ~/.config/kilo is LC16."),
		Route:        probe("LC24", "The same kilo.jsonc custom provider would reach it."),
		MCP:          notCovered("No Observer MCP writer for kilo-code-cli."),
		Grounding:    "doc: Kilo-Org/kilocode packages/kilo-docs/pages/getting-started/settings/index.md (\"All clients, CLI, VS Code, and JetBrains, read the same files\"; re-fetched 2026-10-25); gap review IDE-9",
		GroundingRun: "Covered by LC16: install Kilo Code 7.x in VS Code with Observer's plugin shim in ~/.config/kilo/plugins, run one task with a tool call, record whether the shim fired, and list ~/.local/share/kilo for the session in kilo.db.",
	},
	{
		ID: "kilo-jetbrains-7", Label: "Kilo Code for JetBrains v7", Kind: models.SurfaceIDE, Host: "jetbrains", Tool: "kilo-code-cli", OS: "W M L",
		Detect:       []string{"ai.kilocode.jetbrains"},
		Capture:      probe("LC16", "Native Swing UI that downloads the pinned Kilo CLI at connect time; its store should be kilo.db, not live-checked."),
		Hooks:        probe("LC16", "Whether the downloaded CLI loads the global plugin shim is not grounded."),
		Route:        probe("LC24", "It shares kilo.jsonc, so the custom provider route would reach it."),
		MCP:          notCovered("No Observer MCP writer for kilo-code-cli."),
		Grounding:    "doc: https://raw.githubusercontent.com/Kilo-Org/kilocode/main/packages/kilo-jetbrains/src/main/resources/META-INF/plugin.xml and code-with-ai/platforms/jetbrains.md (re-fetched 2026-10-25); " + inv1025 + "section 2.4 (C4)",
		FU57:         []int{7},
		GroundingRun: "Covered by LC16 on JetBrains too: install ai.kilocode.jetbrains 7.1+ in IntelliJ IDEA, run one task with a tool call, record whether the shim fired, and list the plugin's downloaded CLI directory and ~/.local/share/kilo.",
	},
	{
		ID: "kilo-zed-extension", Label: "Kilo Zed extension", Kind: models.SurfaceIDE, Host: "zed", Tool: "kilo-code-cli", OS: "W M L",
		Detect:       []string{"Zed extension kilo (agent server key opencode)"},
		Capture:      probe("LCR-65", "It downloads Kilo's own opencode-<os> archive; whether its sessions land in kilo.db is not grounded."),
		Hooks:        probe("LCR-65", "Not grounded."),
		Route:        notCovered("Zed agent_servers env could carry it; no writer (D8, LC27)."),
		MCP:          probe("LC27", "Zed context_servers may be forwarded; Observer's Zed MCP writer (mcpregister target zed) is built and switched off until LC27."),
		Grounding:    "doc: https://raw.githubusercontent.com/Kilo-Org/kilocode/main/packages/extensions/zed/extension.toml (7.8.17, agent server key opencode; re-fetched 2026-10-25); " + inv1025 + "X13",
		FU57:         []int{9},
		GroundingRun: "In Zed, install the kilo extension, run one Kilo task, and list Zed's data dir (external_agents/, extensions/work/kilo) and ~/.local/share/kilo and ~/.local/share/opencode (names only) to see which store it wrote.",
	},

	// --- kimchi
	{
		ID: "kimchi-vscode", Label: "Kimchi for VS Code", Kind: models.SurfaceIDE, Host: "vscode", Tool: "kimchi", OS: "W M L",
		Detect:       []string{"Kimchidev.kimchi-vscode (unconfirmed)"},
		Capture:      probe("LCR-70", "It spawns the CLI; whether its sessions reach the harness store the adapter reads is not grounded."),
		Hooks:        probe("LCR-70", "Whether the spawned CLI runs the ~/.config/kimchi/harness/hooks/bash pre-gate is not grounded."),
		Route:        probe("LCR-70", "Its own ~/.config/kimchi/vscode/config.json kimchi.env can set provider env and may override any route."),
		MCP:          probe("LCR-70", "Kimchi's harness mcp.json (mcpServers); whether the extension reads it is not grounded; Observer's MCP writer (mcpregister target kimchi) is built and switched off until LCR-70."),
		Grounding:    "doc: docs.kimchi.dev (via web search 2026-10-25); audit: docs/audits/surface-settings-location-matrix-2026-10-25.md Part 1",
		FU57:         []int{20},
		GroundingRun: "Install the Kimchi VS Code extension and give its exact id from the Extensions view; run one task with a bash call and Observer's Kimchi hook in place; record whether it fired and give the keys (never values) in ~/.config/kimchi/vscode/config.json.",
	},

	// --- kimi-code
	{
		ID: "kimi-acp", Label: "Kimi via ACP (registry kimi, the archived Python CLI)", Kind: models.SurfaceIDE, Tool: "kimi-code", OS: "W M L",
		Detect:       []string{"acp registry kimi"},
		Capture:      notCovered("The registry kimi entry downloads the archived MoonshotAI/kimi-cli, whose ~/.kimi store no adapter reads; Kimi Code (~/.kimi-code) is a different product (FU-58 X1)."),
		Hooks:        vendorNone("", "The archived CLI is not the product Observer's Kimi Code hook writer targets."),
		Route:        notCovered("No route for the archived CLI."),
		MCP:          notCovered("No writer."),
		Grounding:    "doc: https://raw.githubusercontent.com/agentclientprotocol/registry/main/kimi/agent.json and the MoonshotAI/kimi-cli README (re-fetched 2026-10-25); " + inv1025 + "X1",
		FU57:         []int{10},
		GroundingRun: "In IntelliJ IDEA, install kimi from the ACP registry, run one task, and list ~/.kimi and ~/.kimi-code (names only) to confirm which one it wrote.",
	},

	// --- mistral-code
	{
		ID: "mistral-vibe-vscode", Label: "Mistral Vibe for VS Code", Kind: models.SurfaceIDE, Host: "vscode", Tool: "mistral-code", OS: "W M L",
		Detect:       []string{"mistralai.mistral-vibe-code"},
		Capture:      probe("LCR-79", "It bundles its own vibe-acp and shares ~/.vibe; whether its sessions land where the adapter reads is not grounded."),
		Hooks:        probe("LCR-79", "Whether the bundled vibe-acp runs ~/.vibe/hooks.toml is not grounded."),
		Route:        probe("LCR-79", "Not grounded."),
		MCP:          notCovered("No Observer MCP writer for mistral-code."),
		Grounding:    "doc: Mistral install page (via web search 2026-10-25); audit: docs/audits/surface-settings-location-matrix-2026-10-25.md Part 2",
		GroundingRun: "Install mistralai.mistral-vibe-code with Observer's vibe hook in ~/.vibe/hooks.toml; run one task with a tool call; record whether the hook fired and list ~/.vibe/logs/session (names only).",
	},
	{
		ID: "mistral-code-enterprise", Label: "Mistral Code Enterprise (VS Code, JetBrains; deprecated)", Kind: models.SurfaceIDE, Tool: "mistral-code", OS: "W M L",
		Capture:      covered("Its ~/.mistralcode sessions are read by the adapter, but JetBrains sessions are labelled ide/vscode (internal/adapter/mistralcode/ide.go)."),
		Hooks:        probe("LCR-79", "Not grounded."),
		Route:        probe("LCR-79", "Not grounded."),
		MCP:          notCovered("No Observer MCP writer for mistral-code."),
		Grounding:    "doc: Mistral migration guide to Vibe (via web search 2026-10-25); " + inv1025 + "X6",
		FU57:         []int{28},
		GroundingRun: "Only if the operator still has it installed: run one Mistral Code Enterprise task in IntelliJ IDEA and give the session's meta fields that name the IDE (to fix the ide/vscode label).",
	},

	// --- muse
	{
		ID: "muse-community", Label: "Muse community surfaces (Muse Code GUI, muse-code-acp, Helicon)", Kind: models.SurfaceIDE, Tool: "muse", OS: "unverified", Community: true,
		Capture:      probe("LCR-81", "They drive the real muse CLI; whether their sessions land in the store the adapter reads, and with what marker, is not grounded."),
		Hooks:        probe("LCR-81", "Whether a GUI-driven muse runs ~/.config/muse/settings.json hooks is not grounded."),
		Route:        probe("LC35", "Whether muse has a --base-url route at all is LC35."),
		MCP:          notCovered("No Observer MCP writer for muse."),
		Grounding:    "doc: author and directory pages (via web search 2026-10-25); " + inv1025 + "X9",
		FU57:         []int{27},
		GroundingRun: "Only on a host where muse runs: install the Muse Code GUI VS Code extension, run one task with a shell call and Observer's muse hook in place; record whether it fired and list the muse session directory for the new session.",
	},

	// --- openclaw
	{
		ID: "openclaw-control-ui", Label: "OpenClaw Control UI and openclaw acp", Kind: models.SurfaceWeb, Tool: "openclaw", OS: "W M L",
		Capture:      probe("LCR-83", "Both talk to the same Gateway, whose agent store the adapter reads; what marks a Control UI or ACP session is not grounded."),
		Hooks:        probe("LCR-83", "The openclaw plugin shim has no grounded install location."),
		Route:        probe("LCR-83", "Only the Gateway's openclaw.json provider baseUrl routes; an IDE's env cannot (openclaw acp is a thin client)."),
		MCP:          notCovered("No Observer MCP writer for openclaw."),
		Grounding:    "audit: docs/audits/vendor-surface-inventory-2026-09-03.md and the 2026-10-25 matrix Part 2 (carried); " + inv1025 + "section 3.7",
		GroundingRun: "Run one task from the OpenClaw Control UI (:18789) and one through `openclaw acp` in Zed; list ~/.openclaw/agents/<id> (names only) for both sessions and give any field that tells them apart.",
	},

	// --- opencode
	{
		ID: "opencode-desktop-2", Label: "OpenCode Desktop 2.2", Kind: models.SurfaceDesktop, Tool: "opencode", OS: "W M L",
		Capture:      probe("MAC-6", "It is built to share opencode.db, which the adapter reads, but no live run has seen an OpenCode Desktop 2.2 session ingested from it (the MAC-5 runs checked the plugin, not capture)."),
		Hooks:        probe("MAC-5", "OpenCode 2.2 rejected Observer's v1-only plugin shim (\"must export a default definition with an id and an effect or setup function\", tracker FU-121); the shim now exports the v2 setup form beside v1, not yet live-checked on 2.2."),
		Route:        probe("LC42", "The desktop's honouring of the launcher's OPENAI_BASE_URL is not live-verified."),
		MCP:          covered("It reads the same opencode.json MCP that Observer's writer covers."),
		Grounding:    macRound1027 + " batch 1 (OpenCode Desktop 2.2.0 log)",
		GroundingRun: "Rerun MAC-5's OpenCode Desktop check with the v2 plugin form (FU-121): one tool call carrying the deny marker; record the block and the plugin log line. On the MAC-6 run, with `observer start` running, run one Desktop task and confirm Observer ingested that session from opencode.db (give the session id and its surface stamp).",
	},
	{
		ID: "opencode-v2-acp", Label: "OpenCode V2 via ACP (opencode-v2)", Kind: models.SurfaceIDE, Host: "jetbrains", Tool: "opencode", OS: "W M L",
		Detect:       []string{"acp registry opencode-v2"},
		Capture:      probe("LCR-63", "A separate 2.x registry entry; whether its sessions are stamped like opencode 1.x is not grounded (jetbrainshost leaves it unmapped)."),
		Hooks:        probe("LCR-63", "The 2.x line rejected Observer's v1-only plugin shim (FU-121); the shim now exports the v2 setup form, but whether an ACP-spawned 2.x loads the global plugin is not grounded."),
		Route:        probe("LC28", "The launcher env route never reaches a host-spawned OpenCode."),
		MCP:          probe("LCR-63", "Whether 2.x reads the same opencode.json MCP is not grounded."),
		Grounding:    "doc: https://raw.githubusercontent.com/agentclientprotocol/registry/main/opencode-v2/agent.json (2.1.4, re-fetched 2026-10-25); " + inv1025 + "X3",
		FU57:         []int{12},
		GroundingRun: "Covered by the JetBrains ACP pointer runs (LCR-63): install opencode-v2 from the ACP registry, run one task, and give the .agentsession pointer beside the opencode.db session id.",
	},

	// --- poolside
	{
		ID: "poolside-vscode", Label: "Poolside Assistant for VS Code", Kind: models.SurfaceIDE, Host: "vscode", Tool: "poolside", OS: "W M L",
		Detect:       []string{"poolside-ai.poolside-assistant (unconfirmed)"},
		Capture:      probe("LCR-74", "It is built on ACP and runs pool by default; whether it writes poolside/trajectories is not grounded."),
		Hooks:        probe("LCR-74", "Whether a VS Code-run pool runs ~/.config/poolside/settings.yaml hooks is not grounded."),
		Route:        probe("LCR-74", "It has a Poolside URI instance setting; whether pool.api_url reaches it is not grounded (the route writer waits on LCR-1)."),
		MCP:          notCovered("No Observer MCP writer for poolside."),
		Grounding:    "doc: poolside.ai blog and docs index (via web search 2026-10-25); " + inv1025 + "X16",
		FU57:         []int{23},
		GroundingRun: "Install Poolside Assistant for VS Code (give its exact extension id); with Observer's poolside hooks registered run one task with a tool call; record whether the hook fired and list the poolside trajectories directory (names only).",
	},
	{
		ID: "poolside-visual-studio", Label: "Poolside Assistant for Visual Studio", Kind: models.SurfaceIDE, Host: "visual-studio", Tool: "poolside", OS: "W",
		Capture:      probe("LCR-74", "Store not grounded."),
		Hooks:        probe("LCR-74", "Not grounded."),
		Route:        probe("LCR-74", "Instance URI setting; store not grounded."),
		MCP:          notCovered("No Observer MCP writer for poolside."),
		Grounding:    "doc: poolside.ai (via web search 2026-10-25); " + inv1025 + "X16",
		FU57:         []int{23},
		GroundingRun: "Same run on Visual Studio: install Poolside Assistant for Visual Studio, run one task, and list %LOCALAPPDATA%\\poolside and the Visual Studio extension directory (names only).",
	},
	{
		ID: "poolside-desktop", Label: "Poolside Desktop Assistant", Kind: models.SurfaceDesktop, Tool: "poolside", OS: "M",
		Capture:      probe("LCR-74", "ACP-based, runs pool by default and can run Claude Code, Codex or Gemini; paths not grounded."),
		Hooks:        probe("LCR-74", "Not grounded."),
		Route:        probe("LCR-74", "Not grounded."),
		MCP:          notCovered("No Observer MCP writer for poolside."),
		Grounding:    "doc: poolside.ai Desktop Assistant announcement 2026-07-28 (via web search 2026-10-25); " + inv1025 + "X16",
		FU57:         []int{23},
		GroundingRun: "On macOS, install the Poolside Desktop Assistant, run one pool task and one Claude Code task, and list ~/Library/Application Support/poolside* and ~/.config/poolside (names only); give the .app bundle name.",
	},

	// --- qoder
	{
		ID: "qoder-jetbrains", Label: "Qoder JetBrains plugin", Kind: models.SurfaceIDE, Host: "jetbrains", Tool: "qoder", OS: "W M L",
		Detect:       []string{"JetBrains plugin 28926"},
		Capture:      probe("LCR-82", "Store not grounded (auth failed in the 2026-09-06 attempt)."),
		Hooks:        probe("LCR-82", "Whether it runs ~/.qoder/settings.json hooks is not grounded."),
		Route:        vendorNone("", "qodercli is native_exempt."),
		MCP:          probe("LCR-82", "~/.qoder/settings.json mcpServers; whether the plugin reads it is not grounded; Observer's MCP writer (mcpregister target qoder) is built and switched off until LCR-82."),
		Grounding:    "audit: docs/audits/surface-settings-location-matrix-2026-10-25.md Part 2; " + inv1025 + "section 3.5",
		GroundingRun: "Install the Qoder JetBrains plugin (28926) in IntelliJ IDEA, sign in, run one task with a tool call and Observer's qoder hooks in place; record whether the hook fired and list ~/.qoder/projects (names only).",
	},

	// --- qwen-code
	{
		ID: "qwen-companion", Label: "Qwen Code Companion for VS Code", Kind: models.SurfaceIDE, Host: "vscode", Tool: "qwen-code", OS: "W M L",
		Detect:       []string{"qwenlm.qwen-code-vscode-ide-companion"},
		Capture:      covered("It runs the CLI, whose store the adapter reads."),
		Hooks:        probe("LC33", "It runs the CLI, which reads Observer's ~/.qwen/settings.json hooks, but no live run has seen a companion-started session run them."),
		Route:        probe("LC33", "Its qwen-code.provider / apiKey settings \"sync Coding Plan settings\" and may rewrite ~/.qwen/settings.json model.baseUrl, undoing Observer's route."),
		MCP:          probe("LC33", "~/.qwen/settings.json mcpServers, the file the companion syncs; Observer's MCP writer (mcpregister target qwen-code) is built and switched off until LC33."),
		Grounding:    "doc: QwenLM/qwen-code packages/vscode-ide-companion/package.json 0.26.1 (re-fetched 2026-10-25); " + inv1025 + "section 3.7",
		FU57:         []int{21},
		GroundingRun: "Covered by LC33: with Observer's route in ~/.qwen/settings.json, set qwen-code.provider to coding-plan in the companion, reload VS Code, and diff the model.baseUrl key (key only). In the same LC33 session, with Observer's qwen-code hooks in place, run one tool call carrying the deny marker from the companion and record whether it is blocked.",
	},

	// --- trae (no registry row; D10 ruling: capture only)
	{
		ID: "trae", Label: "Trae (built-in agent)", Kind: models.SurfaceIDE, Host: "trae", NewTool: "trae", OS: "W M",
		Capture:   notCovered("Grounded on macOS: prompt history in workspaceStorage/<id>/state.vscdb key icube-ai-agent-storage-input-history and tool calls in logs/<run>/Modular/ai-agent_*_stdout.log; the plan is server-side. No reader (D10: capture only)."),
		Hooks:     vendorNone("MAC-5", "Trae has no hook system Observer could write."),
		Route:     notCovered("Not grounded; out of D10 scope."),
		MCP:       notCovered("Out of D10 scope."),
		Grounding: macRound1027 + " batch 1 (Trae, tracker FU-125)",
	},

	// --- vtcode
	{
		ID: "vtcode-companion", Label: "VT Code Companion (Codex plugin) and VS Code extension", Kind: models.SurfaceSDK, Tool: "vtcode", OS: "unverified",
		Capture:      probe("LCR-88", "The current docs describe a Codex plugin over `vtcode webmcp stdio --companion`; the VS Code extension manifest was not found."),
		Hooks:        vendorNone("", "VT Code hooks run in the TUI only."),
		Route:        probe("LCR-88", "Not grounded."),
		MCP:          probe("LCR-88", "The companion is itself an MCP connection; not grounded."),
		Grounding:    "doc: vinhnx/vtcode docs/user-guide/vtcode-companion.md (re-fetched 2026-10-25); " + inv1025 + "X12",
		GroundingRun: "If the operator uses it: enable the VT Code Companion in Codex, run one task, and list ~/.vtcode (names only); search the VS Code Marketplace for nguyenxuanvinh.vtcode-companion and give its version if it exists.",
	},

	// --- hermes, pi and open-interpreter ACP
	{
		ID: "acp-thin-clients", Label: "hermes acp, pi-acp and interpreter acp", Kind: models.SurfaceIDE, Tool: "hermes", OS: "W M L",
		Capture:      probe("LCR-86", "Each writes its CLI's store; host stamps are absent (pi-acp writes no JetBrains pointer)."),
		Hooks:        probe("LCR-86", "Not grounded for ACP runs."),
		Route:        probe("LCR-86", "hermes routes through its config.yaml provider, which an ACP run reads; pi-acp's defaultProvider decides its route; interpreter acp is a third-party claim."),
		MCP:          probe("LCR-86", "Not grounded."),
		Grounding:    "audit: docs/audits/surface-settings-location-matrix-2026-10-25.md Parts 1 and 2; " + inv1025 + "sections 3.2 and 3.7",
		GroundingRun: "In Zed, run one task each through hermes acp and pi-acp (and interpreter acp if it exists); list ~/.hermes/sessions and ~/.pi/agent/sessions (names only) and record whether an api_turns row landed for hermes.",
	},

	// --- ACP hosts (FU-57 rows 14, 15, 29)
	{
		ID: "zed-acp-host", Label: "Zed external agents (ACP host)", Kind: models.SurfaceIDE, Host: "zed", Tool: "zed", HostRow: true, OS: "W M L",
		Capture:      probe("LC44", "Hosted agents write their own stores, but no Zed enricher stamps ide/zed on them: where the current Zed build keeps agent threads is unknown (FU-95)."),
		Hooks:        vendorNone("", "Zed itself has no hook system; hosted agents run their own (per agent rows)."),
		Route:        probe("LC27", "agent_servers.<id>.env in Zed settings.json comes last in Zed's env order and could carry the route; Observer's per-agent writer (proxyroute RegisterZedAgent, targets zed-acp/<agent>) is built and switched off until LC27 (D8)."),
		MCP:          probe("LC27", "context_servers \"may be forwarded\" to each agent; Observer's writer (mcpregister target zed) is built and switched off until LC27 (D8)."),
		Grounding:    "doc: zed-industries/zed crates/paths/src/paths.rs and crates/project/src/agent_server_store.rs (gap review S-1); live: 2026-10-26 LC44 (no Zed file changed after an agent chat)",
		FU57:         []int{14},
		GroundingRun: "On Windows, run one Zed native agent chat and one registry agent chat; list %LOCALAPPDATA%\\Zed and %APPDATA%\\Zed recursively with modification times (names only) to find where the threads landed (FU-95), and give Zed's version.",
	},
	{
		ID: "jetbrains-acp-host", Label: "JetBrains AI Assistant ACP (acp.json)", Kind: models.SurfaceIDE, Host: "jetbrains", HostRow: true, OS: "W M L",
		Capture:      covered("The surface enricher stamps ide/jetbrains-<product> for the agents whose pointer sid round trip is proven (jetbrainshost acpAgents)."),
		Hooks:        vendorNone("", "The host has no hooks; hosted agents run their own or none (Claude Agent and Junie run none, MAC-5)."),
		Route:        probe("LC28", "~/.jetbrains/acp.json agent_servers.<name>.env could carry the route, but JetBrains documents agent_servers keys only as custom-agent display names: the key a registry agent's env would sit under is not grounded, so the D8 writer is not built until LC28 grounds it."),
		MCP:          probe("LC28", "acp.json default_mcp_settings; not written."),
		Grounding:    "doc: https://www.jetbrains.com/help/ai-assistant/acp.html (gap review S-1); repo: internal/platform/jetbrainshost",
		FU57:         []int{15},
		GroundingRun: "Covered by LC28: add a test env var under acp.json agent_servers for one registry agent and one custom agent, run one task each, and record which saw it.",
	},
	{
		ID: "neovim-acp-host", Label: "Neovim ACP hosts (CodeCompanion.nvim, avante.nvim)", Kind: models.SurfaceIDE, Host: "neovim", HostRow: true, OS: "W M L", Community: true,
		Capture:      probe("LCR-80", "Hosted agents write their own stores; nothing stamps the Neovim host."),
		Hooks:        vendorNone("", "No host hook system; per agent."),
		Route:        notCovered("Env-only routes reach an agent only if the Lua adapter passes the env; nothing writes adapters.acp.* env."),
		MCP:          notCovered("No writer."),
		Grounding:    "audit: docs/audits/surface-settings-location-matrix-2026-10-25.md Part 2; " + inv1025 + "section 3.9",
		FU57:         []int{29},
		GroundingRun: "Optional: run one CodeCompanion ACP task with Claude Agent and record whether the session reached ~/.claude/projects and whether ANTHROPIC_BASE_URL from the shell reached it.",
	},
	{
		ID: "emacs-acp-host", Label: "Emacs agent-shell (ACP host)", Kind: models.SurfaceIDE, Host: "emacs", HostRow: true, OS: "W M L", Community: true,
		Capture:      probe("LCR-80", "Hosted agents write their own stores; nothing stamps the Emacs host."),
		Hooks:        vendorNone("", "No host hook system; per agent."),
		Route:        notCovered("agent-shell starts agents with a minimal env unless :inherit-env t is set, so env-only routes never reach them."),
		MCP:          notCovered("No writer."),
		Grounding:    "audit: docs/audits/surface-settings-location-matrix-2026-10-25.md Part 2; gap review S-1",
		FU57:         []int{29},
		GroundingRun: "Optional: run one agent-shell task with Claude Agent, with and without :inherit-env t, and record whether ANTHROPIC_BASE_URL reached it.",
	},
}

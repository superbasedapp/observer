package integration

import (
	"regexp"
	"sort"
	"strings"
)

// LiveGate is the live-check gate of a writer that is built and tested but
// switched off until a named live check passes (surface-gap decision
// DEC-12). Its value is the live check's id in the surface-gap pending
// tracker (LC11, LC37, ...); the zero value means the writer is not gated.
//
// A gated writer is refused by every caller that would run it unattended
// or by default: `observer start` auto-registration and route maintenance,
// `observer init` (batch and interactive) and the dashboard. The writer
// itself refuses too, so a caller that forgets the gate still writes
// nothing. `observer doctor` names every gated writer with the same
// sentence (Text). Switching a writer on is one commit that clears the
// field once its live check row is done.
type LiveGate string

// liveCheckID is the tracker's live-check id shape: LC<n> (LC11), LC<n> with
// one lowercase letter (LC26b), or the lettered series LCR-<n>. It is the
// ONE pattern for a live-check id in this package: a LiveGate must match it,
// and a coding-surface cell's live check is one of these or a completed
// tracker round (codingsurface.go surfaceCheckRef).
var liveCheckID = regexp.MustCompile(`^(LC[1-9][0-9]*[a-z]?|LCR-[1-9][0-9]*)$`)

// IsLiveCheckID reports whether s has the tracker's live-check id shape.
func IsLiveCheckID(s string) bool { return liveCheckID.MatchString(s) }

// Waiting reports whether the writer still waits on its live check.
func (g LiveGate) Waiting() bool { return strings.TrimSpace(string(g)) != "" }

// Text is the one doctor and refusal sentence for a gated writer:
// "built, waiting on live check LC11", or, once the check ran and found the
// host does not run the hook (Finding), "built, not enforceable: live check
// LCR-91 found ...". Empty when the writer is not gated.
func (g LiveGate) Text() string {
	if !g.Waiting() {
		return ""
	}
	id := strings.TrimSpace(string(g))
	if f := g.Finding(); f != "" {
		return "built, not enforceable: live check " + id + " found " + f
	}
	return "built, waiting on live check " + id
}

// liveCheckFindings are the live checks that RAN and found the gated
// writer cannot do its job on the vendor's host, with what they found. A
// writer gated on one of them stays off for that finding, not for a run
// still owed: its gate row stays, and Text says so. Closed table, one row
// per check; a later vendor build that changes the answer is a new live
// check, not an edit here.
var liveCheckFindings = map[string]string{
	// FU-195, MAC-6 2026-10-30 (docs/handovers/surface-gap-mac6-run-2026-10-30.md):
	// Xcode kept Observer's hooks in its Gemini home's settings.json and
	// ran BeforeAgent, but no BeforeTool for run_shell_command.
	"LCR-91": "that Xcode 26.6's Gemini runs the BeforeAgent hook but not BeforeTool, so a tool gate there cannot block a shell call (MAC-6, 2026-10-30)",
}

// Finding returns what g's live check found when it ran and showed the
// writer cannot work on the host; "" while the check is still owed (or g
// joins several checks).
func (g LiveGate) Finding() string {
	return liveCheckFindings[strings.TrimSpace(string(g))]
}

// RouteLiveGate returns the live-check gate of tool's config-lane route
// writer (the ProxyProbe binding, else the verified Proxy route). A
// "-windows" cross-OS target answers for its base row. Zero when the tool
// has no gated route writer.
func RouteLiveGate(tool string) LiveGate {
	c, ok := For(strings.TrimSuffix(tool, "-windows"))
	if !ok {
		return ""
	}
	for _, r := range []*ProxyRoute{c.ProxyProbe, c.Proxy} {
		if r != nil && r.LiveGate.Waiting() {
			return r.LiveGate
		}
	}
	return ""
}

// DefaultProviderLiveGate returns the live-check gate of tool's
// default-provider writer (ProxyRoute.PersistedDefault on its verified
// Proxy route, else its ProxyProbe binding). Zero when the tool has no gated
// default-provider writer.
func DefaultProviderLiveGate(tool string) LiveGate {
	c, ok := For(strings.TrimSuffix(tool, "-windows"))
	if !ok {
		return ""
	}
	for _, r := range []*ProxyRoute{c.Proxy, c.ProxyProbe} {
		if r != nil && r.PersistedDefault != nil && r.PersistedDefault.LiveGate.Waiting() {
			return r.PersistedDefault.LiveGate
		}
	}
	return ""
}

// HookLiveGate returns the live-check gate of tool's hook writer. A
// "-windows" cross-OS target answers for its base row. Zero when the hook
// writer is not gated.
func HookLiveGate(tool string) LiveGate {
	c, ok := For(strings.TrimSuffix(tool, "-windows"))
	if !ok {
		return ""
	}
	return c.Hook.LiveGate
}

// GatedWriter is one writer that waits on a live check, for the doctor.
type GatedWriter struct {
	// Tool is the registry row.
	Tool string
	// Kind is "route", "default_provider" or "hooks" for a registry row's
	// writer, or a rowless writer's kind (WriterKindRelay,
	// WriterKindHookBridge).
	Kind string
	// Gate is the live check the writer waits on.
	Gate LiveGate
	// Note names the writer and its file (the route's Note, or the hook
	// mechanism).
	Note string
}

// LiveGatedWriters lists every gated writer in the registry, sorted by tool
// then kind.
func LiveGatedWriters() []GatedWriter {
	var out []GatedWriter
	for _, c := range Capabilities() {
		for _, r := range []*ProxyRoute{c.ProxyProbe, c.Proxy} {
			if r != nil && r.LiveGate.Waiting() {
				out = append(out, GatedWriter{Tool: c.Tool, Kind: "route", Gate: r.LiveGate, Note: r.Note})
				break
			}
		}
		for _, r := range []*ProxyRoute{c.Proxy, c.ProxyProbe} {
			if r != nil && r.PersistedDefault != nil && r.PersistedDefault.LiveGate.Waiting() {
				out = append(out, GatedWriter{Tool: c.Tool, Kind: "default_provider", Gate: r.PersistedDefault.LiveGate, Note: r.PersistedDefault.Note})
				break
			}
		}
		if c.Hook.LiveGate.Waiting() {
			out = append(out, GatedWriter{Tool: c.Tool, Kind: "hooks", Gate: c.Hook.LiveGate, Note: string(c.Hook.Mechanism)})
		}
	}
	for _, w := range rowlessGatedWriters {
		if w.Gate.Waiting() {
			out = append(out, w)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Tool != out[j].Tool {
			return out[i].Tool < out[j].Tool
		}
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Gate < out[j].Gate
	})
	return out
}

// The rowless writer kinds: writers built and switched off behind live
// checks that hang off no registry row's ProxyRoute or HookSpec.
const (
	// WriterKindRelay is the fail-open Windows route relay and the Windows
	// Claude Code route target that points at it (surface-gap CC-9, D12;
	// internal/winrelay).
	WriterKindRelay = "relay"
	// WriterKindHookBridge is the fail-closed Windows hook bridge
	// (`observer hook-bridge`) a cross-OS hook registrar writes for the
	// gated events of an enforcing managed node (surface-gap AW-37).
	WriterKindHookBridge = "hook_bridge"
	// WriterKindHostHooks is a hook writer into a host app's own isolated
	// agent home, beside the tool's default home (surface-gap FU-145 and
	// FU-160: the homes Xcode gives its bundled Claude Agent, Codex and
	// Gemini CLI; internal/hook register_xcode.go). Its target is
	// "<tool>-xcode". LCR-89 and LCR-90 passed on Xcode 26.6 on 2026-10-28
	// (Mac round 5b) and their rows were deleted, which switched the Claude
	// and Codex targets on; the Gemini target stays off on LCR-91's finding
	// (liveCheckFindings: no BeforeTool, FU-195).
	WriterKindHostHooks = "host_hooks"
	// WriterKindHostMCP is an MCP writer into a host application's own
	// config file, one the locate table does not cover (surface-gap S-1,
	// S-3, S-4, S-5; internal/mcpregister register_hosts.go).
	WriterKindHostMCP = "host_mcp"
	// WriterKindHostRoute is a per-agent route writer into an ACP host's
	// own settings (surface-gap S-1, D8; internal/proxyroute acphost.go).
	WriterKindHostRoute = "host_route"
)

// rowlessGatedWriters lists the gated writers with no registry field of
// their own, ONE ROW PER LIVE CHECK: a writer that waits on several checks
// has a row for each and stays off while any row is here. Switching a check
// off for a writer is deleting its row. Every Gate must be a live-check id
// (TestLiveGatedRowsAreNotVerified).
var rowlessGatedWriters = []GatedWriter{
	{Tool: "claude-code", Kind: WriterKindRelay, Gate: "LC6", Note: "fail-open Windows route relay (`observer relay serve`) and the Windows route target at it"},
	{Tool: "claude-code", Kind: WriterKindRelay, Gate: "LC14", Note: "fail-open Windows route relay (`observer relay serve`) and the Windows route target at it"},
	{Tool: "claude-code", Kind: WriterKindHookBridge, Gate: "LC6", Note: "fail-closed Windows hook bridge (`observer hook-bridge`) in the Windows settings.json; switch-on also needs a version stamp of the Windows observer.exe"},
	{Tool: "codex", Kind: WriterKindHookBridge, Gate: "LC6", Note: "fail-closed Windows hook bridge (`observer hook-bridge`) in the Windows hooks.json; switch-on also needs a version stamp of the Windows observer.exe"},
	{Tool: "zed", Kind: WriterKindHostMCP, Gate: "LC27", Note: "Zed MCP server (target zed): context_servers.superbased-observer in Zed's settings.json, offered to Zed's own agent and forwarded to ACP agents"},
	{Tool: "zed", Kind: WriterKindHostRoute, Gate: "LC27", Note: "Zed per-agent route (targets zed-acp/<agent>): agent_servers.<agent>.env.<route variable> in Zed's settings.json, for a registry ACP agent whose tool has an env route"},
	{Tool: "copilot", Kind: WriterKindHostMCP, Gate: "LCR-68", Note: "Visual Studio MCP server (target visual-studio): servers.superbased-observer in %USERPROFILE%\\.mcp.json"},
	{Tool: "gemini-code-assist", Kind: WriterKindHostMCP, Gate: "LCR-64", Note: "Gemini Code Assist for JetBrains MCP server (target gemini-code-assist-jetbrains): mcpServers.superbased-observer in each JetBrains IDE configuration directory's mcp.json"},
	{Tool: "aider-desk", Kind: WriterKindHostMCP, Gate: "LCR-60", Note: "AiderDesk MCP server (target aider-desk): mcpServers.superbased-observer in ~/.aider-desk/mcp-servers.json (AIDER_DESK_HOME_DIR)"},
	{Tool: "codebuddy", Kind: WriterKindHostMCP, Gate: "LCR-76", Note: "CodeBuddy MCP server (target codebuddy): mcpServers.superbased-observer in ~/.codebuddy/.mcp.json, for the CodeBuddy IDE and plugin"},
	{Tool: "cortex-code", Kind: WriterKindHostMCP, Gate: "LC18", Note: "Cortex Code MCP server (target cortex-code): mcpServers.superbased-observer in its mcp.json, for Cortex Code Desktop and the VS Code extension"},
	{Tool: "dimcode", Kind: WriterKindHostMCP, Gate: "LCR-77", Note: "DimCode MCP server (target dimcode): mcpServers.superbased-observer in its v2 mcp.json, for DimCode Desktop"},
	{Tool: "gemini-cli", Kind: WriterKindHostMCP, Gate: "LCR-64", Note: "Gemini MCP server (target gemini-cli): mcpServers.superbased-observer in ~/.gemini/settings.json, for Gemini Code Assist agent mode and Gemini via ACP"},
	{Tool: "ibm-bob", Kind: WriterKindHostMCP, Gate: "LCR-75", Note: "IBM Bob MCP server (target ibm-bob): mcpServers.superbased-observer in its settings mcp.json, for the Bob IDE"},
	{Tool: "junie", Kind: WriterKindHostMCP, Gate: "LCR-84", Note: "Junie MCP server (target junie): mcpServers.superbased-observer in its mcp.json, for the Junie IDE plugin and JetBrains Air"},
	{Tool: "kimchi", Kind: WriterKindHostMCP, Gate: "LCR-70", Note: "Kimchi MCP server (target kimchi): mcpServers.superbased-observer in its harness mcp.json, for Kimchi for VS Code"},
	{Tool: "qoder", Kind: WriterKindHostMCP, Gate: "LCR-82", Note: "Qoder MCP server (target qoder): mcpServers.superbased-observer in its settings.json, for the Qoder JetBrains plugin"},
	{Tool: "qwen-code", Kind: WriterKindHostMCP, Gate: "LC33", Note: "Qwen Code MCP server (target qwen-code): mcpServers.superbased-observer in ~/.qwen/settings.json, for Qwen Code Companion"},
	// LCR-91 ran (MAC-6) and found the tool gate cannot block there
	// (liveCheckFindings), so this row stays: the writer is off for good on
	// that Xcode build, not waiting.
	{Tool: "gemini-cli", Kind: WriterKindHostHooks, Gate: "LCR-91", Note: "Gemini in Xcode hook writer (target gemini-cli-xcode): Observer's Gemini CLI hooks in the settings.json of Xcode's Gemini home, ~/Library/Developer/Xcode/CodingAssistant/gemini/.gemini, written only where Xcode created that home"},
}

// LiveGates is a writer's live-check gates; it waits while any of them does.
type LiveGates []LiveGate

// Waiting reports whether any gate still waits.
func (gs LiveGates) Waiting() bool {
	for _, g := range gs {
		if g.Waiting() {
			return true
		}
	}
	return false
}

// Text is the shared sentence over every waiting gate: "built, waiting on
// live check LC6 and LC14". Empty when none waits.
func (gs LiveGates) Text() string {
	var ids []string
	for _, g := range gs {
		if g.Waiting() {
			ids = append(ids, strings.TrimSpace(string(g)))
		}
	}
	if len(ids) == 0 {
		return ""
	}
	return LiveGate(strings.Join(ids, " and ")).Text()
}

// RowlessWriterGates returns the waiting gates of the rowless writer kind
// for tool (WriterKindRelay, WriterKindHookBridge), empty when it is on.
func RowlessWriterGates(tool, kind string) LiveGates {
	var out LiveGates
	for _, w := range rowlessGatedWriters {
		if w.Tool == tool && w.Kind == kind && w.Gate.Waiting() {
			out = append(out, w.Gate)
		}
	}
	return out
}

// AutoWiredNow reports whether Observer registers this hook today: the
// mechanism exists, the row is auto-wired, and its writer is not switched
// off behind a live check (DEC-12). Every surface that advertises a hook as
// wired (clientwire's predicates, the dashboard's register actions and setup
// wizard, `observer contract`, the guard-prompt API, the parity docs) asks
// this, never AutoWired alone.
func (h HookSpec) AutoWiredNow() bool {
	return h.Mechanism != HookNone && h.AutoWired && !h.LiveGate.Waiting()
}

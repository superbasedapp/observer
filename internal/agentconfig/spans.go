package agentconfig

import (
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// Observer-owned spans (plan section 2.3, the Lane 0 boundary). A span is
// the part of a vendor file one of Observer's own writers owns: the editor
// renders it read-only with the owner named, offers the owner's verb
// instead of a text edit, and the hygiene pipeline (section 5.2 step 5)
// refuses a raw edit that removes or changes it. That is how the editor
// and the Lane 0 writers never become two writers of one key.
//
// Spans are COMPUTED from the integration registry, never hand-listed per
// tool: which tools carry an Observer writer comes from Capability.Hook
// (Mechanism, AutoWired, Bindings), Capability.MCP (Format, PathHint,
// Implemented, Remote) and Capability.Proxy / ProxyProbe (Kind). What each
// WRITER owns inside its file is the writer tables below, keyed by the
// capability value that selects the writer (a hook mechanism is one
// format writer; an MCP format is one writer; the proxy-route writers are
// per vendor in internal/proxyroute, so that table is keyed by the
// registry row whose route kind writes a file). Each table row cites the
// writer it describes. TestOwnedSpanTablesMatchRegistry pins both
// directions: every table row is reachable from the registry, and every
// registry writer has a table row or a reason.

// SpanMatch says how much of the value at a span's path Observer owns.
type SpanMatch string

const (
	// SpanWholeKey: the value at Path is Observer's (the "observer" MCP
	// entry, env.ANTHROPIC_BASE_URL while the route is on).
	SpanWholeKey SpanMatch = "whole_key"
	// SpanEntries: only the entries the owner's own predicate recognises
	// inside the value at Path (Observer's hook commands inside a hooks
	// block shared with the user's own hooks).
	SpanEntries SpanMatch = "entries"
	// SpanWholeFile: the whole file is Observer's (a dedicated plugin file).
	SpanWholeFile SpanMatch = "whole_file"
)

// Span owners (the Lane 0 writer families).
const (
	SpanOwnerHook         = "hook"
	SpanOwnerMCP          = "mcp"
	SpanOwnerProxyRoute   = "proxyroute"
	SpanOwnerStatusline   = "statusline"
	SpanOwnerRoutingApply = "routingapply"
	SpanOwnerRelay        = "relay"
)

// OwnedSpan is one Observer-owned span in one vendor file.
type OwnedSpan struct {
	Tool string
	// FileID is the Files row the span lives in; Shape is that row's shape
	// (the SettingRow.FileID the catalogue rows use).
	FileID string
	Shape  string
	Path   KeyPath
	Owner  string
	Match  SpanMatch
	// Entry names the owned entry inside an SpanEntries value when it has a
	// fixed name (the "superbased-observer" plugin); "" = the owner's
	// predicate recognises its entries.
	Entry string
	// Verb is what the editor offers instead of a text edit.
	Verb string
	// From names the registry capability the span was computed from.
	From string
	// Writer cites the code that writes the span.
	Writer string
	Note   string
}

// spanTemplate is one writer-table row: where the writer writes and what it
// owns there. Rel is the Linux spelling of the file path, "~/"-relative,
// matched against the tool's Files rows.
type spanTemplate struct {
	Rel    string
	Path   KeyPath
	Owner  string
	Match  SpanMatch
	Entry  string
	Verb   string
	Writer string
	Note   string
}

const (
	verbHooks      = "observer init / observer start re-registers hooks; observer uninstall removes them"
	verbMCP        = "observer init --skip-mcp=false registers the MCP server; observer uninstall removes it"
	verbRoute      = "observer route on|off (proxy-route verbs)"
	verbStatusline = "observer init --statusline"
	verbRouting    = "observer routing apply / revert"
	verbRelay      = "observer mcp (relay) wrap / unwrap"
)

// hookSpanWriters maps a hook mechanism to what its format writer owns.
// Mechanisms with no config write (a tailer, the browser host manifest), no
// writer yet, or a writer whose file the catalogue carries no row for (the
// editor cannot open that file, so there is no second writer to fence) are
// in hookNoSpan instead.
var hookSpanWriters = map[integration.HookMechanism][]spanTemplate{
	integration.HookClaudeSettings: {
		{
			Rel: "~/.claude/settings.json", Path: KeyPath{"hooks"}, Owner: SpanOwnerHook, Match: SpanEntries, Verb: verbHooks,
			Writer: "internal/hook/register_claude.go",
		},
		{
			Rel: "~/.claude/settings.json", Path: KeyPath{"statusLine"}, Owner: SpanOwnerStatusline, Match: SpanWholeKey, Verb: verbStatusline,
			Writer: "internal/hook/register_statusline.go", Note: "Only when the opt-in statusline is registered; a user's own statusLine is theirs.",
		},
	},
	integration.HookCursor: {
		{
			Rel: "~/.cursor/hooks.json", Path: KeyPath{"hooks"}, Owner: SpanOwnerHook, Match: SpanEntries, Verb: verbHooks,
			Writer: "internal/hook/register_cursor.go",
		},
	},
	integration.HookCodexConfig: {
		{
			Rel: "~/.codex/hooks.json", Path: KeyPath{"hooks"}, Owner: SpanOwnerHook, Match: SpanEntries, Verb: verbHooks,
			Writer: "internal/hook/register_codex.go",
		},
		{
			Rel: "~/.codex/config.toml", Path: KeyPath{"features", "hooks"}, Owner: SpanOwnerHook, Match: SpanWholeKey, Verb: verbHooks,
			Writer: "internal/hook/register_codex.go (ensureCodexHooksFeatureFlag)", Note: "Set true at registration; never flipped back on uninstall.",
		},
	},
	integration.HookHermesPlugin: {
		{
			Rel: "~/.hermes/config.yaml", Path: KeyPath{"plugins", "enabled"}, Owner: SpanOwnerHook, Match: SpanEntries,
			Entry: "superbased-observer", Verb: verbHooks, Writer: "internal/hook/hermes_mcp.go (RegisterHermesPluginEnabled)",
			Note: "The plugin files themselves live in ~/.hermes/plugins/superbased-observer/ (internal/hook/hermes.go).",
		},
	},
	integration.HookGeminiSettings: {
		{
			Rel: "~/.gemini/settings.json", Path: KeyPath{"hooks"}, Owner: SpanOwnerHook, Match: SpanEntries, Verb: verbHooks,
			Writer: "internal/hook/register_generic_settings.go",
		},
	},
	integration.HookQwenSettings: {
		{
			Rel: "~/.qwen/settings.json", Path: KeyPath{"hooks"}, Owner: SpanOwnerHook, Match: SpanEntries, Verb: verbHooks,
			Writer: "internal/hook/register_generic_settings.go",
		},
	},
	integration.HookQoderJSON: {
		{
			Rel: "~/.qoder/settings.json", Path: KeyPath{"hooks"}, Owner: SpanOwnerHook, Match: SpanEntries, Verb: verbHooks,
			Writer: "internal/hook/register_generic_settings.go",
		},
	},
	integration.HookFactoryJSON: {
		{
			// Root: droid's standalone hooks.json keeps its event map at the
			// top level (a "hooks" wrapper is ignored by droid), the shape
			// the dedicated writer writes (b5a15ecc9) and the catalogue
			// declares (61a539fc0). T-366: it no longer reuses Codex's writer.
			Rel: "~/.factory/hooks.json", Path: KeyPath{}, Owner: SpanOwnerHook, Match: SpanEntries, Verb: verbHooks,
			Writer: "internal/hook/register_droid_hooksjson.go (writeDroidHooks)",
		},
	},
	integration.HookPoolsideYAML: {
		{
			Rel: "~/.config/poolside/settings.yaml", Path: KeyPath{"hooks"}, Owner: SpanOwnerHook, Match: SpanEntries, Verb: verbHooks,
			Writer: "internal/hook/register_poolside.go",
		},
	},
	integration.HookCascadeJSON: {
		{
			Rel: "~/.codeium/windsurf/hooks.json", Path: KeyPath{"hooks"}, Owner: SpanOwnerHook, Match: SpanEntries, Verb: verbHooks,
			Writer: "internal/hook/register_cascade.go",
		},
	},
	integration.HookCommandCodeMod: {
		{
			Rel: "~/.commandcode/mods/observer-guard.ts", Owner: SpanOwnerHook, Match: SpanWholeFile, Verb: verbHooks,
			Writer: "internal/hook/register_commandcode.go (commandcodemod.ModFileName)",
		},
	},
	// Integration 5's Lane A6 writers into a shared user file: Observer owns
	// its own entries under the hooks key; the user's other hooks stay theirs.
	integration.HookJunieConfig: {
		{
			Rel: "~/.junie/config.json", Path: KeyPath{"hooks"}, Owner: SpanOwnerHook, Match: SpanEntries, Verb: verbHooks,
			Writer: "internal/hook/register_toolgate_vendors.go (junieHooksTarget)",
		},
	},
	integration.HookCrushJSON: {
		{
			Rel: "~/.config/crush/crush.json", Path: KeyPath{"hooks"}, Owner: SpanOwnerHook, Match: SpanEntries, Verb: verbHooks,
			Writer: "internal/hook/register_toolgate_vendors.go (crushHooksTarget)",
		},
	},
	// T-479's Muse writer (found unlisted by T-378's gate run): Observer owns
	// its own matcher groups under the hooks key of the user settings file.
	integration.HookMuseSettings: {
		{
			Rel: "~/.config/muse/settings.json", Path: KeyPath{"hooks"}, Owner: SpanOwnerHook, Match: SpanEntries, Verb: verbHooks,
			Writer: "internal/hook/register_toolgate_vendors.go (museHooksTarget)",
		},
	},
	integration.HookVibeHooksTOML: {
		{
			Rel: "~/.vibe/hooks.toml", Path: KeyPath{"hooks"}, Owner: SpanOwnerHook, Match: SpanEntries, Verb: verbHooks,
			Writer: "internal/hook/register_vibe_cline.go (vibe [[hooks]])",
		},
	},
	integration.HookAntigravityJSON: {
		{
			Rel: "~/.gemini/config/hooks.json", Owner: SpanOwnerHook, Match: SpanEntries, Entry: "superbased-observer", Verb: verbHooks,
			Writer: "internal/hook/register_agy.go (agyObserverHookName)", Note: "Observer owns one top-level hook name; every other key round-trips.",
		},
	},
	// The 2026-10-21 wave writers into a shared user file (surface-gap lane
	// w4-catalog): Observer owns its own entries under the hooks key; the
	// user's other hooks stay theirs.
	integration.HookIBMBobSettings: {
		{
			Rel: "~/.bob/settings/settings.json", Path: KeyPath{"hooks"}, Owner: SpanOwnerHook, Match: SpanEntries, Verb: verbHooks,
			Writer: "internal/hook/register_wave1021.go (ibm-bob)",
		},
	},
	integration.HookCodeBuddySettings: {
		{
			Rel: "~/.codebuddy/settings.json", Path: KeyPath{"hooks"}, Owner: SpanOwnerHook, Match: SpanEntries, Verb: verbHooks,
			Writer: "internal/hook/register_wave1021.go (codebuddy)",
		},
	},
	integration.HookDeepAgentsJSON: {
		{
			Rel: "~/.deepagents/hooks.json", Path: KeyPath{"hooks"}, Owner: SpanOwnerHook, Match: SpanEntries, Verb: verbHooks,
			Writer: "internal/hook/register_wave1021.go (deepAgentsHooksTarget)",
		},
	},
	integration.HookDimCodeJSON: {
		{
			Rel: "~/.dimcode/v2/hooks.json", Path: KeyPath{"hooks"}, Owner: SpanOwnerHook, Match: SpanEntries, Verb: verbHooks,
			Writer: "internal/hook/register_wave1021.go (dimCodeHooksTarget)",
		},
	},
	// Autohand (FU-45, decision D16): config.json holds provider keys and
	// the account token, and D16 allows the member-only read and write of
	// its hooks member, so the span lands: Observer's own hooks.hooks[]
	// entries. The editor never opens the file (PrivNever); the span names
	// the owner for the hygiene pipeline and the parity docs.
	integration.HookAutohandConfig: {
		{
			Rel: "~/.autohand/config.json", Path: KeyPath{"hooks", "hooks"}, Owner: SpanOwnerHook, Match: SpanEntries, Verb: verbHooks,
			Writer: "internal/hook/register_wave1021_config.go (registerAutohand, hooks member only)",
			Note:   "Only the hooks member is read or written (D16); hooks.enabled is the user's switch and is never flipped off.",
		},
	},
	integration.HookVTCodeTOML: {
		{
			Rel: "$XDG_CONFIG_HOME/vtcode/vtcode.toml", Path: KeyPath{"hooks", "lifecycle"}, Owner: SpanOwnerHook, Match: SpanEntries, Verb: verbHooks,
			Writer: "internal/hook/register_wave1021_config.go (registerVTCodeAt)",
			Note:   "The writer hard-codes ~/.config/vtcode on Linux and skips macOS (location matrix Part 7 items 8 and 9).",
		},
	},
}

// hookNoSpan names the registry mechanisms that write no vendor config key.
var hookNoSpan = map[integration.HookMechanism]string{
	// The 2026-10-21 wave writers that own no user file key (surface-gap
	// lane w4-catalog catalogued their files; the shared-file writers moved
	// to hookSpanWriters).
	integration.HookDiracHookFiles: "dedicated Observer script files under ~/.dirac/Hooks (internal/hook/register_wave1021.go); no user file key is touched",
	integration.HookKimchiBashHook: "a dedicated Observer script, ~/.config/kimchi/harness/hooks/bash/superbased-observer.sh (internal/hook/register_wave1021.go); no user file key is touched",
	integration.HookNone:           "no hook surface",
	// Surface-gap W-2a / DEC-12: the writer is built but switched off, so
	// no key is Observer's yet; the span lands with the switch-on commit.
	integration.HookCortexHooksJSON: "the W-2a writer (internal/hook/register_cortex.go) is switched off until live check LC18, so it owns no entry in ~/.snowflake/cortex/hooks.json yet; " +
		"its span (the hooks entries) lands with the commit that switches it on",
	integration.HookClineCLIJSONL:    "a tailer over the tool's own hooks.jsonl: Observer writes nothing into Cline's config",
	integration.HookBrowserExtension: "a native-messaging host manifest (internal/browserhost), not an AI tool config file",
	integration.HookZcodeJSON: "the hook-parity Lane A6 writer (internal/hook/register_toolgate_vendors.go zcodeHooksTarget) writes hooks.events and hooks.enabled " +
		"into ~/.zcode/cli/config.json, a file this catalogue marks never read or written (plaintext provider keys); no span until that conflict is ruled",
	// The hook-parity Lane A6 / Lane D writers that own a DEDICATED file
	// (Integration 5): no key inside a user file is Observer's, so there is
	// no span to lock; the editor never lists those files.
	integration.HookKimiCodeTOML: "the T-378 writer (internal/hook/register_kimi.go) adds Observer's own [[hooks]] tables to ~/.kimi-code/config.toml, " +
		"a file this catalogue marks never read or written (plaintext provider keys); like zcode, no span until that conflict is ruled",
	integration.HookGrokHooksJSON:        "a dedicated Observer file, ~/.grok/hooks/superbased-observer.json (internal/hook/register_toolgate_vendors.go); no user file key is touched",
	integration.HookCopilotCLIHooks:      "a dedicated Observer file, ~/.copilot/hooks/superbased-observer.json (internal/hook/register_toolgate_vendors.go); no user file key is touched",
	integration.HookGoosePlugin:          "a dedicated Observer plugin, ~/.agents/plugins/superbased-observer/ (internal/hook/register_toolgate_vendors.go); no user file key is touched",
	integration.HookClineHookFiles:       "a dedicated Observer plugin, ~/.cline/plugins/superbased-observer-guard.js, plus a no-op PreToolUse keep-alive under ~/.cline/hooks/ (internal/hook/register_vibe_cline.go); no user file key is touched",
	integration.HookOpenInterpreterHooks: "~/.openinterpreter/hooks.json (internal/hook/register_toolgate_vendors.go) is not a catalogued settings file, so its entries are not addressable here",
	integration.HookPluginShimTS:         "a dedicated Observer plugin file in the host's plugin directory (internal/hook/register_pluginshim.go); no user config key is touched",
	integration.HookKiroAgentJSON: "the gfiD writer (internal/hook/register_kiro.go) owns a dedicated agent ~/.kiro/agents/superbased-observer.json and a dedicated V3 file " +
		"~/.kiro/hooks/superbased-observer.json, adds its own entries to the user's ~/.kiro/agents/*.json (not catalogued files) and sets the flat cli.json key " +
		"chat.defaultAgent only when no default is set; no span until the catalogue models agent JSONs and the flat-versus-nested cli.json spelling is grounded live",
}

// mcpSpanWriters maps an MCP config format to the observer entry's path in
// its servers map (internal/mcp/register.go, ServerName "observer"). The
// file comes from the registry row's MCPTarget.PathHint.
var mcpSpanWriters = map[integration.MCPFormat]KeyPath{
	integration.MCPServersJSON:  {"mcpServers"},
	integration.MCPCodexTOML:    {"mcp_servers"},
	integration.MCPHermesYAML:   {"mcp_servers"},
	integration.MCPOpenCodeJSON: {"mcp"},
}

// mcpServerName is the entry Observer's MCP registrar writes
// (internal/mcp/register.go ServerName).
const mcpServerName = "observer"

// proxySpanWriters is the proxy-route writer table, keyed by the registry
// row whose Proxy or ProxyProbe route kind writes a file (env_settings,
// config_file, provider_json). Launcher-only routes write nothing.
var proxySpanWriters = map[string][]spanTemplate{
	"claude-code": {
		{Rel: "~/.claude/settings.json", Path: KeyPath{"env", "ANTHROPIC_BASE_URL"}, Writer: "internal/proxyroute/claude.go"},
		{
			Rel: "~/.claude/settings.json", Path: KeyPath{"env", "CLAUDE_CODE_GATEWAY_HINT_HEADERS"}, Writer: "internal/proxyroute/claude.go",
			Note: "Added only when absent; an operator's own value is never touched or removed.",
		},
	},
	"codex": {
		{Rel: "~/.codex/config.toml", Path: KeyPath{"model_providers", "openai-observer"}, Writer: "internal/proxyroute/codex.go"},
		{
			Rel: "~/.codex/config.toml", Path: KeyPath{"model_provider"}, Writer: "internal/proxyroute/codex.go",
			Note: "Switched to openai-observer while the route is on; the prior provider is restored by route off.",
		},
	},
	"qwen-code": {
		{Rel: "~/.qwen/settings.json", Path: KeyPath{"model", "baseUrl"}, Writer: "internal/proxyroute/qwencode.go"},
		{
			Rel: "~/.qwen/settings.json", Path: KeyPath{"modelProviders"}, Match: SpanEntries, Writer: "internal/proxyroute/qwencode.go",
			Note: "Only the openai-lane entries retargeted from the known default host; ids and envKey stay.",
		},
	},
	"kimi-code": {
		{
			Rel: "~/.kimi-code/config.toml", Path: KeyPath{"providers", "openai", "base_url"}, Writer: "internal/proxyroute/kimicode.go",
			Note: "Observer writes this key without reading the file into any surface: the file holds a plaintext key.",
		},
	},
	"crush": {
		{Rel: "~/.config/crush/crush.json", Path: KeyPath{"providers", "openai", "base_url"}, Writer: "internal/proxyroute/crush.go"},
	},
	"hermes": {
		{Rel: "~/.hermes/config.yaml", Path: KeyPath{"providers", "observer"}, Writer: "cmd/observer hermes launcher (registry Proxy note)"},
	},
	"pi": {
		{Rel: "~/.pi/agent/models.json", Path: KeyPath{"providers", "observer"}, Writer: "cmd/observer pi launcher (registry Proxy note)"},
	},
}

// proxyNoSpan names the file-writing route rows with no span row, and why.
var proxyNoSpan = map[string]string{
	// Ready for the cline row's ProxyProbe (surface-gap lane w2-d, IDE-8):
	// the writer is internal/proxyroute/cline.go.
	"cline": "the probe writer sets <provider>BaseUrl in ~/.cline/data/globalState.json, extension-managed state the catalogue lists as never form-editable; its span is not addressable",
	"open-interpreter": "the member writer (internal/proxyroute/memberroute.go) is switched off until live check LC11, so it owns no key in ~/.openinterpreter/config.toml yet; " +
		"its spans (model_providers.openai-observer, model_provider) land with the commit that switches it on",
	"poolside": "the member writer (internal/proxyroute/memberroute.go) is switched off until live check LCR-1, so it owns no key in settings.yaml yet; " +
		"its span (pool.api_url) lands with the commit that switches it on",
	"stakpak":   "the member writer (internal/proxyroute/memberroute.go, switched off until live check LC37) sets api_endpoint in ~/.stakpak/config.toml, a credential file the catalogue lists as never readable; its span is not addressable",
	"cline-cli": "the launcher writes settings.baseUrl into ~/.cline/data/settings/providers.json, a credential file the catalogue lists as never readable; its span is not addressable",
}

// staticSpans are writers with no registry capability of their own.
var staticSpans = []OwnedSpan{
	{
		Tool: "claude-code", FileID: "claude-code/agent:~/.claude/agents/*.md", Path: KeyPath{"model"},
		Owner: SpanOwnerRoutingApply, Match: SpanWholeKey, Verb: verbRouting,
		From:   "internal/routingapply (Channel A writes Claude Code subagent frontmatter only; ledger.go)",
		Writer: "internal/routingapply/apply.go", Note: "Only on agents a routing apply wrote; the ledger records each one and revert restores it.",
	},
}

var (
	spansCache      []OwnedSpan
	spansUnresolved []string
)

// OwnedSpans returns every Observer-owned span, sorted by tool, file, path.
func OwnedSpans() []OwnedSpan {
	catalogOnce.Do(build)
	out := make([]OwnedSpan, len(spansCache))
	for i, s := range spansCache {
		s.Path = append(KeyPath(nil), s.Path...)
		out[i] = s
	}
	return out
}

// SpansFor returns the spans that touch one setting row: a span at or above
// the row (the row is inside it) or below it (the row's value contains
// Observer's entries).
func SpansFor(settingID string) []OwnedSpan {
	row, ok := Setting(settingID)
	if !ok {
		return nil
	}
	var out []OwnedSpan
	for _, s := range OwnedSpans() {
		if s.Tool == row.Tool && s.Shape == row.FileID && (pathHasPrefix(row.Path, s.Path) || pathHasPrefix(s.Path, row.Path)) {
			out = append(out, s)
		}
	}
	return out
}

// computeSpans derives the spans from the registry and the Files table.
// unresolved lists writer rows whose file the Files table does not carry
// (pinned empty for every catalogued tool by the tests).
func computeSpans(files []FileRow) (spans []OwnedSpan, unresolved []string) {
	byPath := map[string]FileRow{}
	for _, f := range files {
		if f.Paths.Linux != "" {
			byPath[f.Tool+"\x00"+f.Paths.Linux] = f
		}
	}
	add := func(tool string, t spanTemplate, owner, from, verb string) {
		f, ok := byPath[tool+"\x00"+t.Rel]
		if !ok {
			unresolved = append(unresolved, tool+": "+t.Rel+" ("+from+")")
			return
		}
		match := t.Match
		if match == "" {
			match = SpanWholeKey
		}
		if t.Verb != "" {
			verb = t.Verb
		}
		if t.Owner != "" {
			owner = t.Owner
		}
		spans = append(spans, OwnedSpan{
			Tool: tool, FileID: f.ID, Shape: f.Shape, Path: t.Path, Owner: owner, Match: match,
			Entry: t.Entry, Verb: verb, From: from, Writer: t.Writer, Note: t.Note,
		})
	}
	caps := integration.Capabilities()
	sort.Slice(caps, func(i, j int) bool { return caps[i].Tool < caps[j].Tool })
	for _, c := range caps {
		for _, t := range hookSpanWriters[c.Hook.Mechanism] {
			add(c.Tool, t, SpanOwnerHook, "Hook.Mechanism="+string(c.Hook.Mechanism), verbHooks)
		}
		if c.MCP != nil && c.MCP.Implemented {
			if p, ok := mcpSpanWriters[c.MCP.Format]; ok {
				rel := c.MCP.PathHint
				if !strings.HasPrefix(rel, "<") {
					rel = "~/" + rel
				}
				from := "MCP.Format=" + string(c.MCP.Format)
				add(c.Tool, spanTemplate{
					Rel: rel, Path: append(append(KeyPath{}, p...), mcpServerName),
					Writer: "internal/mcp/register.go",
				}, SpanOwnerMCP, from, verbMCP)
				if c.MCP.Remote != nil {
					add(c.Tool, spanTemplate{
						Rel: rel, Path: p, Match: SpanEntries, Writer: "internal/mcp/register.go (relay writers)",
						Note: "Entries the Agent Access relay wrapped or added; the user's other servers stay theirs.",
					},
						SpanOwnerRelay, from+" + MCP.Remote", verbRelay)
				}
			}
		}
		if routeWritesFile(c) {
			for _, t := range proxySpanWriters[c.Tool] {
				add(c.Tool, t, SpanOwnerProxyRoute, "Proxy route kind (file-writing)", verbRoute)
			}
		}
	}
	for _, s := range staticSpans {
		f, ok := fileByID(files, s.FileID)
		if !ok {
			unresolved = append(unresolved, s.Tool+": "+s.FileID+" (static)")
			continue
		}
		s.Shape = f.Shape
		spans = append(spans, s)
	}
	sort.SliceStable(spans, func(i, j int) bool {
		a, b := spans[i], spans[j]
		if a.Tool != b.Tool {
			return a.Tool < b.Tool
		}
		if a.FileID != b.FileID {
			return a.FileID < b.FileID
		}
		return a.Path.String() < b.Path.String()
	})
	return spans, unresolved
}

// routeWritesFile reports a registry row whose route writes a vendor file.
func routeWritesFile(c integration.Capability) bool {
	for _, r := range []*integration.ProxyRoute{c.Proxy, c.ProxyProbe} {
		if r == nil {
			continue
		}
		switch r.Kind {
		case integration.RouteEnvSettings, integration.RouteConfigFile, integration.RouteProviderJSON:
			return true
		}
	}
	return false
}

func fileByID(files []FileRow, id string) (FileRow, bool) {
	for _, f := range files {
		if f.ID == id {
			return f, true
		}
	}
	return FileRow{}, false
}

func pathHasPrefix(p, prefix KeyPath) bool {
	if len(prefix) > len(p) {
		return false
	}
	for i := range prefix {
		if p[i] != prefix[i] {
			return false
		}
	}
	return true
}

// stampOwnedRows marks the catalogue rows a whole-key span covers as
// Observer-owned. A row that only CONTAINS Observer's entries (a hooks
// event list, a servers map) stays user-owned; SpansFor reports the span
// so the editor locks those entries.
func stampOwnedRows(rows []SettingRow, spans []OwnedSpan) {
	for i := range rows {
		r := &rows[i]
		for _, s := range spans {
			if s.Tool != r.Tool || s.Shape != r.FileID || s.Match == SpanEntries {
				continue
			}
			if !pathHasPrefix(r.Path, s.Path) {
				continue
			}
			r.Owner = ObserverOwner(s.Owner)
			note := "Written by Observer (" + s.Owner + ") in " + s.FileID + "; use: " + s.Verb + "."
			if !strings.Contains(r.Note, note) {
				if r.Note != "" {
					r.Note += " "
				}
				r.Note += note
			}
			break
		}
	}
}

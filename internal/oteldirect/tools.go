package oteldirect

import (
	"sort"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// EventKind is what one export event becomes.
type EventKind int

// Event kinds of a tool's vocabulary.
const (
	// EventTurn is one model call: an api_turns row, through the
	// otlpvendor row of the same tool.
	EventTurn EventKind = iota + 1
	// EventToolResult is one finished tool call: an actions row whose type
	// comes from the tool's native tool name.
	EventToolResult
	// EventPrompt is one user prompt: a user_prompt action (and a prompt
	// content row when the exporter sent the text).
	EventPrompt
	// EventAPIError is one failed model call: a failed api_error action.
	EventAPIError
	// EventIgnored is a known event phase 1 does not map. It is accepted and
	// counted as ignored (never rejected), so the exporter's partial_success
	// stays quiet; a content row the otlpvendor rules make from it still
	// lands.
	EventIgnored
)

// AttrKeys names the record attributes a tool's events are read from. Each
// field lists alternate spellings, first present wins.
type AttrKeys struct {
	Session        []string
	Version        []string
	Entrypoint     []string
	HostPaths      []string
	RepositoryURL  []string
	Branch         []string
	ToolName       []string
	ToolUseID      []string
	Success        []string
	Duration       []string
	RequestID      []string
	PromptID       []string
	ToolParameters []string
	Error          []string
}

// TargetRule is how an action's target is read from the tool-parameters JSON
// for one action type. It only applies when the exporter sent tool details.
type TargetRule struct {
	// Keys are the parameter names tried in order; the first non-empty
	// string wins.
	Keys []string
	// RelativeToRoot relates a path target to the session's project root
	// (lexically; "[external]/<path>" outside it), as the node stores file
	// targets.
	RelativeToRoot bool
	// Scrub runs the target through the secret scrubber (a command line).
	Scrub bool
}

// Surface is a resolved capture surface: a models.Surface* kind and the host
// token that refines it.
type Surface struct {
	Kind string
	Host string
}

// SurfacePrefix resolves every entrypoint starting with Prefix to Kind, the
// host being the rest of the entrypoint (DefaultHost when the rest is
// empty).
type SurfacePrefix struct {
	Prefix      string
	Kind        string
	DefaultHost string
}

// ToolRow is one AI tool OTel-direct ingest maps. Everything the mapper
// needs to know about the tool is data on its row.
type ToolRow struct {
	// ServiceNames are the resource service.name values that select this
	// row (exact match).
	ServiceNames []string
	// Tool is the tool id on every row (sessions.tool, actions.tool) and the
	// otlpvendor and tooltax row it reads.
	Tool string
	// Events maps an event name (the typed LogRecord.EventName or the
	// event.name attribute, every spelling the tool emits) to its kind. An
	// event in no entry is rejected as unmapped_event.
	Events map[string]EventKind
	// Attrs are the attribute keys of the tool's events.
	Attrs AttrKeys
	// Targets maps an action type to how its target is read.
	Targets map[string]TargetRule
	// Surfaces maps an exact entrypoint value to its capture surface;
	// SurfacePrefixes is consulted when no exact value matches. An
	// entrypoint in neither leaves the surface empty (unknown, never a
	// guess).
	Surfaces        map[string]Surface
	SurfacePrefixes []SurfacePrefix
	// SurfaceExact lists entrypoints that resolve to a fixed surface
	// although they would also match a prefix (checked after Surfaces).
	SurfaceExact map[string]Surface
}

// claudeCodeEvents lists a Claude Code event under its claude_code.-prefixed
// typed name and its bare event.name spelling.
func claudeCodeEvents(kind EventKind, names ...string) map[string]EventKind {
	out := map[string]EventKind{}
	for _, n := range names {
		out["claude_code."+n] = kind
		out[n] = kind
	}
	return out
}

func mergeEvents(ms ...map[string]EventKind) map[string]EventKind {
	out := map[string]EventKind{}
	for _, m := range ms {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

// toolRows is THE tool table. Phase 1 has exactly one row.
var toolRows = []ToolRow{
	{
		ServiceNames: []string{"claude-code"},
		Tool:         models.ToolClaudeCode,
		// Event vocabulary: code.claude.com/docs/en/monitoring-usage (read
		// 2026-11-16). tool_decision and assistant_response are known but
		// not mapped in phase 1 (design section 6.1).
		Events: mergeEvents(
			claudeCodeEvents(EventTurn, "api_request"),
			claudeCodeEvents(EventToolResult, "tool_result"),
			claudeCodeEvents(EventPrompt, "user_prompt"),
			claudeCodeEvents(EventAPIError, "api_error"),
			claudeCodeEvents(EventIgnored, "tool_decision", "assistant_response"),
		),
		Attrs: AttrKeys{
			Session:        []string{"session.id", "session_id"},
			Version:        []string{"app.version"},
			Entrypoint:     []string{"app.entrypoint"},
			HostPaths:      []string{"workspace.host_paths"},
			RepositoryURL:  []string{"vcs.repository.url.full"},
			Branch:         []string{"vcs.ref.head.name"},
			ToolName:       []string{"tool_name"},
			ToolUseID:      []string{"tool_use_id", "tool.use_id"},
			Success:        []string{"success"},
			Duration:       []string{"duration_ms"},
			RequestID:      []string{"request_id", "request.id"},
			PromptID:       []string{"prompt.id"},
			ToolParameters: []string{"tool_parameters"},
			Error:          []string{"error"},
		},
		// Targets mirror the node's Claude Code adapter
		// (internal/adapter/claudecode/adapter.go extractTarget), keyed by
		// the action type instead of the native name. The export's
		// tool_parameters spell a Bash command full_command (the
		// transcript says command) and a skill skill_name.
		Targets: map[string]TargetRule{
			models.ActionReadFile:    {Keys: []string{"file_path"}, RelativeToRoot: true},
			models.ActionWriteFile:   {Keys: []string{"file_path"}, RelativeToRoot: true},
			models.ActionEditFile:    {Keys: []string{"file_path"}, RelativeToRoot: true},
			models.ActionRunCommand:  {Keys: []string{"full_command", "command"}, Scrub: true},
			models.ActionSearchText:  {Keys: []string{"pattern"}},
			models.ActionSearchFiles: {Keys: []string{"pattern"}},
			models.ActionWebSearch:   {Keys: []string{"query"}},
			models.ActionWebFetch:    {Keys: []string{"url"}},
			models.ActionSkillInvoke: {Keys: []string{"skill_name", "skill"}},
		},
		// Surface vocabulary: a copy of internal/adapter/claudecode/surface.go
		// claudeEntrypointSurface + the sdk- prefix rule (the source of
		// truth; that package is not pure, so it cannot be imported here).
		// TestClaudeCodeSurfacesMatchAdapter parses the adapter's table and
		// fails on drift.
		Surfaces: map[string]Surface{
			"cli":              {Kind: models.SurfaceCLI, Host: "claude"},
			"claude-vscode":    {Kind: models.SurfaceIDE, Host: "vscode"},
			"claude-jetbrains": {Kind: models.SurfaceIDE, Host: "jetbrains"},
			"claude-desktop":   {Kind: models.SurfaceDesktop, Host: "claude-desktop"},
			"remote_desktop":   {Kind: models.SurfaceDesktop, Host: "claude-desktop"},
			"remote":           {Kind: models.SurfaceWeb, Host: "claude-remote"},
			"remote_mobile":    {Kind: models.SurfaceMobile, Host: "claude-mobile"},
		},
		SurfacePrefixes: []SurfacePrefix{{Prefix: "sdk-", Kind: models.SurfaceSDK, DefaultHost: "sdk"}},
		SurfaceExact:    map[string]Surface{"sdk": {Kind: models.SurfaceSDK, Host: "sdk"}},
	},
}

// ToolRows returns a copy of the tool table, in order.
func ToolRows() []ToolRow {
	out := make([]ToolRow, len(toolRows))
	copy(out, toolRows)
	return out
}

// ToolForService returns the row whose ServiceNames contains serviceName.
func ToolForService(serviceName string) (ToolRow, bool) {
	if r := rowForService(serviceName); r != nil {
		return *r, true
	}
	return ToolRow{}, false
}

func rowForService(serviceName string) *ToolRow {
	if serviceName == "" {
		return nil
	}
	for i := range toolRows {
		for _, n := range toolRows[i].ServiceNames {
			if n == serviceName {
				return &toolRows[i]
			}
		}
	}
	return nil
}

// SupportedTools returns the tool ids of the table, sorted.
func SupportedTools() []string {
	out := make([]string, 0, len(toolRows))
	for _, r := range toolRows {
		out = append(out, r.Tool)
	}
	sort.Strings(out)
	return out
}

// ToolRowFor returns the table row whose tool id is tool.
func ToolRowFor(tool string) (ToolRow, bool) {
	for _, r := range toolRows {
		if r.Tool == tool {
			return r, true
		}
	}
	return ToolRow{}, false
}

// The OTLP signals the receiver serves (POST <prefix>/v1/<signal>).
const (
	SignalLogs    = "logs"
	SignalMetrics = "metrics"
	SignalTraces  = "traces"
)

// sourceFilePrefix prefixes the actions.source_file value of an exported
// action: there is no transcript file, so the value names the capture path.
const sourceFilePrefix = "otel:"

// SourceFileFor is the actions.source_file value of every action OTel-direct
// maps for tool ("otel:claude-code"). With source_event_id it is the
// action's idempotency key, so a redelivered export upserts the same rows.
func SourceFileFor(tool string) string { return sourceFilePrefix + tool }

// surface resolves an entrypoint through the row's vocabulary.
func (r *ToolRow) surface(entrypoint string) (Surface, bool) {
	if entrypoint == "" {
		return Surface{}, false
	}
	if s, ok := r.Surfaces[entrypoint]; ok {
		return s, true
	}
	if s, ok := r.SurfaceExact[entrypoint]; ok {
		return s, true
	}
	for _, p := range r.SurfacePrefixes {
		if len(entrypoint) >= len(p.Prefix) && entrypoint[:len(p.Prefix)] == p.Prefix {
			host := entrypoint[len(p.Prefix):]
			if host == "" {
				host = p.DefaultHost
			}
			return Surface{Kind: p.Kind, Host: host}, true
		}
	}
	return Surface{}, false
}

package copilot

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/platform/pathnorm"
	"github.com/marmutapp/superbased-observer/internal/platform/vscodehost"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// Adapter parses GitHub Copilot agent debug session logs written by VS Code
// under User/workspaceStorage/*/GitHub.copilot-chat/debug-logs/<session>/.
//
// Cache-token gap (audit C3): Copilot's debug-log llm_request span only
// surfaces inputTokens / outputTokens in its attrs. There is no cache_read
// or cache_creation field in the published shape — Copilot uses its own
// caching layer between the IDE and the upstream model and does not
// expose Anthropic-style ephemeral cache tier counts. As a result, cost
// rollups for Copilot will under-count any cached prompt-side tokens
// relative to what GitHub bills the user. The adapter writes 0 for the
// cache columns rather than estimate; if Copilot's debug shape ever adds
// cache fields, parseLine and rawUsage gain new struct tags then.
type Adapter struct {
	scrubber *scrub.Scrubber
	roots    []string
}

// New returns an adapter with platform defaults.
func New() *Adapter {
	return &Adapter{scrubber: scrub.New(), roots: defaultRoots()}
}

// NewWithOptions customizes scrubber and/or roots for tests.
func NewWithOptions(s *scrub.Scrubber, roots []string) *Adapter {
	if s == nil {
		s = scrub.New()
	}
	if len(roots) == 0 {
		roots = defaultRoots()
	}
	return &Adapter{scrubber: s, roots: roots}
}

// Name implements adapter.Adapter.
func (*Adapter) Name() string { return models.ToolCopilot }

// WatchPaths implements adapter.Adapter.
func (a *Adapter) WatchPaths() []string { return a.roots }

// IsSessionFile implements adapter.Adapter.
//
// Copilot session files come in two formats:
//
//  1. Legacy debug-log: <ws>/GitHub.copilot-chat/debug-logs/<sess>/main.jsonl
//     (gated by github.copilot.chat.advanced.debug; v1.4.26 auto-flips it).
//  2. Modern snapshot+patches: <ws>/chatSessions/<sessId>.jsonl and
//     <globalStorage>/emptyWindowChatSessions/<sessId>.jsonl, both written
//     unconditionally by VS Code Copilot Chat ≥0.45.
//  3. Modern empty-window DOCUMENT:
//     <globalStorage>/emptyWindowChatSessions/<sessId>.json — the same
//     session state as a kind=0 snapshot's `v` payload, written as a plain
//     JSON document instead of a snapshot+patches log (audit IDE-10).
//
// Paths originate on Windows and macOS; we normalize both native and foreign
// separators so the matcher works regardless of host OS (Linux CI sees
// Windows-formatted paths in fixtures and tests).
func (a *Adapter) IsSessionFile(path string) bool {
	if !isLegacySessionPath(path) && !isModernSessionPath(path) {
		return false
	}
	return adapter.UnderAnyWatchRoot(path, a.WatchPaths())
}

func isLegacySessionPath(path string) bool {
	lower := normalizeLower(path)
	return strings.HasSuffix(lower, "/main.jsonl") &&
		strings.Contains(lower, "/github.copilot-chat/debug-logs/")
}

// isModernSessionPath matches both modern shapes: the snapshot+patches
// `.jsonl` log (chatSessions and emptyWindowChatSessions alike) and the
// `.json` empty-window session document.
func isModernSessionPath(path string) bool {
	lower := normalizeLower(path)
	if strings.HasSuffix(lower, ".jsonl") {
		return strings.Contains(lower, "/chatsessions/") ||
			strings.Contains(lower, "/emptywindowchatsessions/")
	}
	return isEmptyWindowDocumentPath(path)
}

// isEmptyWindowDocumentPath matches the `.json` session document VS Code
// writes for a chat opened with no folder attached
// (`<globalStorage>/emptyWindowChatSessions/<sessId>.json`). Only the
// empty-window directory is accepted: `chatSessions/` carries no observed
// `.json` variant, so widening it there would ingest files whose payload
// shape is unverified.
func isEmptyWindowDocumentPath(path string) bool {
	lower := normalizeLower(path)
	return strings.HasSuffix(lower, ".json") &&
		strings.Contains(lower, "/emptywindowchatsessions/")
}

// normalizeLower lower-cases path and folds `\` to `/` so every matcher
// works on a foreign host's separators (Linux CI reads Windows fixtures).
func normalizeLower(path string) string {
	return strings.ReplaceAll(strings.ToLower(path), `\`, "/")
}

type rawLine struct {
	Version      int             `json:"v"`
	TimestampMS  int64           `json:"ts"`
	DurationMS   int64           `json:"dur"`
	SessionID    string          `json:"sid"`
	Type         string          `json:"type"`
	Name         string          `json:"name"`
	SpanID       string          `json:"spanId"`
	ParentSpanID string          `json:"parentSpanId"`
	Status       string          `json:"status"`
	Attrs        json.RawMessage `json:"attrs"`
}

type commonAttrs struct {
	Content      string `json:"content"`
	Model        string `json:"model"`
	InputTokens  int64  `json:"inputTokens"`
	OutputTokens int64  `json:"outputTokens"`
	TTFT         int64  `json:"ttft"`
	UserRequest  string `json:"userRequest"`
	Args         string `json:"args"`
	Result       string `json:"result"`
	Response     string `json:"response"`
	Reasoning    string `json:"reasoning"`
}

type toolArgs struct {
	Path     string `json:"path"`
	File     string `json:"file"`
	FilePath string `json:"filePath"`
	Command  string `json:"command"`
	Cmd      string `json:"cmd"`
	Query    string `json:"query"`
	Pattern  string `json:"pattern"`
	URL      string `json:"url"`
}

// ParseSessionFile implements adapter.Adapter. It dispatches between the
// legacy debug-log scanner and the modern snapshot+patches parser based on
// the path shape (see isLegacySessionPath / isModernSessionPath).
func (a *Adapter) ParseSessionFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	return a.dispatchParse(ctx, path, fromOffset)
}

type sessionContext struct {
	SessionID   string
	ProjectRoot string
	Model       string
}

func (a *Adapter) parseLine(sourceFile string, line rawLine, lineNum int, state *sessionContext, res *adapter.ParseResult) {
	if line.SessionID != "" {
		state.SessionID = line.SessionID
	}
	ts := millisToTime(line.TimestampMS)

	var attrs commonAttrs
	if len(line.Attrs) > 0 {
		_ = json.Unmarshal(line.Attrs, &attrs)
	}

	switch line.Type {
	case "user_message":
		text := strings.TrimSpace(attrs.Content)
		if text == "" {
			return
		}
		res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
			SourceFile:         sourceFile,
			SourceEventID:      firstNonEmpty(line.SpanID, fmt.Sprintf("user:L%d", lineNum)),
			SessionID:          state.SessionID,
			MessageID:          "user:" + firstNonEmpty(line.SpanID, fmt.Sprintf("user:L%d", lineNum)),
			ProjectRoot:        state.ProjectRoot,
			Timestamp:          ts,
			Model:              state.Model,
			Tool:               models.ToolCopilot,
			ActionType:         models.ActionUserPrompt,
			Target:             truncate(text, 200),
			Success:            true,
			PrecedingReasoning: truncate(text, 200),
			RawToolName:        "user_message",
			RawToolInput:       a.scrubber.String(text),
		})
	case "tool_call":
		ev := a.toolCallEvent(sourceFile, line, lineNum, ts, *state, attrs)
		res.ToolEvents = append(res.ToolEvents, ev)
	case "llm_request":
		if attrs.Model != "" {
			state.Model = attrs.Model
		}
		if attrs.InputTokens != 0 || attrs.OutputTokens != 0 {
			res.TokenEvents = append(res.TokenEvents, models.TokenEvent{
				SourceFile:    sourceFile,
				SourceEventID: firstNonEmpty(line.SpanID, fmt.Sprintf("usage:L%d", lineNum)),
				SessionID:     state.SessionID,
				MessageID:     assistantMessageID(line),
				ProjectRoot:   state.ProjectRoot,
				Timestamp:     ts,
				Tool:          models.ToolCopilot,
				Model:         state.Model,
				InputTokens:   attrs.InputTokens,
				OutputTokens:  attrs.OutputTokens,
				Source:        models.TokenSourceJSONL,
				Reliability:   models.ReliabilityApproximate,
			})
		}
	case "agent_response":
		output := extractAssistantText(attrs.Response)
		if output == "" {
			output = strings.TrimSpace(attrs.Response)
		}
		reasoning := strings.TrimSpace(attrs.Reasoning)
		if output == "" && reasoning == "" {
			return
		}
		spanID := firstNonEmpty(line.SpanID, fmt.Sprintf("complete:L%d", lineNum))
		// B3 (2026-07-31): the reasoning mints NO row of its own — it
		// briefly emitted a standalone `copilot.reasoning`
		// task_complete, a phantom action for something the model never
		// did. `attrs.reasoning` is a SIBLING FIELD of the agent_response
		// it belongs to, so the threading is direct and unconditional
		// (no pending state, no consumption ordering): the
		// agent_response row below carries it in PrecedingReasoning,
		// capped at the same 200 chars the retired row's Target used.
		// A reasoning-only agent_response (no response text) therefore
		// produces nothing — there is no successor to carry it.
		//
		// Assistant message row (only when there is actual response text).
		if output != "" {
			res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
				SourceFile:         sourceFile,
				SourceEventID:      spanID,
				SessionID:          state.SessionID,
				MessageID:          assistantMessageID(line),
				ProjectRoot:        state.ProjectRoot,
				Timestamp:          ts,
				Model:              state.Model,
				Tool:               models.ToolCopilot,
				ActionType:         models.ActionAssistantMessage,
				Target:             "agent_response",
				Success:            strings.EqualFold(line.Status, "ok") || line.Status == "",
				DurationMs:         line.DurationMS,
				PrecedingReasoning: truncate(reasoning, 200),
				RawToolName:        "agent_response",
				ToolOutput:         a.scrubber.String(output),
			})
		}
	}
}

func (a *Adapter) toolCallEvent(sourceFile string, line rawLine, lineNum int, ts time.Time, state sessionContext, attrs commonAttrs) models.ToolEvent {
	target, rawInput := parseToolArgs(attrs.Args, line.Name)
	return models.ToolEvent{
		SourceFile:    sourceFile,
		SourceEventID: firstNonEmpty(line.SpanID, fmt.Sprintf("tool:%s:L%d", line.Name, lineNum)),
		SessionID:     state.SessionID,
		MessageID:     assistantMessageID(line),
		ProjectRoot:   state.ProjectRoot,
		Timestamp:     ts,
		Model:         state.Model,
		Tool:          models.ToolCopilot,
		ActionType:    mapToolName(line.Name),
		Target:        truncate(target, 200),
		Success:       strings.EqualFold(line.Status, "ok") || line.Status == "",
		DurationMs:    line.DurationMS,
		RawToolName:   line.Name,
		RawToolInput:  a.scrubber.String(rawInput),
		ToolOutput:    a.scrubber.String(attrs.Result),
	}
}

func mapToolName(name string) string {
	// Modern Copilot agent tools arrive in camelCase ("runInTerminal");
	// legacy debug-log tools arrive in snake_case ("run_in_terminal").
	// Normalizing to lowercase-with-underscores-stripped collapses both
	// into a single key, so we don't have to maintain parallel entries.
	key := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(name)), "_", "")
	switch key {
	case "managetodolist":
		return models.ActionTodoUpdate
	case "runsubagent":
		return models.ActionSpawnSubagent
	case "readfile", "openfile", "readsemantic", "searchbyname", "viewimage":
		return models.ActionReadFile
	case "createfile", "writefile":
		return models.ActionWriteFile
	case "replacestringinfile", "replacelinesinfile", "applypatch", "deletefile", "editfiles":
		return models.ActionEditFile
	case "runinterminal", "executecommand", "shell",
		"powershell", "pwsh", "cmd", "cmdexe", "bash":
		return models.ActionRunCommand
	case "findtextinfiles", "grep", "grepsearch":
		return models.ActionSearchText
	case "filesearch", "findfiles", "listdir":
		return models.ActionSearchFiles
	case "fetchwebpage", "webfetch":
		return models.ActionWebFetch
	case "websearch":
		return models.ActionWebSearch
	default:
		// mcp__<server>__<tool> calls have no fixed key; label them MCP
		// (identity stays in the raw tool name). Uses the raw name, not
		// the underscore-stripped key, so the mcp__ prefix survives.
		if models.IsMCPToolName(name) {
			return models.ActionMCPCall
		}
		return models.ActionUnknown
	}
}

func parseToolArgs(raw string, fallback string) (string, string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback, raw
	}
	var args toolArgs
	if err := json.Unmarshal([]byte(raw), &args); err != nil {
		return fallback, raw
	}
	for _, v := range []string{args.Path, args.File, args.FilePath, args.Command, args.Cmd, args.Query, args.Pattern, args.URL} {
		if strings.TrimSpace(v) != "" {
			return v, raw
		}
	}
	return fallback, raw
}

func extractAssistantText(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	var payload []struct {
		Role  string `json:"role"`
		Parts []struct {
			Type    string `json:"type"`
			Content string `json:"content"`
		} `json:"parts"`
	}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return ""
	}
	var parts []string
	for _, msg := range payload {
		if msg.Role != "assistant" {
			continue
		}
		for _, part := range msg.Parts {
			if part.Type == "text" && strings.TrimSpace(part.Content) != "" {
				parts = append(parts, part.Content)
			}
		}
	}
	return strings.TrimSpace(strings.Join(parts, "\n"))
}

// defaultRoots emits the workspaceStorage and
// globalStorage/emptyWindowChatSessions paths of EVERY VS Code-family
// product under every cross-mount-resolved $HOME, via the shared
// internal/platform/vscodehost product table.
//
// Copilot Chat is not a VS Code-only extension: it installs into the forks
// too (Code - Insiders, VSCodium, Cursor, Windsurf, Kiro, Qoder, Trae) and
// into the remote-server layouts (.vscode-server, .cursor-server), and the
// hand-rolled Code-only switch this replaced silently missed every session
// recorded inside one of them (audit finding IDE-14). vscodehost owns the
// per-OS convention (including the native-Windows %APPDATA% override), so
// branching on h.OS (logical) rather than runtime.GOOS — the fix for a
// WSL2-installed observer never seeing Copilot data at
// /mnt/c/Users/<u>/AppData/... — now lives in exactly one place.
//
// workspaceStorage hosts both the legacy debug-logs path and the modern
// chatSessions path. globalStorage/emptyWindowChatSessions hosts the modern
// empty-window sessions (chats opened with no folder attached), in both the
// `.jsonl` snapshot+patches and the `.json` document shape.
func defaultRoots() []string {
	var roots []string
	seen := map[string]struct{}{}
	add := func(p string) {
		if p == "" {
			return
		}
		p = filepath.Clean(p)
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		roots = append(roots, p)
	}

	for _, h := range crossmount.AllHomes() {
		for _, ref := range vscodehost.WorkspaceStorageDirs(h) {
			add(ref.Path)
		}
		for _, ref := range vscodehost.GlobalStorageDirs(h) {
			add(filepath.Join(ref.Path, emptyWindowDirName))
		}
	}
	return roots
}

// emptyWindowDirName is VS Code's own casing for the globalStorage
// subdirectory holding folder-less chat sessions.
const emptyWindowDirName = "emptyWindowChatSessions"

// chatSessionsDirName is the workspaceStorage subdirectory holding
// project-attached modern sessions.
const chatSessionsDirName = "chatSessions"

// modernLogSiblingExists reports whether a `.jsonl` snapshot+patches log
// exists anywhere we watch for sessionID — the guard that stops a
// `<sid>.json` empty-window DOCUMENT from being ingested alongside a
// `<sid>.jsonl` log of the same session (C1; see parseModernDocument).
//
// Both shapes derive their SourceEventIDs from the same request ids, so
// the store's UNIQUE(source_file, source_event_id) index CANNOT dedupe
// them — the source files differ by extension. The dedup therefore has
// to happen here, before emission, exactly like cursor's
// cursorSiblingExists gate.
//
// docPath's own directory is checked first because that is the only place
// a coexisting pair can appear without any watch-root configuration at
// all (and the only place tests stage one). The watch roots are then
// swept for the two layouts a modern log can live in:
//
//	<globalStorage>/emptyWindowChatSessions/<sid>.jsonl   (root IS that dir)
//	<workspaceStorage>/<wsHash>/chatSessions/<sid>.jsonl  (root is workspaceStorage)
//
// A session id that is not a plain filename component (empty, or carrying
// a separator or a glob metacharacter) is refused rather than globbed:
// it cannot name a real VS Code session file, and feeding it to
// filepath.Glob would be a path-traversal-shaped read.
//
// Cost: two stats plus one single-level glob per watch root, and only on
// the `.json` document path — which exists for empty-window chats alone
// and is rewritten in place, so it is parsed rarely. The glob's readdir
// covers one workspaceStorage root (one entry per workspace).
func (a *Adapter) modernLogSiblingExists(sessionID, docPath string) bool {
	if !safeSessionIDComponent(sessionID) {
		return false
	}
	name := sessionID + ".jsonl"

	if fileExists(filepath.Join(filepath.Dir(docPath), name)) {
		return true
	}
	for _, root := range a.WatchPaths() {
		if fileExists(filepath.Join(root, name)) {
			return true
		}
		if fileExists(filepath.Join(root, chatSessionsDirName, name)) {
			return true
		}
		matches, err := filepath.Glob(filepath.Join(root, "*", chatSessionsDirName, name))
		if err == nil && len(matches) > 0 {
			return true
		}
	}
	return false
}

// safeSessionIDComponent reports whether sessionID can be joined into a
// path as a single filename component: non-empty, no separator, no `..`,
// and no glob metacharacter (which filepath.Glob would expand).
func safeSessionIDComponent(sessionID string) bool {
	if sessionID == "" || sessionID == "." || sessionID == ".." {
		return false
	}
	return !strings.ContainsAny(sessionID, `/\*?[]`)
}

// fileExists reports whether path names an existing regular file (never
// a directory). Any stat error is "no".
func fileExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular()
}

// sessionIDFromPath returns the session identifier embedded in a Copilot
// session file path. Legacy debug-logs put the id in the parent directory
// (`<sess>/main.jsonl`); modern chatSessions and emptyWindowChatSessions
// put it in the file basename (`<sess>.jsonl`, or `<sess>.json` for the
// empty-window document).
func sessionIDFromPath(path string) string {
	if isModernSessionPath(path) {
		base := filepath.Base(path)
		return strings.TrimSuffix(base, filepath.Ext(base))
	}
	return filepath.Base(filepath.Dir(path))
}

// surfaceHostFor resolves the VS Code-family host token for a session file
// through the shared vscodehost product table — "vscode" for desktop Code,
// "cursor" for a Cursor host, "vscode-remote" for a VS Code Server layout,
// and so on. Copilot Chat only ever runs inside such a host, so a path we
// cannot attribute (a fixture under a temp dir, an unusual relocation)
// falls back to the overwhelmingly common "vscode" rather than dropping
// the stamp: the KIND (ide) is certain either way, and the host token is
// the refinement.
func surfaceHostFor(path string) string {
	if p, ok := vscodehost.ProductForPath(path); ok && p.Host != "" {
		return p.Host
	}
	return defaultSurfaceHost
}

const defaultSurfaceHost = "vscode"

// appendSessionSurface stamps one models.SessionSurface for sessionID.
// Every Copilot Chat session is an IDE chat by construction (there is no
// Copilot Chat CLI writing these stores — `copilot-cli` is a separate
// adapter with its own tool id), so the kind is always models.SurfaceIDE
// and only the host varies. A parse that never resolved a session id
// stamps nothing.
func appendSessionSurface(res *adapter.ParseResult, sessionID, path string) {
	if strings.TrimSpace(sessionID) == "" {
		return
	}
	res.SessionSurfaces = append(res.SessionSurfaces, models.SessionSurface{
		SessionID:   sessionID,
		Surface:     models.SurfaceIDE,
		SurfaceHost: surfaceHostFor(path),
	})
}

// projectRootFromPath walks up from the source file's directory until it
// finds an ancestor whose parent is named `workspaceStorage` — that
// ancestor is the workspace ID dir. We use filepath.Dir for the walk
// because the previous Split + filepath.Join approach silently dropped
// the leading separator on absolute Linux/macOS paths (filepath.Join
// strips empty leading elements), turning `/tmp/.../ws-1` into the
// relative `tmp/.../ws-1` and breaking the workspace.json read.
//
// Returns the resolved folder URI from `workspace.json` when present,
// the workspace ID dir as a fallback, or `[copilot]` if the source
// file isn't under a workspaceStorage tree at all.
func projectRootFromPath(path string) string {
	for cur := filepath.Dir(path); cur != "" && cur != filepath.Dir(cur); cur = filepath.Dir(cur) {
		if filepath.Base(filepath.Dir(cur)) != "workspaceStorage" {
			continue
		}
		if root := workspaceFolderFromMetadata(cur); root != "" {
			return root
		}
		return cur
	}
	return "[copilot]"
}

func assistantMessageID(line rawLine) string {
	root := firstNonEmpty(line.ParentSpanID, line.SpanID)
	if root == "" {
		return ""
	}
	return "assistant:" + root
}

// workspaceFolderFromMetadata reads VS Code's workspace.json — the
// canonical map from workspaceStorage hash → project folder file URI —
// and returns the decoded filesystem path. Returns "" when the file is
// missing, unparseable, or the `folder` field doesn't look like a
// file:// URI (Code stores raw paths only in unusual / corrupted
// states; keeping the legacy empty-string return preserves the
// existing fallback in projectRootFromPath).
//
// v1.6.29 routed the URI decoding + cross-mount translation through
// pathnorm.NormalizeWithFormat. The FormatFileURI gate replaces the
// previous standalone decodeFileURI helper — equivalent on all
// previously-handled inputs and additionally covers percent-encoded
// space, percent-encoded drive separator, and surrounding quotes that
// upstream tools sometimes emit.
func workspaceFolderFromMetadata(workspaceStorageDir string) string {
	body, err := os.ReadFile(filepath.Join(workspaceStorageDir, "workspace.json"))
	if err != nil {
		return ""
	}
	var payload struct {
		Folder string `json:"folder"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return ""
	}
	decoded, format := pathnorm.NormalizeWithFormat(payload.Folder)
	if format != pathnorm.FormatFileURI {
		// Preserve the legacy "non-URI → empty" contract so
		// projectRootFromPath falls back to the workspaceStorage dir
		// rather than displaying a garbage value as the project name.
		return ""
	}
	return decoded
}

func millisToTime(ms int64) time.Time {
	if ms <= 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms).UTC()
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

package devin

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/contentcap"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// Adapter parses Cognition's Devin CLI SQLite store (sessions.db). The
// watch roots are the per-home Devin CLI store directories; see the
// package doc for the store shape.
type Adapter struct {
	scrubber *scrub.Scrubber
	roots    []string
}

// New returns an adapter whose roots are discovered across every
// cross-mount-resolved home.
func New() *Adapter {
	return &Adapter{scrubber: scrub.New(), roots: defaultRoots()}
}

// NewWithOptions customizes scrubber and/or roots for tests. A nil
// scrubber falls back to the default; empty roots fall back to discovery.
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
func (*Adapter) Name() string { return models.ToolDevin }

// WatchPaths implements adapter.Adapter. The roots are a snapshot taken at
// construction: the Devin CLI store directory per cross-mount-resolved
// home. Devin's store is a single central sessions.db, so one root per
// home covers every session.
func (a *Adapter) WatchPaths() []string { return a.roots }

// IsSessionFile implements adapter.Adapter. Matches Devin's central store
// sessions.db (and its -wal/-shm siblings) whose immediate parent
// directory is "cli" and which lives under one of the watch roots. The
// parent-dir guard keeps a stray sessions.db elsewhere from being claimed.
func (a *Adapter) IsSessionFile(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	if base != "sessions.db" && base != "sessions.db-wal" && base != "sessions.db-shm" {
		return false
	}
	if !strings.EqualFold(filepath.Base(filepath.Dir(path)), "cli") {
		return false
	}
	return adapter.UnderAnyWatchRoot(path, a.roots)
}

// ParseSessionFile implements adapter.Adapter. It performs a watermark
// incremental read of the sessions.db at path: fromOffset is the largest
// message_nodes.row_id already processed. When the current MAX(row_id)
// hasn't advanced, nothing is re-read. Otherwise every session that
// gained a node since fromOffset has its ACTIVE conversation chain (the
// path from sessions.main_chain_id up to the tree root) re-walked and
// emitted; downstream (source_file, source_event_id) dedup makes the
// re-emit of already-seen nodes a no-op.
func (a *Adapter) ParseSessionFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	dbPath := resolveDBPath(path)

	db, err := openReadOnlyDB(dbPath)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("devin.ParseSessionFile: open: %w", err)
	}
	defer db.Close()

	latest, err := maxRowID(ctx, db)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("devin.ParseSessionFile: watermark: %w", err)
	}
	res := adapter.ParseResult{NewOffset: latest}
	if latest <= fromOffset {
		return res, nil
	}

	sessions, err := loadTouchedSessions(ctx, db, fromOffset)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("devin.ParseSessionFile: sessions: %w", err)
	}
	for _, s := range sessions {
		tools, tokens, warns := a.parseSession(ctx, db, dbPath, s)
		res.ToolEvents = append(res.ToolEvents, tools...)
		res.TokenEvents = append(res.TokenEvents, tokens...)
		res.Warnings = append(res.Warnings, warns...)
		// Session-lane attribution (surface.go). Both writes are
		// idempotent and preserving on the store side, so re-emitting
		// them on every touched-session parse converges without
		// watermark state of their own.
		if surf, ok := surfaceForSession(s); ok {
			res.SessionSurfaces = append(res.SessionSurfaces, surf)
		}
		if lin, ok := lineageForSession(s); ok {
			res.SessionLineages = append(res.SessionLineages, lin)
		}
	}
	return res, nil
}

// sessionRow is the sessions-table metadata this adapter needs.
type sessionRow struct {
	ID          string
	WorkingDir  string
	Model       string
	MainChainID sql.NullInt64
	// Hidden is the sessions.hidden flag (store migration 15): Devin
	// sets it on the sessions it spawns for ITSELF (the summary agent),
	// which never appear in the session picker. Drives the sidecar
	// lineage stamp — see lineageForSession.
	Hidden bool
	// Metadata is the raw sessions.metadata JSON (store migration 16).
	// Carries the requesting client's `client_meta` bag, from which the
	// capture surface is resolved — see surfaceForSession. Empty on
	// stores predating the column.
	Metadata string
}

// node is one decoded message_nodes row on a session's active chain.
type node struct {
	NodeID   int64
	ParentID sql.NullInt64
	RawMsg   string
	Created  int64
}

// chatMessage is the decoded chat_message JSON payload of a message node.
type chatMessage struct {
	MessageID string          `json:"message_id"`
	Role      string          `json:"role"`
	Content   json.RawMessage `json:"content"`
	ToolCalls []toolCall      `json:"tool_calls"`
	Thinking  json.RawMessage `json:"thinking"`
	ToolCall  string          `json:"tool_call_id"`
	Metadata  *nodeMetadata   `json:"metadata"`
}

type toolCall struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
	Index     int             `json:"index"`
	Kind      string          `json:"kind"`
}

type nodeMetadata struct {
	IsUserInput     *bool           `json:"is_user_input"`
	GenerationModel string          `json:"generation_model"`
	FinishReason    string          `json:"finish_reason"`
	Metrics         *nodeMetrics    `json:"metrics"`
	Extensions      json.RawMessage `json:"extensions"`
}

type nodeMetrics struct {
	InputTokens         *int64   `json:"input_tokens"`
	OutputTokens        *int64   `json:"output_tokens"`
	CacheReadTokens     *int64   `json:"cache_read_tokens"`
	CacheCreationTokens *int64   `json:"cache_creation_tokens"`
	TTFTMs              *float64 `json:"ttft_ms"`
	TotalTimeMs         *float64 `json:"total_time_ms"`
}

// toolInput decodes the argument fields this adapter maps onto the action
// taxonomy / display target. Devin's built-in tool set: write, str_replace,
// exec, read, grep, ls/glob, fetch, web_search, run_subagent, request_scope.
type toolInput struct {
	FilePath    string `json:"file_path"`
	TargetFile  string `json:"target_file"`
	Path        string `json:"path"`
	Command     string `json:"command"`
	Pattern     string `json:"pattern"`
	GlobPattern string `json:"glob_pattern"`
	Query       string `json:"query"`
	URL         string `json:"url"`
	Content     string `json:"content"`
	NewString   string `json:"new_string"`
	NewStr      string `json:"new_str"`
}

// toolResult is a paired tool-role result on the active chain.
type toolResult struct {
	Content string
	Success bool
}

// parseSession walks a session's active chain and emits its events.
func (a *Adapter) parseSession(ctx context.Context, db *sql.DB, sourceFile string, s sessionRow) ([]models.ToolEvent, []models.TokenEvent, []string) {
	chain, warns := loadActiveChain(ctx, db, s)
	if len(chain) == 0 {
		return nil, nil, warns
	}
	projectRoot, gitRemote, projectIdentity := a.resolveProjectRoot(s.WorkingDir)

	// First pass: collect tool-role results keyed by tool_call_id.
	results := map[string]toolResult{}
	decoded := make([]*chatMessage, len(chain))
	for i, n := range chain {
		var cm chatMessage
		if err := json.Unmarshal([]byte(n.RawMsg), &cm); err != nil {
			warns = append(warns, fmt.Sprintf("devin: session %s node %d: malformed chat_message: %v", s.ID, n.NodeID, err))
			continue
		}
		decoded[i] = &cm
		if strings.EqualFold(cm.Role, "tool") && cm.ToolCall != "" {
			results[cm.ToolCall] = toolResult{
				Content: contentString(cm.Content),
				Success: resultSuccess(cm.Metadata),
			}
		}
	}

	var tools []models.ToolEvent
	var tokens []models.TokenEvent
	for i, cm := range decoded {
		if cm == nil {
			continue
		}
		n := chain[i]
		switch strings.ToLower(cm.Role) {
		case "user":
			if ev, ok := a.userPromptEvent(sourceFile, projectRoot, gitRemote, s, n, cm); ok {
				tools = append(tools, ev)
			}
		case "assistant":
			tools = append(tools, a.assistantEvents(sourceFile, projectRoot, gitRemote, s, n, cm, results)...)
			if tok, ok := a.tokenEvent(sourceFile, projectRoot, gitRemote, s, n, cm); ok {
				tokens = append(tokens, tok)
			}
		}
		// system + tool roles are consumed above / intentionally dropped.
	}
	stamped := adapter.ParseResult{ToolEvents: tools, TokenEvents: tokens}
	adapter.ApplyProjectIdentity(&stamped, projectIdentity)
	return stamped.ToolEvents, stamped.TokenEvents, warns
}

func (a *Adapter) userPromptEvent(sourceFile, projectRoot, gitRemote string, s sessionRow, n node, cm *chatMessage) (models.ToolEvent, bool) {
	body := strings.TrimSpace(contentString(cm.Content))
	if body == "" {
		return models.ToolEvent{}, false
	}
	preview := a.scrub(truncate(body, 500))
	return models.ToolEvent{
		SourceFile:    sourceFile,
		SourceEventID: "prompt:" + eventKey(cm.MessageID, n.NodeID),
		SessionID:     s.ID,
		ProjectRoot:   projectRoot,
		GitRemote:     gitRemote,
		Timestamp:     secondsToTime(n.Created),
		Tool:          models.ToolDevin,
		ActionType:    models.ActionUserPrompt,
		Target:        truncate(preview, 200),
		Success:       true,
		RawToolName:   "devin.user_prompt",
		MessageID:     cm.MessageID,
	}, true
}

// assistantEvents emits the assistant narration (as an assistant_message)
// plus one tool event per tool_call. The node's thinking is carried as
// PrecedingReasoning on both the narration and every tool call.
func (a *Adapter) assistantEvents(sourceFile, projectRoot, gitRemote string, s sessionRow, n node, cm *chatMessage, results map[string]toolResult) []models.ToolEvent {
	when := secondsToTime(n.Created)
	model := firstNonEmpty(metaModel(cm.Metadata), s.Model)
	reasoning := a.scrub(truncate(thinkingText(cm.Thinking), 500))

	var out []models.ToolEvent
	if body := strings.TrimSpace(contentString(cm.Content)); body != "" {
		action := models.ActionAssistantMessage
		if len(cm.ToolCalls) == 0 && strings.EqualFold(metaFinish(cm.Metadata), "stop") {
			action = models.ActionTaskComplete
		}
		out = append(out, models.ToolEvent{
			SourceFile:         sourceFile,
			SourceEventID:      "text:" + eventKey(cm.MessageID, n.NodeID),
			SessionID:          s.ID,
			ProjectRoot:        projectRoot,
			GitRemote:          gitRemote,
			Timestamp:          when,
			Model:              model,
			Tool:               models.ToolDevin,
			ActionType:         action,
			Target:             a.scrub(truncate(body, 200)),
			Success:            true,
			PrecedingReasoning: reasoning,
			RawToolName:        "devin.assistant_message",
			ToolOutput:         a.scrub(contentcap.Cap(body, contentcap.DefaultMaxBytes)),
			MessageID:          cm.MessageID,
		})
	}

	for _, tc := range cm.ToolCalls {
		out = append(out, a.toolCallEvent(sourceFile, projectRoot, gitRemote, s, when, model, reasoning, cm.MessageID, tc, results))
	}
	return out
}

func (a *Adapter) toolCallEvent(sourceFile, projectRoot, gitRemote string, s sessionRow, when time.Time, model, reasoning, messageID string, tc toolCall, results map[string]toolResult) models.ToolEvent {
	actionType, target := mapTool(tc.Name, tc.Arguments)

	success := true
	var errMsg, output string
	if res, ok := results[tc.ID]; ok {
		success = res.Success
		output = a.scrub(contentcap.Cap(res.Content, contentcap.DefaultMaxBytes))
		if !res.Success {
			errMsg = res.Content
		}
	}

	sourceID := "tool:" + tc.ID
	if tc.ID == "" {
		sourceID = "tool:" + eventKey(messageID, int64(tc.Index)) + ":" + tc.Name
	}
	return models.ToolEvent{
		SourceFile:         sourceFile,
		SourceEventID:      sourceID,
		SessionID:          s.ID,
		ProjectRoot:        projectRoot,
		GitRemote:          gitRemote,
		Timestamp:          when,
		Model:              model,
		Tool:               models.ToolDevin,
		ActionType:         actionType,
		Target:             truncate(target, 200),
		Success:            success,
		ErrorMessage:       a.scrub(truncate(errMsg, 500)),
		PrecedingReasoning: reasoning,
		RawToolName:        tc.Name,
		RawToolInput:       a.scrubRaw(tc.Arguments),
		ContentBytes:       authoredBytes(tc.Name, tc.Arguments),
		ToolOutput:         output,
		MessageID:          messageID,
	}
}

// tokenEvent emits one approximate TokenEvent per assistant node that
// carries metrics. Devin has no proxy tier, so this is the sole token
// source. cache_* fields were null in the capture (0 in practice);
// reasoning/thinking is folded into output_tokens (no separate count),
// so ReasoningTokens stays 0.
func (a *Adapter) tokenEvent(sourceFile, projectRoot, gitRemote string, s sessionRow, n node, cm *chatMessage) (models.TokenEvent, bool) {
	if cm.Metadata == nil || cm.Metadata.Metrics == nil {
		return models.TokenEvent{}, false
	}
	m := cm.Metadata.Metrics
	in := deref(m.InputTokens)
	out := deref(m.OutputTokens)
	cr := deref(m.CacheReadTokens)
	cc := deref(m.CacheCreationTokens)
	if in == 0 && out == 0 && cr == 0 && cc == 0 {
		return models.TokenEvent{}, false
	}
	return models.TokenEvent{
		SourceFile:          sourceFile,
		SourceEventID:       "tokens:" + eventKey(cm.MessageID, n.NodeID),
		SessionID:           s.ID,
		ProjectRoot:         projectRoot,
		GitRemote:           gitRemote,
		Timestamp:           secondsToTime(n.Created),
		Tool:                models.ToolDevin,
		Model:               firstNonEmpty(metaModel(cm.Metadata), s.Model),
		InputTokens:         in,
		OutputTokens:        out,
		CacheReadTokens:     cr,
		CacheCreationTokens: cc,
		Source:              models.TokenSourceJSONL,
		Reliability:         models.ReliabilityApproximate,
		MessageID:           cm.MessageID,
	}, true
}

// resolveProjectRoot turns a session's raw working_directory into a stable
// project root plus its normalized git remote. Foreign-mount Windows paths
// (a raw C:\… string on a Windows-side session) are translated to their
// /mnt/c equivalent BEFORE git.Resolve so a Windows-side project doesn't
// misfile under the observer's own repo. Empty/unresolvable cwds fall back
// to "[devin]" with no remote.
func (a *Adapter) resolveProjectRoot(workingDir string) (root, remote string, id git.Identity) {
	wd := strings.TrimSpace(workingDir)
	if wd == "" {
		return "[devin]", "", git.Identity{}
	}
	wd = crossmount.TranslateForeignPath(wd)
	identity, err := git.ResolveIdentity(wd, git.IdentityOptions{})
	if err != nil {
		return wd, "", git.Identity{}
	}
	// identity.Remote is already NormalizeRemote'd by ResolveIdentity.
	return identity.Root, identity.Remote, identity
}

// mapTool resolves a Devin built-in tool name onto the normalized action
// taxonomy, deriving a display target from the decoded arguments.
func mapTool(name string, args []byte) (actionType, target string) {
	var in toolInput
	_ = json.Unmarshal(args, &in)
	fp := firstNonEmpty(in.FilePath, in.TargetFile, in.Path)
	fallback := firstNonEmpty(in.Command, fp, in.Pattern, in.GlobPattern, in.Query, in.URL, name)

	switch strings.ToLower(strings.TrimSpace(name)) {
	case "exec", "bash", "shell", "command", "run_command", "run_terminal_cmd":
		return models.ActionRunCommand, firstNonEmpty(in.Command, name)
	case "read", "view", "cat", "read_file", "open":
		return models.ActionReadFile, firstNonEmpty(fp, name)
	case "write", "create", "create_file", "write_file":
		return models.ActionWriteFile, firstNonEmpty(fp, name)
	case "str_replace", "edit", "multiedit", "replace", "edit_file", "apply_patch", "str_replace_editor":
		return models.ActionEditFile, firstNonEmpty(fp, name)
	case "ls", "glob", "find", "list_dir", "list_files":
		return models.ActionSearchFiles, firstNonEmpty(in.Path, in.GlobPattern, in.Pattern, name)
	case "grep", "rg", "search", "codebase_search":
		return models.ActionSearchText, firstNonEmpty(in.Pattern, in.Query, name)
	case "fetch", "download", "http", "web_fetch", "read_url":
		return models.ActionWebFetch, firstNonEmpty(in.URL, name)
	case "web_search", "websearch", "search_web":
		return models.ActionWebSearch, firstNonEmpty(in.Query, name)
	case "run_subagent", "subagent", "task", "agent", "spawn_subagent":
		return models.ActionSpawnSubagent, firstNonEmpty(in.Query, name)
	case "request_scope", "request_permission":
		return models.ActionPermissionRequest, name
	case "ask_user", "ask_question", "request_input":
		return models.ActionAskUser, firstNonEmpty(in.Query, name)
	default:
		if strings.Contains(strings.ToLower(name), "mcp") {
			return models.ActionMCPCall, fallback
		}
		return models.ActionUnknown, fallback
	}
}

// authoredBytes returns the byte length of code the model authored in a
// write/edit tool call, from the argument body it emitted.
func authoredBytes(name string, args []byte) int64 {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "write", "create", "create_file", "write_file",
		"str_replace", "edit", "multiedit", "replace", "edit_file", "str_replace_editor":
		var in toolInput
		_ = json.Unmarshal(args, &in)
		return int64(len(firstNonEmpty(in.Content, in.NewString, in.NewStr)))
	default:
		return 0
	}
}

func (a *Adapter) scrub(v string) string {
	if a.scrubber == nil {
		return v
	}
	return a.scrubber.String(v)
}

func (a *Adapter) scrubRaw(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	if a.scrubber == nil {
		return string(raw)
	}
	return a.scrubber.RawJSON(raw)
}

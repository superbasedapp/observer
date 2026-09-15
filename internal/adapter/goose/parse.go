package goose

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/contentcap"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// sessionRow is the sessions-table metadata + accumulated token bundle this
// adapter needs. The accumulated_* columns and accumulated_cost are
// nullable (a session persists token-EMPTY when the provider errors), so
// they scan into Null* wrappers.
type sessionRow struct {
	ID              string
	WorkingDir      string
	ModelConfigJSON string
	Provider        string
	UpdatedAt       string
	AccInput        sql.NullInt64
	AccOutput       sql.NullInt64
	AccCacheRead    sql.NullInt64
	AccCacheWrite   sql.NullInt64
	AccTotal        sql.NullInt64
	AccCost         sql.NullFloat64
}

// messageRow is one row of the goose `messages` table.
type messageRow struct {
	ID          int64
	MessageID   string
	Role        string
	ContentJSON string
	Created     int64
}

// contentBlock is one element of a message's content_json array. The
// discriminating `type` selects which of the remaining fields is populated.
type contentBlock struct {
	Type string `json:"type"`
	// text
	Text string `json:"text"`
	// toolRequest / toolResponse
	ID         string         `json:"id"`
	ToolCall   *toolCallEnv   `json:"toolCall"`
	ToolResult *toolResultEnv `json:"toolResult"`
}

type toolCallEnv struct {
	Status string       `json:"status"`
	Value  toolCallSpec `json:"value"`
}

type toolCallSpec struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

type toolResultEnv struct {
	Status string          `json:"status"`
	Value  toolResultValue `json:"value"`
}

type toolResultValue struct {
	Content           []toolResultContent `json:"content"`
	StructuredContent *structuredContent  `json:"structuredContent"`
	IsError           bool                `json:"isError"`
}

type toolResultContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type structuredContent struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exit_code"`
}

// toolInput decodes the argument fields this adapter maps onto the action
// taxonomy / display target. goose's developer extension emits `write`
// (path/content) and `shell` (command); the remaining keys tolerate the
// other developer-extension tools.
type toolInput struct {
	Path     string `json:"path"`
	FilePath string `json:"file_path"`
	Command  string `json:"command"`
	Pattern  string `json:"pattern"`
	Query    string `json:"query"`
	URL      string `json:"url"`
	Content  string `json:"content"`
	NewStr   string `json:"new_str"`
	FileText string `json:"file_text"`
}

// modelConfig is the decoded model_config_json.
type modelConfig struct {
	ModelName string `json:"model_name"`
}

// toolResult is a paired tool-role result, extracted from a toolResponse
// block.
type toolResult struct {
	Content string
	Success bool
}

// parseSession loads a session's full message list, pairs toolResponse
// blocks with the toolRequest they answer, and emits its events plus one
// session-level TokenEvent. All emitted rows carry the STORE-SCOPED
// session id (see scopedSessionID) so sessions from two different stores
// can never fold together.
func (a *Adapter) parseSession(ctx context.Context, db *sql.DB, sourceFile string, s sessionRow) ([]models.ToolEvent, []models.TokenEvent, []string) {
	msgs, err := loadMessages(ctx, db, s.ID)
	if err != nil {
		return nil, nil, []string{fmt.Sprintf("goose: session %s: load messages: %v", s.ID, err)}
	}

	sessionID := scopedSessionID(s.ID, sourceFile)
	projectRoot, gitRemote, projectIdentity := a.resolveProjectRoot(s.WorkingDir)
	model := modelName(s.ModelConfigJSON)

	// Decode each message's blocks once; collect tool results by call id.
	type decodedMsg struct {
		row    messageRow
		blocks []contentBlock
	}
	decoded := make([]decodedMsg, 0, len(msgs))
	results := map[string]toolResult{}
	var warns []string
	for _, m := range msgs {
		var blocks []contentBlock
		if err := json.Unmarshal([]byte(m.ContentJSON), &blocks); err != nil {
			warns = append(warns, fmt.Sprintf("goose: session %s message %d: malformed content_json: %v", s.ID, m.ID, err))
			continue
		}
		decoded = append(decoded, decodedMsg{row: m, blocks: blocks})
		for _, b := range blocks {
			if b.Type == "toolResponse" && b.ID != "" && b.ToolResult != nil {
				results[b.ID] = toolResult{
					Content: flattenResult(b.ToolResult.Value),
					Success: resultSuccess(b.ToolResult),
				}
			}
		}
	}

	var tools []models.ToolEvent
	for _, dm := range decoded {
		tools = append(tools, a.eventsForMessage(sourceFile, projectRoot, gitRemote, model, sessionID, dm.row, dm.blocks, results)...)
	}

	var tokens []models.TokenEvent
	if tok, ok := a.tokenEvent(sourceFile, projectRoot, gitRemote, model, sessionID, s); ok {
		tokens = append(tokens, tok)
	}
	stamped := adapter.ParseResult{ToolEvents: tools, TokenEvents: tokens}
	adapter.ApplyProjectIdentity(&stamped, projectIdentity)
	return stamped.ToolEvents, stamped.TokenEvents, warns
}

// eventsForMessage converts one message's content blocks into ToolEvents.
// A text block emits a user_prompt (role=user) or assistant_message
// (role=assistant); a toolRequest emits the mapped tool action; a
// toolResponse is consumed into the results map and never emitted alone.
func (a *Adapter) eventsForMessage(sourceFile, projectRoot, gitRemote, model, sessionID string, m messageRow, blocks []contentBlock, results map[string]toolResult) []models.ToolEvent {
	when := secondsToTime(m.Created)
	isUser := strings.EqualFold(m.Role, "user")
	var out []models.ToolEvent
	for i, b := range blocks {
		switch b.Type {
		case "text":
			body := strings.TrimSpace(b.Text)
			if body == "" {
				continue
			}
			if isUser {
				out = append(out, a.userPromptEvent(sourceFile, projectRoot, gitRemote, sessionID, m, i, body))
			} else {
				out = append(out, a.assistantTextEvent(sourceFile, projectRoot, gitRemote, model, sessionID, m, i, body))
			}
		case "toolRequest":
			if b.ToolCall == nil {
				continue
			}
			out = append(out, a.toolCallEvent(sourceFile, projectRoot, gitRemote, model, sessionID, when, m, i, b, results))
		case "toolResponse":
			// consumed into results; not emitted on its own.
		}
	}
	return out
}

func (a *Adapter) userPromptEvent(sourceFile, projectRoot, gitRemote, sessionID string, m messageRow, idx int, body string) models.ToolEvent {
	preview := a.scrub(truncate(body, 500))
	return models.ToolEvent{
		SourceFile:    sourceFile,
		SourceEventID: "prompt:" + msgKey(m) + ":" + strconv.Itoa(idx),
		SessionID:     sessionID,
		ProjectRoot:   projectRoot,
		GitRemote:     gitRemote,
		Timestamp:     secondsToTime(m.Created),
		Tool:          models.ToolGoose,
		ActionType:    models.ActionUserPrompt,
		Target:        truncate(preview, 200),
		Success:       true,
		RawToolName:   "goose.user_prompt",
		MessageID:     m.MessageID,
	}
}

func (a *Adapter) assistantTextEvent(sourceFile, projectRoot, gitRemote, model, sessionID string, m messageRow, idx int, body string) models.ToolEvent {
	preview := a.scrub(truncate(body, 200))
	output := a.scrub(contentcap.Cap(body, contentcap.DefaultMaxBytes))
	return models.ToolEvent{
		SourceFile:    sourceFile,
		SourceEventID: "text:" + msgKey(m) + ":" + strconv.Itoa(idx),
		SessionID:     sessionID,
		ProjectRoot:   projectRoot,
		GitRemote:     gitRemote,
		Timestamp:     secondsToTime(m.Created),
		Model:         model,
		Tool:          models.ToolGoose,
		ActionType:    models.ActionAssistantMessage,
		Target:        preview,
		Success:       true,
		RawToolName:   "goose.assistant_message",
		ToolOutput:    output,
		MessageID:     m.MessageID,
	}
}

func (a *Adapter) toolCallEvent(sourceFile, projectRoot, gitRemote, model, sessionID string, when time.Time, m messageRow, idx int, b contentBlock, results map[string]toolResult) models.ToolEvent {
	name := b.ToolCall.Value.Name
	args := b.ToolCall.Value.Arguments
	actionType, target := mapTool(name, args)

	// A toolRequest whose toolCall.status is not "success" is a
	// malformed/rejected call; surface it as a failed action.
	success := b.ToolCall.Status == "" || strings.EqualFold(b.ToolCall.Status, "success")
	var errMsg, output string
	if res, ok := results[b.ID]; ok {
		success = res.Success
		output = a.scrub(contentcap.Cap(res.Content, contentcap.DefaultMaxBytes))
		if !res.Success {
			errMsg = res.Content
		}
	}

	sourceID := "tool:" + b.ID
	if b.ID == "" {
		sourceID = "tool:" + msgKey(m) + ":" + strconv.Itoa(idx) + ":" + name
	}
	return models.ToolEvent{
		SourceFile:    sourceFile,
		SourceEventID: sourceID,
		SessionID:     sessionID,
		ProjectRoot:   projectRoot,
		GitRemote:     gitRemote,
		Timestamp:     when,
		Model:         model,
		Tool:          models.ToolGoose,
		ActionType:    actionType,
		Target:        truncate(target, 200),
		Success:       success,
		ErrorMessage:  a.scrub(truncate(errMsg, 500)),
		RawToolName:   name,
		RawToolInput:  a.scrubRaw(args),
		ContentBytes:  authoredBytes(name, args),
		ToolOutput:    output,
		MessageID:     m.MessageID,
	}
}

// tokenEvent emits one approximate session-level TokenEvent from the
// accumulated_* sums. goose reports messages.tokens as NULL, so the
// session row is the sole token source; the accumulated_* columns are
// monotonic, so re-emitting on every touched-session parse is idempotent
// under the store's MAX-upgrade ON CONFLICT. input is GROSS (includes the
// cache_read subset), so the net non-cached input is
// accumulated_input − accumulated_cache_read (clamped ≥0). A token-EMPTY
// provider-error session (all NULL/0) yields no event. sessionID is the
// store-scoped id (see scopedSessionID).
func (a *Adapter) tokenEvent(sourceFile, projectRoot, gitRemote, model, sessionID string, s sessionRow) (models.TokenEvent, bool) {
	in := s.AccInput.Int64
	out := s.AccOutput.Int64
	cr := s.AccCacheRead.Int64
	cw := s.AccCacheWrite.Int64
	cost := s.AccCost.Float64
	if in == 0 && out == 0 && cr == 0 && cw == 0 && cost == 0 {
		return models.TokenEvent{}, false
	}
	netIn := in - cr
	if netIn < 0 {
		netIn = 0
	}
	return models.TokenEvent{
		SourceFile:          sourceFile,
		SourceEventID:       "tokens:" + sessionID,
		SessionID:           sessionID,
		ProjectRoot:         projectRoot,
		GitRemote:           gitRemote,
		Timestamp:           parseUTC(s.UpdatedAt),
		Tool:                models.ToolGoose,
		Model:               model,
		InputTokens:         netIn,
		OutputTokens:        out,
		CacheReadTokens:     cr,
		CacheCreationTokens: cw,
		EstimatedCostUSD:    cost,
		Source:              models.TokenSourceJSONL,
		Reliability:         models.ReliabilityApproximate,
	}, true
}

// mapTool resolves a goose developer-extension tool name onto the
// normalized action taxonomy, deriving a display target from the decoded
// arguments. The grounded names are `write` (path/content) and `shell`
// (command); the rest are best-effort with an ActionUnknown fallback that
// preserves the raw name in RawToolName.
func mapTool(name string, args []byte) (actionType, target string) {
	var in toolInput
	_ = json.Unmarshal(args, &in)
	fp := firstNonEmpty(in.Path, in.FilePath)
	fallback := firstNonEmpty(in.Command, fp, in.Pattern, in.Query, in.URL, name)

	switch strings.ToLower(strings.TrimSpace(name)) {
	case "shell", "bash", "run_command", "command", "terminal":
		return models.ActionRunCommand, firstNonEmpty(in.Command, name)
	case "read", "view", "cat", "read_file":
		return models.ActionReadFile, firstNonEmpty(fp, name)
	case "write", "write_file", "create", "create_file":
		return models.ActionWriteFile, firstNonEmpty(fp, name)
	case "text_editor", "str_replace", "edit", "edit_file", "apply_patch", "replace":
		return models.ActionEditFile, firstNonEmpty(fp, name)
	case "glob", "list", "list_dir", "ls", "find":
		return models.ActionSearchFiles, firstNonEmpty(in.Pattern, fp, name)
	case "grep", "search", "rg", "ripgrep":
		return models.ActionSearchText, firstNonEmpty(in.Pattern, in.Query, name)
	case "fetch", "web_fetch", "read_url", "download":
		return models.ActionWebFetch, firstNonEmpty(in.URL, name)
	case "web_search", "websearch", "search_web":
		return models.ActionWebSearch, firstNonEmpty(in.Query, name)
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
	case "write", "write_file", "create", "create_file",
		"text_editor", "str_replace", "edit", "edit_file", "replace":
		var in toolInput
		_ = json.Unmarshal(args, &in)
		return int64(len(firstNonEmpty(in.Content, in.NewStr, in.FileText)))
	default:
		return 0
	}
}

// flattenResult joins a tool result's text content, appending the
// structured stdout when the text content is empty (a shell result with
// only structuredContent).
func flattenResult(v toolResultValue) string {
	var parts []string
	for _, c := range v.Content {
		if t := strings.TrimSpace(c.Text); t != "" {
			parts = append(parts, t)
		}
	}
	joined := strings.Join(parts, "\n")
	if joined == "" && v.StructuredContent != nil {
		joined = strings.TrimSpace(v.StructuredContent.Stdout)
	}
	return joined
}

// resultSuccess reads a tool result's success signal from isError (the
// status string is a secondary fallback).
func resultSuccess(env *toolResultEnv) bool {
	if env == nil {
		return true
	}
	if env.Value.IsError {
		return false
	}
	if env.Status != "" && !strings.EqualFold(env.Status, "success") {
		return false
	}
	return true
}

// modelName extracts model_config_json.model_name; empty on a missing or
// malformed config.
func modelName(cfg string) string {
	if strings.TrimSpace(cfg) == "" {
		return ""
	}
	var mc modelConfig
	if err := json.Unmarshal([]byte(cfg), &mc); err != nil {
		return ""
	}
	return mc.ModelName
}

// scopedSessionID namespaces a goose session id with a short, stable hash
// of its store path. goose ids are date+sequence slugs (`YYYYMMDD_seq`)
// generated INDEPENDENTLY per store, so two stores on one machine (the
// common case: a WSL store plus a Windows store reached via the foreign
// mount) both contain a `20260708_1` and would fold into one merged
// session without a per-store discriminator. The scope is
// sha256(filepath.Clean(dbPath))[:8], applied UNIFORMLY to native and
// foreign stores alike: a foreign-only suffix would key the id off
// crossmount CLASSIFICATION, and a classification change (new mount
// detection, daemon moved OSes) would silently re-key every session —
// the same re-key trap the Gemini header-UUID incident documented. The
// hash input is the REAL store path (pre-mirror), so the tmp mirror of a
// foreign store scopes identically across rescans. Strip the `@…` suffix
// to recover goose's own id (e.g. for `goose session -r`).
func scopedSessionID(id, dbPath string) string {
	sum := sha256.Sum256([]byte(filepath.Clean(dbPath)))
	return id + "@" + hex.EncodeToString(sum[:4])
}

// msgKey prefers the native message_id; it falls back to the session-stable
// db id so SourceEventID stays deterministic across re-parses when a row
// carries no message_id.
func msgKey(m messageRow) string {
	if m.MessageID != "" {
		return m.MessageID
	}
	return "m" + strconv.FormatInt(m.ID, 10)
}

// parseUTC parses goose's TIMESTAMP wall-clock text ("2026-07-09 09:46:40",
// UTC) into a time. An unparseable/empty value yields the zero time.
func parseUTC(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse("2006-01-02 15:04:05", s); err == nil {
		return t.UTC()
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC()
	}
	return time.Time{}
}

// secondsToTime converts a goose epoch-SECONDS created_timestamp into a UTC
// time. Zero/negative yields the zero time.
func secondsToTime(sec int64) time.Time {
	if sec <= 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0).UTC()
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	return s[:n]
}

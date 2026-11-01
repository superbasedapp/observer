package ibmbob

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/contentcap"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// threadSourceSubagent is the SessionLineage.ThreadSource value for a child
// task Bob spawned (task_type subagent / subtask).
const threadSourceSubagent = "subagent"

// taskEnv is the decoded tasks.env JSON. model is either an object
// {id, contextWindow, ...} (every grounded row) or a bare string id (the
// vendor's loader tolerates both), so it decodes lazily.
type taskEnv struct {
	Workspace string          `json:"workspace"`
	Model     json.RawMessage `json:"model"`
	// ModeID is the Bob mode the task runs in ("agent", "ask", ...).
	ModeID string `json:"modeId"`
}

// modelInfo is the object form of tasks.env.model.
type modelInfo struct {
	ID string `json:"id"`
}

// bobMessage is one decoded messages.data blob. The role selects which of
// the remaining fields is populated (see the package doc).
type bobMessage struct {
	Role      string          `json:"role"`
	Content   json.RawMessage `json:"content"`
	ToolCalls []toolCall      `json:"toolCalls"`
	ToolUsage *toolUsage      `json:"toolUsage"`
	Meta      messageMeta     `json:"_meta"`
	// Stop is true on the assistant message that ended the turn (a bool on
	// every grounded row; tolerated as a string reason too).
	Stop json.RawMessage `json:"stop"`
	// Images is the user/tool message's image attachment array (vendor
	// TaskMessage.images; items carry mediaType + data, or a data URI
	// string). Never grounded in a live row; read for presence + media
	// type only, the bytes are never touched.
	Images json.RawMessage `json:"images"`
	// Reasoning is the assistant message's accumulated reasoning text
	// (vendor pushToAssistant with the reasoning flag); absent on every
	// grounded row, whose tier model emits none.
	Reasoning string `json:"reasoning"`
}

// toolCall is one element of an assistant message's toolCalls array.
type toolCall struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// toolUsage is the envelope a tool-role (result) message carries; its
// signature restates the call it answers.
type toolUsage struct {
	Signature toolSignature `json:"signature"`
}

// toolSignature restates the answered call plus Bob's isError verdict.
type toolSignature struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
	IsError   bool            `json:"isError"`
}

// messageMeta is the subset of a message's _meta this adapter reads.
// timestamp is epoch MILLISECONDS; exitCode is present only on
// execute_command results.
type messageMeta struct {
	Timestamp  int64  `json:"timestamp"`
	ExitCode   *int   `json:"exitCode"`
	DurationMs int64  `json:"durationMs"`
	NotAI      bool   `json:"notAi"`
	Hide       bool   `json:"hide"`
	SubagentID string `json:"subagentId"`
	// Summary marks the assistant message Bob writes when it compacts a
	// conversation (live: notAi + summary, content "Previous conversation
	// summary: ..."); CompactedAt stamps the message that was compacted.
	Summary     bool  `json:"summary"`
	CompactedAt int64 `json:"compactedAt"`
	// Mode is the Bob mode the message was sent under (user/system rows).
	Mode struct {
		ID string `json:"id"`
	} `json:"mode"`
	// Changes is an edit/write result's per-file change record, keyed by
	// file URI (only the diff is decoded; see fileChange).
	Changes map[string]fileChange `json:"changes"`
}

// contentPart is one element of an array-form content field.
type contentPart struct {
	Type      string          `json:"type"`
	Text      string          `json:"text"`
	MediaType string          `json:"mediaType"`
	MimeType  string          `json:"mimeType"`
	Source    json.RawMessage `json:"source"`
}

// toolInput decodes the argument fields this adapter maps onto the action
// taxonomy / display target. Field names are the grounded Bob Shell 2.0.6
// tool parameters (see docs/ibmbob-adapter.md "Tool taxonomy").
type toolInput struct {
	Path        string `json:"path"`
	Command     string `json:"command"`
	Pattern     string `json:"pattern"`
	Query       string `json:"query"`
	URL         string `json:"url"`
	Content     string `json:"content"`
	Replace     string `json:"replace"`
	SkillName   string `json:"skill_name"`
	ModeID      string `json:"mode_id"`
	Description string `json:"description"`
	Name        string `json:"name"`
	LibraryName string `json:"library_name"`
}

// toolResult is a paired tool-role result, extracted from a tool message.
type toolResult struct {
	Content    string
	Success    bool
	DurationMs int64
	// Changes is the result's `_meta.changes` (exact per-file diffs).
	Changes map[string]fileChange
}

// taskResult is what parseTask yields for one task: its events plus the
// tool version to stamp on the session.
type taskResult struct {
	Events   []models.ToolEvent
	Warnings []string
	Version  string
}

// parseTask loads a task's full message list, pairs tool results with the
// calls they answer, and emits the task's ToolEvents under SessionID =
// tasks.id (what `bob --resume <id>` accepts). installVersion is the
// install-level Bob version, the fallback when the task row records none.
func (a *Adapter) parseTask(ctx context.Context, db *sql.DB, sourceFile string, t taskRow, installVersion string) taskResult {
	msgs, err := loadMessages(ctx, db, t.ID)
	if err != nil {
		return taskResult{Warnings: []string{fmt.Sprintf("ibmbob: task %s: load messages: %v", t.ID, err)}}
	}
	errRaw, hasErr := lastErrorOf(t.LastError)
	if len(msgs) == 0 && !hasErr {
		// The placeholder task Bob creates on every launch.
		return taskResult{}
	}

	env := decodeEnv(t.EnvJSON)
	projectRoot, gitRemote, projectIdentity := a.resolveProjectRoot(workspaceOf(env, t.ProjectID))
	model := modelID(env.Model)

	type decodedMsg struct {
		row messageRow
		msg bobMessage
	}
	decoded := make([]decodedMsg, 0, len(msgs))
	results := map[string]toolResult{}
	var warns []string
	for _, m := range msgs {
		var bm bobMessage
		if err := json.Unmarshal([]byte(m.Data), &bm); err != nil {
			warns = append(warns, fmt.Sprintf("ibmbob: task %s message %s: malformed data: %v", t.ID, m.ID, err))
			continue
		}
		decoded = append(decoded, decodedMsg{row: m, msg: bm})
		if strings.EqualFold(m.Role, "tool") && bm.ToolUsage != nil && bm.ToolUsage.Signature.ID != "" {
			results[bm.ToolUsage.Signature.ID] = resultFor(bm)
		}
	}

	ev := eventCtx{
		sourceFile:  sourceFile,
		sessionID:   t.ID,
		projectRoot: projectRoot,
		gitRemote:   gitRemote,
		gitBranch:   firstNonEmpty(strings.TrimSpace(t.GitBranch), projectIdentity.Branch),
		model:       model,
		permission:  permissionMode(t.ApprovalConfig),
		mode:        strings.TrimSpace(env.ModeID),
		isSubagent:  isChildTask(t),
		parentID:    strings.TrimSpace(t.ParentID),
	}
	var tools []models.ToolEvent
	for _, dm := range decoded {
		// The mode a message was sent under rides its _meta; track the
		// latest so a mid-task switch_mode shows on the events after it.
		if id := strings.TrimSpace(dm.msg.Meta.Mode.ID); id != "" {
			ev.mode = id
		}
		tools = append(tools, a.eventsForMessage(&ev, dm.row, dm.msg, results)...)
	}
	if hasErr {
		tools = append(tools, a.lastErrorEvent(ev, t, errRaw))
	}
	stamped := adapter.ParseResult{ToolEvents: tools}
	adapter.ApplyProjectIdentity(&stamped, projectIdentity)
	return taskResult{
		Events:   stamped.ToolEvents,
		Warnings: warns,
		Version:  firstNonEmpty(strings.TrimSpace(t.Version), installVersion),
	}
}

// eventCtx carries the per-task fields every emitted event shares.
type eventCtx struct {
	sourceFile  string
	sessionID   string
	projectRoot string
	gitRemote   string
	gitBranch   string
	model       string
	// permission is the task's auto-approval posture (permissionMode);
	// mode the Bob mode in force (latest _meta.mode.id, else env.modeId).
	permission string
	mode       string
	// isSubagent / parentID describe a spawned child task.
	isSubagent bool
	parentID   string
	// turn counts user prompts seen so far (1-based; 0 before the first).
	turn int
}

// metadata builds the per-event ActionMetadata from the task context. stop
// is the assistant message's terminal reason ("" for every other row).
// Returns nil when nothing applies so the column stays NULL.
func (ev *eventCtx) metadata(stop string) *models.ActionMetadata {
	m := models.ActionMetadata{
		PermissionMode:    ev.permission,
		CollaborationMode: ev.mode,
		StopReason:        stop,
		IsSubagent:        ev.isSubagent,
		ParentSessionID:   ev.parentID,
	}
	if m.IsZero() {
		return nil
	}
	return &m
}

// eventsForMessage converts one message into ToolEvents. A user message
// emits a user_prompt; an assistant message emits an assistant_message for
// its text plus one action per tool call; a tool message is consumed into
// the results map; the system prompt is not emitted.
func (a *Adapter) eventsForMessage(ev *eventCtx, row messageRow, m bobMessage, results map[string]toolResult) []models.ToolEvent {
	when := msToTime(m.Meta.Timestamp)
	if when.IsZero() {
		when = msToTime(row.CreatedAt)
	}
	var out []models.ToolEvent
	switch strings.ToLower(row.Role) {
	case "user":
		if m.Meta.Hide {
			return nil
		}
		body := strings.TrimSpace(contentText(m.Content))
		atts := attachmentsOf(m)
		if body != "" || len(atts) > 0 {
			ev.turn++
			out = append(out, a.userPromptEvent(*ev, row, when, body, atts))
		}
	case "assistant":
		reasoning := strings.TrimSpace(m.Reasoning)
		stop := stopReason(m.Stop)
		body := strings.TrimSpace(contentText(m.Content))
		switch {
		case body != "" && m.Meta.Summary:
			out = append(out, a.compactionEvent(*ev, row, when, body))
		case body != "":
			e := a.assistantTextEvent(*ev, row, when, body, m.Meta.NotAI, stop)
			if reasoning != "" {
				e.PrecedingReasoning, reasoning = a.reasoningFor(reasoning), ""
			}
			out = append(out, e)
		}
		for i, tc := range m.ToolCalls {
			e := a.toolCallEvent(*ev, row, when, i, tc, results)
			if reasoning != "" {
				e.PrecedingReasoning, reasoning = a.reasoningFor(reasoning), ""
			}
			out = append(out, e)
		}
	}
	return out
}

// reasoningFor scrubs and caps an assistant message's reasoning text.
func (a *Adapter) reasoningFor(r string) string {
	return a.scrub(contentcap.Cap(r, contentcap.DefaultMaxBytes))
}

func (a *Adapter) userPromptEvent(ev eventCtx, row messageRow, when time.Time, body string, atts []models.UserAttachment) models.ToolEvent {
	preview := a.scrub(truncate(body, 500))
	if preview == "" {
		preview = "(attachment only)"
	}
	return models.ToolEvent{
		SourceFile:      ev.sourceFile,
		SourceEventID:   "prompt:" + ev.sessionID + ":" + row.ID,
		SessionID:       ev.sessionID,
		ProjectRoot:     ev.projectRoot,
		GitRemote:       ev.gitRemote,
		GitBranch:       ev.gitBranch,
		Timestamp:       when,
		TurnIndex:       ev.turn,
		Tool:            models.ToolIBMBob,
		ActionType:      models.ActionUserPrompt,
		Target:          truncate(preview, 200),
		Success:         true,
		RawToolName:     "ibm-bob.user_prompt",
		MessageID:       row.ID,
		Metadata:        ev.metadata(""),
		UserAttachments: atts,
	}
}

// assistantTextEvent emits the assistant's narration. A `notAi` message is
// a harness-authored notice (e.g. "Stopped: context limit reached ...")
// rather than model output, so it lands as a notification. stop is the
// message's terminal reason ("end_turn" on the turn-ending message).
func (a *Adapter) assistantTextEvent(ev eventCtx, row messageRow, when time.Time, body string, notAI bool, stop string) models.ToolEvent {
	action, raw, model := models.ActionAssistantMessage, "ibm-bob.assistant_message", ev.model
	if notAI {
		action, raw, model, stop = models.ActionNotification, "ibm-bob.notice", "", ""
	}
	return models.ToolEvent{
		SourceFile:    ev.sourceFile,
		SourceEventID: "text:" + ev.sessionID + ":" + row.ID,
		SessionID:     ev.sessionID,
		ProjectRoot:   ev.projectRoot,
		GitRemote:     ev.gitRemote,
		GitBranch:     ev.gitBranch,
		Timestamp:     when,
		TurnIndex:     ev.turn,
		Model:         model,
		Tool:          models.ToolIBMBob,
		ActionType:    action,
		Target:        a.scrub(truncate(body, 200)),
		Success:       true,
		RawToolName:   raw,
		ToolOutput:    a.scrub(contentcap.Cap(body, contentcap.DefaultMaxBytes)),
		MessageID:     row.ID,
		Metadata:      ev.metadata(stop),
	}
}

// compactionEvent records Bob compacting the conversation: the harness
// writes a notAi assistant message flagged `_meta.summary` whose content is
// the replacement summary. Only its size is kept (the summary text is
// model-authored conversation content; Claude Code's compact_boundary row
// likewise carries counts, not the summary).
func (a *Adapter) compactionEvent(ev eventCtx, row messageRow, when time.Time, body string) models.ToolEvent {
	raw, _ := json.Marshal(map[string]int{"summary_chars": len(body)})
	return models.ToolEvent{
		SourceFile:    ev.sourceFile,
		SourceEventID: "compact:" + ev.sessionID + ":" + row.ID,
		SessionID:     ev.sessionID,
		ProjectRoot:   ev.projectRoot,
		GitRemote:     ev.gitRemote,
		GitBranch:     ev.gitBranch,
		Timestamp:     when,
		TurnIndex:     ev.turn,
		Tool:          models.ToolIBMBob,
		ActionType:    models.ActionContextCompacted,
		Target:        fmt.Sprintf("summary: %d chars", len(body)),
		Success:       true,
		RawToolName:   "ibm-bob.compact_summary",
		RawToolInput:  string(raw),
		MessageID:     row.ID,
		Metadata:      ev.metadata(""),
	}
}

// toolCallEvent emits one assistant tool call, joined to its result. The
// SourceEventID is scoped by the task id because Bob's task-copy path
// re-mints message ids but copies message data (and so tool-call ids)
// verbatim into the new task — the call id alone is not store-unique.
func (a *Adapter) toolCallEvent(ev eventCtx, row messageRow, when time.Time, idx int, tc toolCall, results map[string]toolResult) models.ToolEvent {
	actionType, target := mapTool(tc.Name, tc.Arguments)

	success := true
	var errMsg, output string
	var duration int64
	var changes map[string]fileChange
	if res, ok := results[tc.ID]; ok {
		success = res.Success
		changes = res.Changes
		duration = res.DurationMs
		output = a.scrub(contentcap.Cap(res.Content, contentcap.DefaultMaxBytes))
		if !res.Success {
			errMsg = res.Content
		}
	}

	sourceID := "tool:" + ev.sessionID + ":" + tc.ID
	if tc.ID == "" {
		sourceID = "tool:" + ev.sessionID + ":" + row.ID + ":" + strconv.Itoa(idx) + ":" + tc.Name
	}
	return models.ToolEvent{
		SourceFile:    ev.sourceFile,
		SourceEventID: sourceID,
		SessionID:     ev.sessionID,
		ProjectRoot:   ev.projectRoot,
		GitRemote:     ev.gitRemote,
		GitBranch:     ev.gitBranch,
		Timestamp:     when,
		TurnIndex:     ev.turn,
		Model:         ev.model,
		Tool:          models.ToolIBMBob,
		ActionType:    actionType,
		Target:        a.scrub(truncate(target, 200)),
		Success:       success,
		ErrorMessage:  a.scrub(truncate(errMsg, 500)),
		DurationMs:    duration,
		RawToolName:   tc.Name,
		RawToolInput:  a.rawToolInput(actionType, tc.Arguments, changes),
		ContentBytes:  authoredBytes(tc.Name, tc.Arguments),
		ToolOutput:    output,
		MessageID:     row.ID,
		Metadata:      ev.metadata(""),
	}
}

// resultFor extracts a tool result's outcome. A call failed when Bob marked
// the signature isError, or when an execute_command result carries a
// non-zero exit code.
func resultFor(m bobMessage) toolResult {
	success := !m.ToolUsage.Signature.IsError
	if m.Meta.ExitCode != nil && *m.Meta.ExitCode != 0 {
		success = false
	}
	return toolResult{
		Content:    contentText(m.Content),
		Success:    success,
		DurationMs: m.Meta.DurationMs,
		Changes:    m.Meta.Changes,
	}
}

// lineageFor links a spawned child task to the task that spawned it.
func lineageFor(t taskRow) (models.SessionLineage, bool) {
	if strings.TrimSpace(t.ParentID) == "" {
		return models.SessionLineage{}, false
	}
	return models.SessionLineage{
		SessionID:      t.ID,
		ParentThreadID: t.ParentID,
		ThreadSource:   threadSourceSubagent,
	}, true
}

// mapTool resolves a Bob Shell tool name onto the normalized action
// taxonomy, deriving a display target from the decoded arguments. The case
// labels are the built-in tool ids grounded in bobshell 2.0.6; MCP tools
// are `mcp__<server>__<tool>`; anything else falls back to ActionUnknown
// with the raw name preserved in RawToolName.
func mapTool(name string, args []byte) (actionType, target string) {
	var in toolInput
	_ = json.Unmarshal(args, &in)
	fallback := firstNonEmpty(in.Command, in.Path, in.Pattern, in.Query, in.URL, name)

	switch strings.ToLower(strings.TrimSpace(name)) {
	case "execute_command":
		return models.ActionRunCommand, firstNonEmpty(in.Command, name)
	case "read_file", "office_read":
		return models.ActionReadFile, firstNonEmpty(in.Path, name)
	case "write_file":
		return models.ActionWriteFile, firstNonEmpty(in.Path, name)
	case "apply_diff", "insert_content", "search_and_replace", "office_edit":
		return models.ActionEditFile, firstNonEmpty(in.Path, name)
	case "list_files", "glob":
		return models.ActionSearchFiles, firstNonEmpty(in.Pattern, in.Path, name)
	case "grep":
		return models.ActionSearchText, firstNonEmpty(in.Pattern, in.Path, name)
	case "web_fetch":
		return models.ActionWebFetch, firstNonEmpty(in.URL, name)
	case "web_search", "search_ibm_docs":
		return models.ActionWebSearch, firstNonEmpty(in.Query, in.LibraryName, name)
	case "update_todo_list":
		return models.ActionTodoUpdate, name
	case "spawn_subagent":
		return models.ActionSpawnSubagent, firstNonEmpty(in.Description, in.Name, name)
	case "use_skill":
		return models.ActionSkillInvoke, firstNonEmpty(in.SkillName, name)
	case "switch_mode", "list_ibm_doc_libraries":
		return models.ActionHarnessCall, firstNonEmpty(in.ModeID, name)
	default:
		if strings.HasPrefix(strings.ToLower(name), "mcp__") {
			return models.ActionMCPCall, name
		}
		return models.ActionUnknown, fallback
	}
}

// authoredBytes returns the byte length of code the model authored in a
// write/edit tool call, from the argument body it emitted: write_file and
// insert_content `content`, search_and_replace `replace`. apply_diff's body
// is a diff (context + removed lines), not authored code, so it is not
// counted.
func authoredBytes(name string, args []byte) int64 {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "write_file", "insert_content", "search_and_replace":
		var in toolInput
		_ = json.Unmarshal(args, &in)
		return int64(len(firstNonEmpty(in.Content, in.Replace)))
	default:
		return 0
	}
}

// decodeEnv decodes tasks.env; a missing or malformed blob yields the zero
// value.
func decodeEnv(raw string) taskEnv {
	var env taskEnv
	if strings.TrimSpace(raw) == "" {
		return env
	}
	_ = json.Unmarshal([]byte(raw), &env)
	return env
}

// modelID reads tasks.env.model in either of its two shapes: an object
// with an `id` (every grounded row: "premium-ide", a Bob tier alias) or a
// bare string.
func modelID(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return strings.TrimSpace(s)
	}
	var mi modelInfo
	if err := json.Unmarshal(raw, &mi); err == nil {
		return strings.TrimSpace(mi.ID)
	}
	return ""
}

// workspaceOf returns the task's workspace path: env.workspace (a plain
// path), else tasks.project_id with Bob's "file:" scheme prefix removed. A
// full file:// URI is left for crossmount's path normalizer to decode.
func workspaceOf(env taskEnv, projectID string) string {
	if ws := strings.TrimSpace(env.Workspace); ws != "" {
		return ws
	}
	pid := strings.TrimSpace(projectID)
	if strings.HasPrefix(pid, "file:") && !strings.HasPrefix(pid, "file://") {
		return strings.TrimPrefix(pid, "file:")
	}
	return pid
}

// contentText flattens a message content field: a plain string (every
// grounded row), or an array of {type:"text", text} parts whose text parts
// are joined. Non-text parts (images) are skipped.
func contentText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var parts []contentPart
	if err := json.Unmarshal(raw, &parts); err != nil {
		return ""
	}
	var texts []string
	for _, p := range parts {
		if (p.Type == "" || p.Type == "text") && strings.TrimSpace(p.Text) != "" {
			texts = append(texts, p.Text)
		}
	}
	return strings.Join(texts, "\n")
}

// msToTime converts an epoch-MILLISECONDS value into a UTC time.
// Zero/negative yields the zero time.
func msToTime(ms int64) time.Time {
	if ms <= 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms).UTC()
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func firstPositive(vals ...int64) int64 {
	for _, v := range vals {
		if v > 0 {
			return v
		}
	}
	return 0
}

func truncate(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	return s[:n]
}

// permissionMode summarizes a task's approval_config into one token:
// "auto:<groups>" when auto-approval is on with at least one permission
// group allowed (live: auto:read, auto:read+todo+edit+execute), "ask" when
// every action needs the user. Empty when the store has no config. The
// per-task command approvals and allow-lists stay out (they name commands).
func permissionMode(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "null" {
		return ""
	}
	var cfg struct {
		AutoApprovalEnabled bool     `json:"autoApprovalEnabled"`
		AllowedPermissions  []string `json:"allowed_permissions"`
	}
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return ""
	}
	if !cfg.AutoApprovalEnabled || len(cfg.AllowedPermissions) == 0 {
		return "ask"
	}
	return "auto:" + strings.Join(cfg.AllowedPermissions, "+")
}

// isChildTask reports whether a task is a spawned child (subagent /
// subtask) of another task.
func isChildTask(t taskRow) bool {
	if strings.TrimSpace(t.ParentID) != "" {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(t.TaskType)) {
	case "subagent", "subtask":
		return true
	}
	return false
}

// stopReason reads the assistant message's `stop` field: true (every
// grounded row) is the turn terminus, reported as "end_turn"; a string is
// taken as the reason itself; false/absent yields "".
func stopReason(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var b bool
	if err := json.Unmarshal(raw, &b); err == nil {
		if b {
			return "end_turn"
		}
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return strings.TrimSpace(s)
	}
	return ""
}

// errorClasses maps a tasks.last_error `name` onto the normalized action,
// first match wins: errors raised by a hook, or by the user cancelling,
// are an aborted turn (the model never answered); everything else is an
// API/runtime failure.
var errorClasses = []struct {
	contains []string
	action   string
}{
	{[]string{"HookError", "Abort", "Cancel", "Interrupt"}, models.ActionTurnAborted},
}

// lastErrorOf returns the tasks.last_error JSON when it holds an error.
// Bob stores the JSON text "null" for a clear task.
func lastErrorOf(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "null" {
		return "", false
	}
	return raw, true
}

// lastErrorEvent emits the task's persisted error ({name, category,
// message, data}) as one failed action. A hook-blocked prompt never reaches
// the model, so it leaves NO message rows: this row is the session's only
// trace of it. Keyed on a hash of the error JSON (not updated_at, which
// moves on every later write) so a re-read never duplicates it.
func (a *Adapter) lastErrorEvent(ev eventCtx, t taskRow, raw string) models.ToolEvent {
	var e struct {
		Name     string `json:"name"`
		Category string `json:"category"`
		Message  string `json:"message"`
	}
	_ = json.Unmarshal([]byte(raw), &e)
	action := models.ActionAPIError
classify:
	for _, c := range errorClasses {
		for _, sub := range c.contains {
			if strings.Contains(e.Name, sub) {
				action = c.action
				break classify
			}
		}
	}
	sum := sha256.Sum256([]byte(raw))
	return models.ToolEvent{
		SourceFile:    ev.sourceFile,
		SourceEventID: "err:" + t.ID + ":" + hex.EncodeToString(sum[:6]),
		SessionID:     ev.sessionID,
		ProjectRoot:   ev.projectRoot,
		GitRemote:     ev.gitRemote,
		GitBranch:     ev.gitBranch,
		Timestamp:     msToTime(firstPositive(t.UpdatedAt, t.CreatedAt)),
		TurnIndex:     ev.turn,
		Model:         ev.model,
		Tool:          models.ToolIBMBob,
		ActionType:    action,
		Target:        a.scrub(truncate(firstNonEmpty(e.Name, e.Category, "task_error"), 200)),
		Success:       false,
		ErrorMessage:  a.scrub(truncate(e.Message, 500)),
		RawToolName:   "ibm-bob.last_error",
		RawToolInput:  a.scrubRaw([]byte(raw)),
		Metadata:      ev.metadata(""),
	}
}

// attachmentsOf extracts the user attachments a message carries, metadata
// only (kind + media type; never bytes or names): the message-level
// `images` array and any non-text part of an array-form `content`.
func attachmentsOf(m bobMessage) []models.UserAttachment {
	var out []models.UserAttachment
	if len(m.Images) > 0 {
		var items []json.RawMessage
		if err := json.Unmarshal(m.Images, &items); err == nil {
			for _, it := range items {
				out = append(out, models.UserAttachment{Kind: "image", MediaType: imageMediaType(it)})
			}
		}
	}
	var parts []contentPart
	if len(m.Content) > 0 && json.Unmarshal(m.Content, &parts) == nil {
		for _, p := range parts {
			switch strings.ToLower(p.Type) {
			case "image", "image_url", "input_image":
				out = append(out, models.UserAttachment{Kind: "image", MediaType: firstNonEmpty(p.MediaType, p.MimeType, sourceMediaType(p.Source))})
			case "file", "document", "input_file":
				out = append(out, models.UserAttachment{Kind: "file", MediaType: firstNonEmpty(p.MediaType, p.MimeType)})
			}
		}
	}
	return out
}

// imageMediaType reads the media type of one `images` item: an object with
// mediaType/mimeType, or a "data:<type>;base64,..." URI string.
func imageMediaType(raw json.RawMessage) string {
	var o contentPart
	if err := json.Unmarshal(raw, &o); err == nil && (o.MediaType != "" || o.MimeType != "") {
		return firstNonEmpty(o.MediaType, o.MimeType)
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return dataURIMediaType(s)
	}
	return ""
}

func sourceMediaType(raw json.RawMessage) string {
	var src struct {
		MediaType string `json:"media_type"`
	}
	if len(raw) > 0 && json.Unmarshal(raw, &src) == nil {
		return src.MediaType
	}
	return ""
}

// dataURIMediaType returns "image/png" from "data:image/png;base64,...".
func dataURIMediaType(s string) string {
	rest, ok := strings.CutPrefix(s, "data:")
	if !ok {
		return ""
	}
	if i := strings.IndexAny(rest, ";,"); i > 0 {
		return rest[:i]
	}
	return ""
}

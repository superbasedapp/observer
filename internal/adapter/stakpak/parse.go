package stakpak

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/contentcap"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// toolNamespace is the prefix Stakpak puts on every tool of its own tool
// server (`stakpak__run_command`). It carries no information, so the
// adapter records the bare native name.
const toolNamespace = "stakpak__"

// Result sentinels Stakpak writes as (the head of) a tool message's content
// when the call did not complete normally. Both are live-verified:
// TOOL_CALL_CANCELLED on a call the user cancelled, COMMAND_FAILED as the
// first line of a run_command whose exit status was non-zero.
const (
	sentinelCancelled     = "TOOL_CALL_CANCELLED"
	sentinelCommandFailed = "COMMAND_FAILED"
)

// localContextTag opens the block Stakpak appends to a prompt it sends to
// the model (machine name, date, directory tree, git state). It is harness
// context, not something the user typed, so it is cut off the prompt text.
const localContextTag = "<local_context>"

// stateDoc is the decoded checkpoints.state JSON.
type stateDoc struct {
	Messages []rawMessage `json:"messages"`
}

// rawMessage is one OpenAI-chat-shaped message of a checkpoint state. Only
// the assistant message of a step carries `usage`; `model` is decoded for
// forward compatibility (the vendor binary's message struct names it; no
// live capture has it).
type rawMessage struct {
	Role       string          `json:"role"`
	Content    json.RawMessage `json:"content"`
	ToolCalls  []rawToolCall   `json:"tool_calls"`
	ToolCallID string          `json:"tool_call_id"`
	Usage      *rawUsage       `json:"usage"`
	Model      string          `json:"model"`
}

type rawToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name string `json:"name"`
		// Arguments is a JSON document encoded as a string on the wire
		// (OpenAI function-call shape); an inline object is tolerated.
		Arguments json.RawMessage `json:"arguments"`
	} `json:"function"`
}

// rawUsage is the per-call token usage Stakpak stores on the assistant
// message. Details is the optional prompt_tokens_details block.
type rawUsage struct {
	PromptTokens     int64 `json:"prompt_tokens"`
	CompletionTokens int64 `json:"completion_tokens"`
	TotalTokens      int64 `json:"total_tokens"`
	Details          *struct {
		InputTokens      *int64 `json:"input_tokens"`
		OutputTokens     *int64 `json:"output_tokens"`
		CacheReadTokens  *int64 `json:"cache_read_input_tokens"`
		CacheWriteTokens *int64 `json:"cache_write_input_tokens"`
	} `json:"prompt_tokens_details"`
}

// contentPart is one element of an array-shaped message content.
type contentPart struct {
	Type     string `json:"type"`
	Text     string `json:"text"`
	ImageURL *struct {
		URL string `json:"url"`
	} `json:"image_url"`
}

// toolInput decodes the argument fields this adapter maps onto the action
// taxonomy / display target.
type toolInput struct {
	Path        string `json:"path"`
	Command     string `json:"command"`
	Glob        string `json:"glob"`
	Query       string `json:"query"`
	FileText    string `json:"file_text"`
	NewStr      string `json:"new_str"`
	Description string `json:"description"`
	TaskID      string `json:"task_id"`
	TaskIDs     string `json:"task_ids"`
	Skill       string `json:"name"`
}

// sessionCtx is the resolved project identity of one session, cached for the
// duration of a parse so each cwd is resolved once.
type sessionCtx struct {
	root, remote string
	identity     git.Identity
}

// processCheckpoint folds the messages one checkpoint adds into the parse
// state. The added messages are messages[parentLen:]; created_at is the
// only timestamp the store has, so it stamps all of them.
func (a *Adapter) processCheckpoint(st *parseState, r checkpointRow) {
	var doc stateDoc
	if err := json.Unmarshal([]byte(r.State), &doc); err != nil {
		st.warn("stakpak: checkpoint %s: malformed state: %v", r.ID, err)
		return
	}
	start := 0
	if r.HasParent {
		start = r.ParentLen
	}
	if start > len(doc.Messages) {
		// The state shrank relative to its parent (history rewritten): there
		// is nothing provably new to attribute.
		start = len(doc.Messages)
	}
	when := parseTime(r.CreatedAt)
	sc := st.sessionContext(a, r.SessionID)
	usageSeen := 0
	if !r.HasParent {
		a.addSessionStart(st, sc, r, when)
	}

	for i := start; i < len(doc.Messages); i++ {
		m := doc.Messages[i]
		switch strings.ToLower(m.Role) {
		case "user":
			a.addUserPrompt(st, sc, r, i, when, m)
		case "assistant":
			a.addAssistant(st, sc, r, i, when, m, &usageSeen)
		case "tool":
			a.addToolResult(st, r, m)
		}
	}
}

// addSessionStart emits the explicit session-start row once per session,
// stamped with sessions.created_at (the checkpoint clock when the session
// row has none). It rides the ROOT checkpoint — the first one the vendor
// writes — so a later parse window never re-emits it.
func (a *Adapter) addSessionStart(st *parseState, sc sessionCtx, r checkpointRow, fallback time.Time) {
	if st.started[r.SessionID] {
		return
	}
	st.started[r.SessionID] = true
	when := parseTime(st.meta[r.SessionID].CreatedAt)
	if when.IsZero() {
		when = fallback
	}
	st.tools = append(st.tools, models.ToolEvent{
		SourceFile:    st.sourceFile,
		SourceEventID: "session_start:" + r.SessionID,
		SessionID:     r.SessionID,
		ProjectRoot:   sc.root,
		GitRemote:     sc.remote,
		GitBranch:     sc.identity.Branch,
		Timestamp:     when,
		Tool:          models.ToolStakpak,
		ActionType:    models.ActionSessionStart,
		Target:        "startup",
		Success:       true,
		RawToolName:   "stakpak.session_start",
	})
}

func (a *Adapter) addUserPrompt(st *parseState, sc sessionCtx, r checkpointRow, idx int, when time.Time, m rawMessage) {
	text, atts := decodeContent(m.Content)
	text = strings.TrimSpace(stripLocalContext(text))
	if text == "" && len(atts) == 0 {
		return
	}
	preview := a.scrub(truncate(text, 500))
	st.tools = append(st.tools, models.ToolEvent{
		SourceFile:      st.sourceFile,
		SourceEventID:   "prompt:" + r.ID + ":" + strconv.Itoa(idx),
		SessionID:       r.SessionID,
		ProjectRoot:     sc.root,
		GitRemote:       sc.remote,
		GitBranch:       sc.identity.Branch,
		Timestamp:       when,
		Tool:            models.ToolStakpak,
		ActionType:      models.ActionUserPrompt,
		Target:          truncate(preview, 200),
		Success:         true,
		RawToolName:     "stakpak.user_prompt",
		UserAttachments: atts,
		MessageID:       r.ID,
	})
}

func (a *Adapter) addAssistant(st *parseState, sc sessionCtx, r checkpointRow, idx int, when time.Time, m rawMessage, usageSeen *int) {
	model := strings.TrimSpace(m.Model)
	text, _ := decodeContent(m.Content)
	if body := strings.TrimSpace(text); body != "" {
		st.tools = append(st.tools, models.ToolEvent{
			SourceFile:    st.sourceFile,
			SourceEventID: "text:" + r.ID + ":" + strconv.Itoa(idx),
			SessionID:     r.SessionID,
			ProjectRoot:   sc.root,
			GitRemote:     sc.remote,
			GitBranch:     sc.identity.Branch,
			Timestamp:     when,
			Model:         model,
			Tool:          models.ToolStakpak,
			ActionType:    models.ActionAssistantMessage,
			Target:        truncate(a.scrub(truncate(body, 200)), 200),
			Success:       true,
			RawToolName:   "stakpak.assistant_message",
			ToolOutput:    a.scrub(contentcap.Cap(body, contentcap.DefaultMaxBytes)),
			MessageID:     r.ID,
		})
	}
	for j, tc := range m.ToolCalls {
		name := nativeName(tc.Function.Name)
		args := argumentBytes(tc.Function.Arguments)
		actionType, target := mapTool(name, args)
		key := toolEventID(r.SessionID, tc.ID, r.ID, idx, j)
		st.calls[key] = len(st.tools)
		st.tools = append(st.tools, models.ToolEvent{
			SourceFile:     st.sourceFile,
			SourceEventID:  key,
			SessionID:      r.SessionID,
			ProjectRoot:    sc.root,
			GitRemote:      sc.remote,
			GitBranch:      sc.identity.Branch,
			Timestamp:      when,
			Model:          model,
			Tool:           models.ToolStakpak,
			ActionType:     actionType,
			Target:         truncate(target, 200),
			Success:        true,
			RawToolName:    name,
			RawToolInput:   a.scrubRaw(args),
			ContentBytes:   authoredBytes(name, args),
			MessageID:      r.ID,
			OutcomePending: true,
		})
	}
	if m.Usage != nil {
		key := "tokens:" + r.ID
		if *usageSeen > 0 {
			key += ":" + strconv.Itoa(idx)
		}
		*usageSeen++
		if tok, ok := a.tokenEvent(st.sourceFile, sc, r, key, when, model, m.Usage); ok {
			st.tokens = append(st.tokens, tok)
		}
	}
}

// addToolResult pairs a tool message with the call it answers. The call's
// SourceEventID is derivable from the result record alone (session id +
// tool_call_id), so a result whose call was persisted by an EARLIER parse
// window becomes an ActionOutcomeUpdate instead of being dropped.
func (a *Adapter) addToolResult(st *parseState, r checkpointRow, m rawMessage) {
	if m.ToolCallID == "" {
		return
	}
	content, _ := decodeContent(m.Content)
	ok, errMsg := resultVerdict(content)
	output := a.scrub(contentcap.Cap(content, contentcap.DefaultMaxBytes))
	scrubbedErr := a.scrub(truncate(errMsg, 500))
	key := toolEventID(r.SessionID, m.ToolCallID, "", 0, 0)
	if idx, found := st.calls[key]; found {
		ev := &st.tools[idx]
		ev.Success = ok
		ev.ErrorMessage = scrubbedErr
		ev.ToolOutput = output
		ev.OutcomePending = false
		return
	}
	st.outcomes = append(st.outcomes, models.ActionOutcomeUpdate{
		SourceFile:    st.sourceFile,
		SourceEventID: key,
		SuccessKnown:  true,
		Success:       ok,
		ErrorMessage:  scrubbedErr,
		ToolOutput:    output,
	})
}

// tokenEvent builds the per-call TokenEvent from the assistant message's
// usage. See the package doc "Token capture" for the netting rule.
func (a *Adapter) tokenEvent(sourceFile string, sc sessionCtx, r checkpointRow, key string, when time.Time, model string, u *rawUsage) (models.TokenEvent, bool) {
	in, out, cr, cw := netUsage(u)
	if in == 0 && out == 0 && cr == 0 && cw == 0 {
		return models.TokenEvent{}, false
	}
	return models.TokenEvent{
		SourceFile:          sourceFile,
		SourceEventID:       key,
		SessionID:           r.SessionID,
		ProjectRoot:         sc.root,
		GitRemote:           sc.remote,
		GitBranch:           sc.identity.Branch,
		Timestamp:           when,
		Tool:                models.ToolStakpak,
		Model:               model,
		InputTokens:         in,
		OutputTokens:        out,
		CacheReadTokens:     cr,
		CacheCreationTokens: cw,
		Source:              models.TokenSourceJSONL,
		Reliability:         models.ReliabilityApproximate,
		MessageID:           r.ID,
	}, true
}

// netUsage resolves a usage block into NET non-cached input, output and the
// two cache counts. prompt_tokens is the provider's prompt size; with a
// prompt_tokens_details block, details.input_tokens is the NET input and is
// taken as-is. Without it (every live capture) the cache counts are zero and
// the gross prompt equals the net input. When only cache counts are present,
// they are subtracted from the gross prompt (clamped at zero).
// completion_tokens is the whole output; reasoning is not reported
// separately, so no reasoning field is populated.
func netUsage(u *rawUsage) (in, out, cacheRead, cacheWrite int64) {
	out = u.CompletionTokens
	in = u.PromptTokens
	if d := u.Details; d != nil {
		if d.CacheReadTokens != nil {
			cacheRead = *d.CacheReadTokens
		}
		if d.CacheWriteTokens != nil {
			cacheWrite = *d.CacheWriteTokens
		}
		if d.InputTokens != nil {
			in = *d.InputTokens
		} else {
			in = u.PromptTokens - cacheRead - cacheWrite
		}
	}
	if in < 0 {
		in = 0
	}
	return in, out, cacheRead, cacheWrite
}

// toolEventID is the deterministic SourceEventID of a tool-call action. The
// provider's tool_call_id is unique within a session, and combining it with
// the session id keeps two sessions of one store apart. A call without an id
// falls back to its checkpoint position.
func toolEventID(sessionID, callID, checkpointID string, msgIdx, callIdx int) string {
	if callID != "" {
		return "tool:" + sessionID + ":" + callID
	}
	return "tool:" + sessionID + ":" + checkpointID + ":" + strconv.Itoa(msgIdx) + ":" + strconv.Itoa(callIdx)
}

// nativeName strips Stakpak's own tool-server namespace.
func nativeName(name string) string {
	return strings.TrimPrefix(strings.TrimSpace(name), toolNamespace)
}

// mapTool resolves a Stakpak native tool name onto the normalized action
// taxonomy and derives a display target from the decoded arguments.
//
// Live-seen names: view, create, str_replace, remove, run_command,
// dynamic_subagent_task, wait_for_tasks, get_task_details. The remaining
// cases are names that appear in the vendor binary's tool registry and its
// `stakpak config sample` allow-lists (run_remote_command, search_docs,
// load_skill, local_code_search, get_all_tasks) but were not exercised in the
// grounding sessions. Anything else stays ActionUnknown with the raw name
// preserved.
func mapTool(name string, args []byte) (actionType, target string) {
	var in toolInput
	_ = json.Unmarshal(args, &in)
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "run_command", "run_remote_command":
		return models.ActionRunCommand, firstNonEmpty(in.Command, name)
	case "view":
		return models.ActionReadFile, firstNonEmpty(in.Path, in.Glob, name)
	case "create":
		return models.ActionWriteFile, firstNonEmpty(in.Path, name)
	case "str_replace", "remove":
		// remove has no canonical delete action; edit_file is the closest
		// honest bucket (same call kiro-cli's delete_file makes).
		return models.ActionEditFile, firstNonEmpty(in.Path, name)
	case "local_code_search":
		return models.ActionSearchText, firstNonEmpty(in.Query, in.Path, name)
	case "search_docs":
		return models.ActionWebSearch, firstNonEmpty(in.Query, name)
	case "load_skill":
		return models.ActionSkillInvoke, firstNonEmpty(in.Skill, name)
	case "dynamic_subagent_task":
		return models.ActionSpawnSubagent, firstNonEmpty(in.Description, name)
	case "wait_for_tasks":
		return models.ActionSubagentWait, firstNonEmpty(in.TaskIDs, name)
	case "get_task_details", "get_all_tasks":
		return models.ActionAgentControl, firstNonEmpty(in.TaskID, name)
	default:
		return models.ActionUnknown, firstNonEmpty(in.Command, in.Path, in.Query, name)
	}
}

// authoredBytes returns the byte length of code the model authored in a
// create / str_replace call from the argument body it emitted.
func authoredBytes(name string, args []byte) int64 {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "create", "str_replace":
		var in toolInput
		_ = json.Unmarshal(args, &in)
		return int64(len(firstNonEmpty(in.FileText, in.NewStr)))
	default:
		return 0
	}
}

// resultVerdict reads success from a tool message's content using the two
// live-verified sentinels. Everything else is treated as success: the
// content is free text with no structured exit field.
func resultVerdict(content string) (ok bool, errMsg string) {
	trimmed := strings.TrimSpace(content)
	switch {
	case trimmed == sentinelCancelled:
		return false, "tool call cancelled"
	case strings.HasPrefix(trimmed, sentinelCommandFailed):
		return false, strings.TrimSpace(strings.TrimPrefix(trimmed, sentinelCommandFailed))
	}
	return true, ""
}

// decodeContent flattens a message content (string, null or a content-part
// array) into text, and reports image parts as presence-only attachments.
func decodeContent(raw json.RawMessage) (string, []models.UserAttachment) {
	raw = []byte(strings.TrimSpace(string(raw)))
	if len(raw) == 0 || string(raw) == "null" {
		return "", nil
	}
	if raw[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return "", nil
		}
		return s, nil
	}
	var parts []contentPart
	if err := json.Unmarshal(raw, &parts); err != nil {
		return "", nil
	}
	var texts []string
	var atts []models.UserAttachment
	for _, p := range parts {
		switch {
		case p.ImageURL != nil:
			atts = append(atts, models.UserAttachment{Kind: "image", MediaType: dataURIMediaType(p.ImageURL.URL)})
		case p.Text != "":
			texts = append(texts, p.Text)
		}
	}
	return strings.Join(texts, "\n"), atts
}

// dataURIMediaType returns the media type of a `data:<type>;base64,...` URI
// and "" for anything else. The payload is never decoded.
func dataURIMediaType(u string) string {
	rest, ok := strings.CutPrefix(u, "data:")
	if !ok {
		return ""
	}
	end := strings.IndexAny(rest, ";,")
	if end <= 0 {
		return ""
	}
	return rest[:end]
}

// argumentBytes returns the JSON document of a tool call's arguments,
// unwrapping the string encoding the OpenAI function-call shape uses.
func argumentBytes(raw json.RawMessage) []byte {
	raw = []byte(strings.TrimSpace(string(raw)))
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	if raw[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil
		}
		return []byte(s)
	}
	return raw
}

// stripLocalContext removes the harness-appended <local_context> block from
// a prompt.
func stripLocalContext(s string) string {
	if i := strings.Index(s, localContextTag); i >= 0 {
		return s[:i]
	}
	return s
}

// parseTime parses Stakpak's RFC 3339 timestamps (nanosecond precision,
// +00:00 offset). An unparseable or empty value yields the zero time.
func parseTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC()
	}
	return time.Time{}
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

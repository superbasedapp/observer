package cortexcode

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/contentcap"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
)

const (
	maxTargetLen    = 500
	maxErrorLen     = 500
	maxReasoningLen = 2000
	// statusSuccess is the tool_result status of a successful call (the
	// only value observed live).
	statusSuccess = "success"
	// interruptMarker is the harness's internalOnly user block written
	// when the operator interrupts a running turn (live, both OSes).
	interruptMarker = "[Request interrupted by user]"
	// accountSource / accountScope label the account-level observation
	// read off the session metadata's thread.accountHost (operator ruling
	// 2026-10-21: an account, never a person).
	accountSource = "cortex_session_meta"
	accountScope  = models.ToolAccountScopeAccount + ":snowflake_host"
)

// histRecord is one history.jsonl line.
type histRecord struct {
	Role              string    `json:"role"`
	ID                string    `json:"id"`
	Content           blockList `json:"content"`
	UserSentTime      string    `json:"user_sent_time"`
	AssistantSentTime string    `json:"assistant_sent_time"`
	CreatedOn         int64     `json:"created_on"`
	Model             string    `json:"model"`
	ThinkingEffort    string    `json:"thinking_effort"`
}

// histBlock is one content block. Text-shaped fields sit on the block;
// thinking / tool_use / tool_result payloads are nested one level down
// under a key named after the type.
type histBlock struct {
	Type         string          `json:"type"`
	Text         string          `json:"text"`
	DisplayText  string          `json:"displayText"`
	IsUserPrompt bool            `json:"is_user_prompt"`
	InternalOnly bool            `json:"internalOnly"`
	MessageID    string          `json:"message_id"`
	Thinking     json.RawMessage `json:"thinking"`
	ToolUse      *toolUse        `json:"tool_use"`
	ToolResult   *toolResult     `json:"tool_result"`
}

type toolUse struct {
	ToolUseID string          `json:"tool_use_id"`
	Name      string          `json:"name"`
	Input     json.RawMessage `json:"input"`
}

type toolResult struct {
	Name      string          `json:"name"`
	ToolUseID string          `json:"tool_use_id"`
	Content   json.RawMessage `json:"content"`
	Status    string          `json:"status"`
	Metrics   struct {
		DurationMs int64 `json:"duration_ms"`
	} `json:"metrics"`
}

// blockList decodes `content` tolerantly (§4.4d): the live shape is a block
// array on every record, but a bare string becomes one text block and a
// single object one block rather than dropping the whole line.
type blockList []histBlock

// UnmarshalJSON implements json.Unmarshaler.
func (b *blockList) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		*b = nil
		return nil
	}
	switch trimmed[0] {
	case '[':
		var arr []histBlock
		if err := json.Unmarshal(trimmed, &arr); err != nil {
			return fmt.Errorf("cortexcode.blockList: %w", err)
		}
		*b = arr
	case '"':
		var s string
		if err := json.Unmarshal(trimmed, &s); err != nil {
			return fmt.Errorf("cortexcode.blockList: %w", err)
		}
		*b = []histBlock{{Type: "text", Text: s}}
	case '{':
		var one histBlock
		if err := json.Unmarshal(trimmed, &one); err != nil {
			return fmt.Errorf("cortexcode.blockList: %w", err)
		}
		*b = []histBlock{one}
	default:
		*b = nil
	}
	return nil
}

// histState is the per-parse context.
type histState struct {
	a        *Adapter
	path     string
	sessID   string
	root     string
	branch   string
	res      *adapter.ParseResult
	seen     map[string]bool // SourceEventIDs already emitted in this window
	pending  map[string]int  // tool_use_id -> index of its ToolEvent awaiting a result
	resolved map[string]bool // tool_use_ids whose outcome this window already carries
	unknown  map[string]bool // unrecognised tool names already warned about
	// accountHost is the session's Snowflake account host ("" when the
	// metadata carries none); every message-bound event gets one
	// account-level observation.
	accountHost string
	accounts    map[string]bool // role+message ids already observed
}

// parseHistory streams a history log from fromOffset to its last complete
// line. The sibling metadata document is re-read on every call: it is the
// only statement of the session's working directory.
func (a *Adapter) parseHistory(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	res := adapter.ParseResult{NewOffset: fromOffset}
	f, err := os.Open(path) //nolint:gosec // path comes from the watcher's own watch roots
	if err != nil {
		if os.IsNotExist(err) {
			return res, nil // vanished mid-poll; nothing to do
		}
		return res, fmt.Errorf("cortexcode.parseHistory: open %s: %w", path, err)
	}
	defer f.Close()
	if fromOffset > 0 {
		if _, err := f.Seek(fromOffset, io.SeekStart); err != nil {
			return res, fmt.Errorf("cortexcode.parseHistory: seek: %w", err)
		}
	}

	meta, _, _ := readMeta(metaPathFor(path))
	root, branch, identity := resolveProjectRoot(meta.WorkingDirectory)
	if branch == "" {
		branch = meta.GitBranch
	}
	st := &histState{
		a: a, path: path, sessID: sessionIDFromPath(path),
		root: root, branch: branch, res: &res,
		seen: map[string]bool{}, pending: map[string]int{},
		resolved: map[string]bool{}, unknown: map[string]bool{},
		accountHost: meta.accountHost(), accounts: map[string]bool{},
	}

	// bufio.Reader.ReadString (not Scanner): the cursor advances by the
	// exact bytes read, CRLF included, and a long tool-result line is not
	// capped by a token-size limit.
	reader := bufio.NewReaderSize(f, 64*1024)
	offset := fromOffset
	for {
		if err := ctx.Err(); err != nil {
			st.finish(identity)
			return res, err
		}
		line, readErr := reader.ReadString('\n')
		if readErr != nil && readErr != io.EOF {
			st.finish(identity)
			return res, fmt.Errorf("cortexcode.parseHistory: read: %w", readErr)
		}
		// An unterminated trailing line is a record still being written:
		// leave the cursor before it so the next pass reads it whole.
		if !strings.HasSuffix(line, "\n") {
			break
		}
		lineStart := offset
		offset += int64(len(line))
		res.NewOffset = offset
		raw := strings.TrimSpace(line)
		if raw != "" {
			var rec histRecord
			if err := json.Unmarshal([]byte(raw), &rec); err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("offset %d: malformed line skipped: %v", lineStart, err))
			} else {
				st.record(&rec, lineStart)
			}
		}
		if readErr == io.EOF {
			break
		}
	}
	a.stampFromLog(&res, path, st.sessID, meta.WorkingDirectory)
	st.finish(identity)
	return res, nil
}

// finish marks still-unpaired tool calls as outcome-pending and stamps the
// project identity on every event.
func (st *histState) finish(identity git.Identity) {
	for _, idx := range st.pending {
		if idx < len(st.res.ToolEvents) {
			st.res.ToolEvents[idx].OutcomePending = true
		}
	}
	adapter.ApplyProjectIdentity(st.res, identity)
}

// record dispatches one record by role.
func (st *histState) record(rec *histRecord, lineStart int64) {
	recKey := rec.ID
	if recKey == "" {
		recKey = "@" + strconv.FormatInt(lineStart, 10)
	}
	switch rec.Role {
	case "user":
		st.userRecord(rec, recKey)
	case "assistant":
		st.assistantRecord(rec, recKey)
	}
	// Any other role is untyped noise (§4.4e): skipped silently.
}

// userRecord emits the typed prompts and applies the tool results a user
// record carries. Harness-injected blocks (internalOnly: system
// reminders, hook output) are not operator prompts and are skipped; the
// interrupt marker becomes one turn_aborted row.
func (st *histState) userRecord(rec *histRecord, recKey string) {
	ts := parseTime(rec.UserSentTime)
	for i, blk := range rec.Content {
		switch blk.Type {
		case "text":
			if blk.InternalOnly && strings.TrimSpace(blk.Text) == interruptMarker {
				st.emit(models.ToolEvent{
					SourceEventID: "abort:" + st.sessID + ":" + firstNonEmpty(blk.MessageID, recKey+":"+strconv.Itoa(i)),
					Timestamp:     ts,
					ActionType:    models.ActionTurnAborted,
					RawToolName:   models.ToolCortexCode + ".turn_aborted",
					Target:        "interrupted by user",
					Success:       false,
					ErrorMessage:  "turn aborted: interrupted by user",
				})
				continue
			}
			if !blk.IsUserPrompt || blk.InternalOnly {
				continue
			}
			text := firstNonEmpty(strings.TrimSpace(blk.DisplayText), strings.TrimSpace(blk.Text))
			if text == "" {
				continue
			}
			key := blk.MessageID
			if key == "" {
				key = recKey + ":" + strconv.Itoa(i)
			}
			scrubbed := st.a.scrubber.String(text)
			st.emit(models.ToolEvent{
				SourceEventID: "prompt:" + st.sessID + ":" + key,
				Timestamp:     ts,
				ActionType:    models.ActionUserPrompt,
				RawToolName:   models.ToolCortexCode + ".user_prompt",
				RawToolInput:  scrubbed,
				Target:        truncate(scrubbed, maxTargetLen),
				Success:       true,
				MessageID:     key,
			})
		case "tool_result":
			if blk.ToolResult != nil {
				st.toolResult(blk.ToolResult)
			}
		}
	}
}

// assistantRecord emits the record's text as one assistant message and
// each tool_use as one tool call, all carrying the record's model, effort
// and reasoning.
func (st *histState) assistantRecord(rec *histRecord, recKey string) {
	ts := parseTime(rec.AssistantSentTime)
	if ts.IsZero() && rec.CreatedOn > 0 {
		ts = time.UnixMilli(rec.CreatedOn).UTC()
	}
	var meta *models.ActionMetadata
	if e := strings.TrimSpace(rec.ThinkingEffort); e != "" {
		meta = &models.ActionMetadata{EffortLevel: e}
	}
	reasoning := truncate(st.a.scrubber.String(thinkingText(rec.Content)), maxReasoningLen)

	var text strings.Builder
	for _, blk := range rec.Content {
		if blk.Type != "text" || blk.InternalOnly || strings.TrimSpace(blk.Text) == "" {
			continue
		}
		if text.Len() > 0 {
			text.WriteByte('\n')
		}
		text.WriteString(blk.Text)
	}
	if text.Len() > 0 {
		out := st.a.scrubber.String(contentcap.Cap(text.String(), contentcap.DefaultMaxBytes))
		st.emit(models.ToolEvent{
			SourceEventID:      "asst:" + st.sessID + ":" + recKey,
			Timestamp:          ts,
			Model:              rec.Model,
			ActionType:         models.ActionAssistantMessage,
			RawToolName:        models.ToolCortexCode + ".assistant_text",
			Target:             truncate(out, maxTargetLen),
			ToolOutput:         out,
			Success:            true,
			PrecedingReasoning: reasoning,
			MessageID:          recKey,
			Metadata:           meta,
		})
	}

	pos := 0
	for _, blk := range rec.Content {
		if blk.Type != "tool_use" || blk.ToolUse == nil {
			continue
		}
		st.toolUse(rec, recKey, pos, blk.ToolUse, ts, reasoning, meta)
		pos++
	}
}

// toolUse emits one tool call, optimistically successful until its
// tool_result arrives (in this window, or in a later one as an
// OutcomeUpdate).
func (st *histState) toolUse(rec *histRecord, recKey string, pos int, tu *toolUse, ts time.Time, reasoning string, meta *models.ActionMetadata) {
	action, known := mapTool(tu.Name)
	if !known && !st.unknown[tu.Name] {
		st.unknown[tu.Name] = true
		st.res.Warnings = append(st.res.Warnings,
			fmt.Sprintf("unrecognised tool name %q normalized to %q", tu.Name, action))
	}
	callKey := tu.ToolUseID
	if callKey == "" {
		callKey = recKey + ":" + strconv.Itoa(pos)
	}
	input := st.a.scrubber.RawJSON(tu.Input)
	target, targetKey := targetFromInput(tu.Input)
	target = relativeTarget(target, targetKey, st.root)
	idx, ok := st.emit(models.ToolEvent{
		SourceEventID:      toolEventID(st.sessID, callKey),
		Timestamp:          ts,
		Model:              rec.Model,
		ActionType:         action,
		RawToolName:        tu.Name,
		RawToolInput:       input,
		Target:             truncate(st.a.scrubber.String(target), maxTargetLen),
		ContentBytes:       authoredBytes(action, tu.Input),
		Success:            true,
		PrecedingReasoning: reasoning,
		MessageID:          recKey,
		Metadata:           meta,
	})
	if ok && tu.ToolUseID != "" {
		st.pending[tu.ToolUseID] = idx
	}
}

// toolResult applies a result to its call: in place when the call was
// emitted in this window, otherwise as an OutcomeUpdate keyed by the
// call's reconstructable SourceEventID. A result re-appearing in a later
// snapshot of the same record is applied once per window.
func (st *histState) toolResult(tr *toolResult) {
	id := tr.ToolUseID
	if id == "" || st.resolved[id] {
		return
	}
	st.resolved[id] = true
	out := st.a.scrubber.String(contentcap.Cap(resultText(tr.Content), contentcap.DefaultMaxBytes))
	status := strings.ToLower(strings.TrimSpace(tr.Status))
	known := status != ""
	success := status == statusSuccess
	errMsg := ""
	if known && !success {
		errMsg = truncate(firstNonEmpty(out, "status: "+status), maxErrorLen)
	}
	if idx, ok := st.pending[id]; ok {
		ev := &st.res.ToolEvents[idx]
		if known {
			ev.Success = success
			ev.ErrorMessage = errMsg
		}
		ev.ToolOutput = out
		ev.DurationMs = tr.Metrics.DurationMs
		delete(st.pending, id)
		return
	}
	st.res.OutcomeUpdates = append(st.res.OutcomeUpdates, models.ActionOutcomeUpdate{
		SourceFile:    st.path,
		SourceEventID: toolEventID(st.sessID, id),
		SuccessKnown:  known,
		Success:       success,
		ErrorMessage:  errMsg,
		ToolOutput:    out,
		DurationMs:    tr.Metrics.DurationMs,
	})
}

// emit appends ev with the per-session fields stamped, skipping an event
// whose SourceEventID this window already emitted (a block re-appearing in
// a later snapshot line). It returns the event's index and whether it was
// appended.
func (st *histState) emit(ev models.ToolEvent) (int, bool) {
	if st.seen[ev.SourceEventID] {
		return -1, false
	}
	st.seen[ev.SourceEventID] = true
	ev.SourceFile = st.path
	ev.SessionID = st.sessID
	ev.ProjectRoot = st.root
	ev.GitBranch = st.branch
	ev.Tool = models.ToolCortexCode
	st.res.ToolEvents = append(st.res.ToolEvents, ev)
	st.observeAccount(ev)
	return len(st.res.ToolEvents) - 1, true
}

// observeAccount records the session's Snowflake account host against the
// event's exact message id, once per (role, message). It is an
// ACCOUNT-level observation: AccountID only, never a person.
func (st *histState) observeAccount(ev models.ToolEvent) {
	if st.accountHost == "" || ev.MessageID == "" {
		return
	}
	role := "assistant"
	if ev.ActionType == models.ActionUserPrompt {
		role = "user"
	}
	key := role + "|" + ev.MessageID
	if st.accounts[key] {
		return
	}
	st.accounts[key] = true
	st.res.ToolAccounts = append(st.res.ToolAccounts, models.ToolAccountObservation{
		SessionID:   st.sessID,
		Tool:        models.ToolCortexCode,
		BindingKind: "message",
		BindingID:   ev.MessageID,
		Role:        role,
		AccountID:   st.accountHost,
		Source:      accountSource,
		Scope:       accountScope,
		Stage:       "activity",
		ObservedAt:  ev.Timestamp,
	})
}

// toolEventID is the deterministic id of a tool call; a later window
// rebuilds it from the result's tool_use_id alone.
func toolEventID(sessID, callKey string) string {
	return "tool:" + sessID + ":" + callKey
}

// thinkingText concatenates a record's thinking blocks. The live shape is
// {"thinking":{"text":..,"signature":..}}; a bare-string payload is
// accepted too.
func thinkingText(blocks []histBlock) string {
	var b strings.Builder
	for _, blk := range blocks {
		if blk.Type != "thinking" || len(blk.Thinking) == 0 {
			continue
		}
		var text string
		var obj struct {
			Text string `json:"text"`
		}
		if json.Unmarshal(blk.Thinking, &obj) == nil {
			text = obj.Text
		} else {
			_ = json.Unmarshal(blk.Thinking, &text)
		}
		if strings.TrimSpace(text) == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(text)
	}
	return strings.TrimSpace(b.String())
}

// resultText flattens a tool_result's content: a block array of
// {type:"text",text} (live), or a bare string.
func resultText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &parts) != nil {
		return ""
	}
	var b strings.Builder
	for _, p := range parts {
		if p.Text == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(p.Text)
	}
	return b.String()
}

// truncate caps s at n bytes.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

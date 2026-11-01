package dimcode

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/contentcap"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// part is one element of a message's `parts` JSON array. The `type` field
// selects which of the remaining fields is populated: text -> Text,
// thinking -> Thinking, tool_use -> ID/Name/Input/StartTime, tool_result ->
// ToolUseID/Content/StructuredContent/IsError.
type part struct {
	Type              string          `json:"type"`
	Text              string          `json:"text"`
	Thinking          string          `json:"thinking"`
	ID                string          `json:"id"`
	Name              string          `json:"name"`
	Input             json.RawMessage `json:"input"`
	StartTime         string          `json:"startTime"`
	ToolUseID         string          `json:"tool_use_id"`
	Content           json.RawMessage `json:"content"`
	StructuredContent json.RawMessage `json:"structuredContent"`
	IsError           bool            `json:"is_error"`
}

// structured is the subset of a tool_result's structuredContent this adapter
// reads. exec carries exitCode + wallTimeMs; the pointer distinguishes "no
// exit code reported" from exit 0.
type structured struct {
	ExitCode   *int  `json:"exitCode"`
	WallTimeMs int64 `json:"wallTimeMs"`
}

// messageMeta is the `metadata` column: only runId is read.
type messageMeta struct {
	RunID string `json:"runId"`
}

// resultMeta is the `toolMetadata` column of a role=tool_result message:
// DimCode's own verdict on the call (observed: "success").
type resultMeta struct {
	Status string `json:"status"`
}

// toolInput decodes the argument fields the mapper turns into a display
// target. The write/edit/exec/todowrite/agent shapes were observed live;
// read/glob/grep/find are named in DimCode's permission table but never ran in
// the grounding sessions, so their keys are tolerated defensively.
type toolInput struct {
	Path        string `json:"path"`
	FilePath    string `json:"file_path"`
	Command     string `json:"command"`
	Pattern     string `json:"pattern"`
	Query       string `json:"query"`
	URL         string `json:"url"`
	Content     string `json:"content"`
	NewText     string `json:"newText"`
	Action      string `json:"action"`
	TaskTitle   string `json:"taskTitle"`
	AgentName   string `json:"agentName"`
	Prompt      string `json:"prompt"`
	Name        string `json:"name"`
	Skill       string `json:"skill"`
	Description string `json:"description"`
	Todos       []struct {
		Status string `json:"status"`
	} `json:"todos"`
}

// settingsJSON is the subset of session_states.settings this adapter reads.
// metadata carries the vendor's per-session bookkeeping: the branch the
// session last ran on, and, on a sub-agent's own session, the marker and
// pointers back to the spawning parent.
type settingsJSON struct {
	ReasoningEffort string `json:"reasoningEffort"`
	Metadata        struct {
		LastUsedGitBranch string `json:"lastUsedGitBranch"`
		SubagentOrigin    bool   `json:"__subagentOrigin"`
		SubagentType      string `json:"subagentType"`
		ParentSessionID   string `json:"parentSessionId"`
	} `json:"metadata"`
}

// permissionJSON is the subset of session_states.permissionSettings this
// adapter reads: the human-approval posture ("never" = tools run without
// asking, "auto" = the permission engine decides, observed live).
type permissionJSON struct {
	HumanApprovalMode string `json:"humanApprovalMode"`
}

// sessionSettings decodes the session-level settings the events carry.
func sessionSettings(s sessionRow) (settingsJSON, permissionJSON) {
	var st settingsJSON
	var pm permissionJSON
	if strings.TrimSpace(s.Settings) != "" {
		_ = json.Unmarshal([]byte(s.Settings), &st)
	}
	if strings.TrimSpace(s.PermissionSettings) != "" {
		_ = json.Unmarshal([]byte(s.PermissionSettings), &pm)
	}
	return st, pm
}

// toolResult is a tool_result paired to the tool_use it answers.
type toolResult struct {
	Content   string
	Success   bool
	Err       string
	WallMs    int64
	UpdatedMs int64
}

// sessionCtx carries the per-session values every emitted event shares.
type sessionCtx struct {
	sourceFile   string
	sessionID    string
	projectRoot  string
	gitRemote    string
	defaultModel string
	effort       string
	// permission is session_states.permissionSettings.humanApprovalMode and
	// mode is session_states.currentMode; both are the session's CURRENT
	// posture (the store keeps no per-turn history), stamped on every event.
	permission string
	mode       string
	// branch is settings.metadata.lastUsedGitBranch.
	branch string
	// sidechain marks a sub-agent's own session: every event it emits is
	// flagged IsSidechain, the same marker Claude Code uses for sub-agent
	// work, so sub-agent volume segments the same way on every adapter.
	sidechain bool
	// parentID is the spawning parent's session id on a sub-agent's own
	// session (relation row, else the session's own settings pointer).
	parentID string
	runModel map[string]string
}

// modelFor resolves a message's model: the run's recorded model, else the
// session's currently-selected one.
func (c *sessionCtx) modelFor(runID string) string {
	if m := c.runModel[runID]; m != "" {
		return m
	}
	return c.defaultModel
}

// metadata returns the per-event ActionMetadata (reasoning effort, approval
// mode, collaboration mode), or nil when the session carries none.
func (c *sessionCtx) metadata() *models.ActionMetadata {
	md := models.ActionMetadata{
		EffortLevel:       c.effort,
		PermissionMode:    c.permission,
		CollaborationMode: c.mode,
	}
	if c.sidechain {
		// The sub-agent's lifecycle lives in its OWN session row (the
		// cline-cli / hermes model), so ParentSessionID + IsSubagent mark it.
		md.IsSubagent = true
		md.ParentSessionID = c.parentID
	}
	if md.IsZero() {
		return nil
	}
	return &md
}

// parseSession loads a session's full message list and usage rows, pairs
// tool_result messages with the tool_use they answer, and emits its events.
// Every row carries DimCode's own sessionId, which is globally unique and
// what `dim --session` / `dim exec resume` accept. A top-level session's id is
// `sess_<ms>_<random>`; a sub-agent's own session is `subagent_<ms>_<random>`
// (live-grounded 2026-10-21), linked to its parent by childOf (the
// session_relations index) and flagged sidechain.
func (a *Adapter) parseSession(ctx context.Context, db *sql.DB, sourceFile string, s sessionRow, fromOffset int64, childOf map[string]string) (adapter.ParseResult, []string) {
	msgs, err := loadMessages(ctx, db, s.ID)
	if err != nil {
		return adapter.ParseResult{}, []string{fmt.Sprintf("dimcode: session %s: load messages: %v", s.ID, err)}
	}
	runs, err := loadRuns(ctx, db, s.ID)
	if err != nil {
		return adapter.ParseResult{}, []string{fmt.Sprintf("dimcode: session %s: load runs: %v", s.ID, err)}
	}
	ledger, err := loadLedger(ctx, db, s.ID)
	if err != nil {
		return adapter.ParseResult{}, []string{fmt.Sprintf("dimcode: session %s: load ledger: %v", s.ID, err)}
	}

	projectRoot, gitRemote, identity := a.resolveProjectRoot(s.CWD)
	settings, perm := sessionSettings(s)
	parent := childOf[s.ID]
	c := &sessionCtx{
		sourceFile:   sourceFile,
		sessionID:    s.ID,
		projectRoot:  projectRoot,
		gitRemote:    gitRemote,
		defaultModel: s.Model,
		effort:       strings.TrimSpace(settings.ReasoningEffort),
		permission:   strings.TrimSpace(perm.HumanApprovalMode),
		mode:         strings.TrimSpace(s.CurrentMode),
		branch:       strings.TrimSpace(settings.Metadata.LastUsedGitBranch),
		sidechain:    parent != "" || settings.Metadata.SubagentOrigin,
		parentID:     firstNonEmpty(parent, settings.Metadata.ParentSessionID),
		runModel:     map[string]string{},
	}
	for _, r := range runs {
		if r.Model != "" {
			c.runModel[r.RunID] = r.Model
		}
	}

	var warns []string
	decoded := make([][]part, len(msgs))
	results := map[string]toolResult{}
	finalAssistant := map[string]string{}
	for i, m := range msgs {
		var parts []part
		if strings.TrimSpace(m.Parts) != "" {
			if err := json.Unmarshal([]byte(m.Parts), &parts); err != nil {
				warns = append(warns, fmt.Sprintf("dimcode: session %s message %s: malformed parts: %v", s.ID, m.ID, err))
				continue
			}
		}
		decoded[i] = parts
		runID := runIDOf(m)
		switch m.Role {
		case "tool_result":
			var meta resultMeta
			_ = json.Unmarshal([]byte(m.ToolMetadata), &meta)
			for _, p := range parts {
				if p.Type != "tool_result" || p.ToolUseID == "" {
					continue
				}
				results[resultKey(runID, p.ToolUseID)] = decodeResult(p, meta, parseTime(m.UpdatedAt).UnixMilli(), a)
			}
		case "assistant":
			if runID != "" {
				finalAssistant[runID] = m.ID
			}
		}
	}

	var out adapter.ParseResult
	for i, m := range msgs {
		runID := runIDOf(m)
		switch m.Role {
		case "user":
			if ev, ok := a.userRowEvent(c, m, decoded[i]); ok {
				out.ToolEvents = append(out.ToolEvents, ev)
			}
		case "assistant":
			evs, updates := a.assistantEvents(c, m, runID, decoded[i], results, fromOffset)
			out.ToolEvents = append(out.ToolEvents, evs...)
			out.OutcomeUpdates = append(out.OutcomeUpdates, updates...)
		}
	}
	out.TokenEvents = a.tokenEvents(c, runs, ledger, finalAssistant)
	c.stamp(&out)

	// A sub-agent session that the relation table does not (yet) name still
	// carries its parent in its own settings; emit that lineage so the link
	// does not depend on the relation row having been written.
	if parent == "" && settings.Metadata.SubagentOrigin && settings.Metadata.ParentSessionID != "" {
		out.SessionLineages = append(out.SessionLineages, models.SessionLineage{
			SessionID:      s.ID,
			ParentThreadID: settings.Metadata.ParentSessionID,
			ThreadSource:   "subagent",
		})
	}

	adapter.ApplyProjectIdentity(&out, identity)
	return out, warns
}

// stamp applies the session-level values every event shares and that are not
// threaded through each constructor: the git branch and the sidechain flag.
func (c *sessionCtx) stamp(res *adapter.ParseResult) {
	for i := range res.ToolEvents {
		res.ToolEvents[i].GitBranch = c.branch
		res.ToolEvents[i].IsSidechain = c.sidechain
	}
	for i := range res.TokenEvents {
		res.TokenEvents[i].GitBranch = c.branch
		res.TokenEvents[i].IsSidechain = c.sidechain
	}
}

// runIDOf returns the run a message belongs to. User and assistant messages
// carry it in the `metadata` column; tool_result messages leave `metadata`
// empty and carry it in `toolMetadata` (assistant rows carry it in both).
func runIDOf(m messageRow) string {
	for _, raw := range []string{m.Metadata, m.ToolMetadata} {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		var mm messageMeta
		if err := json.Unmarshal([]byte(raw), &mm); err == nil && mm.RunID != "" {
			return mm.RunID
		}
	}
	return ""
}

// resultKey scopes a tool_use id to its run: provider-issued call ids are
// only unique within a run (some providers reuse small ordinals).
func resultKey(runID, toolUseID string) string {
	return runID + "\x00" + toolUseID
}

// decodeResult turns a tool_result part into the verdict, scrubbed output and
// timing the paired action needs.
func decodeResult(p part, meta resultMeta, updatedMs int64, a *Adapter) toolResult {
	text := flattenContent(p.Content)
	var sc structured
	if len(p.StructuredContent) > 0 {
		_ = json.Unmarshal(p.StructuredContent, &sc)
	}
	success := !p.IsError
	if meta.Status != "" && !strings.EqualFold(meta.Status, "success") {
		success = false
	}
	if sc.ExitCode != nil && *sc.ExitCode != 0 {
		success = false
	}
	r := toolResult{
		Content:   a.scrub(contentcap.Cap(text, contentcap.DefaultMaxBytes)),
		Success:   success,
		WallMs:    sc.WallTimeMs,
		UpdatedMs: updatedMs,
	}
	if !success {
		r.Err = a.scrub(truncate(text, 500))
		if r.Err == "" && sc.ExitCode != nil {
			r.Err = "exit code " + strconv.Itoa(*sc.ExitCode)
		}
	}
	return r
}

// flattenContent renders a tool_result `content` that may be a bare string, an
// array of {type,text} blocks, or something else (kept verbatim).
func flattenContent(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var blocks []struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &blocks); err == nil {
		var parts []string
		for _, b := range blocks {
			if t := strings.TrimSpace(b.Text); t != "" {
				parts = append(parts, t)
			}
		}
		return strings.Join(parts, "\n")
	}
	return string(raw)
}

// userRowEvent routes a role=user message: a person's prompt becomes a
// user_prompt row, a runtime-injected row (run terminal status, recovery
// notice, background-task notification, ...) goes through harnessRules to
// the action it really is.
func (a *Adapter) userRowEvent(c *sessionCtx, m messageRow, parts []part) (models.ToolEvent, bool) {
	t := harnessMeta(m.Metadata)
	if userAuthored(t) {
		return a.userPromptEvent(c, m, parts)
	}
	return a.harnessEvent(c, m, t)
}

// userPromptEvent emits the user_prompt row for a role=user message.
func (a *Adapter) userPromptEvent(c *sessionCtx, m messageRow, parts []part) (models.ToolEvent, bool) {
	var texts []string
	for _, p := range parts {
		if p.Type == "text" {
			if t := strings.TrimSpace(p.Text); t != "" {
				texts = append(texts, t)
			}
		}
	}
	body := strings.Join(texts, "\n")
	if body == "" {
		return models.ToolEvent{}, false
	}
	return models.ToolEvent{
		SourceFile:    c.sourceFile,
		SourceEventID: "prompt:" + m.ID,
		SessionID:     c.sessionID,
		ProjectRoot:   c.projectRoot,
		GitRemote:     c.gitRemote,
		Timestamp:     parseTime(m.CreatedAt),
		Tool:          models.ToolDimCode,
		ActionType:    models.ActionUserPrompt,
		Target:        truncate(a.scrub(body), 200),
		Success:       true,
		RawToolName:   "dimcode.user_prompt",
		MessageID:     m.ID,
		Metadata:      c.metadata(),
	}, true
}

// assistantEvents converts one role=assistant message into events: a text
// block emits assistant_message, a tool_use emits the mapped action paired
// with its tool_result, and thinking blocks are threaded onto the first tool
// call that follows (PrecedingReasoning). When fromOffset > 0 and a paired
// result is newer than the cursor, an OutcomeUpdate rides along so an action
// first stored as pending (or before its result existed) is resolved.
func (a *Adapter) assistantEvents(c *sessionCtx, m messageRow, runID string, parts []part, results map[string]toolResult, fromOffset int64) ([]models.ToolEvent, []models.ActionOutcomeUpdate) {
	model := c.modelFor(runID)
	created := parseTime(m.CreatedAt)
	var (
		events    []models.ToolEvent
		updates   []models.ActionOutcomeUpdate
		reasoning []string
	)
	hasToolUse := false
	for _, p := range parts {
		if p.Type == "tool_use" {
			hasToolUse = true
			break
		}
	}
	for i, p := range parts {
		switch p.Type {
		case "thinking":
			if t := strings.TrimSpace(p.Thinking); t != "" {
				reasoning = append(reasoning, t)
			}
		case "text":
			body := strings.TrimSpace(p.Text)
			if body == "" {
				continue
			}
			ev := models.ToolEvent{
				SourceFile:    c.sourceFile,
				SourceEventID: "text:" + m.ID + ":" + strconv.Itoa(i),
				SessionID:     c.sessionID,
				ProjectRoot:   c.projectRoot,
				GitRemote:     c.gitRemote,
				Timestamp:     firstTime(parseTime(p.StartTime), created),
				Model:         model,
				Tool:          models.ToolDimCode,
				ActionType:    models.ActionAssistantMessage,
				Target:        truncate(a.scrub(body), 200),
				Success:       true,
				RawToolName:   "dimcode.assistant_message",
				ToolOutput:    a.scrub(contentcap.Cap(body, contentcap.DefaultMaxBytes)),
				MessageID:     m.ID,
				Metadata:      c.metadata(),
			}
			// A thinking block that streams before narration belongs to it
			// when the message makes no tool call (a thinking -> text
			// message would otherwise drop the reasoning); when a tool_use
			// follows, the reasoning stays pending for that call, which is
			// what it explains.
			if len(reasoning) > 0 && !hasToolUse {
				ev.PrecedingReasoning = a.scrub(truncate(strings.Join(reasoning, "\n"), 2000))
				reasoning = nil
			}
			events = append(events, ev)
		case "tool_use":
			ev := a.toolEvent(c, m, model, created, i, p, results[resultKey(runID, p.ID)], hasResult(results, runID, p.ID))
			if len(reasoning) > 0 {
				ev.PrecedingReasoning = a.scrub(truncate(strings.Join(reasoning, "\n"), 2000))
				reasoning = nil
			}
			events = append(events, ev)
			if res, ok := results[resultKey(runID, p.ID)]; ok && fromOffset > 0 && res.UpdatedMs > fromOffset {
				updates = append(updates, models.ActionOutcomeUpdate{
					SourceFile:    ev.SourceFile,
					SourceEventID: ev.SourceEventID,
					SuccessKnown:  true,
					Success:       res.Success,
					ErrorMessage:  res.Err,
					ToolOutput:    res.Content,
					DurationMs:    res.WallMs,
				})
			}
		}
	}
	return events, updates
}

// hasResult reports whether a tool_result was paired for (runID, toolUseID).
func hasResult(results map[string]toolResult, runID, toolUseID string) bool {
	_, ok := results[resultKey(runID, toolUseID)]
	return ok
}

// toolEvent builds the action row for one tool_use block.
func (a *Adapter) toolEvent(c *sessionCtx, m messageRow, model string, created time.Time, idx int, p part, res toolResult, paired bool) models.ToolEvent {
	actionType, target := mapTool(p.Name, p.Input)
	sourceID := "tool:" + m.ID + ":" + p.ID
	if p.ID == "" {
		sourceID = "tool:" + m.ID + ":" + strconv.Itoa(idx) + ":" + p.Name
	}
	ev := models.ToolEvent{
		SourceFile:    c.sourceFile,
		SourceEventID: sourceID,
		SessionID:     c.sessionID,
		ProjectRoot:   c.projectRoot,
		GitRemote:     c.gitRemote,
		Timestamp:     firstTime(parseTime(p.StartTime), created),
		Model:         model,
		Tool:          models.ToolDimCode,
		ActionType:    actionType,
		Target:        truncate(a.scrub(target), 200),
		Success:       true,
		RawToolName:   p.Name,
		RawToolInput:  a.scrubRaw(p.Input),
		ContentBytes:  authoredBytes(p.Name, p.Input),
		MessageID:     m.ID,
		Metadata:      c.metadata(),
	}
	if !paired {
		ev.OutcomePending = true
		return ev
	}
	ev.Success = res.Success
	ev.ErrorMessage = res.Err
	ev.ToolOutput = res.Content
	ev.DurationMs = res.WallMs
	return ev
}

// mapTool resolves a DimCode tool name onto the normalized action taxonomy,
// deriving a display target from the decoded arguments. The names are the
// builtins read out of DimCode's own tool registry (read, write, edit, exec,
// glob, grep, todowrite, AskUserQuestion, agent, skill, wait, WebFetch,
// WebSearch, chrome, goal, workflow, workflow_result) plus find/rg/search from
// its permission table. Unmapped names (MCP/dynamic tools, whose name format
// is not grounded) fall back to ActionUnknown with the raw name preserved in
// RawToolName.
func mapTool(name string, args []byte) (actionType, target string) {
	var in toolInput
	_ = json.Unmarshal(args, &in)
	fp := firstNonEmpty(in.Path, in.FilePath)

	switch strings.ToLower(strings.TrimSpace(name)) {
	case "exec":
		return models.ActionRunCommand, firstNonEmpty(in.Command, name)
	case "read":
		return models.ActionReadFile, firstNonEmpty(fp, name)
	case "write":
		return models.ActionWriteFile, firstNonEmpty(fp, name)
	case "edit":
		return models.ActionEditFile, firstNonEmpty(fp, name)
	case "glob", "find":
		return models.ActionSearchFiles, firstNonEmpty(in.Pattern, fp, name)
	case "grep", "rg", "search":
		return models.ActionSearchText, firstNonEmpty(in.Pattern, in.Query, name)
	case "webfetch":
		return models.ActionWebFetch, firstNonEmpty(in.URL, name)
	case "websearch":
		return models.ActionWebSearch, firstNonEmpty(in.Query, name)
	case "todowrite":
		return models.ActionTodoUpdate, todoSummary(in)
	case "askuserquestion":
		return models.ActionAskUser, name
	case "agent":
		// The agent tool multiplexes create / create_external / list /
		// cancel on its `action` argument: only the first two launch a
		// sub-agent; list and cancel are pool-control verbs.
		// (An if, not a nested switch: the tooltax conformance pin
		// extracts the case labels of this function's switches as the
		// native-name domain, and "list"/"cancel" are not tool names.)
		if act := strings.ToLower(strings.TrimSpace(in.Action)); act == "list" || act == "cancel" {
			return models.ActionAgentControl, firstNonEmpty(in.Action, name)
		}
		return models.ActionSpawnSubagent, firstNonEmpty(in.TaskTitle, in.AgentName, in.Prompt, name)
	case "wait":
		return models.ActionSubagentWait, name
	case "skill":
		return models.ActionSkillInvoke, firstNonEmpty(in.Skill, in.Name, name)
	case "chrome":
		return models.ActionBrowserAction, firstNonEmpty(in.Action, in.URL, name)
	case "goal", "workflow", "workflow_result":
		return models.ActionHarnessCall, firstNonEmpty(in.Action, in.Name, name)
	default:
		return models.ActionUnknown, firstNonEmpty(in.Command, fp, in.Pattern, in.Query, in.URL, name)
	}
}

// todoSummary renders a todowrite call as "N todos (M completed)".
func todoSummary(in toolInput) string {
	if len(in.Todos) == 0 {
		return "todowrite"
	}
	done := 0
	for _, t := range in.Todos {
		if t.Status == "completed" {
			done++
		}
	}
	return fmt.Sprintf("%d todos (%d completed)", len(in.Todos), done)
}

// authoredBytes returns the byte length of code the model authored in a
// write/edit tool call, from the argument body it emitted.
func authoredBytes(name string, args []byte) int64 {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "write":
		var in toolInput
		_ = json.Unmarshal(args, &in)
		return int64(len(in.Content))
	case "edit":
		var in toolInput
		_ = json.Unmarshal(args, &in)
		return int64(len(in.NewText))
	default:
		return 0
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// firstTime returns the first non-zero time.
func firstTime(ts ...time.Time) time.Time {
	for _, t := range ts {
		if !t.IsZero() {
			return t
		}
	}
	return time.Time{}
}

// truncate shortens s to at most n bytes without splitting a UTF-8 rune.
func truncate(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

package mistralcode

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// This file implements the SECOND on-disk layout this package captures:
// the Mistral Code IDE store.
//
// Mistral Code ships two very different clients that share nothing but a
// name and a vendor:
//
//   - the `vibe` CLI (adapter.go), writing per-session directories under
//     $VIBE_HOME ?? ~/.vibe/logs/session/;
//   - the VS Code extension `mistralai.mistral-code` and the JetBrains
//     "Mistral Code Enterprise" plugin — both forks of Continue — writing
//     $MISTRALCODE_GLOBAL_DIR ?? ~/.mistralcode/sessions/, as a
//     `sessions.json` index plus one `<sessionId>.json` document per
//     session.
//
// Layout dispatch is on the file's SHAPE (classifyLayout), never on a tool
// or client identity (CLAUDE.md Module Boundaries #3) — the same
// layout-sniffing pattern kirocli and gemini already use. Both layouts
// stay under models.ToolMistralCode: it is one vendor's product, and
// splitting the tool id would fragment its cost rollups for no capture
// benefit. What DOES differ per layout — the capture surface — is carried
// honestly in models.SessionSurface (cli/vibe vs ide/vscode).
//
// # Grounding
//
// The document shape below is Continue's own `Session` type
// (continuedev/continue, core/index.d.ts) — the upstream the extension
// forks — cross-read against the Mistral Code extension bundle. The store
// is LOGIN-GATED and is NOT present on the machine this adapter was
// written on, so every fixture under testdata/mistralcode/ide/ is
// SYNTHETIC and labelled as such in that directory's README. Unknown
// fields are ignored, absent fields degrade to zero values, and no row is
// invented from a field we did not observe.
//
// # JetBrains
//
// The JetBrains plugin writes the SAME store in the SAME location with no
// client discriminator anywhere in the document, so a session authored
// from IntelliJ is indistinguishable on disk from one authored in VS
// Code. The surface stamp therefore says `ide` + host `vscode` — the
// overwhelmingly common case — rather than guessing `jetbrains` per
// session. Correcting this needs a discriminator Mistral does not
// currently persist; it is a documented gap, not a heuristic.

// layout names the on-disk shape a path belongs to.
type layout int

const (
	// layoutNone means the path is not one this adapter parses.
	layoutNone layout = iota
	// layoutVibe is the `vibe` CLI's per-session directory
	// (<root>/session_<ts>_<8hex>/messages.jsonl + meta.json).
	layoutVibe
	// layoutIDE is the Continue-fork IDE store
	// (<root>/<sessionId>.json + the sibling sessions.json index).
	layoutIDE
)

const (
	// ideSessionsDirName is the directory both env-overridden and
	// default IDE roots end in.
	ideSessionsDirName = "sessions"
	// ideIndexName is the session INDEX, deliberately not a session
	// document: it is read as a sibling for timestamps, never tracked.
	ideIndexName = "sessions.json"
	// ideHomeDirName is the IDE store's home directory name.
	ideHomeDirName = ".mistralcode"
	// ideGlobalDirEnv is the extension's own storage-root override.
	ideGlobalDirEnv = "MISTRALCODE_GLOBAL_DIR"
	// surfaceHostIDE is the host token stamped for the IDE layout.
	// See the JetBrains note in this file's header.
	surfaceHostIDE = "vscode"
	// surfaceHostCLI is the host token stamped for the vibe layout.
	surfaceHostCLI = "vibe"
)

// classifyLayout reports which on-disk layout path belongs to, independent
// of watch roots (the root gate lives in IsSessionFile). Comparison is on
// a slash-normalized, lower-cased copy so a foreign host's separators and
// case-insensitive mounts match too.
func classifyLayout(path string) layout {
	switch {
	case matchesShape(path):
		return layoutVibe
	case matchesIDEShape(path):
		return layoutIDE
	default:
		return layoutNone
	}
}

// matchesIDEShape reports whether path is an IDE session DOCUMENT:
// `<root>/<sessionId>.json`, where <root> is a directory named `sessions`.
// The `sessions.json` index is excluded (it is metadata about sessions,
// not a session), as is anything nested deeper — Continue keeps per-thread
// artifacts in sibling subdirectories that carry no transcript.
func matchesIDEShape(path string) bool {
	lower := strings.ReplaceAll(strings.ToLower(path), `\`, "/")
	base := filepath.Base(lower)
	if !strings.HasSuffix(base, ".json") || base == ideIndexName {
		return false
	}
	return filepath.Base(filepath.Dir(lower)) == ideSessionsDirName
}

// ideRoots returns the IDE store roots: $MISTRALCODE_GLOBAL_DIR/sessions
// first when the operator has overridden the extension's storage root,
// then <home>/.mistralcode/sessions for every cross-mount-resolved $HOME
// (the same add(env)+per-home shape clinecli uses for CLINE_DIR). The env
// var is only meaningful for THIS process's environment, so it is not
// re-resolved per home.
func ideRoots() []string {
	var roots []string
	if env := strings.TrimSpace(os.Getenv(ideGlobalDirEnv)); env != "" {
		roots = append(roots, filepath.Join(env, ideSessionsDirName))
	}
	for _, h := range homeRoots() {
		roots = append(roots, filepath.Join(h, ideHomeDirName, ideSessionsDirName))
	}
	return roots
}

// continueSession is the subset of Continue's `Session` this adapter
// reads. Everything else in the document (UI state, context providers,
// rules) is deliberately ignored.
type continueSession struct {
	SessionID          string                `json:"sessionId"`
	Title              string                `json:"title"`
	WorkspaceDirectory string                `json:"workspaceDirectory"`
	History            []continueHistoryItem `json:"history"`
	Mode               string                `json:"mode"`
	ChatModelTitle     string                `json:"chatModelTitle"`
}

// continueHistoryItem is one entry of `history[]` — a message plus the
// context/tool bookkeeping Continue hangs off it.
type continueHistoryItem struct {
	Message        continueMessage         `json:"message"`
	ContextItems   []continueContextItem   `json:"contextItems"`
	ToolCallStates []continueToolCallState `json:"toolCallStates"`
	PromptLogs     []continuePromptLog     `json:"promptLogs"`
}

// continueMessage is a chat message. Role is one of
// user|assistant|tool|system|thinking; content is a bare string OR an
// array of typed parts.
type continueMessage struct {
	Role       string             `json:"role"`
	Content    json.RawMessage    `json:"content"`
	ToolCalls  []continueToolCall `json:"toolCalls"`
	Usage      *continueUsage     `json:"usage"`
	ToolCallID string             `json:"toolCallId"`
}

// continueToolCall is an OpenAI-shaped function call.
type continueToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

// continueToolCallState carries a tool call's status and rendered output.
// Used only as a FALLBACK for outcomes: the role="tool" message is the
// primary source, because it is what the model actually saw.
type continueToolCallState struct {
	ToolCallID string                `json:"toolCallId"`
	ToolCall   continueToolCall      `json:"toolCall"`
	Status     string                `json:"status"`
	Output     []continueContextItem `json:"output"`
}

// continueContextItem is Continue's uniform {name,description,content}
// envelope, used both for context attachments and tool output.
type continueContextItem struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Content     string `json:"content"`
}

// continuePromptLog records which model actually served a turn.
type continuePromptLog struct {
	ModelTitle    string `json:"modelTitle"`
	ModelProvider string `json:"modelProvider"`
}

// continueUsage is the per-assistant-message token envelope. promptTokens
// is GROSS (it includes cachedTokens), matching the OpenAI convention the
// vibe layer already nets against.
type continueUsage struct {
	PromptTokens        int64 `json:"promptTokens"`
	CompletionTokens    int64 `json:"completionTokens"`
	PromptTokensDetails *struct {
		CachedTokens     int64 `json:"cachedTokens"`
		CacheWriteTokens int64 `json:"cacheWriteTokens"`
	} `json:"promptTokensDetails"`
	CompletionTokensDetails *struct {
		ReasoningTokens int64 `json:"reasoningTokens"`
	} `json:"completionTokensDetails"`
}

// continueIndexEntry is one row of the sibling `sessions.json` index. It
// is read for its timestamps only — the document itself carries none.
type continueIndexEntry struct {
	SessionID   string          `json:"sessionId"`
	DateCreated json.RawMessage `json:"dateCreated"`
	DateUpdated json.RawMessage `json:"dateUpdated"`
}

// parseIDESession parses one Continue-fork session document.
//
// The store rewrites the WHOLE document on every turn, so a byte cursor
// has no meaning: fromOffset is ignored and NewOffset is the file size
// (the same contract copilot's modern snapshot path uses). Every row's
// SourceEventID is derived deterministically from (sessionId, history
// index), so the store's UNIQUE (source_file, source_event_id) index
// collapses the re-emitted prefix on every reparse.
func (a *Adapter) parseIDESession(ctx context.Context, path string) (adapter.ParseResult, error) {
	body, err := os.ReadFile(path) //nolint:gosec // watched session file
	if err != nil {
		return adapter.ParseResult{}, nil // vanished mid-poll; try later
	}
	if err := ctx.Err(); err != nil {
		return adapter.ParseResult{}, err
	}

	res := adapter.ParseResult{NewOffset: int64(len(body))}
	var sess continueSession
	if err := json.Unmarshal(body, &sess); err != nil {
		res.Warnings = append(res.Warnings, "ide session document decode: "+err.Error())
		return res, nil
	}

	sessID := firstNonEmpty(sess.SessionID, strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)))
	root, branch, projectIdentity := resolveProjectRoot(sess.WorkspaceDirectory)
	base := ideSessionStart(path, sessID)

	outcomes := collectIDEOutcomes(sess.History)
	ctxRow := ideContext{
		sourceFile:   path,
		sessionID:    sessID,
		projectRoot:  root,
		gitBranch:    branch,
		sessionModel: sess.ChatModelTitle,
	}
	for i, item := range sess.History {
		ctxRow.timestamp = base.Add(time.Duration(i) * time.Millisecond)
		ctxRow.index = i
		a.emitIDEItem(ctxRow, item, outcomes, &res)
	}

	adapter.ApplyProjectIdentity(&res, projectIdentity)
	if sessID != "" {
		res.SessionSurfaces = append(res.SessionSurfaces, models.SessionSurface{
			SessionID:   sessID,
			Surface:     models.SurfaceIDE,
			SurfaceHost: surfaceHostIDE,
		})
	}
	return res, nil
}

// ideOutcome is a tool call's observed result.
type ideOutcome struct {
	output  string
	success bool
}

// collectIDEOutcomes indexes every tool result in the document by the
// toolCallId it answers. The role="tool" message wins over the
// toolCallStates mirror because it is the text the model actually saw;
// the mirror fills in calls whose result message has not landed yet.
func collectIDEOutcomes(history []continueHistoryItem) map[string]ideOutcome {
	out := map[string]ideOutcome{}
	for _, item := range history {
		for _, st := range item.ToolCallStates {
			id := firstNonEmpty(st.ToolCallID, st.ToolCall.ID)
			if id == "" {
				continue
			}
			text := contextItemsText(st.Output)
			if text == "" && st.Status == "" {
				continue
			}
			out[id] = ideOutcome{output: text, success: ideStatusSuccess(st.Status, text)}
		}
	}
	for _, item := range history {
		if item.Message.Role != "tool" || item.Message.ToolCallID == "" {
			continue
		}
		text := continueText(item.Message.Content)
		out[item.Message.ToolCallID] = ideOutcome{output: text, success: !looksLikeIDEError(text)}
	}
	return out
}

// ideStatusSuccess resolves a toolCallStates entry's verdict from its
// status field, falling back to the output text when the status is one
// this adapter has no grounded meaning for.
func ideStatusSuccess(status, text string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "errored", "canceled", "cancelled":
		return false
	case "done", "":
		return !looksLikeIDEError(text)
	default:
		return !looksLikeIDEError(text)
	}
}

// looksLikeIDEError is the documented Continue convention: a failed tool
// renders its result as an "Error: ..." string. Deliberately narrower
// than the vibe layer's looksLikeError, whose `<tool_error>` wrapper and
// Python traceback markers are vibe-specific renderings.
func looksLikeIDEError(text string) bool {
	return strings.HasPrefix(strings.TrimSpace(text), "Error")
}

// ideContext is the per-row invariant state of one IDE session parse. It
// exists so the emit helpers take one parameter instead of six positional
// strings — the fields never vary within a document except timestamp and
// index, which advance per history entry.
type ideContext struct {
	sourceFile   string
	sessionID    string
	projectRoot  string
	gitBranch    string
	sessionModel string
	timestamp    time.Time
	index        int
}

// eventID is the deterministic per-history-entry row id
// (`<sessionId>:<historyIndex>`). Tool rows suffix it further.
func (c ideContext) eventID() string {
	return c.sessionID + ":" + strconv.Itoa(c.index)
}

// emitIDEItem emits the rows for one history entry: a user prompt, or an
// assistant message plus one row per tool call plus its token event.
// role="tool" entries mint no row of their own — they are the OUTCOME of
// an already-emitted call, folded in through the outcomes map. system and
// thinking entries carry no user-visible action.
func (a *Adapter) emitIDEItem(
	c ideContext,
	item continueHistoryItem,
	outcomes map[string]ideOutcome,
	res *adapter.ParseResult,
) {
	switch item.Message.Role {
	case "user":
		text := a.scrubber.String(continueText(item.Message.Content))
		if text == "" {
			return
		}
		res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
			SourceFile: c.sourceFile, SourceEventID: c.eventID(),
			SessionID: c.sessionID, ProjectRoot: c.projectRoot, GitBranch: c.gitBranch,
			Timestamp: c.timestamp,
			Tool:      models.ToolMistralCode, ActionType: models.ActionUserPrompt,
			Target: truncate(text, maxTargetLen), Success: true,
		})
	case "assistant":
		if text := a.scrubber.String(continueText(item.Message.Content)); text != "" {
			res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
				SourceFile: c.sourceFile, SourceEventID: c.eventID(),
				SessionID: c.sessionID, ProjectRoot: c.projectRoot, GitBranch: c.gitBranch,
				Timestamp: c.timestamp,
				Tool:      models.ToolMistralCode, ActionType: models.ActionAssistantMessage,
				Target: truncate(text, maxTargetLen), Success: true,
			})
		}
		for n, tc := range item.Message.ToolCalls {
			res.ToolEvents = append(res.ToolEvents, a.ideToolEvent(c, n, tc, outcomes))
		}
		if ev, ok := ideTokenEvent(c, ideModel(item, c.sessionModel), item.Message.Usage); ok {
			res.TokenEvents = append(res.TokenEvents, ev)
		}
	}
}

// ideToolEvent builds one tool row from an assistant message's toolCalls[]
// entry, carrying the matching result when the document already holds one.
func (a *Adapter) ideToolEvent(
	c ideContext,
	n int,
	tc continueToolCall,
	outcomes map[string]ideOutcome,
) models.ToolEvent {
	ev := models.ToolEvent{
		SourceFile: c.sourceFile, SourceEventID: c.eventID() + ":tool:" + strconv.Itoa(n),
		SessionID: c.sessionID, ProjectRoot: c.projectRoot, GitBranch: c.gitBranch,
		Timestamp: c.timestamp,
		Tool:      models.ToolMistralCode, ActionType: mapIDETool(tc.Function.Name),
		RawToolName:  tc.Function.Name,
		RawToolInput: a.scrubber.RawJSON([]byte(tc.Function.Arguments)),
		Target:       truncate(a.scrubber.String(ideTargetFromArgs(tc.Function.Arguments)), maxTargetLen),
		Success:      true,
	}
	if out, ok := outcomes[tc.ID]; ok {
		ev.ToolOutput = a.scrubber.String(out.output)
		ev.Success = out.success
	}
	return ev
}

// ideTokenEvent builds the per-assistant-message TokenEvent. Unlike the
// vibe layout — whose only token statement is meta.json's session-
// cumulative block — the IDE store carries usage PER MESSAGE, so this is
// a genuinely finer tier. promptTokens is GROSS and is netted against
// cachedTokens (feedback_openai_input_is_gross).
//
// UNVERIFIED, one direction only — cacheWriteTokens (M1).
// `promptTokensDetails.cachedTokens` is the OpenAI-convention cache READ
// and is definitionally inside promptTokens, so netting it is grounded.
// Whether Continue's promptTokens ALSO includes
// `promptTokensDetails.cacheWriteTokens` is NOT grounded: the field is a
// Continue/Anthropic-passthrough extension with no published statement
// either way, and the store is login-gated so no live session has been
// captured here (the fixture is synthetic — testdata/mistralcode/README.md).
//
// The honest choice is therefore to net ONLY what is known to be
// included: input = promptTokens - cachedTokens, with cacheWriteTokens
// recorded ALONGSIDE as CacheCreationTokens and never subtracted. The
// consequence, stated plainly: if promptTokens turns out to include cache
// writes, InputTokens is over-counted by exactly cacheWriteTokens (and
// cost is over-stated by the same amount at the input rate) until one
// live session settles it. Guessing the other way would UNDER-count on
// the equally likely opposite reality, and an under-count is the harder
// error to notice. Reliability below is ReliabilityApproximate, which is
// what carries this uncertainty downstream.
//
// The check that settles it is in docs/mistral-code-adapter.md's operator
// checklist ("cacheWriteTokens direction"): on a cache-writing turn,
// compare promptTokens against the provider's own billed input.
func ideTokenEvent(c ideContext, model string, usage *continueUsage) (models.TokenEvent, bool) {
	if usage == nil {
		return models.TokenEvent{}, false
	}
	var cacheRead, cacheWrite, reasoning int64
	if d := usage.PromptTokensDetails; d != nil {
		cacheRead, cacheWrite = d.CachedTokens, d.CacheWriteTokens
	}
	if d := usage.CompletionTokensDetails; d != nil {
		reasoning = d.ReasoningTokens
	}
	if usage.PromptTokens == 0 && usage.CompletionTokens == 0 && cacheRead == 0 && cacheWrite == 0 {
		return models.TokenEvent{}, false
	}
	// Net against the cache READ only — see the M1 note above: whether
	// promptTokens also includes cacheWrite is unverified, so cacheWrite
	// is recorded but never subtracted.
	netInput := usage.PromptTokens - cacheRead
	if netInput < 0 {
		netInput = 0
	}
	return models.TokenEvent{
		SourceFile:          c.sourceFile,
		SourceEventID:       c.eventID() + ":usage",
		SessionID:           c.sessionID,
		ProjectRoot:         c.projectRoot,
		GitBranch:           c.gitBranch,
		Timestamp:           c.timestamp,
		Tool:                models.ToolMistralCode,
		Model:               model,
		InputTokens:         netInput,
		OutputTokens:        usage.CompletionTokens,
		CacheReadTokens:     cacheRead,
		CacheCreationTokens: cacheWrite,
		ReasoningTokens:     reasoning,
		// Per-message counts read out of the client's own transcript
		// store: trustworthy but not invoice-verified, exactly like the
		// vibe layout's session block.
		Source:      models.TokenSourceJSONL,
		Reliability: models.ReliabilityApproximate,
	}, true
}

// ideModel resolves the model that served one history entry:
// promptLogs[0].modelTitle (what actually ran) beats the session's
// chatModelTitle (what was selected at the top of the document), and an
// entry with neither yields "" rather than a guess. This is a strictly
// better ladder than the vibe layout's, whose last rung is an admitted
// sorted-first-key guess — here there is nothing left to guess FROM.
func ideModel(item continueHistoryItem, sessionModel string) string {
	for _, log := range item.PromptLogs {
		if t := strings.TrimSpace(log.ModelTitle); t != "" {
			return t
		}
	}
	return strings.TrimSpace(sessionModel)
}

// ideToolActions maps a Continue-fork tool name to a normalized action.
// Keys are the built-in tool names Continue registers (the `builtin_`
// prefix is how the fork namespaces them); the bare aliases cover
// documents written by builds that omit the prefix. An unlisted name is
// NOT forced into a category — it falls through mapIDETool to the MCP
// check and then to the vibe table, and finally to ActionUnknown with the
// raw name preserved on the row.
var ideToolActions = map[string]string{
	"builtin_read_file":                  models.ActionReadFile,
	"builtin_read_currently_open_file":   models.ActionReadFile,
	"builtin_view_diff":                  models.ActionReadFile,
	"builtin_view_repo_map":              models.ActionReadFile,
	"builtin_request_rule":               models.ActionReadFile,
	"builtin_create_new_file":            models.ActionWriteFile,
	"builtin_create_rule_block":          models.ActionWriteFile,
	"builtin_edit_existing_file":         models.ActionEditFile,
	"builtin_search_and_replace_in_file": models.ActionEditFile,
	"builtin_run_terminal_command":       models.ActionRunCommand,
	"builtin_grep_search":                models.ActionSearchText,
	"builtin_codebase_tool":              models.ActionSearchText,
	"builtin_file_glob_search":           models.ActionSearchFiles,
	"builtin_ls":                         models.ActionSearchFiles,
	"builtin_view_subdirectory":          models.ActionSearchFiles,
	"builtin_search_web":                 models.ActionWebSearch,
	"builtin_fetch_url_content":          models.ActionWebFetch,
	"read_file":                          models.ActionReadFile,
	"read_currently_open_file":           models.ActionReadFile,
	"create_new_file":                    models.ActionWriteFile,
	"edit_existing_file":                 models.ActionEditFile,
	"run_terminal_command":               models.ActionRunCommand,
	"grep_search":                        models.ActionSearchText,
	"file_glob_search":                   models.ActionSearchFiles,
	"ls":                                 models.ActionSearchFiles,
	"search_web":                         models.ActionWebSearch,
	"fetch_url_content":                  models.ActionWebFetch,
}

// mapIDETool resolves a Continue-fork tool name to a normalized action:
// the IDE table first, then the MCP-name shape, then the vibe CLI's own
// table (both clients are the same vendor and share several tool names),
// then ActionUnknown.
func mapIDETool(name string) string {
	if action, ok := ideToolActions[strings.ToLower(strings.TrimSpace(name))]; ok {
		return action
	}
	if models.IsMCPToolName(name) {
		return models.ActionMCPCall
	}
	action, _ := mapVibeTool(name, "")
	return action
}

// ideTargetKeys is the ordered list of argument fields that can hold a
// tool call's human-meaningful target — the path it touched, the command
// it ran, the query it searched. First hit wins.
var ideTargetKeys = []string{
	"filepath", "filePath", "file_path", "path", "dirpath", "dirPath",
	"command", "query", "pattern", "url", "name",
}

// ideTargetFromArgs pulls the target out of a tool call's JSON arguments
// string, walking ideTargetKeys in order.
func ideTargetFromArgs(args string) string {
	args = strings.TrimSpace(args)
	if args == "" {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(args), &m); err != nil {
		return ""
	}
	for _, k := range ideTargetKeys {
		if v, ok := m[k].(string); ok && strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// continueText flattens a Continue message's `content`, which is either a
// bare string or an array of typed parts. Only `type:"text"` parts
// contribute; image parts and other typed payloads are skipped rather
// than rendered as noise.
func continueText(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return strings.TrimSpace(s)
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &parts); err != nil {
		return ""
	}
	var b strings.Builder
	for _, p := range parts {
		if p.Type != "text" || strings.TrimSpace(p.Text) == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.WriteString(p.Text)
	}
	return strings.TrimSpace(b.String())
}

// contextItemsText joins the `content` of a tool call's rendered output
// items.
func contextItemsText(items []continueContextItem) string {
	var b strings.Builder
	for _, it := range items {
		if strings.TrimSpace(it.Content) == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.WriteString(it.Content)
	}
	return strings.TrimSpace(b.String())
}

// ideSessionStart resolves the session's start time. The session document
// carries NO timestamps at all, so the sibling `sessions.json` index is
// consulted for this session's dateCreated; when that is missing or
// unparseable the document's own modification time stands in. Per-entry
// timestamps are then a stable +1ms ladder, the same convention the vibe
// layout uses over meta.json's start_time.
func ideSessionStart(path, sessID string) time.Time {
	if t := ideIndexDate(filepath.Join(filepath.Dir(path), ideIndexName), sessID); !t.IsZero() {
		return t
	}
	if info, err := os.Stat(path); err == nil {
		return info.ModTime().UTC()
	}
	return time.Time{}
}

// ideIndexDate reads the sessions.json index and returns the named
// session's dateCreated (falling back to dateUpdated). Returns the zero
// time when the index is absent, unreadable, malformed, or silent about
// this session — every one of which is a normal state, not an error.
func ideIndexDate(indexPath, sessID string) time.Time {
	body, err := os.ReadFile(indexPath) //nolint:gosec // sibling of a watched file
	if err != nil {
		return time.Time{}
	}
	var entries []continueIndexEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return time.Time{}
	}
	for _, e := range entries {
		if e.SessionID != sessID {
			continue
		}
		if t := parseFlexTime(e.DateCreated); !t.IsZero() {
			return t
		}
		return parseFlexTime(e.DateUpdated)
	}
	return time.Time{}
}

// parseFlexTime decodes an index timestamp, which Continue has written as
// a JSON number of epoch milliseconds, as a stringified number of the
// same, and as an ISO-8601 string across versions. All three are
// accepted; anything else yields the zero time.
func parseFlexTime(raw json.RawMessage) time.Time {
	if len(raw) == 0 || string(raw) == "null" {
		return time.Time{}
	}
	var n json.Number
	if err := json.Unmarshal(raw, &n); err == nil {
		if ms, err := n.Int64(); err == nil && ms > 0 {
			return time.UnixMilli(ms).UTC()
		}
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return time.Time{}
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	if ms, err := strconv.ParseInt(s, 10, 64); err == nil && ms > 0 {
		return time.UnixMilli(ms).UTC()
	}
	return parseTime(s)
}

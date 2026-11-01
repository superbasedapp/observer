package kimchi

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/adapter/cacheobs"
	"github.com/marmutapp/superbased-observer/internal/contentcap"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// placeholderRoot is the synthetic project root used when the session
// header carries no cwd. store.Ingest promotes it via ON CONFLICT once a
// real cwd is observed.
const placeholderRoot = "[kimchi]"

// agentDirEnv relocates kimchi's whole data home (pi-mono's
// `<APP>_CODING_AGENT_DIR`, read verbatim off the 1.17.0 bundle:
// `process.env.KIMCHI_CODING_AGENT_DIR ? resolve(…) : join(homedir(),
// ".config", "kimchi", "harness", …)`).
const agentDirEnv = "KIMCHI_CODING_AGENT_DIR"

// targetMax / reasoningMax / errorMax bound the short display columns.
const (
	targetMax    = 200
	reasoningMax = 200
	errorMax     = 500
)

// genTimingV is this adapter's gen-timing parser version (see genMs).
const genTimingV = 1

// maxGenSpan rejects an implausible stream span (a clock jump, a record
// rewritten long after the fact) rather than stamping it.
const maxGenSpan = time.Hour

// Adapter parses Kimchi session transcripts under
// ~/.config/kimchi/harness/sessions. See the package doc for the layout,
// the token semantics and the off-limits file list.
type Adapter struct {
	scrubber *scrub.Scrubber
	roots    []string
}

// New returns an adapter with the default scrubber and the platform watch
// roots.
func New() *Adapter {
	return &Adapter{scrubber: scrub.New(), roots: defaultRoots()}
}

// NewWithOptions customizes the scrubber and/or watch roots for tests. A
// nil scrubber falls back to scrub.New(); no roots falls back to the
// platform defaults.
func NewWithOptions(s *scrub.Scrubber, roots ...string) *Adapter {
	if s == nil {
		s = scrub.New()
	}
	if len(roots) == 0 {
		roots = defaultRoots()
	}
	return &Adapter{scrubber: s, roots: roots}
}

// Name implements adapter.Adapter.
func (*Adapter) Name() string { return models.ToolKimchi }

// WatchPaths implements adapter.Adapter.
func (a *Adapter) WatchPaths() []string { return a.roots }

// defaultRoots returns every plausible Kimchi session tree.
//
// Kimchi keeps its data home at `<home>/.config/kimchi/harness` on EVERY
// platform — grounded on both of the operator's installs: WSL
// `/home/<u>/.config/kimchi/harness` and native Windows
// `C:\Users\<u>\.config\kimchi\harness` (NOT %APPDATA%; the bundle joins
// homedir() with ".config" unconditionally). One join per cross-mount-
// resolved $HOME therefore covers a WSL2 observer reading the Windows
// home and vice versa.
//
// $KIMCHI_CODING_AGENT_DIR wins when set; like junie's JUNIE_HOME it is
// only meaningful for this process's own environment, so it contributes
// one extra absolutized root alongside the per-home defaults (deduped).
func defaultRoots() []string {
	seen := map[string]bool{}
	var roots []string
	add := func(p string) {
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		roots = append(roots, p)
	}
	if dir := adapter.AbsEnvRoot(agentDirEnv); dir != "" {
		add(filepath.Join(dir, "sessions"))
	}
	for _, h := range crossmount.AllHomes() {
		if h.Path == "" {
			continue
		}
		add(filepath.Join(h.Path, ".config", "kimchi", "harness", "sessions"))
	}
	return roots
}

// IsSessionFile implements adapter.Adapter. Two predicates ANDed: the
// `.jsonl` extension and under one of this adapter's own watch roots.
// Sessions live one level down (`sessions/--<cwd-slug>--/<ts>_<uuid>.jsonl`),
// next to an `image-cache/` dir that never holds JSONL. The under-root
// gate is the real authority: the bare extension collides with
// claude-code, codex, pi, prime-agent and openclaw.
func (a *Adapter) IsSessionFile(path string) bool {
	if !strings.HasSuffix(strings.ToLower(path), ".jsonl") {
		return false
	}
	return adapter.UnderAnyWatchRoot(path, a.WatchPaths())
}

// ParseSessionFile implements adapter.Adapter. It streams the JSONL from
// fromOffset to EOF, emitting ToolEvents (session start, user prompts,
// assistant messages, tool calls stamped with their paired results, API
// errors, shell executions, compactions), TokenEvents (one per usage-
// bearing assistant record), Tier-2 cache observations and, for a forked
// or sub-agent transcript, one SessionLineage marker.
//
// On a resumed parse the already-consumed prefix is re-scanned for the
// session-level state it established (header cwd + parentSession, the
// selected model, the thinking level, the sub-agent marker) — all of it
// sits behind the cursor once the session has any history.
//
// Malformed lines are warned about and skipped with the cursor advanced.
// A partial trailing line and a tool call whose result has not landed yet
// are DEFERRED (pending.go) so the next parse re-reads them whole.
func (a *Adapter) ParseSessionFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	f, err := os.Open(path) //nolint:gosec // path comes from the watcher's own watch roots
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("kimchi.ParseSessionFile: open %s: %w", path, err)
	}
	defer f.Close()

	st := &parseState{
		adapter:     a,
		path:        path,
		sessionID:   sessionIDFromPath(path),
		rootCache:   map[string]string{},
		pendingCall: map[string]pendingMark{},
		cacheAcc:    cacheobs.New(MaxBlocksPerSession),
		firstOffset: fromOffset,
	}
	if fromOffset > 0 {
		if err := st.recoverPrefix(f, fromOffset); err != nil {
			return adapter.ParseResult{}, err
		}
	}
	if _, err := f.Seek(fromOffset, io.SeekStart); err != nil {
		return adapter.ParseResult{}, fmt.Errorf("kimchi.ParseSessionFile: seek: %w", err)
	}

	res := adapter.ParseResult{NewOffset: fromOffset}
	// bufio.Reader.ReadString (not Scanner) so the cursor advances by the
	// exact terminator length including CRLF, and a long tool-output line
	// is not capped by a token-size limit ([[feedback-jsonl-parser-cursor]]).
	reader := bufio.NewReaderSize(f, 64*1024)
	bytesRead := fromOffset
	lineNum := 0
	for {
		if ctx.Err() != nil {
			adapter.ApplyProjectIdentity(&res, st.identity)
			return res, ctx.Err()
		}
		lineStr, readErr := reader.ReadString('\n')
		if readErr != nil && readErr != io.EOF {
			adapter.ApplyProjectIdentity(&res, st.identity)
			return res, fmt.Errorf("kimchi.ParseSessionFile: read: %w", readErr)
		}
		// A partial trailing line at EOF is a record still being written:
		// defer it and do NOT advance past it.
		if !strings.HasSuffix(lineStr, "\n") && readErr == io.EOF {
			break
		}
		lineStart := bytesRead
		bytesRead += int64(len(lineStr))
		lineNum++
		res.NewOffset = bytesRead

		raw := strings.TrimRight(lineStr, "\r\n")
		if raw != "" {
			var rec rawLine
			if err := json.Unmarshal([]byte(raw), &rec); err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("line %d: malformed JSON: %v", lineNum, err))
			} else {
				st.handle(&rec, lineNum, lineStart, &res)
			}
		}
		if readErr == io.EOF {
			break
		}
	}
	st.deferUnpairedTail(&res)
	st.emitLineage(&res)
	st.emitToolVersion(&res)
	adapter.ApplyProjectIdentity(&res, st.identity)
	return res, nil
}

// parseState carries the per-call bookkeeping across lines.
type parseState struct {
	adapter *Adapter
	path    string

	// sessionID is the UUIDv7 suffix of `<ts>_<uuid>.jsonl` — the header's
	// own `id` and exactly what `kimchi --session <id>` / `--resume <id>`
	// accept. Derived from the PATH and never re-keyed from the header, so
	// a resumed parse that seeks past the header cannot split the session
	// (§4.5a).
	sessionID string

	// cwd / parentSession come from the `session` header.
	cwd           string
	parentSession string
	// headerInWindow records that the header was parsed in THIS window, so
	// the lineage marker is emitted once, not on every incremental poll.
	headerInWindow bool
	// subagent is set by the `kimchi:subagent-session` custom entry the
	// harness writes right after the header of a spawned agent's file.
	subagent bool
	// permMode is the latest `custom:permission_mode` payload mode (the live
	// stores carry `default`); stamped on every row as
	// ActionMetadata.PermissionMode.
	permMode string

	// branch / remote / identity are resolved once from cwd (projectRoot).
	branch    string
	remote    string
	identity  git.Identity
	rootCache map[string]string

	// provider / model track the selected model (model_change), refined by
	// each assistant record's own inline fields; effort is the current
	// thinking level (thinking_level_change).
	provider string
	model    string
	effort   string

	pendingCall map[string]pendingMark
	cacheAcc    *cacheobs.Accumulator

	firstOffset    int64
	sessionStarted bool
}

// recoverPrefix replays the session-state entries of [0, until) without
// emitting anything. Best-effort per line: a malformed line is skipped.
func (st *parseState) recoverPrefix(f *os.File, until int64) error {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("kimchi.recoverPrefix: seek: %w", err)
	}
	reader := bufio.NewReaderSize(f, 64*1024)
	var pos int64
	for pos < until {
		lineStr, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return fmt.Errorf("kimchi.recoverPrefix: read: %w", err)
		}
		pos += int64(len(lineStr))
		if raw := strings.TrimRight(lineStr, "\r\n"); raw != "" {
			var rec rawLine
			if json.Unmarshal([]byte(raw), &rec) == nil {
				st.applyState(&rec)
			}
		}
		if err == io.EOF {
			break
		}
	}
	return nil
}

// applyState applies the session-level state one entry carries. Shared by
// the prefix replay and the main loop so both read the state identically.
func (st *parseState) applyState(rec *rawLine) {
	switch rec.Type {
	case typeSession:
		st.cwd = rec.Cwd
		st.parentSession = rec.ParentSession
	case typeModelChange:
		if rec.Provider != "" {
			st.provider = rec.Provider
		}
		if rec.ModelID != "" {
			st.model = rec.ModelID
		}
	case typeThinkingChange:
		st.effort = strings.TrimSpace(rec.ThinkingLevel)
	case typeCustom:
		switch rec.CustomType {
		case customSubagentEntry:
			st.subagent = true
		case customPermissionMode:
			var pd permissionData
			if len(rec.Data) > 0 && json.Unmarshal(rec.Data, &pd) == nil {
				if m := strings.TrimSpace(pd.Mode); m != "" {
					st.permMode = m
				}
			}
		}
	}
}

// handle dispatches one decoded entry. Every type this adapter does not
// consume — the harness's many `custom` telemetry entries
// (llm_response_debug, cache_summary, context_assembly, …), the injected
// `custom_message` reminders, `session_info` names — falls through
// SILENTLY (§4.4e): they outnumber messages roughly 2:1.
func (st *parseState) handle(rec *rawLine, lineNum int, lineStart int64, res *adapter.ParseResult) {
	st.applyState(rec)
	switch rec.Type {
	case typeSession:
		st.headerInWindow = true
		st.emitSessionStart(rec, res)
	case typeMessage:
		if rec.Message != nil {
			st.emitMessage(rec, rec.Message, lineNum, lineStart, res)
		}
	case typeCompaction:
		st.emitCompaction(rec, lineNum, res)
	}
}

// emitSessionStart records the header as a session-start marker, only when
// parsing from the very top of the file.
func (st *parseState) emitSessionStart(rec *rawLine, res *adapter.ParseResult) {
	if st.firstOffset != 0 || st.sessionStarted || st.sessionID == "" {
		return
	}
	st.sessionStarted = true
	res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
		SourceFile:    st.path,
		SourceEventID: "session_start:" + st.sessionID,
		SessionID:     st.sessionID,
		ProjectRoot:   st.projectRoot(),
		Timestamp:     parseTimestamp(rec.Timestamp),
		GitBranch:     st.branch,
		GitRemote:     st.remote,
		Tool:          models.ToolKimchi,
		ActionType:    models.ActionSessionStart,
		Target:        "startup",
		RawToolName:   models.ToolKimchi + ".session_start",
		Success:       true,
	})
}

// emitMessage walks one `message` entry into its rows.
func (st *parseState) emitMessage(rec *rawLine, msg *agentMessage, lineNum int, lineStart int64, res *adapter.ParseResult) {
	if msg.Provider != "" {
		st.provider = msg.Provider
	}
	if msg.Model != "" {
		st.model = msg.Model
	}
	ts := parseUnixMillis(msg.Timestamp)
	if ts.IsZero() {
		ts = parseTimestamp(rec.Timestamp)
	}

	switch msg.Role {
	case roleUser:
		st.emitUserPrompt(rec, msg, lineNum, ts, res)
	case roleAssistant:
		st.emitAssistant(rec, msg, lineNum, lineStart, ts, res)
	case roleToolResult:
		st.stampToolResult(msg, res)
	case roleBashExecution:
		st.emitBashExecution(rec, msg, lineNum, ts, res)
	case roleCompactionSummary:
		st.emitCompactionSummary(rec, msg, lineNum, ts, res)
	}
}

// emitUserPrompt records a user turn. An image-only turn still produces a
// row (§7.3): the attachments ride on it as kind + media type only.
func (st *parseState) emitUserPrompt(rec *rawLine, msg *agentMessage, lineNum int, ts time.Time, res *adapter.ParseResult) {
	text := msg.Content.text()
	attachments := userAttachments(msg.Content)
	if text == "" && len(attachments) == 0 {
		return
	}
	scrubbed := st.adapter.scrubber.String(contentcap.Cap(text, contentcap.DefaultMaxBytes))
	observeText(st.cacheAcc, scrubbed, "user")
	target := truncate(scrubbed, targetMax)
	if target == "" {
		target = fmt.Sprintf("[%d attachment(s)]", len(attachments))
	}
	res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
		SourceFile:      st.path,
		SourceEventID:   eventID("user", rec.ID, lineNum),
		SessionID:       st.sessionID,
		ProjectRoot:     st.projectRoot(),
		Timestamp:       ts,
		GitBranch:       st.branch,
		GitRemote:       st.remote,
		Model:           st.modelString(),
		Tool:            models.ToolKimchi,
		ActionType:      models.ActionUserPrompt,
		Target:          target,
		Success:         true,
		RawToolName:     "message.user",
		RawToolInput:    scrubbed,
		MessageID:       messageID(rec.ID, lineNum),
		UserAttachments: attachments,
		Metadata:        st.effortMetadata(""),
	})
}

// emitAssistant produces, from one assistant record (one model call): a
// row per toolCall, an assistant_message row when the model said
// something, a terminal row for an error / abort stopReason, the record's
// token row and its cache observation.
//
// Thinking blocks are carried ONLY as PrecedingReasoning on those rows —
// never as a standalone action (the B3 reasoning convergence pi went
// through) — and fan out to every row the record produces.
func (st *parseState) emitAssistant(rec *rawLine, msg *agentMessage, lineNum int, lineStart int64, ts time.Time, res *adapter.ParseResult) {
	toolLen, tokenLen, cacheLen := len(res.ToolEvents), len(res.TokenEvents), len(res.CacheObservations)
	reasoning := st.adapter.scrubber.String(truncate(msg.Content.thinking(), reasoningMax))
	model := st.modelString()
	msgID := messageID(rec.ID, lineNum)
	root := st.projectRoot()

	for i, call := range msg.Content.toolCalls() {
		rawArgs, _ := json.Marshal(call.Arguments)
		scrubbedInput := st.adapter.scrubber.RawJSON(rawArgs)
		observeToolCall(st.cacheAcc, call.Name, scrubbedInput)
		ev := models.ToolEvent{
			SourceFile:         st.path,
			SourceEventID:      eventID(fmt.Sprintf("tool%d", i), call.ID, lineNum),
			SessionID:          st.sessionID,
			ProjectRoot:        root,
			Timestamp:          ts,
			GitBranch:          st.branch,
			GitRemote:          st.remote,
			Model:              model,
			Tool:               models.ToolKimchi,
			ActionType:         mapToolName(call.Name),
			Target:             truncate(st.adapter.scrubber.String(targetFromArgs(call.Arguments, call.Name)), targetMax),
			Success:            true,
			PrecedingReasoning: reasoning,
			RawToolName:        call.Name,
			RawToolInput:       scrubbedInput,
			ContentBytes:       authoredBytes(call),
			MessageID:          msgID,
			Metadata:           st.effortMetadata(""),
		}
		if call.ID != "" {
			ev.OutcomePending = true
			st.pendingCall[call.ID] = pendingMark{
				idx:       len(res.ToolEvents),
				lineStart: lineStart,
				toolLen:   toolLen,
				tokenLen:  tokenLen,
				cacheLen:  cacheLen,
			}
		}
		res.ToolEvents = append(res.ToolEvents, ev)
	}

	if text := msg.Content.text(); text != "" {
		scrubbed := st.adapter.scrubber.String(contentcap.Cap(text, contentcap.DefaultMaxBytes))
		observeText(st.cacheAcc, scrubbed, "assistant")
		res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
			SourceFile:         st.path,
			SourceEventID:      eventID("assistant", rec.ID, lineNum),
			SessionID:          st.sessionID,
			ProjectRoot:        root,
			Timestamp:          ts,
			GitBranch:          st.branch,
			GitRemote:          st.remote,
			Model:              model,
			Tool:               models.ToolKimchi,
			ActionType:         models.ActionAssistantMessage,
			Target:             truncate(scrubbed, targetMax),
			Success:            true,
			PrecedingReasoning: reasoning,
			RawToolName:        "message.assistant",
			ToolOutput:         scrubbed,
			MessageID:          msgID,
			Metadata:           st.effortMetadata(msg.StopReason),
		})
	}

	st.emitTerminal(rec, msg, lineNum, ts, model, root, reasoning, msgID, res)
	st.emitUsage(rec, msg, lineNum, ts, model, root, msgID, res)
}

// terminalActions maps a stopReason that ended the turn badly onto its
// action type. "stop" and "length" are ordinary completions already
// represented by the assistant_message row, and "toolUse" is a mid-turn
// pause — none of the three gets a row of its own.
var terminalActions = map[string]string{
	"error":   models.ActionAPIError,
	"aborted": models.ActionTurnAborted,
}

// emitTerminal records a turn that ended badly (the operator's three
// exhausted-credit kimchi-dev turns are `stopReason:"error"`).
func (st *parseState) emitTerminal(rec *rawLine, msg *agentMessage, lineNum int, ts time.Time, model, root, reasoning, msgID string, res *adapter.ParseResult) {
	action, ok := terminalActions[msg.StopReason]
	if !ok {
		return
	}
	errMsg := st.adapter.scrubber.String(truncate(msg.ErrorMessage, errorMax))
	res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
		SourceFile:         st.path,
		SourceEventID:      eventID(msg.StopReason, rec.ID, lineNum),
		SessionID:          st.sessionID,
		ProjectRoot:        root,
		Timestamp:          ts,
		GitBranch:          st.branch,
		GitRemote:          st.remote,
		Model:              model,
		Tool:               models.ToolKimchi,
		ActionType:         action,
		Target:             truncate(firstNonEmpty(errMsg, msg.StopReason), targetMax),
		Success:            false,
		ErrorMessage:       errMsg,
		PrecedingReasoning: reasoning,
		RawToolName:        "message.assistant." + msg.StopReason,
		MessageID:          msgID,
		Metadata:           st.effortMetadata(msg.StopReason),
	})
}

// emitUsage records the record's token envelope plus its Tier-2 cache
// observation. An all-zero envelope (a provider error) produces neither.
func (st *parseState) emitUsage(rec *rawLine, msg *agentMessage, lineNum int, ts time.Time, model, root, msgID string, res *adapter.ParseResult) {
	if msg.Usage.empty() {
		return
	}
	u := msg.Usage
	output, reasoning := u.split()
	ev := models.TokenEvent{
		SourceFile:    st.path,
		SourceEventID: eventID("usage", rec.ID, lineNum),
		SessionID:     st.sessionID,
		ProjectRoot:   root,
		GitBranch:     st.branch,
		GitRemote:     st.remote,
		Timestamp:     ts,
		Tool:          models.ToolKimchi,
		Model:         model,
		// NOT netted: `input` already excludes the cached prefix
		// (totalTokens == input + output + cacheRead + cacheWrite).
		InputTokens:         u.Input,
		CacheReadTokens:     u.CacheRead,
		CacheCreationTokens: u.CacheWrite,
		// `output` INCLUDES `reasoning`; the engine bills Reasoning on top
		// of Output at the output rate, so the two are made disjoint here.
		OutputTokens:     output,
		ReasoningTokens:  reasoning,
		EstimatedCostUSD: u.Cost.Total,
		Source:           models.TokenSourceJSONL,
		Reliability:      models.ReliabilityApproximate,
		MessageID:        msgID,
	}
	if ms := genMs(parseTimestamp(rec.Timestamp), parseUnixMillis(msg.Timestamp)); ms > 0 {
		ev.GenMs, ev.GenBasis, ev.GenTimingV = ms, models.GenBasisNative, genTimingV
	}
	res.TokenEvents = append(res.TokenEvents, ev)
	if obs := emitCacheObservation(st.cacheAcc, st.path, st.sessionID, msgID, model, msg.API, ts, u); obs != nil {
		res.CacheObservations = append(res.CacheObservations, *obs)
	}
}

// genMs is the model call's own stream span, both ends recorded by kimchi
// in the SAME record: the assistant message's inner `timestamp` is set
// when the stream starts and the entry envelope's `timestamp` when the
// finished record is appended (grounded on all 25 live assistant records:
// the inner value precedes the record's own llm_response_debug sibling by
// exactly the envelope delta). Zero when either end is missing, the span
// is non-positive, or it exceeds maxGenSpan.
func genMs(end, start time.Time) int64 {
	if end.IsZero() || start.IsZero() {
		return 0
	}
	d := end.Sub(start)
	if d <= 0 || d > maxGenSpan {
		return 0
	}
	return d.Milliseconds()
}

// stampToolResult attaches a result to the call it answers. A result whose
// call is not in this window is dropped: the deferral in pending.go exists
// so that cannot happen for a call observer emitted.
func (st *parseState) stampToolResult(msg *agentMessage, res *adapter.ParseResult) {
	output := st.adapter.scrubber.String(contentcap.Cap(msg.Content.text(), contentcap.DefaultMaxBytes))
	observeToolResult(st.cacheAcc, output)
	mark, ok := st.pendingCall[msg.ToolCallID]
	if !ok || mark.idx >= len(res.ToolEvents) {
		return
	}
	delete(st.pendingCall, msg.ToolCallID)
	ev := &res.ToolEvents[mark.idx]
	ev.ToolOutput = output
	// isError tracks the shell exit code for bash/powershell (exit 49 and
	// 127 both arrived isError:true on the Windows session).
	ev.Success = !msg.IsError
	ev.OutcomePending = false
	if msg.IsError {
		ev.ErrorMessage = truncate(output, errorMax)
	}
	if msg.Details != nil && msg.Details.ElapsedSeconds > 0 {
		ev.DurationMs = int64(msg.Details.ElapsedSeconds * 1000)
	}
}

// emitBashExecution records pi-mono's `bashExecution` role — an operator
// `!`-prefixed shell command run from the TUI. A cancelled command is a
// failure even though its exitCode is undefined.
func (st *parseState) emitBashExecution(rec *rawLine, msg *agentMessage, lineNum int, ts time.Time, res *adapter.ParseResult) {
	success := !msg.Cancelled && (msg.ExitCode == nil || *msg.ExitCode == 0)
	command := st.adapter.scrubber.String(msg.Command)
	output := st.adapter.scrubber.String(contentcap.Cap(msg.Output, contentcap.DefaultMaxBytes))
	errMsg := ""
	switch {
	case msg.Cancelled:
		errMsg = "cancelled"
	case !success:
		errMsg = truncate(output, errorMax)
	}
	res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
		SourceFile:    st.path,
		SourceEventID: eventID("bash", rec.ID, lineNum),
		SessionID:     st.sessionID,
		ProjectRoot:   st.projectRoot(),
		Timestamp:     ts,
		GitBranch:     st.branch,
		GitRemote:     st.remote,
		Model:         st.modelString(),
		Tool:          models.ToolKimchi,
		ActionType:    models.ActionRunCommand,
		Target:        truncate(command, targetMax),
		Success:       success,
		ErrorMessage:  errMsg,
		RawToolName:   "message.bashExecution",
		RawToolInput:  command,
		ToolOutput:    output,
		MessageID:     messageID(rec.ID, lineNum),
		Metadata:      st.effortMetadata(""),
	})
}

// emitCompaction records a `compaction` entry (pi-mono session format v3's
// context-window summarisation, with the token count it reclaimed).
func (st *parseState) emitCompaction(rec *rawLine, lineNum int, res *adapter.ParseResult) {
	st.cacheAcc.ObserveCompaction()
	res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
		SourceFile:    st.path,
		SourceEventID: eventID("compaction", rec.ID, lineNum),
		SessionID:     st.sessionID,
		ProjectRoot:   st.projectRoot(),
		Timestamp:     parseTimestamp(rec.Timestamp),
		GitBranch:     st.branch,
		GitRemote:     st.remote,
		Model:         st.modelString(),
		Tool:          models.ToolKimchi,
		ActionType:    models.ActionContextCompacted,
		Target:        truncate(fmt.Sprintf("%d tokens before compaction", rec.TokensBefore), targetMax),
		Success:       true,
		RawToolName:   "compaction",
		ToolOutput:    st.adapter.scrubber.String(contentcap.Cap(rec.Summary, contentcap.DefaultMaxBytes)),
		MessageID:     messageID(rec.ID, lineNum),
	})
}

// emitCompactionSummary records the compactionSummary MESSAGE role — the
// in-context form of the same event.
func (st *parseState) emitCompactionSummary(rec *rawLine, msg *agentMessage, lineNum int, ts time.Time, res *adapter.ParseResult) {
	st.cacheAcc.ObserveCompaction()
	summary := st.adapter.scrubber.String(contentcap.Cap(msg.Summary, contentcap.DefaultMaxBytes))
	res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
		SourceFile:    st.path,
		SourceEventID: eventID("compaction_summary", rec.ID, lineNum),
		SessionID:     st.sessionID,
		ProjectRoot:   st.projectRoot(),
		Timestamp:     ts,
		GitBranch:     st.branch,
		GitRemote:     st.remote,
		Model:         st.modelString(),
		Tool:          models.ToolKimchi,
		ActionType:    models.ActionContextCompacted,
		Target:        truncate(summary, targetMax),
		Success:       true,
		RawToolName:   "message.compactionSummary",
		ToolOutput:    summary,
		MessageID:     messageID(rec.ID, lineNum),
	})
}

// Lineage ThreadSource values (the codex vocabulary every lineage-emitting
// adapter shares).
const (
	threadSourceUser     = "user"
	threadSourceSubagent = "subagent"
)

// emitLineage emits the fork / sub-agent marker for a session whose header
// names a parentSession. A spawned agent's file (the harness's
// prepareAgentSessionFile) carries the `kimchi:subagent-session` entry and
// is a sub-agent of the parent; every other parentSession (pi-mono's
// branch-to-new-file and fork-to-cwd flows) is an operator fork. Emitted
// only when the header was read in this window, so an incremental poll
// does not re-stamp it.
func (st *parseState) emitLineage(res *adapter.ParseResult) {
	if !st.headerInWindow || strings.TrimSpace(st.parentSession) == "" {
		return
	}
	parent := sessionIDFromPath(st.parentSession)
	if parent == "" || parent == st.sessionID {
		return
	}
	lin := models.SessionLineage{SessionID: st.sessionID, ForkedFromID: parent, ThreadSource: threadSourceUser}
	if st.subagent {
		lin.ParentThreadID = parent
		lin.ThreadSource = threadSourceSubagent
	}
	res.SessionLineages = append(res.SessionLineages, lin)
}

// projectRoot resolves the header cwd to a git working-tree root. The
// crossmount translation is unconditional and happens BEFORE git so a WSL2
// observer reading the Windows install's `C:\...` cwd never CWD-prefixes
// its own repo onto it ([[feedback-foreign-path-git-resolve]]); and a cwd
// that is not reachable from this host even after translation (a Windows
// observer reading the WSL install's `/home/...`) is kept RAW with no git
// identity rather than handed to git, whose filepath.Abs would graft the
// observer's current drive onto it (pi's stat gate).
func (st *parseState) projectRoot() string {
	if st.cwd == "" {
		return placeholderRoot
	}
	cwd := crossmount.TranslateForeignPath(st.cwd)
	if root, ok := st.rootCache[cwd]; ok {
		return root
	}
	if _, err := os.Stat(cwd); err != nil {
		st.rootCache[cwd] = st.cwd
		return st.cwd
	}
	id, err := git.ResolveIdentity(cwd, git.IdentityOptions{})
	if err != nil {
		st.rootCache[cwd] = cwd
		return cwd
	}
	st.rootCache[cwd] = id.Root
	st.branch = id.Branch
	st.remote = id.Remote
	st.identity = id
	return id.Root
}

// modelString renders the billed model as `provider/model` — the record's
// own lane (`kimchi-dev`, `openai-codex`) is always prefixed so the same
// bare id served by two lanes stays distinguishable, the convention pi and
// prime-agent established for this envelope.
func (st *parseState) modelString() string {
	switch {
	case st.provider != "" && st.model != "":
		return st.provider + "/" + st.model
	default:
		return st.model
	}
}

// effortMetadata carries the session's current thinking level (an effort
// SETTING, §7.2), the harness's permission mode (`custom:permission_mode`),
// the sub-agent marker and parent session id for a spawned agent's own file,
// and, when set, the record's stopReason. nil leaves the metadata column
// NULL.
func (st *parseState) effortMetadata(stopReason string) *models.ActionMetadata {
	m := models.ActionMetadata{
		EffortLevel:    st.effort,
		PermissionMode: st.permMode,
		StopReason:     stopReason,
	}
	if st.subagent {
		m.IsSubagent = true
		if parent := sessionIDFromPath(st.parentSession); parent != "" && parent != st.sessionID {
			m.ParentSessionID = parent
		}
	}
	if m.EffortLevel == "" && m.PermissionMode == "" && m.StopReason == "" && !m.IsSubagent {
		return nil
	}
	return &m
}

// userAttachments resolves a user record's image parts into kind + media
// type (§7.3). The base64 payload is never decoded and no name is kept.
func userAttachments(parts contentParts) []models.UserAttachment {
	var out []models.UserAttachment
	for _, p := range parts {
		if p.Type == partImage {
			out = append(out, models.UserAttachment{Kind: "image", MediaType: strings.TrimSpace(p.MimeType)})
		}
	}
	return out
}

// eventID builds a deterministic source event id: the native id (an 8-hex
// entry id, or a `call_…|fc_…` tool-call id) when present, the line number
// otherwise (§4.5).
func eventID(kind, id string, lineNum int) string {
	if strings.TrimSpace(id) != "" {
		return kind + ":" + id
	}
	return fmt.Sprintf("%s:L%d", kind, lineNum)
}

// messageID identifies the model call a row belongs to.
func messageID(id string, lineNum int) string {
	if strings.TrimSpace(id) != "" {
		return id
	}
	return fmt.Sprintf("L%d", lineNum)
}

// sessionIDFromPath recovers the session UUID from a transcript path
// `<ISO-ts>_<uuid>.jsonl`. Both separators are honoured because a header's
// parentSession may be a Windows path read on Linux (or vice versa).
// Falls back to the whole stem when the suffix is not UUID-shaped.
func sessionIDFromPath(path string) string {
	base := path
	if i := strings.LastIndexAny(base, `/\`); i >= 0 {
		base = base[i+1:]
	}
	if strings.EqualFold(filepath.Ext(base), ".jsonl") {
		base = base[:len(base)-len(".jsonl")]
	}
	if i := strings.LastIndexByte(base, '_'); i >= 0 && looksLikeUUID(base[i+1:]) {
		return base[i+1:]
	}
	return base
}

// looksLikeUUID reports whether s is a canonical 8-4-4-4-12 hex UUID.
func looksLikeUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// mapToolName maps a native tool name onto a normalized action type.
//
// Every label is GROUNDED: the 25 names kimchi 1.17.0 registered in the
// operator's two live sessions (the `custom:context_assembly` entry lists
// the model-visible tool surface), plus `mcp`, `skill` and `ask_user`
// read off the bundle's own tool tables (SHARED_CORE_TOOLS /
// FERMENT_MODE_TOOLS). The DAP `debug_*` family and the remaining ferment
// lifecycle verbs are deliberately left to ActionUnknown (RawToolName
// keeps them) rather than forced into a bucket they do not fit.
//
// Every case label has a matching internal/tooltax row; the conformance
// test in this package pins both directions.
func mapToolName(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "read":
		return models.ActionReadFile
	case "write":
		return models.ActionWriteFile
	case "edit":
		return models.ActionEditFile
	case "bash", "powershell":
		return models.ActionRunCommand
	case "bash_control":
		// Inspects, waits on or stops BACKGROUND processes a prior bash
		// call started — process-pool control, not a fresh shell exec.
		return models.ActionAgentControl
	case "grep":
		return models.ActionSearchText
	case "find", "ls":
		return models.ActionSearchFiles
	case "web_search":
		return models.ActionWebSearch
	case "web_fetch":
		return models.ActionWebFetch
	case "agent", "dispatch_to_cloud_agent":
		return models.ActionSpawnSubagent
	case "resume_subagent", "steer_subagent":
		// Hand a new prompt to an EXISTING sub-agent (codex followup_task's
		// slot). Live: resume_subagent {agent_id, prompt, purpose:
		// "continuation"}; the Agent result's addedToolNames lists both.
		return models.ActionAgentMessage
	case "get_subagent_result":
		return models.ActionSubagentWait
	case "create_todos", "update_todos", "add_todo", "mark_todo", "clear_todos":
		return models.ActionTodoUpdate
	case "questionnaire", "ask_user":
		return models.ActionAskUser
	case "skill", "skill_view":
		return models.ActionSkillInvoke
	case "submit_plan":
		// Plan mode's exit: submits the plan for approval (claude-code
		// ExitPlanMode's slot).
		return models.ActionPermissionMode
	case "set_model", "list_models", "set_phase", "list_ferments":
		return models.ActionHarnessCall
	case "mcp":
		// The pi-mcp-adapter proxy tool: one tool fronting every server.
		return models.ActionMCPCall
	default:
		if models.IsMCPToolName(name) {
			return models.ActionMCPCall
		}
		return models.ActionUnknown
	}
}

// argTargetKeys is the ordered list of argument keys that can carry a tool
// call's display target (read/write/edit `path`, bash `command`, grep
// `pattern`, dispatch `task`, skill_view `name`).
var argTargetKeys = []string{"path", "file_path", "filePath", "command", "pattern", "query", "url", "task", "prompt", "name"}

// targetFromArgs picks the most descriptive argument for the Target
// column, falling back to the tool name.
func targetFromArgs(args map[string]any, fallback string) string {
	for _, key := range argTargetKeys {
		if v, ok := args[key].(string); ok && strings.TrimSpace(v) != "" {
			return v
		}
	}
	return fallback
}

// authoredBytes is the §8.5 ContentBytes decision, made explicitly from
// the grounded argument shapes: write `content`, edit Σ `edits[].newText`
// (and a bare `newText` for the single-edit form), and a shell `command`.
// Every other tool authored nothing and reports zero.
func authoredBytes(call contentPart) int64 {
	args := call.Arguments
	switch mapToolName(call.Name) {
	case models.ActionWriteFile:
		s, _ := args["content"].(string)
		return int64(len(s))
	case models.ActionEditFile:
		var n int64
		if s, ok := args["newText"].(string); ok {
			n += int64(len(s))
		}
		if edits, ok := args["edits"].([]any); ok {
			for _, e := range edits {
				if m, ok := e.(map[string]any); ok {
					if s, ok := m["newText"].(string); ok {
						n += int64(len(s))
					}
				}
			}
		}
		return n
	case models.ActionRunCommand:
		s, _ := args["command"].(string)
		return int64(len(s))
	}
	return 0
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// truncate cuts to at most n bytes (the byte truncation every adapter
// applies to its display columns).
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// compile-time interface check.
var _ adapter.Adapter = (*Adapter)(nil)

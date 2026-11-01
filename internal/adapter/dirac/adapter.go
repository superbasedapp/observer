package dirac

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
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

const (
	// opsName is the live API-conversation operation log — the ONE file
	// this adapter claims per task (bundle mm.apiConversationHistoryOperations).
	opsName = "api_conversation_history.jsonl"
	// archivePrefix is the rotated-operation-log prefix: at 8 MiB Dirac
	// writes a baseline and RENAMES the live log to
	// `api_conversation_history.jsonl.archive.<lastOffset>`; the next
	// append recreates the live log empty.
	archivePrefix = opsName + ".archive."
	// placeholderRoot is the project root used until taskHistory.json
	// lists the task (the store promotes it once a real cwd arrives).
	placeholderRoot = "[dirac]"
	// reasoningCap bounds PrecedingReasoning (cline precedent).
	reasoningCap = 2048
)

// Adapter parses Dirac CLI task operation logs. See the package doc.
type Adapter struct {
	scrubber *scrub.Scrubber
	roots    []string
	history  *historyIndex
	logs     *logIndex
}

// New returns an adapter with the default scrubber and platform-default
// cross-mount roots (`<home>/.dirac/data/tasks`, plus the DIRAC_DIR /
// DIRAC_DATA_DIR overrides).
func New() *Adapter { return NewWithOptions(nil) }

// NewWithOptions customizes the scrubber and/or watch roots (tests). A
// nil scrubber falls back to scrub.New(); no roots falls back to the
// platform defaults.
func NewWithOptions(s *scrub.Scrubber, roots ...string) *Adapter {
	if s == nil {
		s = scrub.New()
	}
	if len(roots) == 0 {
		roots = defaultRoots()
	}
	return &Adapter{scrubber: s, roots: roots, history: &historyIndex{}, logs: &logIndex{}}
}

// Name implements adapter.Adapter.
func (*Adapter) Name() string { return models.ToolDirac }

// WatchPaths implements adapter.Adapter.
func (a *Adapter) WatchPaths() []string { return a.roots }

// IsSessionFile implements adapter.Adapter: exactly
// `<root>/<taskId>/api_conversation_history.jsonl` under one of this
// adapter's watch roots. The task's ui_messages.jsonl, task_metadata.json,
// baseline and rotated archives are read as siblings, never claimed, so
// every row of a task carries ONE source_file.
func (a *Adapter) IsSessionFile(path string) bool {
	if filepath.Base(path) != opsName {
		return false
	}
	if !strings.EqualFold(filepath.Base(filepath.Dir(filepath.Dir(path))), tasksDirName) {
		return false
	}
	return adapter.UnderAnyWatchRoot(path, a.WatchPaths())
}

// CursorSemanticsFor implements adapter.CursorSemantics. The live log is
// an append-only byte-offset tail that is SEEKED and streamed, and
// Dirac rotates it by rename at 8 MiB (a fresh, shorter file at the same
// path), so a cursor past EOF means "new file".
func (a *Adapter) CursorSemanticsFor(path string) adapter.FileCursorSemantics {
	return adapter.FileCursorSemantics{
		Kind:              adapter.CursorByteOffset,
		Detail:            "Dirac task operation log; rotated by rename at 8 MiB",
		StreamsFromCursor: true,
		RewindsOnTruncate: true,
	}
}

// ParseSessionFile implements adapter.Adapter. It streams the live
// operation log from fromOffset; on a parse from 0 (first sight of the
// task, or after a rotation) it first replays the task's rotated
// `.archive.<n>` logs in offset order so history that rotated out before
// the observer saw it is still captured. Every event carries the live
// log as SourceFile and a content-derived SourceEventID, so a message
// re-listed by a `reset` op (or re-read after a rotation) dedups.
func (a *Adapter) ParseSessionFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	info, err := os.Stat(path)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("dirac.ParseSessionFile: stat: %w", err)
	}
	if fromOffset > info.Size() || fromOffset < 0 {
		fromOffset = 0 // rotated: the path now names a new, shorter log
	}
	res := adapter.ParseResult{NewOffset: fromOffset}
	if fromOffset > 0 && fromOffset == info.Size() {
		return res, nil
	}
	st := a.newParseState(path)
	st.fromOffset = fromOffset
	if fromOffset == 0 {
		st.baseKnown = true // a full replay counts every message itself
		for _, archive := range archivesOf(st.taskDir) {
			if _, err := st.readLog(ctx, archive, 0, &res); err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("archive %s: %v", filepath.Base(archive), err))
			}
		}
	}
	next, err := st.readLog(ctx, path, fromOffset, &res)
	res.NewOffset = next
	st.finish(&res)
	if err != nil {
		return res, fmt.Errorf("dirac.ParseSessionFile: %w", err)
	}
	return res, nil
}

// archivesOf lists `api_conversation_history.jsonl.archive.<n>` in the
// task dir, ascending by n (the last operation offset each holds).
func archivesOf(taskDir string) []string {
	entries, err := os.ReadDir(taskDir)
	if err != nil {
		return nil
	}
	type arc struct {
		path string
		n    int64
	}
	var arcs []arc
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, archivePrefix) || !e.Type().IsRegular() {
			continue
		}
		n, err := strconv.ParseInt(strings.TrimPrefix(name, archivePrefix), 10, 64)
		if err != nil {
			continue
		}
		arcs = append(arcs, arc{filepath.Join(taskDir, name), n})
	}
	sort.Slice(arcs, func(i, j int) bool { return arcs[i].n < arcs[j].n })
	out := make([]string, len(arcs))
	for i, x := range arcs {
		out[i] = x.path
	}
	return out
}

// parseState is the per-call bookkeeping.
type parseState struct {
	a         *Adapter
	path      string // the live log: SourceFile of every event
	taskDir   string
	sessionID string
	root      string
	cwd       string
	branch    string
	remote    string
	identity  git.Identity

	meta         taskMetadata
	haveMeta     bool
	metaModel    string
	metaProvider string
	lastModel    string
	lastProvider string
	lastUserTs   int64

	// pending maps a tool_use id to its event index until the result lands.
	pending map[string]int
	// seenMsg dedups messages within one parse (a reset re-lists them).
	seenMsg map[string]bool
	// unknownWarned dedups the unmapped-tool warning.
	unknownWarned map[string]bool

	// ui is the replayed presentation log (api_status split + request
	// starts + tool cards), loaded once per parse on first need.
	ui           *uiData
	uiLoaded     bool
	statusCursor int

	// fromOffset is where the live-log stream started. msgCount is the
	// number of conversation messages the history held before this
	// window's ops: msgBase (exact once baseKnown; a mid-file resume
	// derives it lazily, only when a reset needs it) + appended.
	fromOffset int64
	msgBase    int
	appended   int
	baseKnown  bool
	// lastTs is the newest message ts seen (the reset row's time).
	lastTs int64
	// condensePending is set by a `condense` tool call and consumed by
	// the reset that applies it, so one compaction is not two rows.
	condensePending bool
	// mode is the last plan/act mode seen on an assistant message.
	mode string

	// dataDir / snap are the Dirac data dir and its parsed vendor log
	// (pid, install id, package dir). snap is nil when no log exists.
	dataDir string
	snap    *logSnapshot
	// accounts collects account-level observations (ruling 3).
	accounts []models.ToolAccountObservation

	cacheAcc *cacheobs.Accumulator
}

func (a *Adapter) newParseState(path string) *parseState {
	taskDir := filepath.Dir(path)
	st := &parseState{
		a:             a,
		path:          path,
		taskDir:       taskDir,
		sessionID:     filepath.Base(taskDir),
		pending:       map[string]int{},
		seenMsg:       map[string]bool{},
		unknownWarned: map[string]bool{},
		cacheAcc:      cacheobs.New(MaxBlocksPerSession),
	}
	st.meta, st.haveMeta = readTaskMetadata(taskDir)
	if st.haveMeta {
		st.metaModel, st.metaProvider = st.meta.latestModel()
	}
	st.dataDir = filepath.Dir(filepath.Dir(taskDir))
	st.snap = a.logs.snapshot(st.dataDir)
	st.cwd = a.history.cwdFor(taskDir, st.sessionID)
	st.resolveRoot(st.cwd)
	return st
}

// resolveRoot maps the task cwd onto a project root. The translation is
// unconditional: a Windows `C:\…` cwd read by a WSL observer becomes
// `/mnt/c/…` before git sees it, so a drive-letter string can never be
// CWD-prefixed onto the observer's own repo.
func (st *parseState) resolveRoot(cwd string) {
	if cwd == "" {
		st.root = placeholderRoot
		return
	}
	cwd = crossmount.TranslateForeignPath(cwd)
	id, err := git.ResolveIdentity(cwd, git.IdentityOptions{})
	if err != nil {
		st.root = cwd
		return
	}
	st.root, st.branch, st.remote, st.identity = id.Root, id.Branch, id.Remote, id
}

// readLog streams one operation log from `from`, dispatching every
// complete line. A partial trailing line (still being written) is
// deferred — the returned offset stops before it.
func (st *parseState) readLog(ctx context.Context, path string, from int64, res *adapter.ParseResult) (int64, error) {
	f, err := os.Open(path) //nolint:gosec // watched task file or its rotated sibling
	if err != nil {
		return from, fmt.Errorf("open: %w", err)
	}
	defer f.Close()
	if _, err := f.Seek(from, io.SeekStart); err != nil {
		return from, fmt.Errorf("seek: %w", err)
	}
	r := bufio.NewReaderSize(f, 64*1024)
	offset := from
	lineNum := 0
	for {
		if err := ctx.Err(); err != nil {
			return offset, err
		}
		line, readErr := r.ReadString('\n')
		if readErr != nil && readErr != io.EOF {
			return offset, fmt.Errorf("read: %w", readErr)
		}
		if !strings.HasSuffix(line, "\n") {
			break // EOF, possibly with a deferred partial line
		}
		offset += int64(len(line))
		lineNum++
		raw := strings.TrimRight(line, "\r\n")
		if raw != "" {
			var op rawOp
			if err := json.Unmarshal([]byte(raw), &op); err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("%s line %d: malformed JSON: %v", filepath.Base(path), lineNum, err))
			} else {
				st.handleOp(&op, res)
			}
		}
		if readErr == io.EOF {
			break
		}
	}
	return offset, nil
}

func (st *parseState) handleOp(op *rawOp, res *adapter.ParseResult) {
	switch op.Type {
	case "append_message":
		if op.Message != nil {
			st.handleMessage(op.Message, res)
			st.appended++
		}
	case "reset":
		st.handleReset(op, res)
	case "append_user_content":
		key := "op" + strconv.FormatInt(op.Offset, 10)
		st.handleUserBlocks(decodeBlocks(op.Content), st.lastUserTs, key, res)
	}
	// Any other op type is skipped silently (forward-compat).
}

// handleReset applies a `reset` (Dirac's overwriteApiConversationHistory:
// truncation, condensation or a checkpoint restore replaces the whole
// history). The re-listed messages dedup; when the new history is SHORTER
// than what it replaced, the history was cut or condensed, which is a
// compaction event. A reset right after a `condense` tool call is that
// call's own effect and adds no second row, and a reset that does not
// shrink (the empty reset of a task cancelled before its first request)
// adds none either.
func (st *parseState) handleReset(op *rawOp, res *adapter.ParseResult) {
	n := len(op.Messages)
	prior, known := st.priorMessages()
	for i := range op.Messages {
		st.handleMessage(&op.Messages[i], res)
	}
	if known && n < prior {
		if st.condensePending {
			st.condensePending = false
		} else {
			st.emitHistoryReset(op, n, prior, res)
		}
	}
	st.msgBase, st.appended, st.baseKnown = n, 0, true
}

// priorMessages is the message count of the history before the current
// op. A parse from offset 0 knows it exactly; a mid-file resume counts
// the already-consumed prefix once (rotated archives + the live log up to
// the cursor). known is false when that prefix cannot be read.
func (st *parseState) priorMessages() (int, bool) {
	if !st.baseKnown {
		n, ok := countHistory(st.taskDir, st.path, st.fromOffset)
		if !ok {
			return 0, false
		}
		st.msgBase, st.baseKnown = n, true
	}
	return st.msgBase + st.appended, true
}

// emitHistoryReset records one context_compacted row for a shrinking
// reset. The id is the op's per-task offset (stable across re-parses).
func (st *parseState) emitHistoryReset(op *rawOp, n, prior int, res *adapter.ParseResult) {
	ts := st.lastTs
	for i := range op.Messages {
		if op.Messages[i].Ts > ts {
			ts = op.Messages[i].Ts
		}
	}
	if ts <= 0 {
		return // no honest timestamp: never fabricate one
	}
	res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
		SourceFile:    st.path,
		SourceEventID: "reset:op" + strconv.FormatInt(op.Offset, 10),
		SessionID:     st.sessionID,
		ProjectRoot:   st.root,
		Timestamp:     msTime(ts),
		GitBranch:     st.branch,
		GitRemote:     st.remote,
		Model:         st.lastModel,
		Tool:          models.ToolDirac,
		ActionType:    models.ActionContextCompacted,
		Target:        fmt.Sprintf("%d msgs (was %d)", n, prior),
		Success:       true,
		RawToolName:   models.ToolDirac + ".history_reset",
		RawToolInput:  fmt.Sprintf(`{"messages":%d,"previous_messages":%d}`, n, prior),
	})
}

func msTime(ms int64) time.Time {
	if ms <= 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms).UTC()
}

func (st *parseState) handleMessage(m *rawMessage, res *adapter.ParseResult) {
	key := m.Role + ":" + messageKey(m)
	if m.Ts > st.lastTs {
		st.lastTs = m.Ts
	}
	if st.seenMsg[key] {
		return
	}
	st.seenMsg[key] = true
	blocks := decodeBlocks(m.Content)
	switch m.Role {
	case "user":
		st.lastUserTs = m.Ts
		st.handleUserBlocks(blocks, m.Ts, messageKey(m), res)
	case "assistant":
		st.handleAssistant(m, blocks, res)
	}
}

// handleUserBlocks walks a user message (or an appended user block):
// tool_result blocks stamp outcomes, a tagged text block is the prompt,
// image blocks are attachments.
func (st *parseState) handleUserBlocks(blocks []rawBlock, tsMs int64, key string, res *adapter.ParseResult) {
	prompt := ""
	var atts []models.UserAttachment
	for _, b := range blocks {
		switch b.Type {
		case "tool_result":
			st.applyResult(b, res)
		case "text":
			if prompt == "" {
				prompt = extractPrompt(b.Text)
			}
		case "image":
			atts = append(atts, models.UserAttachment{Kind: "image", MediaType: b.imageMediaType()})
		}
	}
	if prompt == "" && len(atts) == 0 {
		return
	}
	scrubbed := st.a.scrubber.String(prompt)
	if scrubbed != "" {
		accumulateTextCache(st.cacheAcc, scrubbed, "user")
	}
	target := truncate(scrubbed, 200)
	if target == "" {
		target = "[image attachment]"
	}
	userMsgID := models.ToolDirac + ":user:" + shortHash(prompt)
	st.noteAccount("user", userMsgID, msTime(tsMs))
	res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
		SourceFile:         st.path,
		SourceEventID:      "prompt:" + key + ":" + shortHash(prompt),
		SessionID:          st.sessionID,
		ProjectRoot:        st.root,
		Timestamp:          msTime(tsMs),
		GitBranch:          st.branch,
		GitRemote:          st.remote,
		Tool:               models.ToolDirac,
		ActionType:         models.ActionUserPrompt,
		Target:             target,
		Success:            true,
		PrecedingReasoning: truncate(scrubbed, 200),
		RawToolName:        models.ToolDirac + ".user_prompt",
		RawToolInput:       scrubbed,
		MessageID:          userMsgID,
		UserAttachments:    atts,
	})
}

func (st *parseState) handleAssistant(m *rawMessage, blocks []rawBlock, res *adapter.ParseResult) {
	model, provider := st.lastModel, st.lastProvider
	if m.ModelInfo != nil && m.ModelInfo.ModelID != "" {
		model, provider = m.ModelInfo.ModelID, m.ModelInfo.ProviderID
		st.lastModel, st.lastProvider = model, provider
	}
	if m.ModelInfo != nil && m.ModelInfo.Mode != "" {
		st.mode = m.ModelInfo.Mode
	}
	if model == "" {
		model, provider = st.metaModel, st.metaProvider
	}
	key := messageKey(m)
	ts := msTime(m.Ts)
	hasTokens := m.Metrics != nil && !m.Metrics.Tokens.isZero()
	// The request api_status is matched FIRST: it pairs the message with
	// the request start (generation span) and delimits the tool cards
	// that carry each call execution time.
	var matched *uiStatus
	if hasTokens {
		matched = st.matchStatus(m)
	}
	sameName := map[string]int{}
	for _, b := range blocks {
		if b.Type == "tool_use" {
			sameName[b.Name]++
		}
	}
	before := len(res.ToolEvents)
	var reasoning []string
	pos := 0
	for i, b := range blocks {
		switch b.Type {
		case "thinking":
			if t := strings.TrimSpace(b.Thinking); t != "" {
				reasoning = append(reasoning, t)
			}
		case "tool_use":
			st.emitTool(m, b, key, pos, model, ts, strings.Join(reasoning, " "), matched, sameName[b.Name], res)
			pos++
		case "text":
			st.emitAssistantText(m, b, key, i, model, ts, strings.Join(reasoning, " "), res)
		}
		// redacted_thinking is an opaque provider blob: never content.
	}
	if hasTokens {
		st.emitTokens(m, key, model, provider, ts, matched, res)
	}
	if hasTokens || len(res.ToolEvents) > before {
		st.noteAccount("assistant", m.ID, ts)
	}
}

// modeMetadata stamps the message plan/act mode (modelInfo.mode, the
// bundle act | plan) as the collaboration mode, the same slot the Codex
// plan/default toggle uses. nil when no mode was recorded.
func (st *parseState) modeMetadata(m *rawMessage) *models.ActionMetadata {
	mode := st.mode
	if m.ModelInfo != nil && m.ModelInfo.Mode != "" {
		mode = m.ModelInfo.Mode
	}
	if mode == "" {
		return nil
	}
	return &models.ActionMetadata{CollaborationMode: mode}
}

// loadUI returns the replayed presentation log, loading it once per parse.
func (st *parseState) loadUI() *uiData {
	if !st.uiLoaded {
		st.uiLoaded = true
		st.ui = loadUI(st.taskDir)
	}
	return st.ui
}

// matchStatus pairs an assistant message with its api_status (nil when
// the ui log is missing or has no matching record) and advances the
// ordered cursor.
func (st *parseState) matchStatus(m *rawMessage) *uiStatus {
	s, idx := st.loadUI().pick(m.Metrics.Tokens, m.Ts, st.statusCursor)
	if s != nil {
		st.statusCursor = idx + 1
	}
	return s
}

// noteAccount records one account-level observation (operator ruling
// 2026-10-21) for a message: the hashed per-install telemetry id Dirac
// logs at startup for the process that worked this task. It is a device
// id, never a person (no email or name; Scope marks it account-level).
func (st *parseState) noteAccount(role, messageID string, ts time.Time) {
	acct := st.snap.accountFor(st.sessionID)
	if acct == "" || messageID == "" {
		return
	}
	stage := "activity"
	if role == "user" {
		stage = "submission"
	}
	st.accounts = append(st.accounts, models.ToolAccountObservation{
		SessionID: st.sessionID, Tool: models.ToolDirac, BindingKind: "message", BindingID: messageID,
		Role: role, AccountID: acct, Source: "dirac_log_distinct_id",
		Scope: models.ToolAccountScopeAccount + ":device", Stage: stage, ObservedAt: ts,
	})
}

func (st *parseState) emitTool(m *rawMessage, b rawBlock, key string, pos int, model string, ts time.Time, reasoning string, matched *uiStatus, sameName int, res *adapter.ParseResult) {
	rawName, action, ok := classifyTool(b.Name, b.Input)
	if !ok && !st.unknownWarned[b.Name] {
		st.unknownWarned[b.Name] = true
		res.Warnings = append(res.Warnings, fmt.Sprintf("unrecognised tool %q normalized to %q", rawName, action))
	}
	in := decodeToolInput(b.Input)
	target, isPath := targetFor(rawName, in)
	// Dirac tool paths are workspace-relative as written; only an
	// absolute one is relativized against the project root (a relative
	// path handed to git.RelativePath would resolve against the
	// OBSERVER's own working directory).
	if isPath && isAbsAnyOS(target) && st.root != placeholderRoot {
		target = git.RelativePath(st.root, crossmount.TranslateForeignPath(target))
	}
	target = st.a.scrubber.String(target)
	scrubbedInput := st.a.scrubber.RawJSON(b.Input)
	accumulateToolCallCache(st.cacheAcc, b.Name, scrubbedInput)
	id := b.ID
	if id == "" {
		id = key + ":tool:" + strconv.Itoa(pos)
	}
	ev := models.ToolEvent{
		SourceFile:    st.path,
		SourceEventID: id,
		SessionID:     st.sessionID,
		ProjectRoot:   st.root,
		Timestamp:     ts,
		GitBranch:     st.branch,
		GitRemote:     st.remote,
		Model:         model,
		Tool:          models.ToolDirac,
		ActionType:    action,
		Target:        truncate(target, 500),
		Success:       true,
		RawToolName:   rawName,
		RawToolInput:  scrubbedInput,
		ContentBytes:  authoredBytes(rawName, in),
		MessageID:     m.ID,
		Metadata:      st.modeMetadata(m),
	}
	if reasoning != "" {
		ev.PrecedingReasoning = truncate(st.a.scrubber.String(reasoning), reasoningCap)
	}
	// The tool own execution time from its ui card(s). A message that
	// calls the same tool twice cannot be split between its cards, so it
	// carries none rather than a guess; respond is a message, not work.
	if sameName == 1 && !strings.HasPrefix(rawName, respondTool) && matched != nil {
		if ms, ok := st.loadUI().toolDuration(matched, b.Name); ok {
			ev.DurationMs = ms
		}
	}
	if action == models.ActionContextCompacted {
		st.condensePending = true
	}
	if strings.HasPrefix(rawName, respondTool) && in.Text != "" {
		// respond IS Dirac's assistant voice: carry its text as the row body.
		ev.ToolOutput = st.a.scrubber.String(contentcap.Cap(in.Text, contentcap.DefaultMaxBytes))
		ev.Target = truncate(ev.ToolOutput, 200)
	}
	// respond.* is delivered the moment it is written; a completion has
	// no tool_result at all, so it is never an unobserved outcome.
	if b.ID != "" && !strings.HasPrefix(rawName, respondTool) {
		st.pending[b.ID] = len(res.ToolEvents)
	}
	res.ToolEvents = append(res.ToolEvents, ev)
}

func (st *parseState) emitAssistantText(m *rawMessage, b rawBlock, key string, blockIdx int, model string, ts time.Time, reasoning string, res *adapter.ParseResult) {
	if strings.TrimSpace(b.Text) == "" {
		return
	}
	body := st.a.scrubber.String(contentcap.Cap(b.Text, contentcap.DefaultMaxBytes))
	accumulateTextCache(st.cacheAcc, body, "assistant")
	ev := models.ToolEvent{
		SourceFile:    st.path,
		SourceEventID: "asst:" + key + ":" + strconv.Itoa(blockIdx) + ":" + shortHash(b.Text),
		SessionID:     st.sessionID,
		ProjectRoot:   st.root,
		Timestamp:     ts,
		GitBranch:     st.branch,
		GitRemote:     st.remote,
		Model:         model,
		Tool:          models.ToolDirac,
		ActionType:    models.ActionAssistantMessage,
		Target:        truncate(body, 200),
		Success:       true,
		RawToolName:   models.ToolDirac + ".assistant_text",
		ToolOutput:    body,
		MessageID:     m.ID,
		Metadata:      st.modeMetadata(m),
	}
	if reasoning != "" {
		ev.PrecedingReasoning = truncate(st.a.scrubber.String(reasoning), reasoningCap)
	}
	res.ToolEvents = append(res.ToolEvents, ev)
}

// applyResult stamps a tool_result onto its call, or — when the call was
// persisted by an earlier parse window — emits an ActionOutcomeUpdate
// keyed by the tool_use id (the call's SourceEventID).
func (st *parseState) applyResult(b rawBlock, res *adapter.ParseResult) {
	text := resultText(b.Content)
	scrubbed := st.a.scrubber.String(contentcap.Cap(text, contentcap.DefaultMaxBytes))
	if scrubbed != "" {
		accumulateToolResultCache(st.cacheAcc, scrubbed)
	}
	if idx, ok := st.pending[b.ToolUseID]; ok && idx < len(res.ToolEvents) {
		ev := &res.ToolEvents[idx]
		failed := resultFailed(ev.RawToolName, b.IsError, text)
		ev.Success = !failed
		if isDenied(text) {
			if ev.Metadata == nil {
				ev.Metadata = &models.ActionMetadata{}
			}
			ev.Metadata.PermissionApprovalKind = "denied"
		}
		if !strings.HasPrefix(ev.RawToolName, respondTool) {
			ev.ToolOutput = scrubbed
		}
		if failed {
			ev.ErrorMessage = truncate(scrubbed, reasoningCap)
		}
		delete(st.pending, b.ToolUseID)
		return
	}
	if b.ToolUseID == "" {
		return
	}
	failed := resultFailed(resultToolHint(text), b.IsError, text)
	upd := models.ActionOutcomeUpdate{
		SourceFile:    st.path,
		SourceEventID: b.ToolUseID,
		SuccessKnown:  true,
		Success:       !failed,
		ToolOutput:    scrubbed,
	}
	if failed {
		upd.ErrorMessage = truncate(scrubbed, reasoningCap)
	}
	res.OutcomeUpdates = append(res.OutcomeUpdates, upd)
}

// resultToolHint recovers the tool of a result whose call is outside
// this parse window from the result's own shape: execute_command results
// open with "--- Output for '<cmd>' ---" (grounded on both OSes).
func resultToolHint(text string) string {
	if strings.HasPrefix(strings.TrimSpace(text), "--- Output for ") {
		return "execute_command"
	}
	return ""
}

// diracGenTimingV is this parser gen-timing version (TokenEvent.
// GenTimingV): bump it when the span rule changes.
const diracGenTimingV = 1

// maxGenMs bounds a plausible generation span (30 minutes): a longer
// start-to-persist gap is a retry storm or a mismatched request, not a
// generation time.
const maxGenMs = 30 * 60 * 1000

func (st *parseState) emitTokens(m *rawMessage, key, model, provider string, ts time.Time, matched *uiStatus, res *adapter.ParseResult) {
	tp := resolveSplit(m.Metrics.Tokens, matched, provider)
	srcID := "tok:" + key
	if obs := emitCacheObservation(st.cacheAcc, st.path, st.sessionID, srcID, model, provider, ts, tp); obs != nil {
		res.CacheObservations = append(res.CacheObservations, *obs)
	}
	tok := models.TokenEvent{
		SourceFile:          st.path,
		SourceEventID:       srcID,
		SessionID:           st.sessionID,
		ProjectRoot:         st.root,
		GitBranch:           st.branch,
		GitRemote:           st.remote,
		Timestamp:           ts,
		Tool:                models.ToolDirac,
		Model:               model,
		InputTokens:         tp.input,
		OutputTokens:        tp.output,
		CacheReadTokens:     tp.cacheRead,
		CacheCreationTokens: tp.cacheWrite,
		ReasoningTokens:     tp.reasoning,
		EstimatedCostUSD:    requestCost(m.Metrics, matched),
		Source:              models.TokenSourceJSONL,
		Reliability:         models.ReliabilityApproximate,
		MessageID:           m.ID,
	}
	// Generation span: the request api_status start to the moment the
	// assistant message was persisted (the stream end).
	if matched != nil && matched.startMs > 0 && m.Ts > matched.startMs {
		if gen := m.Ts - matched.startMs; gen <= maxGenMs {
			tok.GenMs, tok.GenBasis, tok.GenTimingV = gen, models.GenBasisNative, diracGenTimingV
		}
	}
	res.TokenEvents = append(res.TokenEvents, tok)
}

// requestCost is Dirac own per-request cost (taskMetrics.totalCost) when
// it reported one: 0 on the subscription provider, a real figure on a
// metered one. Zero means not reported, so the cost engine prices it.
func requestCost(mt *rawMetrics, st *uiStatus) float64 {
	if mt != nil && mt.Cost > 0 {
		return mt.Cost
	}
	if st != nil && st.Cost != nil && *st.Cost > 0 {
		return *st.Cost
	}
	return 0
}

// finish flags still-unpaired calls, backfills the task-level model,
// stamps surface/version and applies the project identity.
func (st *parseState) finish(res *adapter.ParseResult) {
	for _, idx := range st.pending {
		if idx < len(res.ToolEvents) {
			res.ToolEvents[idx].OutcomePending = true
		}
	}
	if st.metaModel != "" {
		for i := range res.ToolEvents {
			if res.ToolEvents[i].Model == "" {
				res.ToolEvents[i].Model = st.metaModel
			}
		}
	}
	surfaces, versions := sessionStamps(st.sessionID, st.meta)
	// Fallbacks (operator ruling 2026-10-21: stamp EVERY session): a task
	// with no environment record takes the surface from the log channel
	// of the process that ran it and the version from that process
	// installed package.
	if len(surfaces) == 0 {
		if row, ok := channelSurfaces[strings.ToLower(strings.TrimSpace(st.snap.channelFor(st.sessionID)))]; ok {
			surfaces = append(surfaces, models.SessionSurface{SessionID: st.sessionID, Surface: row.kind, SurfaceHost: row.host})
		}
	}
	if len(versions) == 0 {
		if v := st.snap.versionFor(st.sessionID); v != "" {
			versions = append(versions, models.SessionToolVersion{SessionID: st.sessionID, Version: v})
		}
	}
	res.SessionSurfaces = append(res.SessionSurfaces, surfaces...)
	res.SessionToolVersions = append(res.SessionToolVersions, versions...)
	// pid -> session seed from the vendor log. A log read through a
	// foreign-OS mount names a pid of the other OS, so it is skipped.
	if !isForeignMountPath(st.path) {
		if seed, ok := pidSeed(st.sessionID, st.snap.pidFor(st.sessionID), crossmount.TranslateForeignPath(st.cwd)); ok {
			res.SessionProcessSeeds = append(res.SessionProcessSeeds, seed)
		}
	}
	res.ToolAccounts = append(res.ToolAccounts, st.accounts...)
	adapter.ApplyProjectIdentity(res, st.identity)
}

// isAbsAnyOS reports whether p is absolute on EITHER OS family — a POSIX
// `/…` path, a Windows drive path (`C:\…`, `C:/…`) or a UNC `\\…` path —
// because a task written on one OS may be parsed by an observer on the
// other, where filepath.IsAbs applies the wrong rules.
func isAbsAnyOS(p string) bool {
	if p == "" {
		return false
	}
	if p[0] == '/' || strings.HasPrefix(p, `\\`) {
		return true
	}
	if len(p) < 3 || p[1] != ':' || (p[2] != '\\' && p[2] != '/') {
		return false
	}
	c := p[0]
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// Back off to a rune boundary so a multi-byte character is never split.
	for n > 0 && n < len(s) && (s[n]&0xC0) == 0x80 {
		n--
	}
	return s[:n]
}

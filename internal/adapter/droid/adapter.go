package droid

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/contentcap"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// maxReasoningPreview caps the scrubbed thinking summary carried on
// ToolEvent.PrecedingReasoning.
const maxReasoningPreview = 1000

// maxSummaryPreview caps the scrubbed compaction summary carried on the
// ActionContextCompacted row's ToolOutput, mirroring the codex adapter.
const maxSummaryPreview = 2048

// Adapter parses Factory AI droid session transcripts under
// ~/.factory/sessions/<dash-encoded-cwd>/<uuid>.jsonl, reading session-
// level token usage from the sibling <uuid>.settings.json sidecar. See
// the package doc for the record shapes and the token / project-root
// resolution model.
type Adapter struct {
	scrubber *scrub.Scrubber
	roots    []string
}

// New returns an adapter with the default scrubber and platform-default
// cross-mount watch roots (~/.factory/sessions under every resolved
// $HOME).
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
func (*Adapter) Name() string { return models.ToolDroid }

// WatchPaths implements adapter.Adapter. The roots are scoped to
// `<home>/.factory/sessions` and NEVER the parent `~/.factory`, which
// holds the global settings.json (plaintext BYOK API keys), auth.v2.*,
// certs/ and history.json.
func (a *Adapter) WatchPaths() []string { return a.roots }

// IsSessionFile implements adapter.Adapter. A path qualifies only when it
// is BOTH under one of this adapter's watch roots AND matches the droid
// transcript shape `.factory/sessions/<dir>/<uuid>.jsonl`. The sibling
// `<uuid>.settings.json` and `<uuid>.settings.json.bak` are rejected by
// the `.jsonl` suffix requirement — the sidecar is read directly by
// ParseSessionFile, never dispatched as a session file of its own.
func (a *Adapter) IsSessionFile(path string) bool {
	if !matchesShape(path) {
		return false
	}
	return adapter.UnderAnyWatchRoot(path, a.WatchPaths())
}

// matchesShape reports whether path has the droid transcript shape,
// independent of watch roots. Comparison is on a slash-normalized,
// lower-cased copy so Windows separators and case-insensitive mounts
// match too.
func matchesShape(path string) bool {
	lower := strings.ReplaceAll(strings.ToLower(path), `\`, "/")
	if !strings.Contains(lower, "/.factory/sessions/") {
		return false
	}
	return strings.HasSuffix(filepath.Base(lower), ".jsonl")
}

// defaultRoots returns ~/.factory/sessions under every cross-mount-
// resolved $HOME, so a WSL2 observer picks up Windows-side droid sessions
// on /mnt/c/Users/<u>/.factory and vice versa. droid mirrors the same
// relative layout onto %USERPROFILE%\.factory — there is no
// %APPDATA%/%LOCALAPPDATA% variant to enumerate.
func defaultRoots() []string {
	var roots []string
	for _, h := range crossmount.AllHomes() {
		roots = append(roots, filepath.Join(h.Path, ".factory", "sessions"))
	}
	return roots
}

// header carries the session-identifying fields of the session_start
// record on line 1 of every transcript.
type header struct {
	sessionID string
	cwd       string
	// parent is the source session id when this transcript is a
	// Factory Desktop fork of another session (see lineageForHeader).
	// Empty for a normal or CLI-authored session.
	parent string
}

// readHeader reads line 1 of the transcript and decodes the session_start
// record. It runs on EVERY parse, including resumed parses whose byte
// range starts past line 1 — the session id and the authoritative cwd
// live only there, so a resumed parse would otherwise lose both.
//
// A missing/short/malformed first line is tolerated: the session id falls
// back to the transcript's own `<uuid>` basename (droid names the file
// after the session id) and the project root is left unresolved.
func readHeader(path string) header {
	h := header{sessionID: strings.TrimSuffix(filepath.Base(path), ".jsonl")}
	f, err := os.Open(path) //nolint:gosec // path comes from the watcher's own watch roots
	if err != nil {
		return h
	}
	defer f.Close()

	line, err := bufio.NewReaderSize(f, 64*1024).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return h
	}
	var rec rawRecord
	if json.Unmarshal([]byte(strings.TrimRight(line, "\r\n")), &rec) != nil {
		return h
	}
	if rec.Type != typeSessionStart {
		return h
	}
	if strings.TrimSpace(rec.ID) != "" {
		h.sessionID = rec.ID
	}
	h.cwd = rec.Cwd
	h.parent = strings.TrimSpace(rec.Parent)
	return h
}

// ParseSessionFile implements adapter.Adapter. It streams the JSONL from
// fromOffset to EOF emitting ToolEvents (session start, user prompts,
// context injection, host notices, assistant text, tool calls + their
// paired results, todo updates, compactions, failed turn outcomes) plus
// at most ONE session-level TokenEvent read from the sibling
// `<uuid>.settings.json` sidecar.
//
// Malformed lines are skipped with a warning; the byte cursor advances
// past every fully terminated line so repeated calls make progress. Two
// record shapes are deliberately deferred instead of consumed, so the
// next parse re-reads them whole:
//
//   - a partial trailing line (droid still writing it), and
//   - the record of a tool_use whose tool_result has not been written
//     yet (see pending.go — a cross-tick pair would otherwise persist a
//     permanently wrong outcome).
//
// A resumed parse (fromOffset > 0) first REPLAYS the bytes before the
// cursor with emission suppressed, rebuilding the cross-line state the
// live window needs (current model, last host notice, last timestamp).
// Same shape as codex's prefetchSessionContext.
func (a *Adapter) ParseSessionFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	f, err := os.Open(path) //nolint:gosec // path comes from the watcher's own watch roots
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("droid.ParseSessionFile: open %s: %w", path, err)
	}
	defer f.Close()

	hdr := readHeader(path)
	sc, sidecarMod, hasSidecar := readSidecar(path)

	st := &parseState{
		adapter:     a,
		path:        path,
		sessionID:   hdr.sessionID,
		firstOffset: fromOffset,
		pendingTool: map[string]pendingMark{},
	}
	st.projectRoot, st.gitBranch, st.gitRemote, st.identity = resolveProjectRoot(hdr.cwd)
	if hasSidecar {
		st.model = sc.resolvedModel()
	}

	if fromOffset > 0 {
		st.replayPrefix(ctx, f, fromOffset)
		if _, err := f.Seek(fromOffset, io.SeekStart); err != nil {
			return adapter.ParseResult{}, fmt.Errorf("droid.ParseSessionFile: seek %s: %w", path, err)
		}
	}

	res := adapter.ParseResult{NewOffset: fromOffset}
	// Fork lineage lives entirely on line 1, which readHeader above just
	// re-read regardless of fromOffset — so, like emitSessionStart, this
	// only needs to run on the very first (offset 0) parse; every later
	// resumed parse would just re-derive and re-append the identical row.
	if fromOffset == 0 {
		if lin, ok := lineageForHeader(st.sessionID, hdr.parent); ok {
			res.SessionLineages = append(res.SessionLineages, lin)
		}
	}
	if err := st.stream(ctx, f, fromOffset, &res); err != nil {
		adapter.ApplyProjectIdentity(&res, st.identity)
		return res, err
	}
	st.deferUnpairedTail(&res)

	if hasSidecar {
		ts := st.lastTS
		if ts.IsZero() {
			ts = sidecarMod
		}
		if ev, ok := tokenEvent(sc, path, st.sessionID, st.projectRoot, st.gitBranch, st.gitRemote, ts); ok {
			res.TokenEvents = append(res.TokenEvents, ev)
		}
	}
	adapter.ApplyProjectIdentity(&res, st.identity)
	// Capture-surface attribution (see surface.go): stamped once, at most,
	// per parse window, when this window observed a real user-typed
	// message carrying droid's own Factory Desktop marker.
	if st.surfaceDesktop {
		res.SessionSurfaces = append(res.SessionSurfaces, desktopSurface(st.sessionID))
	}
	return res, nil
}

// stream runs the line loop, committing res.NewOffset past every fully
// terminated line.
func (st *parseState) stream(ctx context.Context, f *os.File, fromOffset int64, res *adapter.ParseResult) error {
	// bufio.Reader.ReadString (not Scanner) so the byte cursor advances by
	// the exact terminator length including CRLF, and long tool-output
	// lines aren't capped by a token-size limit.
	reader := bufio.NewReaderSize(f, 64*1024)
	bytesRead := fromOffset
	lineNum := 0
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		lineStr, readErr := reader.ReadString('\n')
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return fmt.Errorf("droid.ParseSessionFile: read %s: %w", st.path, readErr)
		}
		// A partial trailing line (no '\n' at EOF) is a still-being-written
		// record: defer it, do NOT advance the cursor past it.
		if !strings.HasSuffix(lineStr, "\n") && errors.Is(readErr, io.EOF) {
			return nil
		}
		lineStart := bytesRead
		bytesRead += int64(len(lineStr))
		lineNum++
		// Commit the offset for every terminated line, even empty or
		// malformed ones, so the poll loop can't spin on a bad line.
		res.NewOffset = bytesRead

		raw := strings.TrimRight(lineStr, "\r\n")
		if raw != "" {
			var rec rawRecord
			if err := json.Unmarshal([]byte(raw), &rec); err != nil {
				res.Warnings = append(res.Warnings,
					fmt.Sprintf("%s line %d: malformed JSON: %v", filepath.Base(st.path), lineNum, err))
			} else {
				// Rewind coordinates for the tool_use deferral: where this
				// record starts, and what the result held BEFORE it was
				// handled (so a truncation removes the record whole).
				st.curLineStart = lineStart
				st.curToolLen = len(res.ToolEvents)
				st.curTokenLen = len(res.TokenEvents)
				st.handle(&rec, res)
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
	}
}

// replayPrefix re-reads [0, until) with emission suppressed, rebuilding
// only the cross-line state a resumed parse would otherwise start blind
// on: the running model id, the last host notice (which a later failed
// agent_turn_outcome reports as its cause), and the last record
// timestamp (substituted onto records that carry none). It emits
// nothing, registers no pending tool_use, and never touches
// res.NewOffset.
//
// Best-effort by design, mirroring codex's prefetchSessionContext: a
// seek or read failure just leaves the state at its pre-replay value and
// the live parse proceeds. A line straddling `until` is NOT applied —
// the live parse re-reads it and applies it itself.
//
// This is deliberately NOT a re-run of the emit handlers: it decodes the
// same records but skips scrubbing, content capping and event
// construction, so replaying a multi-megabyte transcript on every poll
// stays cheap. The handlers it mirrors are handleMessage (modelId) and
// emitUserText (the user_only notice); a change to either must be
// reflected here.
func (st *parseState) replayPrefix(ctx context.Context, f *os.File, until int64) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return
	}
	reader := bufio.NewReaderSize(f, 64*1024)
	var bytesRead int64
	for {
		if ctx.Err() != nil {
			return
		}
		lineStr, readErr := reader.ReadString('\n')
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return
		}
		if !strings.HasSuffix(lineStr, "\n") {
			return
		}
		bytesRead += int64(len(lineStr))
		if bytesRead > until {
			return
		}
		if raw := strings.TrimRight(lineStr, "\r\n"); raw != "" {
			var rec rawRecord
			if json.Unmarshal([]byte(raw), &rec) == nil {
				st.replayRecord(&rec)
			}
		}
		if errors.Is(readErr, io.EOF) {
			return
		}
	}
}

// replayRecord folds one pre-cursor record into the parse state without
// emitting anything.
func (st *parseState) replayRecord(rec *rawRecord) {
	st.stamp(rec.Timestamp)
	if rec.Type != typeMessage || rec.Message == nil {
		return
	}
	if m := strings.TrimSpace(rec.Message.ModelID); m != "" {
		st.model = m
	}
	if rec.Message.Role == "assistant" || rec.Message.Visibility != visibilityUserOnly {
		return
	}
	if text := joinTexts(userTexts(decodeBlocks(rec.Message.Content))); text != "" {
		st.lastNotice = st.adapter.scrubber.String(text)
	}
}

// resolveProjectRoot translates a foreign-OS cwd (a WSL2 observer reading
// a Windows `C:\...` session, or a Windows observer reading
// \\wsl.localhost) BEFORE git.Resolve. The translation is UNCONDITIONAL:
// a drive-letter path reaching git.Resolve would be treated as relative
// by filepath.Abs and get the observer's OWN cwd prefixed onto it
// (feedback_foreign_path_git_resolve). Returns (projectRoot, gitBranch,
// gitRemote); a blank cwd yields ("", "", "").
func resolveProjectRoot(rawCWD string) (root, branch, remote string, id git.Identity) {
	cwd := strings.TrimSpace(rawCWD)
	if cwd == "" {
		return "", "", "", git.Identity{}
	}
	cwd = crossmount.TranslateForeignPath(cwd)
	identity, err := git.ResolveIdentity(cwd, git.IdentityOptions{})
	if err != nil {
		return cwd, "", "", git.Identity{}
	}
	// identity.Remote is already NormalizeRemote'd by ResolveIdentity.
	return identity.Root, identity.Branch, identity.Remote, identity
}

// parseState carries the per-call bookkeeping the record handlers share.
type parseState struct {
	adapter     *Adapter
	path        string
	sessionID   string
	projectRoot string
	gitBranch   string
	gitRemote   string
	// identity is the Project Identity Resolver v2 bundle (2026-09-06,
	// §3.1 / W1) resolved alongside gitBranch/gitRemote.
	identity git.Identity
	// model is the current model id: seeded from the sidecar's `model`
	// and upgraded by each assistant message's own `modelId`.
	model string
	// firstOffset is the fromOffset the parse started at; the session-start
	// marker is only emitted when parsing from the very top of the file.
	firstOffset int64
	// lastTS is the most recent record timestamp, substituted onto records
	// that carry none (agent_turn_outcome).
	lastTS time.Time
	// lastNotice is the most recent user_only host notice, reused as the
	// ErrorMessage of a subsequent failed agent_turn_outcome (which itself
	// carries no message).
	lastNotice string
	// pendingTool maps a tool_use id to the location of its ToolEvent in
	// res.ToolEvents, so the later tool_result block can stamp
	// success/output onto it. Whatever is still pending at EOF drives
	// the tail deferral in pending.go.
	pendingTool map[string]pendingMark
	// surfaceDesktop is set once this parse window observes a real
	// user-typed message carrying userMessageSourceDesktop. See
	// surface.go for the grounding and why there is no negative case.
	surfaceDesktop bool
	// curLineStart / curToolLen / curTokenLen are the rewind coordinates
	// of the record currently being handled, captured by stream before
	// dispatch.
	curLineStart int64
	curToolLen   int
	curTokenLen  int
}

// handle dispatches one record onto the appropriate emit path.
func (st *parseState) handle(rec *rawRecord, res *adapter.ParseResult) {
	ts := st.stamp(rec.Timestamp)
	switch rec.Type {
	case typeSessionStart:
		st.emitSessionStart(rec, res)
	case typeMessage:
		st.handleMessage(rec, ts, res)
	case typeAgentTurnOutcome:
		st.emitTurnOutcome(rec, ts, res)
	case typeCompactionState:
		st.emitCompaction(rec, ts, res)
	case typeTodoState:
		st.emitTodo(rec, ts, res)
	}
}

// stamp parses a record timestamp, remembers it as the running "last
// seen" value, and substitutes that value when the record carries none.
func (st *parseState) stamp(raw string) time.Time {
	if ts := parseTimestamp(raw); !ts.IsZero() {
		st.lastTS = ts
		return ts
	}
	return st.lastTS
}

// event builds a ToolEvent pre-filled with the session-constant fields.
func (st *parseState) event(eventID, actionType string, ts time.Time) models.ToolEvent {
	return models.ToolEvent{
		SourceFile:    st.path,
		SourceEventID: eventID,
		SessionID:     st.sessionID,
		ProjectRoot:   st.projectRoot,
		GitBranch:     st.gitBranch,
		GitRemote:     st.gitRemote,
		Timestamp:     ts,
		Tool:          models.ToolDroid,
		ActionType:    actionType,
		Success:       true,
	}
}

// emitSessionStart records the session-start marker, but only when the
// parse began at the top of the file (a resumed parse never re-emits it;
// the header is still read for the session id and cwd).
func (st *parseState) emitSessionStart(rec *rawRecord, res *adapter.ParseResult) {
	if st.firstOffset != 0 {
		return
	}
	ev := st.event("session_start:"+st.sessionID, models.ActionSessionStart, st.lastTS)
	ev.Target = "startup"
	ev.RawToolName = models.ToolDroid + ".session_start"
	ev.Model = st.model
	ev.PrecedingReasoning = truncate(st.adapter.scrubber.String(rec.Title), 200)
	res.ToolEvents = append(res.ToolEvents, ev)
}

// handleMessage fans a message record's content blocks out onto events.
// Thinking blocks are collected first (droid emits them ahead of the text
// / tool_use blocks they precede) and carried as PrecedingReasoning; the
// encrypted provider reasoning signature is never emitted.
func (st *parseState) handleMessage(rec *rawRecord, ts time.Time, res *adapter.ParseResult) {
	msg := rec.Message
	if msg == nil {
		return
	}
	if msg.Role == "user" && msg.UserMessageSource == userMessageSourceDesktop {
		st.surfaceDesktop = true
	}
	blocks := decodeBlocks(msg.Content)
	if len(blocks) == 0 {
		return
	}
	if m := strings.TrimSpace(msg.ModelID); m != "" {
		st.model = m
	}
	reasoning := st.collectReasoning(blocks)

	if msg.Role == "assistant" {
		st.emitAssistantBlocks(rec, blocks, reasoning, ts, res)
		return
	}
	st.emitUserBlocks(rec, msg, blocks, ts, res)
}

// collectReasoning joins the scrubbed plaintext thinking summaries of a
// message into one capped preview.
func (st *parseState) collectReasoning(blocks []rawBlock) string {
	var b strings.Builder
	for _, blk := range blocks {
		if blk.Type != blockThinking || strings.TrimSpace(blk.Thinking) == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteString("\n\n")
		}
		b.WriteString(blk.Thinking)
	}
	if b.Len() == 0 {
		return ""
	}
	return truncate(st.adapter.scrubber.String(b.String()), maxReasoningPreview)
}

// emitAssistantBlocks walks an assistant message's blocks in order,
// emitting one row per text block and one per tool_use.
func (st *parseState) emitAssistantBlocks(rec *rawRecord, blocks []rawBlock, reasoning string, ts time.Time, res *adapter.ParseResult) {
	for i, blk := range blocks {
		switch blk.Type {
		case blockText:
			if strings.TrimSpace(blk.Text) == "" {
				continue
			}
			scrubbed := st.adapter.scrubber.String(blk.Text)
			ev := st.event("assistant:"+rec.ID+":"+strconv.Itoa(i), models.ActionAssistantMessage, ts)
			ev.Target = truncate(scrubbed, 200)
			ev.RawToolName = models.ToolDroid + ".assistant_text"
			ev.ToolOutput = st.adapter.scrubber.String(contentcap.Cap(blk.Text, contentcap.DefaultMaxBytes))
			ev.Model = st.model
			ev.PrecedingReasoning = reasoning
			res.ToolEvents = append(res.ToolEvents, ev)
		case blockToolUse:
			st.emitToolUse(rec, &blocks[i], i, reasoning, ts, res)
		}
	}
}

// emitToolUse records an assistant tool call, registering it as pending
// so the paired tool_result can stamp its outcome.
func (st *parseState) emitToolUse(rec *rawRecord, blk *rawBlock, pos int, reasoning string, ts time.Time, res *adapter.ParseResult) {
	eventID := "tool:" + blk.ID
	if strings.TrimSpace(blk.ID) == "" {
		eventID = "tool:" + rec.ID + ":" + strconv.Itoa(pos)
	}
	ev := st.event(eventID, mapToolName(blk.Name), ts)
	ev.Target = truncate(st.adapter.scrubber.String(targetFromInput(blk.Input, blk.Name)), 500)
	ev.RawToolName = blk.Name
	ev.RawToolInput = st.adapter.scrubber.RawJSON(blk.Input)
	ev.Model = st.model
	ev.PrecedingReasoning = reasoning
	ev.DurationMs = blk.DurationMs
	// Optimistic; corrected by the paired tool_result block. When that
	// block hasn't been written yet, deferUnpairedTail rewinds past this
	// record rather than shipping the optimistic value — the store
	// cannot flip `success` on a later re-emit.
	res.ToolEvents = append(res.ToolEvents, ev)
	if blk.ID != "" {
		st.pendingTool[blk.ID] = pendingMark{
			idx:       len(res.ToolEvents) - 1,
			lineStart: st.curLineStart,
			toolLen:   st.curToolLen,
			tokenLen:  st.curTokenLen,
		}
	}
}

// emitUserBlocks handles a user-role message: the aggregated text (a real
// prompt, droid's llm_only context injection, or a user_only host notice)
// plus any tool_result blocks, which droid nests in user messages the way
// the Anthropic Messages API does.
func (st *parseState) emitUserBlocks(rec *rawRecord, msg *rawMessage, blocks []rawBlock, ts time.Time, res *adapter.ParseResult) {
	for i := range blocks {
		if blocks[i].Type == blockToolResult {
			st.applyToolResult(&blocks[i], res)
		}
	}
	texts := userTexts(blocks)
	if len(texts) == 0 {
		return
	}
	st.emitUserText(rec, msg.Visibility, joinTexts(texts), ts, res)
}

// userTexts collects the non-blank text blocks of a message. Shared by
// the emit path and the state-only prefix replay so both aggregate a
// user-role body identically.
func userTexts(blocks []rawBlock) []string {
	var texts []string
	for i := range blocks {
		if blocks[i].Type == blockText && strings.TrimSpace(blocks[i].Text) != "" {
			texts = append(texts, blocks[i].Text)
		}
	}
	return texts
}

// joinTexts renders collected text blocks as one body.
func joinTexts(texts []string) string { return strings.Join(texts, "\n\n") }

// emitUserText maps one aggregated user-role text body onto a row,
// discriminated by message.visibility (see the package doc).
func (st *parseState) emitUserText(rec *rawRecord, visibility, text string, ts time.Time, res *adapter.ParseResult) {
	scrubbed := st.adapter.scrubber.String(text)
	switch visibility {
	case visibilityLLMOnly:
		// droid re-injects the identical system-reminder context block on
		// every turn. The SourceEventID is content-addressed so the store's
		// (source_file, source_event_id) dedup collapses the repeats into
		// one row per distinct payload, per the ActionSystemPrompt contract.
		ev := st.event("sysprompt:"+contentHash(scrubbed), models.ActionSystemPrompt, ts)
		ev.Target = truncate(scrubbed, 200)
		ev.RawToolName = models.ToolDroid + ".context"
		ev.RawToolInput = scrubbed
		ev.MessageID = contentHash(scrubbed)
		res.ToolEvents = append(res.ToolEvents, ev)
	case visibilityUserOnly:
		// A host notice rendered to the operator but never sent to the
		// model ("No active subscription found."). Remembered so a failed
		// agent_turn_outcome — which carries no message of its own — can
		// report why it failed.
		st.lastNotice = scrubbed
		ev := st.event("notice:"+rec.ID, models.ActionNotification, ts)
		ev.Target = truncate(scrubbed, 200)
		ev.RawToolName = models.ToolDroid + ".user_notice"
		ev.ErrorMessage = truncate(scrubbed, 500)
		res.ToolEvents = append(res.ToolEvents, ev)
	default:
		ev := st.event("prompt:"+rec.ID, models.ActionUserPrompt, ts)
		ev.Target = truncate(scrubbed, 200)
		ev.RawToolName = models.ToolDroid + ".user_prompt"
		ev.RawToolInput = scrubbed
		res.ToolEvents = append(res.ToolEvents, ev)
	}
}

// applyToolResult stamps success + scrubbed output onto the ToolEvent its
// matching tool_use produced. An unmatched tool_use_id (the call landed
// before the parse window) is silently ignored.
func (st *parseState) applyToolResult(blk *rawBlock, res *adapter.ParseResult) {
	mark, ok := st.pendingTool[blk.ToolUseID]
	if !ok || mark.idx >= len(res.ToolEvents) {
		return
	}
	ev := &res.ToolEvents[mark.idx]
	ev.Success = !blk.IsError
	if out := resultText(blk.Content); out != "" {
		scrubbed := st.adapter.scrubber.String(contentcap.Cap(out, contentcap.DefaultMaxBytes))
		ev.ToolOutput = scrubbed
		if blk.IsError {
			ev.ErrorMessage = truncate(scrubbed, 500)
		}
	}
	delete(st.pendingTool, blk.ToolUseID)
}

// emitTurnOutcome records a FAILED assistant-turn boundary. Successful
// turns are deliberately not rowed: `reason:"completed"` carries no
// information the surrounding messages don't already have, so emitting it
// would be one noise row per turn.
func (st *parseState) emitTurnOutcome(rec *rawRecord, ts time.Time, res *adapter.ParseResult) {
	reason := strings.TrimSpace(rec.Reason)
	if reason == "" || reason == "completed" {
		return
	}
	actionType := models.ActionAPIError
	if reason != "error" {
		// aborted / cancelled / interrupted / max_turns …
		actionType = models.ActionTurnAborted
	}
	ev := st.event("turn:"+firstNonEmpty(rec.TurnID, rec.ID), actionType, ts)
	ev.Target = truncate(fmt.Sprintf("%s (%s)", reason, firstNonEmpty(rec.ResultKind, "unknown")), 200)
	ev.RawToolName = models.ToolDroid + "." + typeAgentTurnOutcome
	ev.Model = st.model
	ev.Success = false
	// droid puts the human-readable cause in the preceding user_only
	// notice, not on the outcome record itself.
	ev.ErrorMessage = truncate(st.lastNotice, 500)
	res.ToolEvents = append(res.ToolEvents, ev)
}

// emitCompaction records a context compaction as an ActionContextCompacted
// row (the existing normalized type used by claudecode / codex / cursor /
// cowork — no new action type is introduced).
//
// The record's `systemInfo` block embeds live pwd / ls / git status /
// git log command+OUTPUT pairs droid captured to re-ground itself. Those
// outputs are deliberately dropped: they are command output, they are
// droid's own bookkeeping rather than agent activity, and they are the
// highest-risk content in the record.
func (st *parseState) emitCompaction(rec *rawRecord, ts time.Time, res *adapter.ParseResult) {
	kind := firstNonEmpty(rec.SummaryKind, "compaction")
	ev := st.event("compact:"+rec.ID, models.ActionContextCompacted, ts)
	ev.Target = truncate(fmt.Sprintf("%s: %d msgs removed, ~%d tokens", kind, rec.RemovedCount, rec.SummaryTokens), 200)
	ev.RawToolName = models.ToolDroid + "." + typeCompactionState
	ev.RawToolInput = fmt.Sprintf(`{"summary_kind":%q,"removed_count":%d,"summary_tokens":%d}`,
		kind, rec.RemovedCount, rec.SummaryTokens)
	ev.ToolOutput = st.adapter.scrubber.String(truncate(rec.SummaryText, maxSummaryPreview))
	ev.Model = st.model
	res.ToolEvents = append(res.ToolEvents, ev)
}

// emitTodo records a todo_state event. droid's payload is a single
// flattened markdown checklist STRING ("1. [in_progress] …"), not a
// structured array; it is stored verbatim rather than re-parsed.
func (st *parseState) emitTodo(rec *rawRecord, ts time.Time, res *adapter.ParseResult) {
	if rec.Todos == nil || strings.TrimSpace(rec.Todos.Todos) == "" {
		return
	}
	scrubbed := st.adapter.scrubber.String(rec.Todos.Todos)
	ev := st.event("todo:"+rec.ID, models.ActionTodoUpdate, ts)
	ev.Target = truncate(strings.ReplaceAll(scrubbed, "\n", " | "), 200)
	ev.RawToolName = models.ToolDroid + "." + typeTodoState
	ev.RawToolInput = scrubbed
	ev.Model = st.model
	res.ToolEvents = append(res.ToolEvents, ev)
}

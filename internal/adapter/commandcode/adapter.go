package commandcode

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
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

// checkpointsSuffix is the `/rewind` restore-point sidecar. It also ends
// in `.jsonl`, so a naive suffix test would misclassify it as a
// transcript — see IsSessionFile.
const checkpointsSuffix = ".checkpoints.jsonl"

// metaSuffix is the per-session metadata sidecar read lazily (at most
// once per parse, only when a usage record omits its inline model) for a
// fallback model string.
const metaSuffix = ".meta.json"

// Adapter parses Command Code session transcripts under
// ~/.commandcode/projects/<dash-encoded-cwd>/<uuid>.jsonl. See the
// package doc for the record shapes, the gross→net token correction and
// the off-limits file list.
type Adapter struct {
	scrubber *scrub.Scrubber
	roots    []string
}

// New returns an adapter with the default scrubber and platform-default
// cross-mount watch roots (~/.commandcode/projects under every resolved
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
func (*Adapter) Name() string { return models.ToolCommandCode }

// WatchPaths implements adapter.Adapter. One root per cross-mount-resolved
// $HOME: Command Code uses `<home>/.commandcode/projects` identically on
// Linux, macOS and native Windows (`%USERPROFILE%\.commandcode`), so a
// WSL2 observer picks up Windows-side sessions on
// /mnt/c/Users/<u>/.commandcode and vice versa with no OS branching.
func (a *Adapter) WatchPaths() []string { return a.roots }

// defaultRoots returns ~/.commandcode/projects under every
// cross-mount-resolved $HOME.
func defaultRoots() []string {
	var roots []string
	for _, h := range crossmount.AllHomes() {
		if h.Path == "" {
			continue
		}
		roots = append(roots, filepath.Join(h.Path, ".commandcode", "projects"))
	}
	return roots
}

// IsSessionFile implements adapter.Adapter. A path qualifies only when it
// is BOTH under one of this adapter's watch roots AND matches the
// transcript shape `.commandcode/projects/<slug>/<uuid>.jsonl`. The
// `<uuid>.checkpoints.jsonl` sidecar is rejected explicitly (it shares
// the `.jsonl` extension); `<uuid>.meta.json`, the per-project
// `config.json` and the top-level `history.jsonl` are all rejected by
// the extension test or the projects/ path test.
func (a *Adapter) IsSessionFile(path string) bool {
	if !matchesShape(path) {
		return false
	}
	return adapter.UnderAnyWatchRoot(path, a.WatchPaths())
}

// matchesShape reports whether path has the Command Code transcript
// shape, independent of watch roots. Comparison is on a slash-normalized,
// lower-cased copy so Windows separators and case-insensitive mounts
// match too.
func matchesShape(path string) bool {
	lower := strings.ReplaceAll(strings.ToLower(path), `\`, "/")
	if !strings.Contains(lower, "/.commandcode/projects/") {
		return false
	}
	base := filepath.Base(lower)
	if !strings.HasSuffix(base, ".jsonl") {
		return false
	}
	return !strings.HasSuffix(base, checkpointsSuffix)
}

// ParseSessionFile implements adapter.Adapter. It streams the JSONL from
// fromOffset to EOF, emitting ToolEvents (a session-start marker, user
// prompts, assistant text, tool calls stamped with their paired results)
// and TokenEvents (one per usage-bearing message record, with the GROSS
// input netted against cache-read).
//
// The session header line is ALWAYS re-read, even on a resumed parse, so
// a mid-file resume still has the session id and the inline cwd needed
// for project-root resolution. Malformed lines are skipped with a
// warning and the byte cursor advances past every fully terminated line,
// so a bad line can't stall the poll loop. Two record shapes are
// deliberately deferred rather than consumed, so the next parse re-reads
// them whole: a partial trailing line (a record still being written),
// and the record of a tool_use whose tool_result has not landed yet (see
// pending.go — a cross-tick pair would otherwise persist a permanently
// wrong outcome).
func (a *Adapter) ParseSessionFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	f, err := os.Open(path) //nolint:gosec // path comes from the watcher's own watch roots
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("commandcode.ParseSessionFile: open %s: %w", path, err)
	}
	defer f.Close()

	st := &parseState{
		adapter:     a,
		path:        path,
		rootCache:   map[string]string{},
		pendingCall: map[string]pendingMark{},
		unknownTool: map[string]bool{},
		firstOffset: fromOffset,
		sessionID:   sessionIDFromPath(path),
		cacheAcc:    cacheobs.New(MaxBlocksPerSession),
	}
	// Read the header before seeking: on a resumed parse the session
	// record is behind the cursor, but its inline cwd is the ONLY source
	// of a project root (the dash-encoded directory name is lossy and is
	// never decoded).
	if err := st.readHeader(f); err != nil {
		return adapter.ParseResult{}, err
	}

	if _, err := f.Seek(fromOffset, io.SeekStart); err != nil {
		return adapter.ParseResult{}, fmt.Errorf("commandcode.ParseSessionFile: seek: %w", err)
	}

	res := adapter.ParseResult{NewOffset: fromOffset}

	// bufio.Reader.ReadString (not Scanner) so the byte cursor advances by
	// the exact terminator length including CRLF, and long tool-output
	// lines aren't capped by a token-size limit.
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
			return res, fmt.Errorf("commandcode.ParseSessionFile: read: %w", readErr)
		}
		hasNewline := strings.HasSuffix(lineStr, "\n")
		// A partial trailing line (no '\n' at EOF) is a still-being-written
		// record: defer it, do NOT advance the cursor past it, so the next
		// parse re-reads it whole.
		if !hasNewline && readErr == io.EOF {
			break
		}
		lineStart := bytesRead
		bytesRead += int64(len(lineStr))
		lineNum++
		// Commit the offset for every terminated line, even empty or
		// malformed ones, so the poll loop can't spin on a bad line.
		res.NewOffset = bytesRead

		raw := strings.TrimRight(lineStr, "\r\n")
		if raw == "" {
			if readErr == io.EOF {
				break
			}
			continue
		}
		var rec rawLine
		if err := json.Unmarshal([]byte(raw), &rec); err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("line %d: malformed JSON: %v", lineNum, err))
			if readErr == io.EOF {
				break
			}
			continue
		}
		st.curLineStart = lineStart
		st.curToolLen = len(res.ToolEvents)
		st.curTokenLen = len(res.TokenEvents)
		st.handle(&rec, lineStart, &res)
		if readErr == io.EOF {
			break
		}
	}
	st.deferUnpairedTail(&res)
	adapter.ApplyProjectIdentity(&res, st.identity)
	return res, nil
}

// parseState carries the per-call mutable bookkeeping the record handler
// needs across lines.
type parseState struct {
	adapter *Adapter
	path    string
	// rootCache memoizes cwd → resolved project root (git.Resolve walks
	// the filesystem, and one transcript shares one cwd throughout).
	rootCache map[string]string
	// pendingCall maps a tool_use id to the location of its ToolEvent in
	// res.ToolEvents, so the later tool_result block can stamp
	// success/output onto it. Whatever is still pending at EOF drives
	// the tail deferral in pending.go.
	pendingCall map[string]pendingMark
	// curLineStart / curToolLen / curTokenLen are the rewind coordinates
	// of the record currently being handled, captured by the line loop
	// before dispatch.
	curLineStart int64
	curToolLen   int
	curTokenLen  int
	// unknownTool dedupes the "unrecognised tool name" warning so a long
	// session with many calls to one unmapped tool warns once.
	unknownTool map[string]bool
	// firstOffset is the fromOffset the parse started at; the session-start
	// marker is only emitted when parsing from the very top of the file.
	firstOffset int64
	// sessionStarted guards against emitting more than one session-start
	// marker per parse call.
	sessionStarted bool
	// sessionID is the session uuid — from the header line when present,
	// otherwise from the `<uuid>.jsonl` filename stem (they are the same
	// value by construction).
	sessionID string
	// cwd is the raw absolute OS path from the header line.
	cwd string
	// branch is the git branch resolved alongside the project root.
	branch string
	// remote is the normalized git remote resolved alongside the project
	// root (see projectRoot).
	remote string
	// identity is the Project Identity Resolver v2 bundle (2026-09-06,
	// §3.1 / W1) resolved alongside branch/remote by projectRoot,
	// applied to every event in the ParseResult via
	// adapter.ApplyProjectIdentity before ParseSessionFile returns.
	identity git.Identity
	// fallbackModel comes from the `<uuid>.meta.json` sidecar and is used
	// only when a usage-bearing record carries no inline model. Loaded
	// LAZILY (metaRead latches the one attempt per parse) so a resumed
	// parse that meets a model-less usage record still gets the
	// fallback — reading it only at offset 0 lost it on every resume.
	fallbackModel string
	metaRead      bool
	// cacheAcc accumulates this parse call's running Tier-2 content-block
	// delta (prompt/assistant text, tool calls, tool results, in wire
	// order) and drains it into one CacheTurnObservation per usage-bearing
	// record (see emitTokens / emitCacheObservation in cachetrack.go).
	cacheAcc *cacheobs.Accumulator
}

// sidecarFallbackModel returns the `<uuid>.meta.json` model, reading the
// sidecar at most once per parse and only when something actually needs
// it. Returns "" when the sidecar is missing, symlinked or malformed.
func (st *parseState) sidecarFallbackModel() string {
	if !st.metaRead {
		st.metaRead = true
		st.fallbackModel = sidecarModel(st.path)
	}
	return st.fallbackModel
}

// readHeader reads the first line of the transcript (position 0,
// independent of the parse cursor) and records the session id and inline
// cwd. A missing, empty or non-session first line is tolerated: the
// filename stem still supplies a session id and the project root simply
// stays empty.
func (st *parseState) readHeader(f *os.File) error {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("commandcode.readHeader: seek: %w", err)
	}
	line, err := bufio.NewReaderSize(f, 64*1024).ReadString('\n')
	if err != nil && err != io.EOF {
		return fmt.Errorf("commandcode.readHeader: read: %w", err)
	}
	raw := strings.TrimRight(line, "\r\n")
	if raw == "" {
		return nil
	}
	var rec rawLine
	if err := json.Unmarshal([]byte(raw), &rec); err != nil || rec.Type != "session" {
		return nil
	}
	if rec.ID != "" {
		st.sessionID = rec.ID
	}
	st.cwd = rec.Cwd
	return nil
}

// sessionIDFromPath recovers the session uuid from the `<uuid>.jsonl`
// filename stem. Command Code names the transcript and both sidecars
// after the session id, so the stem is a deterministic fallback when the
// header line is unavailable (a resumed parse of a truncated file).
func sessionIDFromPath(path string) string {
	return strings.TrimSuffix(filepath.Base(path), ".jsonl")
}

// sidecarModel reads the `<uuid>.meta.json` sidecar and returns its
// `model` field (the LAST model used in the session). A missing,
// symlinked or malformed sidecar yields "" — it is a convenience
// fallback, never a requirement. The sidecar's `title` and `traceIds`
// are deliberately not surfaced (see the package doc).
func sidecarModel(transcriptPath string) string {
	stem := strings.TrimSuffix(transcriptPath, ".jsonl")
	if stem == transcriptPath {
		return ""
	}
	metaPath := stem + metaSuffix
	// The sidecar path is DERIVED, not observed: whatever sits at
	// `<uuid>.meta.json` is read without the watcher having claimed it.
	// A symlink there would let the files this adapter promises never to
	// read — `~/.commandcode/auth.json` (the account credential),
	// `history.jsonl` (a cross-project raw-prompt log) — be pulled in
	// through the sibling lookup. Refuse symlinks outright: a real
	// Command Code install never writes one, so this costs nothing and
	// keeps the package doc's "does NOT read" list true by construction.
	info, err := os.Lstat(metaPath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		return ""
	}
	body, err := os.ReadFile(metaPath) //nolint:gosec // path derives from a watched transcript; symlinks refused above
	if err != nil {
		return ""
	}
	var meta sessionMeta
	if err := json.Unmarshal(body, &meta); err != nil {
		return ""
	}
	return strings.TrimSpace(meta.Model)
}

// handle dispatches one decoded record onto the appropriate emit path.
// lineStart is the record's byte offset in the file, used as a
// resume-independent fallback event id.
func (st *parseState) handle(rec *rawLine, lineStart int64, res *adapter.ParseResult) {
	switch rec.Type {
	case "session":
		if rec.Cwd != "" {
			st.cwd = rec.Cwd
		}
		if rec.ID != "" {
			st.sessionID = rec.ID
		}
		st.emitSessionStart(rec, res)
	case "message":
		st.emitMessage(rec, lineStart, res)
	}
	// Any other record type is informational and skipped silently.
}

// projectRoot resolves the header cwd and memoizes the result.
//
// The translation is UNCONDITIONAL: crossmount.TranslateForeignPath maps
// a Windows `C:\...` cwd (which a WSL2 observer sees when reading a
// Windows-side install over /mnt/c) to its `/mnt/c/...` equivalent, so a
// drive-letter string never reaches git.Resolve — where filepath.Abs
// would treat it as relative and CWD-prefix the observer's OWN .git onto
// every event. Same shape as qwencode / qoder / kirocli.
func (st *parseState) projectRoot() string {
	if st.cwd == "" {
		return ""
	}
	cwd := crossmount.TranslateForeignPath(st.cwd)
	if root, ok := st.rootCache[cwd]; ok {
		return root
	}
	id, err := git.ResolveIdentity(cwd, git.IdentityOptions{})
	if err != nil {
		st.rootCache[cwd] = cwd
		return cwd
	}
	st.rootCache[cwd] = id.Root
	st.branch = id.Branch
	// id.Remote is already NormalizeRemote'd by ResolveIdentity.
	st.remote = id.Remote
	st.identity = id
	return id.Root
}

// emitSessionStart records the transcript's session header as a
// session-start marker, only when parsing from the very top of the file.
func (st *parseState) emitSessionStart(rec *rawLine, res *adapter.ParseResult) {
	if st.firstOffset != 0 || st.sessionStarted || st.sessionID == "" {
		return
	}
	st.sessionStarted = true
	root := st.projectRoot()
	res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
		SourceFile:    st.path,
		SourceEventID: "session_start:" + st.sessionID,
		SessionID:     st.sessionID,
		ProjectRoot:   root,
		Timestamp:     parseTimestamp(rec.Timestamp),
		GitBranch:     st.branch,
		GitRemote:     st.remote,
		Tool:          models.ToolCommandCode,
		ActionType:    models.ActionSessionStart,
		Target:        "startup",
		RawToolName:   models.ToolCommandCode + ".session_start",
		Success:       true,
	})
}

// emitMessage walks one `message` record: its content blocks become tool
// events / assistant text / user prompts / tool-result stamps, and its
// (outer) usage envelope becomes a TokenEvent.
func (st *parseState) emitMessage(rec *rawLine, lineStart int64, res *adapter.ParseResult) {
	if rec.Message == nil {
		return
	}
	root := st.projectRoot()
	ts := parseTimestamp(rec.Timestamp)
	lineID := st.eventKey(rec, lineStart)
	msgID := ""
	if rec.Message.Meta != nil {
		msgID = rec.Message.Meta.MessageID
	}
	blocks := rec.Message.contentBlocks()

	// Reasoning first: a thinking block precedes the tool calls it
	// justifies, so it is carried onto every event of the same record.
	reasoning := st.adapter.scrubber.String(thinkingText(blocks))

	toolPos := 0
	for _, block := range blocks {
		switch block.Type {
		case "tool_use":
			st.emitToolUse(rec, block, emitCtx{
				root: root, ts: ts, lineID: lineID, msgID: msgID,
				reasoning: reasoning, pos: toolPos,
			}, res)
			toolPos++
		case "tool_result":
			st.applyToolResult(block, res)
		case "text":
			st.emitText(rec, block, emitCtx{
				root: root, ts: ts, lineID: lineID, msgID: msgID,
				reasoning: reasoning,
			}, res)
		}
		// thinking blocks are folded into reasoning above; any other
		// block type is skipped silently.
	}

	st.emitTokens(rec, lineID, ts, root, msgID, res)
}

// emitCtx bundles the per-record context every block emitter needs, so
// the emit helpers keep a short parameter list.
type emitCtx struct {
	root      string
	ts        time.Time
	lineID    string
	msgID     string
	reasoning string
	pos       int
}

// eventKey returns the record's deterministic identity for SourceEventID
// construction: the outer 8-hex line `id` when present, otherwise the
// record's byte offset in the file (stable across re-parses AND across
// resume points, unlike a per-call line number).
func (st *parseState) eventKey(rec *rawLine, lineStart int64) string {
	if rec.ID != "" {
		return rec.ID
	}
	return "@" + strconv.FormatInt(lineStart, 10)
}

// emitToolUse records one tool_use block as a ToolEvent, optimistically
// successful until the paired tool_result says otherwise.
func (st *parseState) emitToolUse(rec *rawLine, block rawBlock, ec emitCtx, res *adapter.ParseResult) {
	action, recognised := mapToolName(block.Name)
	if !recognised && !st.unknownTool[block.Name] {
		st.unknownTool[block.Name] = true
		res.Warnings = append(res.Warnings,
			fmt.Sprintf("unrecognised tool name %q normalized to %q", block.Name, action))
	}
	scrubbedInput := st.adapter.scrubber.RawJSON(block.Input)
	accumulateToolCallCache(st.cacheAcc, block.Name, scrubbedInput)
	idx := len(res.ToolEvents)
	res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
		SourceFile:         st.path,
		SourceEventID:      "tool:" + toolEventKey(block.ID, ec.lineID, ec.pos),
		SessionID:          st.sessionID,
		ProjectRoot:        ec.root,
		Timestamp:          ec.ts,
		GitBranch:          st.branch,
		GitRemote:          st.remote,
		Model:              rec.Model,
		Tool:               models.ToolCommandCode,
		ActionType:         action,
		Target:             st.adapter.scrubber.String(targetFromInput(block.Input, block.Name)),
		RawToolName:        block.Name,
		RawToolInput:       scrubbedInput,
		ContentBytes:       authoredBytes(action, block.Input),
		PrecedingReasoning: ec.reasoning,
		MessageID:          ec.msgID,
		// Optimistic; corrected by the paired tool_result. When that
		// block hasn't been written yet, deferUnpairedTail rewinds past
		// this record rather than shipping the optimistic value — the
		// store cannot flip `success` on a later re-emit.
		Success: true,
	})
	if block.ID != "" {
		st.pendingCall[block.ID] = pendingMark{
			idx:       idx,
			lineStart: st.curLineStart,
			toolLen:   st.curToolLen,
			tokenLen:  st.curTokenLen,
		}
	}
}

// toolEventKey builds a deterministic per-call id, preferring the
// provider tool_use id and falling back to the record key + position.
func toolEventKey(callID, lineID string, pos int) string {
	if callID != "" {
		return callID
	}
	return lineID + ":" + strconv.Itoa(pos)
}

// emitText records a text block as a user prompt or an assistant message,
// dispatched on the message role (meta.source is a corroborating
// discriminator, not the authority — role is the Anthropic-shaped field
// every message carries).
func (st *parseState) emitText(rec *rawLine, block rawBlock, ec emitCtx, res *adapter.ParseResult) {
	if strings.TrimSpace(block.Text) == "" {
		return
	}
	scrubbed := st.adapter.scrubber.String(block.Text)
	ev := models.ToolEvent{
		SourceFile:         st.path,
		SessionID:          st.sessionID,
		ProjectRoot:        ec.root,
		Timestamp:          ec.ts,
		GitBranch:          st.branch,
		GitRemote:          st.remote,
		Tool:               models.ToolCommandCode,
		Target:             truncate(scrubbed, 200),
		PrecedingReasoning: ec.reasoning,
		MessageID:          ec.msgID,
		Success:            true,
	}
	if rec.Message.Role == "assistant" {
		ev.SourceEventID = "assistant:" + ec.lineID
		ev.Model = rec.Model
		ev.ActionType = models.ActionAssistantMessage
		ev.RawToolName = models.ToolCommandCode + ".assistant_text"
		capped := st.adapter.scrubber.String(contentcap.Cap(block.Text, contentcap.DefaultMaxBytes))
		ev.ToolOutput = capped
		accumulateTextCache(st.cacheAcc, capped, "assistant")
	} else {
		ev.SourceEventID = "prompt:" + ec.lineID
		ev.ActionType = models.ActionUserPrompt
		ev.RawToolName = models.ToolCommandCode + ".user_prompt"
		ev.RawToolInput = scrubbed
		accumulateTextCache(st.cacheAcc, scrubbed, "user")
	}
	res.ToolEvents = append(res.ToolEvents, ev)
}

// applyToolResult stamps success + scrubbed output onto the ToolEvent the
// matching tool_use produced. A result whose call landed in an earlier
// parse chunk has no pending entry and is skipped (the tool event itself
// was already persisted optimistically successful).
func (st *parseState) applyToolResult(block rawBlock, res *adapter.ParseResult) {
	mark, ok := st.pendingCall[block.ToolUseID]
	if !ok || mark.idx >= len(res.ToolEvents) {
		return
	}
	ev := &res.ToolEvents[mark.idx]
	// is_error was absent/null on every observed success; only an
	// explicit true marks the call failed.
	isErr := block.IsError != nil && *block.IsError
	ev.Success = !isErr
	if out := toolResultText(block.Content); out != "" {
		scrubbed := st.adapter.scrubber.String(contentcap.Cap(out, contentcap.DefaultMaxBytes))
		ev.ToolOutput = scrubbed
		accumulateToolResultCache(st.cacheAcc, scrubbed)
		if isErr {
			ev.ErrorMessage = truncate(scrubbed, 500)
		}
	}
	delete(st.pendingCall, block.ToolUseID)
}

// emitTokens turns a record's outer usage envelope into a TokenEvent with
// the GROSS input netted against cache-read. An absent or all-zero
// envelope emits nothing, so no phantom rows land.
func (st *parseState) emitTokens(rec *rawLine, lineID string, ts time.Time, root, msgID string, res *adapter.ParseResult) {
	if rec.Usage.isZero() {
		return
	}
	tp := tokenBundle(rec.Usage)
	model := rec.Model
	if model == "" {
		model = st.sidecarFallbackModel()
	}
	tokenSourceEventID := "tok:" + lineID
	if obs := emitCacheObservation(st.cacheAcc, st.path, st.sessionID, tokenSourceEventID, model, ts, tp); obs != nil {
		res.CacheObservations = append(res.CacheObservations, *obs)
	}
	res.TokenEvents = append(res.TokenEvents, models.TokenEvent{
		SourceFile:          st.path,
		SourceEventID:       tokenSourceEventID,
		SessionID:           st.sessionID,
		ProjectRoot:         root,
		GitBranch:           st.branch,
		GitRemote:           st.remote,
		Timestamp:           ts,
		Tool:                models.ToolCommandCode,
		Model:               model,
		InputTokens:         tp.inputNet,
		OutputTokens:        tp.output,
		CacheReadTokens:     tp.cacheRead,
		CacheCreationTokens: tp.cacheWrit,
		ReasoningTokens:     tp.reasoning,
		// Provider-reported cost: Command Code bills its own gateway for
		// ~12 open-weight models observer has no rate card for, so its
		// figure is authoritative (the opencode / pi precedent). A free
		// model genuinely reports 0, which the cost engine reads as "no
		// recorded cost" and resolves through the pricing table.
		EstimatedCostUSD: tp.costUSD,
		Source:           models.TokenSourceJSONL,
		Reliability:      models.ReliabilityApproximate,
		MessageID:        msgID,
	})
}

// thinkingText concatenates any thinking/reasoning blocks in a record.
// None were observed in the Phase-0 capture (only a non-reasoning free
// model was run), so this path is defensive: a reasoning-capable model
// is expected to produce them and they must not be dropped.
func thinkingText(blocks []rawBlock) string {
	var b strings.Builder
	for _, blk := range blocks {
		if blk.Type != "thinking" && blk.Type != "reasoning" {
			continue
		}
		text := blk.Thinking
		if strings.TrimSpace(text) == "" {
			text = blk.Text
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
